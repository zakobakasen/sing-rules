use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    net::{IpAddr, Ipv4Addr},
};

pub const PRIVATE_IP: &str = "PrivateIP";
pub const REJECT: &str = "REJECT";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Matcher {
    Ip(IpNet),
    Exact(String),
    Suffix { name: String, subdomains_only: bool },
    PrivateIp,
    Any,
}

pub struct Rule {
    pub target: String,
    pub source: String,
    pub ruleset: Option<String>,
    pub priority: i32,
}

impl Rule {
    fn describe(&self) -> String {
        let label = self
            .ruleset
            .as_deref()
            .map_or_else(|| "table rule".into(), |name| format!("RuleSet {name}"));
        format!(
            "{label} -> {} (priority={}) at {}",
            self.target, self.priority, self.source
        )
    }
}

#[derive(Default)]
pub struct Table {
    pub outbounds: BTreeSet<String>,
    pub rules: BTreeMap<Matcher, Rule>,
    conflicts: BTreeMap<Matcher, Rule>,
}

impl Table {
    pub fn add(&mut self, matcher: Matcher, rule: Rule) {
        match self.rules.entry(matcher) {
            Entry::Vacant(entry) => {
                entry.insert(rule);
            }
            Entry::Occupied(mut entry) => match rule.priority.cmp(&entry.get().priority) {
                Ordering::Greater => {
                    self.conflicts.remove(entry.key());
                    entry.insert(rule);
                }
                Ordering::Equal if rule.target != entry.get().target => {
                    self.conflicts.entry(entry.key().clone()).or_insert(rule);
                }
                _ => {}
            },
        }
    }

    pub fn check_conflicts(&self) -> Result<()> {
        // Check after all rules are loaded. A later higher priority can resolve a tie.
        if let Some((matcher, second)) = self.conflicts.first_key_value() {
            let first = &self.rules[matcher];
            let scope = match matcher {
                Matcher::Ip(net) => format!("IP prefix {net}"),
                Matcher::Exact(name) => format!("exact domain {name}"),
                Matcher::Suffix {
                    name,
                    subdomains_only: true,
                } => format!("subdomains of {name}"),
                Matcher::Suffix {
                    name,
                    subdomains_only: false,
                } => format!("domain suffix {name} (including subdomains)"),
                Matcher::PrivateIp => "PrivateIP".into(),
                Matcher::Any => "global fallback (*)".into(),
            };
            let help = if first.ruleset.is_some() || second.ruleset.is_some() {
                "\n  help: set priority=... on the RuleSet reference that should win"
            } else {
                ""
            };
            bail!(
                "conflicting rules for {scope}\n  {}\n  {}{help}",
                first.describe(),
                second.describe()
            );
        }
        Ok(())
    }
}

pub fn ip(text: &str) -> Result<IpNet> {
    let network = if text.contains('/') {
        text.parse::<IpNet>()?.trunc()
    } else {
        IpNet::from(text.parse::<IpAddr>()?)
    };
    match network {
        IpNet::V6(net) if net.prefix_len() >= 96 => match net.network().to_ipv4_mapped() {
            Some(v4) => Ok(IpNet::new(v4.into(), net.prefix_len() - 96)?),
            None => Ok(network),
        },
        _ => Ok(network),
    }
}

pub fn mapped_network() -> IpNet {
    IpNet::new(Ipv4Addr::UNSPECIFIED.to_ipv6_mapped().into(), 96).unwrap()
}

pub fn ipv4_alias(net: ipnet::Ipv4Net) -> IpNet {
    IpNet::new(net.network().to_ipv6_mapped().into(), net.prefix_len() + 96).unwrap()
}

pub fn domain(text: &str) -> Result<String> {
    let root_dots = ['.', '。', '．', '｡'];
    let unrooted = text.strip_suffix(root_dots).unwrap_or(text);
    let name = idna::domain_to_ascii_strict(unrooted).context("invalid domain")?;
    ensure!(
        !name.is_empty() && !name.contains('*'),
        "invalid domain {text:?}"
    );
    Ok(name)
}
