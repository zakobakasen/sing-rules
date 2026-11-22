use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use std::{
    collections::{BTreeMap, BTreeSet},
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
}

#[derive(Default)]
pub struct Table {
    pub outbounds: BTreeSet<String>,
    pub rules: BTreeMap<Matcher, Rule>,
}

impl Table {
    pub fn add(&mut self, matcher: Matcher, target: &str, source: String) -> Result<()> {
        if let Some(previous) = self.rules.get(&matcher) {
            ensure!(
                previous.target == target,
                "{source}: conflicting rule for {matcher:?}; previous rule at {}",
                previous.source
            );
        } else {
            self.rules.insert(
                matcher,
                Rule {
                    target: target.into(),
                    source,
                },
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
