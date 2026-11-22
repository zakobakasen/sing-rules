use crate::{
    cache::Cache,
    model::{self, Config, DEFAULT_PRIORITY, Matcher, PRIVATE_IP, REJECT, Rule, Table},
    ruleset::{self, Source},
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Clone, Copy)]
enum Section {
    Route,
    Dns,
}

impl Section {
    fn name(self) -> &'static str {
        match self {
            Self::Route => "route",
            Self::Dns => "dns",
        }
    }

    fn target_kind(self) -> &'static str {
        match self {
            Self::Route => "outbound",
            Self::Dns => "DNS server",
        }
    }
}

enum Block {
    Top,
    Targets(Section),
    Rules(Section),
}

pub fn parse(text: &str, path: &Path, sing_box: &Path, cache: &Cache) -> Result<Config> {
    let mut route = Table::default();
    let mut dns = Table::default();
    let mut state = Block::Top;
    let mut blocks = BTreeSet::new();
    let mut sources = BTreeMap::new();
    let mut rows = Vec::new();

    for (index, raw) in text.lines().enumerate() {
        let line = split(raw, '#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let at = format!("{}:{}", path.display(), index + 1);
        let result = (|| -> Result<()> {
            match state {
                Block::Top
                    if matches!(line, "outbounds {" | "route {" | "dns-server {" | "dns {") =>
                {
                    ensure!(blocks.insert(line), "duplicate {line}");
                    state = match line {
                        "outbounds {" => Block::Targets(Section::Route),
                        "route {" => Block::Rules(Section::Route),
                        "dns-server {" => Block::Targets(Section::Dns),
                        "dns {" => Block::Rules(Section::Dns),
                        _ => unreachable!(),
                    };
                }
                Block::Top if line.starts_with("ruleset ") => {
                    let (name, source) = line[8..]
                        .split_once('=')
                        .context("expected ruleset NAME = file(...) or url(...)")?;
                    let name = name.trim();
                    validate_name(name)?;
                    ensure!(name != PRIVATE_IP, "reserved ruleset name {name}");
                    ensure!(!sources.contains_key(name), "duplicate ruleset {name}");
                    sources.insert(
                        name,
                        Source::parse(source.trim()).with_context(|| format!("ruleset {name}"))?,
                    );
                }
                Block::Top => {
                    bail!("expected outbounds, route, dns-server, dns, or ruleset declaration")
                }
                Block::Targets(_) | Block::Rules(_) if line == "}" => state = Block::Top,
                Block::Targets(section) => {
                    let tag = tag(line)?;
                    let table = match section {
                        Section::Route => &mut route,
                        Section::Dns => &mut dns,
                    };
                    ensure!(tag != REJECT, "{REJECT} is a reserved action");
                    ensure!(
                        table.targets.insert(tag.clone()),
                        "duplicate {} {tag:?}",
                        section.target_kind()
                    );
                }
                Block::Rules(section) => rows.push((section, line, at.clone())),
            }
            Ok(())
        })();
        result.with_context(|| at)?;
    }
    ensure!(
        matches!(state, Block::Top),
        "{}: missing closing brace",
        path.display()
    );
    ensure!(
        blocks.contains("route {"),
        "{}: missing route block",
        path.display()
    );
    ensure!(
        blocks.contains("outbounds {"),
        "{}: missing outbounds block",
        path.display()
    );
    let has_dns = blocks.contains("dns {");
    ensure!(
        !has_dns || blocks.contains("dns-server {"),
        "{}: dns requires a dns-server block",
        path.display()
    );
    let directory = path.parent().context("invalid DSL path")?;
    let mut imported = BTreeMap::new();

    for (section, line, at) in rows {
        let is_dns = matches!(section, Section::Dns);
        let table = if is_dns { &mut dns } else { &mut route };
        let result = (|| -> Result<()> {
            let fields: Vec<_> = split(line, ',').map(str::trim).collect();
            let (kind, content, target, priority) = match fields.as_slice() {
                [content, target] => (None, *content, *target, DEFAULT_PRIORITY),
                [kind, content, target] => (Some(*kind), *content, *target, DEFAULT_PRIORITY),
                ["RuleSet", content, target, option] => {
                    (Some("RuleSet"), *content, *target, parse_priority(option)?)
                }
                _ => {
                    bail!("expected [type,] match, target or RuleSet, name, target, integer")
                }
            };
            let target = tag(target)?;
            ensure!(
                target == REJECT || table.targets.contains(&target),
                "undeclared {} {target:?}",
                section.target_kind()
            );

            let rule = |source| Rule {
                target: target.clone(),
                source,
                ruleset: (kind == Some("RuleSet")).then(|| content.to_owned()),
                priority,
            };
            if kind == Some("RuleSet") {
                validate_name(content)?;
                if content == PRIVATE_IP {
                    if is_dns {
                        warn_no_dns_rules(&at, content);
                    } else {
                        table.add(Matcher::PrivateIp, rule(at.clone()));
                    }
                    return Ok(());
                }
                let source = sources
                    .get(content)
                    .with_context(|| format!("unknown ruleset {content:?}"))?;
                if !imported.contains_key(source) {
                    imported.insert(source, ruleset::load(source, directory, sing_box, cache)?);
                }
                let mut any = false;
                for (matcher, origin) in &imported[source] {
                    if !is_dns || matches!(matcher, Matcher::Exact(_) | Matcher::Suffix { .. }) {
                        table.add(matcher.clone(), rule(format!("{at} ({origin})")));
                        any = true;
                    }
                }
                if is_dns && !any {
                    warn_no_dns_rules(&at, content);
                }
            } else {
                let matcher = parse_matcher(kind, content)?;
                ensure!(
                    !is_dns || !matches!(matcher, Matcher::Ip(_)),
                    "IP rules are not allowed in dns"
                );
                ensure!(
                    !is_dns || matcher != Matcher::Any || target != REJECT,
                    "DNS fallback (*) must name a DNS server"
                );
                table.add(matcher, rule(at.clone()));
            }
            Ok(())
        })();
        result.with_context(|| at)?;
    }

    for (section, table) in [
        (Section::Route, Some(&route)),
        (Section::Dns, has_dns.then_some(&dns)),
    ] {
        if let Some(table) = table {
            ensure!(
                table.rules.contains_key(&Matcher::Any),
                "{}: missing {} global fallback (*, {})",
                path.display(),
                section.name(),
                section.target_kind()
            );
            table
                .check_conflicts()
                .with_context(|| format!("in {} block", section.name()))?;
        }
    }
    Ok(Config {
        route,
        dns: has_dns.then_some(dns),
    })
}

fn warn_no_dns_rules(at: &str, name: &str) {
    eprintln!("warning: {at}: RuleSet {name} has no domain rules for dns");
}

fn parse_priority(option: &str) -> Result<i64> {
    option
        .parse()
        .context("priority must be a signed 64-bit integer in the fourth column")
}

fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)),
        "invalid ruleset name {name:?}; expected [A-Za-z0-9._~-]+"
    );
    Ok(())
}

fn tag(text: &str) -> Result<String> {
    if text.starts_with('"') {
        let value: String = serde_json::from_str(text).context("invalid quoted outbound name")?;
        ensure!(!value.is_empty(), "empty outbound name");
        return Ok(value);
    }
    ensure!(
        !text.is_empty()
            && !text.chars().any(char::is_whitespace)
            && !text.contains([',', '"', '{', '}']),
        "invalid outbound name {text:?}; quote names containing spaces or punctuation"
    );
    Ok(text.to_string())
}

fn parse_matcher(kind: Option<&str>, text: &str) -> Result<Matcher> {
    match kind {
        Some("IP") => Ok(Matcher::Ip(model::ip(text).context("invalid IP or CIDR")?)),
        Some("Domain") => Ok(Matcher::Exact(model::domain(text)?)),
        Some("DomainSuffix") => strict_suffix(text),
        Some("Any") if text == "*" => Ok(Matcher::Any),
        Some(kind) => {
            bail!("expected IP, Domain, DomainSuffix, RuleSet, or Any; received {kind:?}")
        }
        None if text == "*" => Ok(Matcher::Any),
        None if text.starts_with('@') => {
            bail!("ruleset references require explicit RuleSet, name, outbound")
        }
        None if text.starts_with("*.") => strict_suffix(text),
        None if text.contains(['/', ':']) => parse_matcher(Some("IP"), text),
        None => match model::ip(text) {
            Ok(ip) => Ok(Matcher::Ip(ip)),
            Err(_) => Ok(Matcher::Exact(model::domain(text)?)),
        },
    }
}

fn strict_suffix(text: &str) -> Result<Matcher> {
    let name = text
        .strip_prefix("*.")
        .context("DomainSuffix requires *.domain")?;
    Ok(Matcher::Suffix {
        name: model::domain(name)?,
        subdomains_only: true,
    })
}

fn split(text: &str, separator: char) -> impl Iterator<Item = &str> {
    let mut quoted = false;
    let mut escaped = false;
    text.split(move |ch| {
        if escaped {
            escaped = false;
        } else if ch == '"' {
            quoted = !quoted;
        } else if quoted && ch == '\\' {
            escaped = true;
        } else if !quoted && ch == separator {
            return true;
        }
        false
    })
}
