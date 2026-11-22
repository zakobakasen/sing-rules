use crate::{
    model::{self, Matcher, PRIVATE_IP, REJECT, Table},
    ruleset::{self, Source},
};
use anyhow::{Context, Result, bail, ensure};
use std::{collections::BTreeMap, path::Path};

enum Block {
    Top,
    Outbound,
    Table,
}

pub fn parse(text: &str, path: &Path, sing_box: &Path) -> Result<Table> {
    let mut table = Table::default();
    let mut state = Block::Top;
    let mut outbound_seen = false;
    let mut table_seen = false;
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
                Block::Top if line == "outbound {" => {
                    ensure!(!outbound_seen, "duplicate outbound block");
                    outbound_seen = true;
                    state = Block::Outbound;
                }
                Block::Top if line == "table default {" => {
                    ensure!(!table_seen, "duplicate default table");
                    table_seen = true;
                    state = Block::Table;
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
                Block::Top => bail!("expected outbound, ruleset, or table default declaration"),
                Block::Outbound if line == "}" => state = Block::Top,
                Block::Outbound => {
                    let tag = tag(line)?;
                    ensure!(tag != REJECT, "{REJECT} is a reserved action");
                    ensure!(
                        table.outbounds.insert(tag.clone()),
                        "duplicate outbound {tag:?}"
                    );
                }
                Block::Table if line == "}" => state = Block::Top,
                Block::Table => rows.push((line, at.clone())),
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
    ensure!(table_seen, "{}: missing table default", path.display());
    ensure!(outbound_seen, "{}: missing outbound block", path.display());
    let directory = path.parent().context("invalid DSL path")?;
    let mut imported = BTreeMap::new();

    for (line, at) in rows {
        let result = (|| -> Result<()> {
            let fields: Vec<_> = split(line, ',').map(str::trim).collect();
            let (kind, content, target) = match fields.as_slice() {
                [content, target] => (None, *content, *target),
                [kind, content, target] => (Some(*kind), *content, *target),
                _ => bail!("expected [type,] match, outbound"),
            };
            let target = tag(target)?;
            ensure!(
                target == REJECT || table.outbounds.contains(&target),
                "undeclared outbound {target:?}"
            );

            if kind == Some("RuleSet") {
                validate_name(content)?;
                if content == PRIVATE_IP {
                    return table.add(Matcher::PrivateIp, &target, at.clone());
                }
                let source = sources
                    .get(content)
                    .with_context(|| format!("unknown ruleset {content:?}"))?;
                if !imported.contains_key(content) {
                    imported.insert(content, ruleset::load(source, directory, sing_box)?);
                }
                for (matcher, origin) in &imported[content] {
                    table.add(matcher.clone(), &target, format!("{at} ({origin})"))?;
                }
                return Ok(());
            }
            table.add(parse_matcher(kind, content)?, &target, at.clone())
        })();
        result.with_context(|| at)?;
    }

    ensure!(
        table.rules.contains_key(&Matcher::Any),
        "{}: missing global fallback (*, outbound)",
        path.display()
    );
    Ok(table)
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
