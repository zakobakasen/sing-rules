use crate::model::{self, Config, Matcher, REJECT, Table};
use anyhow::{Context, Result, ensure};
use ipnet::{IpNet, Ipv6Net};
use serde_json::{Map, Value, json};
use std::{
    borrow::Cow,
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    net::Ipv6Addr,
};

struct Node<'a> {
    matcher: &'a Matcher,
    action: &'a str,
    parent: Option<usize>,
    pending_children: usize,
}

#[derive(Clone, Debug)]
struct Layer<'a> {
    action: &'a str,
    matchers: Vec<Cow<'a, Matcher>>,
}

pub enum BaseRules {
    RequireEmpty,
    Replace,
    First,
}

pub fn compile(
    config: &Config,
    mut base: Value,
    base_rules: BaseRules,
    format: crate::export::Format<'_>,
) -> Result<Value> {
    let root = base
        .as_object_mut()
        .context("base configuration must be an object")?;
    let prefix = compile_route(&config.route, root, base_rules)?;
    if let Some(table) = &config.dns {
        compile_dns(table, root)?;
    }
    crate::export::export(&mut base, prefix, config.dns.is_some(), format)?;
    Ok(base)
}

fn compile_dns(table: &Table, root: &mut Map<String, Value>) -> Result<()> {
    let dns = root
        .get_mut("dns")
        .and_then(Value::as_object_mut)
        .context("dns block requires a base dns object with servers")?;
    let tags = dns
        .get("servers")
        .and_then(Value::as_array)
        .context("dns block requires base dns.servers")?;
    for target in &table.targets {
        ensure!(
            tags.iter()
                .any(|server| server.get("tag").and_then(Value::as_str) == Some(target)),
            "DNS server {target:?} is missing from base dns.servers"
        );
    }
    let rules = domain_layers(table)
        .into_iter()
        .map(|layer| emit(layer, false, "server"))
        .collect();
    dns.insert("rules".into(), Value::Array(rules));
    dns.insert("final".into(), json!(table.rules[&Matcher::Any].target));
    Ok(())
}

fn compile_route(
    table: &Table,
    root: &mut Map<String, Value>,
    base_rules: BaseRules,
) -> Result<usize> {
    let tags: BTreeSet<_> = ["outbounds", "endpoints"]
        .into_iter()
        .filter_map(|field| root.get(field).and_then(Value::as_array))
        .flatten()
        .filter_map(|item| item.get("tag").and_then(Value::as_str))
        .collect();
    for tag in &table.targets {
        ensure!(
            tags.contains(tag.as_str()),
            "outbound {tag:?} is missing from base configuration"
        );
    }

    let route = root
        .entry("route")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .context("base route must be an object")?;
    let existing = route.remove("rules");
    let prefix = match base_rules {
        BaseRules::RequireEmpty => {
            ensure!(
                existing
                    .as_ref()
                    .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty)),
                "base route.rules is populated; pass --base-rules-first to preserve it or --replace-route to replace it"
            );
            Vec::new()
        }
        BaseRules::Replace => Vec::new(),
        BaseRules::First => match existing {
            Some(Value::Array(rules)) => rules,
            None => Vec::new(),
            Some(_) => anyhow::bail!("base route.rules must be an array"),
        },
    };

    let fallback = &table.rules[&Matcher::Any].target;
    let needs_dns = table.rules.iter().any(|(matcher, rule)| {
        matches!(matcher, Matcher::Ip(_) | Matcher::PrivateIp) && rule.target != *fallback
    });
    let mut layers = domain_layers(table);
    let mut trailing_ip_layers = Vec::new();
    if needs_dns {
        let mut ip = ip_layers(table);
        if !prefix.iter().any(contains_resolve) {
            ip = compact_ip_layers(ip);
        }
        trailing_ip_layers = trailing_ip_layers_for_table(table, fallback);
        for layer in ip.into_iter().chain(trailing_ip_layers.iter().cloned()) {
            push_layer(&mut layers, layer);
        }
    }
    let mut rules: Vec<_> = layers
        .into_iter()
        .map(|layer| emit(layer, false, "outbound"))
        .collect();
    if needs_dns {
        // Every existing IP has decided its route before an unmatched domain reaches resolve.
        let mut known_ip_fallback = json!({"ip_cidr": ["0.0.0.0/0", "::/0"]});
        set_action(
            known_ip_fallback.as_object_mut().unwrap(),
            fallback,
            "outbound",
        );
        rules.push(known_ip_fallback);
        rules.push(json!({"action": "resolve"}));

        let mut resolved_layers = resolved_ip_layers(table);
        for layer in trailing_ip_layers {
            push_layer(&mut resolved_layers, layer);
        }
        rules.extend(
            resolved_layers
                .into_iter()
                .map(|layer| emit(layer, true, "outbound")),
        );
    }
    if fallback == REJECT {
        if let Some(last) = rules.last_mut().filter(|last| last["action"] == "reject") {
            *last = json!({"action": "reject"});
        } else {
            rules.push(json!({"action": "reject"}));
        }
        route.remove("final");
    } else {
        route.insert("final".into(), json!(fallback));
    }
    let mut combined = prefix;
    let prefix_len = combined.len();
    combined.append(&mut rules);
    route.insert("rules".into(), Value::Array(combined));
    Ok(prefix_len)
}

fn compact_ip_layers(layers: Vec<Layer<'_>>) -> Vec<Layer<'_>> {
    let input = layers
        .into_iter()
        .map(|layer| crate::ip_opt::IpLayer {
            action: layer.action,
            networks: layer
                .matchers
                .iter()
                .map(|matcher| match matcher.as_ref() {
                    Matcher::Ip(net) => *net,
                    _ => unreachable!("IP layers only contain CIDRs"),
                })
                .collect(),
        })
        .collect();
    crate::ip_opt::compact(input)
        .into_iter()
        .map(|layer| Layer {
            action: layer.action,
            matchers: layer
                .networks
                .into_iter()
                .map(|network| Cow::Owned(Matcher::Ip(network)))
                .collect(),
        })
        .collect()
}

fn contains_resolve(rule: &Value) -> bool {
    rule["action"] == "resolve"
        || rule["rules"]
            .as_array()
            .is_some_and(|rules| rules.iter().any(contains_resolve))
}

fn trailing_ip_layers_for_table<'a>(table: &'a Table, fallback: &str) -> Vec<Layer<'a>> {
    let mut layers = Vec::new();
    if let Some(rule) = table.rules.get(&Matcher::PrivateIp) {
        layers.push(Layer {
            action: &rule.target,
            matchers: vec![Cow::Borrowed(&Matcher::PrivateIp)],
        });
    }

    let defaults: Vec<_> = table
        .rules
        .iter()
        .filter(|(matcher, _)| matches!(matcher, Matcher::Ip(net) if net.prefix_len() == 0))
        .collect();
    if defaults.iter().any(|(_, rule)| rule.target != fallback) {
        // V4 comes first if the DNS answer set contains both families.
        for (matcher, rule) in defaults {
            push_layer(
                &mut layers,
                Layer {
                    action: &rule.target,
                    matchers: vec![Cow::Borrowed(matcher)],
                },
            );
        }
    }
    layers
}

fn resolved_ip_layers(table: &Table) -> Vec<Layer<'_>> {
    // sing-box matches any DNS answer. A shorter prefix must not win merely
    // because its prefix is disjoint from a longer rule on another answer.
    let mut candidates: Vec<_> = table
        .rules
        .iter()
        .filter_map(|(matcher, rule)| match matcher {
            Matcher::Ip(net) if net.prefix_len() > 0 => Some((
                Reverse(net.prefix_len()),
                rule.target != REJECT,
                rule.target.as_str(),
                matcher,
            )),
            _ => None,
        })
        .collect();
    candidates.sort_unstable();

    let mut layers = Vec::new();
    for (_, _, action, matcher) in candidates {
        push_layer(
            &mut layers,
            Layer {
                action,
                matchers: vec![Cow::Borrowed(matcher)],
            },
        );
    }
    layers
}

fn domain_layers(table: &Table) -> Vec<Layer<'_>> {
    let mut regions: BTreeMap<&str, Vec<Cow<'_, Matcher>>> = BTreeMap::new();
    for (matcher, rule) in &table.rules {
        if matches!(matcher, Matcher::DomainRegion { .. }) {
            regions
                .entry(&rule.target)
                .or_default()
                .push(Cow::Borrowed(matcher));
        }
    }
    if !regions.is_empty() {
        return regions
            .into_iter()
            .map(|(action, matchers)| Layer { action, matchers })
            .collect();
    }

    let mut candidates: Vec<_> = table
        .rules
        .keys()
        .filter_map(|matcher| match matcher {
            Matcher::Exact(name) => Some((name, 2, matcher)),
            Matcher::Suffix {
                name,
                subdomains_only,
            } => Some((name, usize::from(*subdomains_only), matcher)),
            _ => None,
        })
        .collect();
    candidates.sort_unstable_by_key(|(name, kind, _)| {
        (name.bytes().filter(|&b| b == b'.').count(), *name, *kind)
    });
    let mut nodes = Vec::with_capacity(candidates.len());
    let mut suffixes = BTreeMap::<(&str, bool), usize>::new();
    for (name, kind, matcher) in candidates {
        let same_root = (kind != 0)
            .then(|| suffixes.get(&(name.as_str(), false)))
            .flatten();
        let covering = same_root
            .or_else(|| {
                let mut suffix = name.as_str();
                while let Some((_, rest)) = suffix.split_once('.') {
                    if let Some(index) = suffixes
                        .get(&(rest, true))
                        .or_else(|| suffixes.get(&(rest, false)))
                    {
                        return Some(index);
                    }
                    suffix = rest;
                }
                None
            })
            .copied();

        let action = &table.rules[matcher].target;
        if let Some(index) = add_node(&mut nodes, matcher, action, covering)
            && kind != 2
        {
            suffixes.insert((name, kind == 1), index);
        }
    }
    compact_domain_layers(schedule(nodes))
}

fn compact_domain_layers(mut layers: Vec<Layer<'_>>) -> Vec<Layer<'_>> {
    let mut index = 0;
    while index + 2 < layers.len() {
        let [first, middle, last] = &layers[index..index + 3] else {
            unreachable!()
        };
        let replacement = (first.action == last.action)
            .then(|| {
                let [a, b, c] = [first, middle, last]
                    .map(|layer| layer.matchers.iter().map(|matcher| matcher.as_ref()));
                let (carved, combined) = crate::domain_set::compact_exception(a, b, c)?;
                let mut result = Vec::new();
                if !carved.is_empty() {
                    result.push(Layer {
                        action: middle.action,
                        matchers: carved.into_iter().map(Cow::Owned).collect(),
                    });
                }
                result.push(Layer {
                    action: first.action,
                    matchers: combined.into_iter().map(Cow::Owned).collect(),
                });
                Some(result)
            })
            .flatten();
        if let Some(replacement) = replacement {
            layers.splice(index..index + 3, replacement);
            index = index.saturating_sub(2);
        } else {
            index += 1;
        }
    }
    let mut merged = Vec::new();
    for layer in layers {
        push_layer(&mut merged, layer);
    }
    merged
}

fn ip_layers(table: &Table) -> Vec<Layer<'_>> {
    let mut candidates: Vec<_> = table
        .rules
        .keys()
        .filter_map(|matcher| match matcher {
            Matcher::Ip(net) if net.prefix_len() != 0 => Some((*net, matcher)),
            _ => None,
        })
        .collect();
    candidates.sort_unstable_by_key(|(net, _)| (net.addr(), net.prefix_len()));
    let mut nodes = Vec::with_capacity(candidates.len());
    // Sorted CIDRs form a preorder traversal of the compressed prefix trie.
    let mut path: Vec<(IpNet, usize)> = Vec::new();
    for (net, matcher) in candidates {
        while path
            .last()
            .is_some_and(|(ancestor, _)| !ancestor.contains(&net))
        {
            path.pop();
        }
        let covering = path.last().map(|(_, index)| *index);
        if let Some(index) = add_node(&mut nodes, matcher, &table.rules[matcher].target, covering) {
            path.push((net, index));
        }
    }
    schedule(nodes)
}

fn add_node<'a>(
    nodes: &mut Vec<Node<'a>>,
    matcher: &'a Matcher,
    action: &'a str,
    parent: Option<usize>,
) -> Option<usize> {
    if let Some(parent) = parent {
        if nodes[parent].action == action {
            return None;
        }
        nodes[parent].pending_children += 1;
    }
    let index = nodes.len();
    nodes.push(Node {
        matcher,
        action,
        parent,
        pending_children: 0,
    });
    Some(index)
}

fn schedule(mut nodes: Vec<Node<'_>>) -> Vec<Layer<'_>> {
    let mut ready = BTreeMap::<&str, Vec<usize>>::new();
    for (index, node) in nodes.iter().enumerate() {
        if node.pending_children == 0 {
            ready.entry(node.action).or_default().push(index);
        }
    }
    let mut layers = Vec::new();
    while let Some((action, indices)) = ready.pop_first() {
        let mut matchers = Vec::with_capacity(indices.len());
        for index in indices {
            matchers.push(Cow::Borrowed(nodes[index].matcher));
            if let Some(parent) = nodes[index].parent {
                nodes[parent].pending_children -= 1;
                if nodes[parent].pending_children == 0 {
                    ready.entry(nodes[parent].action).or_default().push(parent);
                }
            }
        }
        push_layer(&mut layers, Layer { action, matchers });
    }
    layers
}

fn push_layer<'a>(layers: &mut Vec<Layer<'a>>, layer: Layer<'a>) {
    if let Some(previous) = layers
        .last_mut()
        .filter(|previous| previous.action == layer.action)
    {
        previous.matchers.extend(layer.matchers);
    } else {
        layers.push(layer);
    }
}

fn emit(layer: Layer<'_>, multiple_addresses: bool, target_field: &str) -> Value {
    let mut ip = Vec::new();
    let mut ipv6_excluding_mapped = Vec::new();
    let mut exact = BTreeSet::new();
    let mut suffix = BTreeSet::new();
    let mut rule = Map::new();
    let mut branches = Vec::new();
    for matcher in layer.matchers {
        match matcher.as_ref() {
            Matcher::Ip(IpNet::V4(net)) => {
                ip.push(IpNet::V4(*net));
                ip.push(model::ipv4_alias(*net));
            }
            Matcher::Ip(net) if net.contains(&model::mapped_network()) => {
                if multiple_addresses {
                    ip.extend(exclude_mapped_subnet(net.prefix_len()));
                } else {
                    ipv6_excluding_mapped.push(*net);
                }
            }
            Matcher::Ip(net) => ip.push(*net),
            Matcher::Exact(name) => {
                exact.insert(name.clone());
                exact.insert(format!("{name}."));
            }
            Matcher::Suffix {
                name,
                subdomains_only,
            } => {
                let prefix = if *subdomains_only { "." } else { "" };
                suffix.insert(format!("{prefix}{name}"));
                suffix.insert(format!("{prefix}{name}."));
            }
            Matcher::DomainRegion { scope, excluded } => {
                if excluded.is_empty() {
                    use crate::domain_set::Kind;
                    let (field, prefix) = match scope.kind {
                        Kind::Exact => (&mut exact, ""),
                        Kind::Inclusive => (&mut suffix, ""),
                        Kind::Descendants => (&mut suffix, "."),
                    };
                    field.insert(format!("{prefix}{}", scope.name));
                    field.insert(format!("{prefix}{}.", scope.name));
                } else {
                    let mut children = vec![domain_condition(scope)];
                    children.extend(excluded.iter().map(|hole| {
                        let mut condition = domain_condition(hole);
                        condition["invert"] = json!(true);
                        condition
                    }));
                    branches.push(json!({"type": "logical", "mode": "and", "rules": children}));
                }
            }
            Matcher::PrivateIp => {
                rule.insert("ip_is_private".into(), json!(true));
            }
            Matcher::Any => unreachable!("global fallback is emitted separately"),
        }
    }
    // An exact name and its descendants cover one inclusive suffix.
    exact.retain(|name| {
        if suffix.remove(&format!(".{name}")) {
            suffix.insert(name.clone());
            false
        } else {
            true
        }
    });
    for (field, value) in [
        ("ip_cidr", cidrs(ip)),
        ("domain", json!(exact)),
        ("domain_suffix", json!(suffix)),
    ] {
        if !value.as_array().unwrap().is_empty() {
            rule.insert(field.into(), value);
        }
    }
    if !ipv6_excluding_mapped.is_empty() {
        branches.push(json!({"type": "logical", "mode": "and", "rules": [
            {"ip_cidr": cidrs(ipv6_excluding_mapped)},
            {"ip_cidr": [model::mapped_network().to_string()], "invert": true}
        ]}));
    }
    if !branches.is_empty() {
        if !rule.is_empty() {
            branches.insert(0, Value::Object(rule));
        }
        let combined = if branches.len() == 1 {
            branches.pop().unwrap()
        } else {
            json!({"type": "logical", "mode": "or", "rules": branches})
        };
        rule = combined.as_object().unwrap().clone();
    }
    set_action(&mut rule, layer.action, target_field);
    Value::Object(rule)
}

fn domain_condition(scope: &crate::domain_set::Scope) -> Value {
    use crate::domain_set::Kind;
    let name = &scope.name;
    match scope.kind {
        Kind::Exact => json!({"domain": [name, format!("{name}.")]}),
        Kind::Inclusive => json!({"domain_suffix": [name, format!("{name}.")]}),
        Kind::Descendants => json!({"domain_suffix": [format!(".{name}"), format!(".{name}.")]}),
    }
}

fn set_action(rule: &mut Map<String, Value>, target: &str, target_field: &str) {
    let action = if target == REJECT {
        "reject"
    } else {
        rule.insert(target_field.into(), json!(target));
        "route"
    };
    rule.insert("action".into(), json!(action));
}

fn exclude_mapped_subnet(covering_bits: u8) -> impl Iterator<Item = IpNet> {
    // Negating a mapped CIDR would reject the whole answer set if any
    // address were mapped. Use the siblings of the mapped prefix instead.
    let mapped = model::mapped_network();
    let address = match mapped.addr() {
        std::net::IpAddr::V6(address) => u128::from(address),
        _ => unreachable!(),
    };
    (covering_bits + 1..=mapped.prefix_len()).map(move |bits| {
        let sibling = Ipv6Addr::from(address ^ (1 << (128 - bits)));
        IpNet::V6(Ipv6Net::new(sibling, bits).unwrap().trunc())
    })
}

fn cidrs(networks: Vec<IpNet>) -> Value {
    json!(
        IpNet::aggregate(&networks)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    )
}
