use crate::model::{self, Matcher, REJECT, Table};
use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

struct Node<'a> {
    matcher: &'a Matcher,
    action: &'a str,
    parent: Option<usize>,
    pending_children: usize,
}

#[derive(Debug)]
struct Layer<'a> {
    action: &'a str,
    matchers: Vec<&'a Matcher>,
}

pub fn compile(table: &Table, mut base: Value, replace_route: bool) -> Result<Value> {
    let root = base
        .as_object_mut()
        .context("base configuration must be an object")?;
    let tags: BTreeSet<_> = ["outbounds", "endpoints"]
        .into_iter()
        .filter_map(|field| root.get(field).and_then(Value::as_array))
        .flatten()
        .filter_map(|item| item.get("tag").and_then(Value::as_str))
        .collect();
    for tag in &table.outbounds {
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
    if let Some(existing) = route.get("rules") {
        ensure!(
            replace_route || existing.as_array().is_some_and(Vec::is_empty),
            "base route.rules is populated; pass --replace-route to replace it explicitly"
        );
    }

    let mut layers = domain_layers(table);
    for layer in ip_layers(table) {
        push_layer(&mut layers, layer);
    }
    if let Some(rule) = table.rules.get(&Matcher::PrivateIp) {
        push_layer(
            &mut layers,
            Layer {
                action: &rule.target,
                matchers: vec![&Matcher::PrivateIp],
            },
        );
    }

    let fallback = &table.rules[&Matcher::Any].target;
    for (matcher, rule) in &table.rules {
        if matches!(matcher, Matcher::Ip(net) if net.prefix_len() == 0) && rule.target != *fallback
        {
            push_layer(
                &mut layers,
                Layer {
                    action: &rule.target,
                    matchers: vec![matcher],
                },
            );
        }
    }
    let mut rules: Vec<_> = layers.into_iter().map(emit).collect();
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
    route.insert("rules".into(), json!(rules));
    Ok(base)
}

fn domain_layers(table: &Table) -> Vec<Layer<'_>> {
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
    schedule(nodes)
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
            matchers.push(nodes[index].matcher);
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

fn emit(layer: Layer<'_>) -> Value {
    let mut ip = Vec::new();
    let mut ipv6_excluding_mapped = Vec::new();
    let mut exact = BTreeSet::new();
    let mut suffix = BTreeSet::new();
    let mut rule = Map::new();
    for matcher in layer.matchers {
        match matcher {
            Matcher::Ip(IpNet::V4(net)) => {
                ip.push(IpNet::V4(*net));
                ip.push(model::ipv4_alias(*net));
            }
            Matcher::Ip(net) if net.contains(&model::mapped_network()) => {
                ipv6_excluding_mapped.push(*net)
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
            Matcher::PrivateIp => {
                rule.insert("ip_is_private".into(), json!(true));
            }
            Matcher::Any => unreachable!("global fallback is emitted separately"),
        }
    }
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
        let guarded = json!({"type": "logical", "mode": "and", "rules": [
            {"ip_cidr": cidrs(ipv6_excluding_mapped)},
            {"ip_cidr": [model::mapped_network().to_string()], "invert": true}
        ]});
        let ordinary = Value::Object(rule);
        let combined = if ordinary.as_object().unwrap().is_empty() {
            guarded
        } else {
            json!({"type": "logical", "mode": "or", "rules": [ordinary, guarded]})
        };
        rule = combined.as_object().unwrap().clone();
    }
    let action = if layer.action == REJECT {
        "reject"
    } else {
        rule.insert("outbound".into(), json!(layer.action));
        "route"
    };
    rule.insert("action".into(), json!(action));
    Value::Object(rule)
}

fn cidrs(networks: Vec<IpNet>) -> Value {
    json!(
        IpNet::aggregate(&networks)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    )
}
