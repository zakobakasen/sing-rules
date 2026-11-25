//! Local rewrites for the first-match list of known destination IPs.
use crate::model::subtract_ip_prefix;
use ipnet::IpNet;

pub(crate) struct IpLayer<'a> {
    pub action: &'a str,
    pub networks: Vec<IpNet>,
}

pub(crate) fn compact(mut layers: Vec<IpLayer<'_>>) -> Vec<IpLayer<'_>> {
    if layers.len() < 2 {
        return layers;
    }
    for layer in &mut layers {
        layer.networks = IpNet::aggregate(&layer.networks);
    }
    let mut index = 0;
    while index + 2 < layers.len() {
        if let Some(replacement) = merge_sandwich(&layers[index..index + 3]) {
            layers.splice(index..index + 3, replacement);
            // A rewrite can expose another sandwich across its boundary.
            index = index.saturating_sub(2);
        } else {
            index += 1;
        }
    }

    for index in 0..layers.len().saturating_sub(1) {
        let (left, right) = layers.split_at_mut(index + 1);
        let first = left.last_mut().unwrap();
        let second = &mut right[0];
        if first.networks.len().max(second.networks.len()) <= 1 {
            continue;
        }

        // The earlier layer already handles everything we add to the later one.
        let union = union(&first.networks, &second.networks);
        if union.len() < second.networks.len() {
            second.networks = union;
        } else if union.len() < first.networks.len()
            && !first
                .networks
                .iter()
                .any(|net| overlaps(&second.networks, *net))
        {
            // Disjoint layers can swap before the widening.
            std::mem::swap(first, second);
            second.networks = union;
        }
    }

    layers
}

fn merge_sandwich<'a>(layers: &[IpLayer<'a>]) -> Option<Vec<IpLayer<'a>>> {
    let [first, middle, last] = layers else {
        unreachable!()
    };
    if first.action != last.action {
        return None;
    }

    let budget = first.networks.len() + middle.networks.len() + last.networks.len();
    let combined = union(&first.networks, &last.networks);
    // Move the first layer past the middle, cutting its addresses out of the middle.
    let move_later = subtract(&middle.networks, &first.networks, budget - combined.len());
    // Move the last layer ahead of the middle, leaving the middle's addresses alone.
    let move_earlier = subtract(
        &last.networks,
        &middle.networks,
        budget - middle.networks.len(),
    )
    .map(|remainder| union(&first.networks, &remainder))
    .filter(|networks| networks.len() + middle.networks.len() <= budget);

    if let Some(carved) = move_later
        && move_earlier.as_ref().is_none_or(|earlier| {
            carved.len() + combined.len() <= earlier.len() + middle.networks.len()
        })
    {
        let mut result = Vec::new();
        if !carved.is_empty() {
            result.push(IpLayer {
                action: middle.action,
                networks: carved,
            });
        }
        result.push(IpLayer {
            action: first.action,
            networks: combined,
        });
        return Some(result);
    }

    move_earlier.map(|networks| {
        vec![
            IpLayer {
                action: first.action,
                networks,
            },
            IpLayer {
                action: middle.action,
                networks: middle.networks.clone(),
            },
        ]
    })
}

fn union(a: &[IpNet], b: &[IpNet]) -> Vec<IpNet> {
    let combined: Vec<_> = a.iter().chain(b).copied().collect();
    IpNet::aggregate(&combined)
}

fn overlaps(networks: &[IpNet], range: IpNet) -> bool {
    overlapping(networks, range).next().is_some()
}

fn overlapping(networks: &[IpNet], range: IpNet) -> impl Iterator<Item = IpNet> + '_ {
    // Aggregated CIDRs are sorted and disjoint.
    let start = networks.partition_point(|net| net.broadcast() < range.network());
    networks[start..]
        .iter()
        .copied()
        .take_while(move |net| net.network() <= range.broadcast())
}

fn subtract(positive: &[IpNet], negative: &[IpNet], budget: usize) -> Option<Vec<IpNet>> {
    let mut result = Vec::new();
    for &range in positive {
        let mut parts = vec![range];
        for excluded in overlapping(negative, range) {
            parts = parts
                .into_iter()
                .flat_map(|part| subtract_ip_prefix(part, excluded))
                .collect();
            // Avoid expanding a large CIDR into many small ones to save a rule.
            if parts.len() > budget - result.len() {
                return None;
            }
        }
        if parts.len() > budget - result.len() {
            return None;
        }
        result.extend(parts);
    }
    Some(IpNet::aggregate(&result))
}
