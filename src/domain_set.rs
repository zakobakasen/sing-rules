use crate::model::{Matcher, Rule, Table};
use anyhow::{Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Scope {
    pub name: String,
    pub kind: Kind,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Kind {
    Inclusive,
    Descendants,
    Exact,
}

impl Scope {
    pub fn from_matcher(matcher: &Matcher) -> Option<Self> {
        let (name, kind) = match matcher {
            Matcher::Exact(name) => (name, Kind::Exact),
            Matcher::Suffix {
                name,
                subdomains_only,
            } => (
                name,
                if *subdomains_only {
                    Kind::Descendants
                } else {
                    Kind::Inclusive
                },
            ),
            _ => return None,
        };
        Some(Self {
            name: name.clone(),
            kind,
        })
    }

    pub fn matcher(&self) -> Matcher {
        match self.kind {
            Kind::Exact => Matcher::Exact(self.name.clone()),
            Kind::Inclusive | Kind::Descendants => Matcher::Suffix {
                name: self.name.clone(),
                subdomains_only: self.kind == Kind::Descendants,
            },
        }
    }

    fn parent(&self) -> Option<Self> {
        match self.kind {
            Kind::Exact | Kind::Descendants => Some(Self {
                name: self.name.clone(),
                kind: Kind::Inclusive,
            }),
            Kind::Inclusive => {
                let (_, suffix) = self.name.split_once('.')?;
                Some(Self {
                    name: suffix.into(),
                    kind: Kind::Descendants,
                })
            }
        }
    }

    fn rank(&self) -> (usize, Kind) {
        (self.name.len(), self.kind)
    }
}

// At each boundary, store the positive matcher that supplies specificity.
// None is an explicit hole. Missing entries inherit from the nearest parent.
pub type DomainSet = BTreeMap<Scope, Option<Scope>>;

fn lookup<'a, T>(map: &'a BTreeMap<Scope, T>, scope: &Scope) -> Option<&'a T> {
    let mut scope = scope.clone();
    loop {
        if let Some(value) = map.get(&scope) {
            return Some(value);
        }
        scope = scope.parent()?;
    }
}

pub fn combine(left: &DomainSet, right: &DomainSet, op: crate::set_expr::Op) -> DomainSet {
    use crate::set_expr::Op;
    let boundaries: BTreeSet<_> = left.keys().chain(right.keys()).collect();
    boundaries
        .into_iter()
        .map(|scope| {
            let a = lookup(left, scope).and_then(Option::as_ref);
            let b = lookup(right, scope).and_then(Option::as_ref);
            let best = |a: &Scope, b: &Scope| {
                if a.rank() >= b.rank() {
                    a.clone()
                } else {
                    b.clone()
                }
            };
            let result = match op {
                Op::Union => match (a, b) {
                    (Some(a), Some(b)) => Some(best(a, b)),
                    _ => a.or(b).cloned(),
                },
                Op::Intersection => a.zip(b).map(|(a, b)| best(a, b)),
                Op::Difference => a.filter(|_| b.is_none()).cloned(),
            };
            (scope.clone(), result)
        })
        .collect()
}

// For A, B, A, put B first after subtracting the first A from B.
// The two A layers can then use their union.
pub(crate) fn compact_exception<'a>(
    first: impl Iterator<Item = &'a Matcher>,
    middle: impl Iterator<Item = &'a Matcher>,
    last: impl Iterator<Item = &'a Matcher>,
) -> Option<(Vec<Matcher>, Vec<Matcher>)> {
    let first: Vec<_> = first.map(Scope::from_matcher).collect::<Option<_>>()?;
    let middle: Vec<_> = middle.map(Scope::from_matcher).collect::<Option<_>>()?;
    let last: Vec<_> = last.map(Scope::from_matcher).collect::<Option<_>>()?;
    let budget = first.len() + middle.len() + last.len();

    let first = minimal_union(first);
    let combined = minimal_union(first.iter().cloned().chain(last));
    let mut carved: BTreeMap<_, Vec<Scope>> = minimal_union(middle)
        .into_iter()
        .filter(|scope| !covered_by(&first, scope.clone()))
        .map(|scope| (scope, Vec::new()))
        .collect();
    let mut cost = carved.len() + combined.len();
    for scope in &first {
        let mut parent = scope.parent();
        while let Some(ancestor) = parent {
            if let Some(holes) = carved.get_mut(&ancestor) {
                cost += 1;
                if cost > budget {
                    return None;
                }
                holes.push(scope.clone());
                break;
            }
            parent = ancestor.parent();
        }
    }

    Some((
        carved
            .into_iter()
            .map(|(scope, excluded)| {
                if excluded.is_empty() {
                    scope.matcher()
                } else {
                    Matcher::DomainRegion { scope, excluded }
                }
            })
            .collect(),
        combined.into_iter().map(|scope| scope.matcher()).collect(),
    ))
}

fn minimal_union(scopes: impl IntoIterator<Item = Scope>) -> BTreeSet<Scope> {
    let scopes: BTreeSet<_> = scopes.into_iter().collect();
    scopes
        .iter()
        .filter(|scope| {
            scope
                .parent()
                .is_none_or(|parent| !covered_by(&scopes, parent))
        })
        .cloned()
        .collect()
}

fn covered_by(scopes: &BTreeSet<Scope>, mut scope: Scope) -> bool {
    loop {
        if scopes.contains(&scope) {
            return true;
        }
        let Some(parent) = scope.parent() else {
            return false;
        };
        scope = parent;
    }
}

pub fn install(
    table: &mut Table,
    plain: BTreeMap<Scope, Vec<Rule>>,
    derived: Vec<(&DomainSet, Rule)>,
) -> Result<()> {
    let boundaries: BTreeSet<_> = plain
        .keys()
        .chain(derived.iter().flat_map(|(domains, _)| domains.keys()))
        .collect();
    let mut boundaries: Vec<_> = boundaries.into_iter().collect();
    boundaries.sort_by_key(|scope| (scope.rank(), &scope.name));

    let mut layers = BTreeMap::<Scope, Option<String>>::new();
    let mut holes = BTreeMap::<Scope, Vec<Scope>>::new();
    for scope in boundaries {
        let mut candidates = Vec::new();
        // Every enclosing ordinary rule is a candidate. A sibling rule
        // never applies to this cell.
        let mut ancestor = Some(scope.clone());
        while let Some(anchor) = ancestor {
            if let Some(rules) = plain.get(&anchor) {
                candidates.extend(rules.iter().map(|rule| (anchor.rank(), rule)));
            }
            ancestor = anchor.parent();
        }
        candidates.extend(derived.iter().filter_map(|(domains, rule)| {
            let anchor = lookup(domains, scope)?.as_ref()?;
            Some((anchor.rank(), rule))
        }));
        candidates.sort_by_key(|(rank, rule)| (std::cmp::Reverse(*rank), rule.priority));
        let target = if let Some(&(rank, winner)) = candidates.first() {
            for &(_, other) in candidates
                .iter()
                .skip(1)
                .take_while(|(candidate_rank, rule)| {
                    *candidate_rank == rank && rule.priority == winner.priority
                })
            {
                ensure!(
                    other.target == winner.target,
                    "conflicting domain rules at {}: {} and {} (priority={})",
                    scope.name,
                    winner.describe(),
                    other.describe(),
                    winner.priority
                );
            }
            Some(winner.target.clone())
        } else {
            None
        };

        let mut ancestor = scope.parent();
        let mut parent = None;
        while let Some(anchor) = ancestor {
            if let Some(previous) = layers.get_key_value(&anchor) {
                parent = Some(previous);
                break;
            }
            ancestor = anchor.parent();
        }
        if parent.and_then(|(_, previous)| previous.as_ref()) == target.as_ref() {
            continue;
        }
        if let Some((parent, Some(_))) = parent {
            holes.entry(parent.clone()).or_default().push(scope.clone());
        }
        layers.insert(scope.clone(), target);
    }

    for (scope, target) in layers {
        if let Some(target) = target {
            let excluded = holes.remove(&scope).unwrap_or_default();
            table.add(
                Matcher::DomainRegion { scope, excluded },
                Rule {
                    target,
                    source: String::new(),
                    ruleset: None,
                    priority: crate::model::DEFAULT_PRIORITY,
                },
            );
        }
    }
    Ok(())
}
