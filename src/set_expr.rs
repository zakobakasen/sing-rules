use crate::{
    cache::Cache,
    domain_set::{self, DomainSet, Scope},
    model::{Matcher, PRIVATE_IP},
    ruleset::{self, Source},
};
use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Clone, Copy)]
pub enum Op {
    Union,
    Difference,
    Intersection,
}

pub enum Expr {
    Source(Source),
    Reference(String),
    Binary(Op, Box<Expr>, Box<Expr>),
}

pub struct Definition {
    pub expr: Expr,
    pub location: String,
}

pub type Definitions<'a> = BTreeMap<&'a str, Definition>;
pub type Imports<'a> = BTreeMap<&'a Source, Vec<(Matcher, String)>>;

#[derive(Default)]
pub struct Set {
    pub domains: DomainSet,
    pub ips: BTreeSet<IpNet>,
}

pub fn parse(text: &str) -> Result<Expr> {
    let mut parser = Expression(text);
    let result = parser.binary(1)?;
    ensure!(
        parser.0.trim().is_empty(),
        "unexpected text in ruleset expression: {:?}",
        parser.0.trim()
    );
    Ok(result)
}

struct Expression<'a>(&'a str);

impl Expression<'_> {
    fn binary(&mut self, minimum: u8) -> Result<Expr> {
        let mut lhs = self.atom()?;
        loop {
            let rest = self.0.trim_start();
            let (op, rank) = match rest.as_bytes().first() {
                Some(b'+') => (Op::Union, 1),
                Some(b'-') => (Op::Difference, 1),
                Some(b'*') => (Op::Intersection, 2),
                _ => break,
            };
            if rank < minimum {
                break;
            }
            self.0 = &rest[1..];
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(self.binary(rank + 1)?));
        }
        Ok(lhs)
    }

    fn atom(&mut self) -> Result<Expr> {
        self.0 = self.0.trim_start();
        if let Some(rest) = self.0.strip_prefix('(') {
            self.0 = rest;
            let result = self.binary(1)?;
            self.0 = self
                .0
                .trim_start()
                .strip_prefix(')')
                .context("expected ')'")?;
            return Ok(result);
        }
        if self.0.starts_with("file(") || self.0.starts_with("url(") {
            let mut quoted = false;
            let mut escaped = false;
            for (index, ch) in self.0.char_indices() {
                if escaped {
                    escaped = false;
                } else if ch == '\\' && quoted {
                    escaped = true;
                } else if ch == '"' {
                    quoted = !quoted;
                } else if ch == ')' && !quoted {
                    let (source, rest) = self.0.split_at(index + 1);
                    self.0 = rest;
                    return Ok(Expr::Source(Source::parse(source)?));
                }
            }
            bail!("expected ')' at end of ruleset source");
        }
        let length = self
            .0
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(byte))
            .count();
        ensure!(
            length > 0,
            "expected ruleset name, file(...), url(...), or '('"
        );
        let (name, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(Expr::Reference(name.to_owned()))
    }
}

pub fn validate(definitions: &Definitions<'_>) -> Result<()> {
    fn visit<'a>(
        name: &'a str,
        defs: &'a Definitions<'_>,
        stack: &mut Vec<&'a str>,
        done: &mut BTreeSet<&'a str>,
    ) -> Result<()> {
        if done.contains(name) {
            return Ok(());
        }
        if let Some(start) = stack.iter().position(|part| *part == name) {
            bail!(
                "cyclic ruleset reference: {} -> {name}",
                stack[start..].join(" -> ")
            );
        }
        ensure!(
            name != PRIVATE_IP,
            "PrivateIP is available only as a standalone RuleSet reference"
        );
        let definition = defs
            .get(name)
            .with_context(|| format!("unknown ruleset {name:?}"))?;
        stack.push(name);
        fn references<'a>(
            expr: &'a Expr,
            defs: &'a Definitions<'_>,
            stack: &mut Vec<&'a str>,
            done: &mut BTreeSet<&'a str>,
        ) -> Result<()> {
            match expr {
                Expr::Source(_) => Ok(()),
                Expr::Reference(name) => visit(name, defs, stack, done),
                Expr::Binary(_, lhs, rhs) => {
                    references(lhs, defs, stack, done)?;
                    references(rhs, defs, stack, done)
                }
            }
        }
        references(&definition.expr, defs, stack, done)
            .with_context(|| definition.location.clone())?;
        stack.pop();
        done.insert(name);
        Ok(())
    }

    let mut done = BTreeSet::new();
    for name in definitions.keys() {
        visit(name, definitions, &mut Vec::new(), &mut done)?;
    }
    Ok(())
}

pub struct Resolver<'a, 'b> {
    pub definitions: &'a Definitions<'b>,
    pub imports: Imports<'a>,
    pub resolved: BTreeMap<&'a str, Set>,
    pub directory: &'a Path,
    pub sing_box: &'a Path,
    pub cache: &'a Cache,
}

impl<'a> Resolver<'a, '_> {
    pub fn source(&mut self, source: &'a Source) -> Result<&[(Matcher, String)]> {
        if !self.imports.contains_key(source) {
            self.imports.insert(
                source,
                ruleset::load(source, self.directory, self.sing_box, self.cache)?,
            );
        }
        Ok(&self.imports[source])
    }

    pub fn resolve(&mut self, name: &str) -> Result<&Set> {
        let (name, definition) = self
            .definitions
            .get_key_value(name)
            .with_context(|| format!("unknown ruleset {name:?}"))?;
        if !self.resolved.contains_key(name) {
            let value = self
                .eval(&definition.expr)
                .with_context(|| definition.location.clone())?;
            self.resolved.insert(name, value);
        }
        Ok(&self.resolved[name])
    }

    fn eval(&mut self, expression: &'a Expr) -> Result<Set> {
        Ok(match expression {
            Expr::Source(source) => {
                let mut set = Set::default();
                for (matcher, _) in self.source(source)? {
                    if let Matcher::Ip(ip) = matcher {
                        set.ips.insert(*ip);
                    } else if let Some(scope) = Scope::from_matcher(matcher) {
                        set.domains.insert(scope.clone(), Some(scope));
                    }
                }
                set
            }
            Expr::Reference(name) => {
                let set = self.resolve(name)?;
                Set {
                    domains: set.domains.clone(),
                    ips: set.ips.clone(),
                }
            }
            Expr::Binary(op, lhs, rhs) => {
                let lhs = self.eval(lhs)?;
                let rhs = self.eval(rhs)?;
                Set {
                    domains: domain_set::combine(&lhs.domains, &rhs.domains, *op),
                    ips: combine_ips(lhs.ips, rhs.ips, *op),
                }
            }
        })
    }
}

fn combine_ips(mut left: BTreeSet<IpNet>, right: BTreeSet<IpNet>, op: Op) -> BTreeSet<IpNet> {
    match op {
        Op::Union => {
            left.extend(right);
            left
        }
        Op::Intersection => left
            .into_iter()
            .flat_map(|a| {
                right.iter().filter_map(move |&b| {
                    if a.contains(&b) {
                        Some(b)
                    } else if b.contains(&a) {
                        Some(a)
                    } else {
                        None
                    }
                })
            })
            .collect(),
        Op::Difference => {
            for excluded in right {
                left = left
                    .into_iter()
                    .flat_map(|range| crate::model::subtract_ip_prefix(range, excluded))
                    .collect();
            }
            left
        }
    }
}
