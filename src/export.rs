use anyhow::{Context, Result, ensure};
use ring::digest::{SHA256, digest};
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::Path,
    process::Command,
};

pub enum Format<'a> {
    Inline,
    Srs {
        output: &'a Path,
        sing_box: &'a Path,
    },
}

pub fn export(
    base: &mut Value,
    route_prefix: usize,
    has_dns: bool,
    format: Format<'_>,
) -> Result<()> {
    let existing = base["route"].as_object_mut().unwrap().remove("rule_set");
    let had_sets = existing.is_some();
    let mut sets = match existing {
        None => Vec::new(),
        Some(Value::Array(sets)) => sets,
        Some(_) => anyhow::bail!("base route.rule_set must be an array"),
    };
    let mut used = BTreeSet::new();
    for set in &sets {
        match &set["tag"] {
            Value::String(tag) => {
                used.insert(tag.clone());
            }
            Value::Array(tags) => {
                used.extend(tags.iter().filter_map(Value::as_str).map(str::to_owned))
            }
            _ => {}
        }
    }
    let mut registry = Registry {
        format,
        used,
        sets: &mut sets,
        by_content: BTreeMap::new(),
    };

    for rule in &mut base["route"]["rules"].as_array_mut().unwrap()[route_prefix..] {
        registry.convert(rule)?;
    }
    if has_dns {
        for rule in base["dns"]["rules"].as_array_mut().unwrap() {
            registry.convert(rule)?;
        }
    }
    if had_sets || !sets.is_empty() {
        base["route"]["rule_set"] = Value::Array(sets);
    }
    Ok(())
}

struct Registry<'a, 'b> {
    format: Format<'a>,
    used: BTreeSet<String>,
    sets: &'b mut Vec<Value>,
    by_content: BTreeMap<String, String>,
}

impl Registry<'_, '_> {
    fn convert(&mut self, rule: &mut Value) -> Result<()> {
        let Value::Object(mut condition) = std::mem::take(rule) else {
            unreachable!("generated rules are objects");
        };
        let mut action = Map::new();
        for field in ["action", "outbound", "server"] {
            if let Some(value) = condition.remove(field) {
                action.insert(field.into(), value);
            }
        }

        let private = take_private(&mut condition);
        if condition.is_empty() {
            if private {
                action.insert("ip_is_private".into(), json!(true));
            }
        } else {
            let tag = self.register(Value::Object(condition))?;
            if private {
                action.insert("type".into(), json!("logical"));
                action.insert("mode".into(), json!("or"));
                action.insert(
                    "rules".into(),
                    json!([
                        {"rule_set": [tag]},
                        {"ip_is_private": true}
                    ]),
                );
            } else {
                action.insert("rule_set".into(), json!([tag]));
            }
        }
        *rule = Value::Object(action);
        Ok(())
    }

    fn register(&mut self, condition: Value) -> Result<String> {
        let source = json!({"version": 2, "rules": [condition]});
        let bytes = serde_json::to_vec(&source)?;
        let key = hash(&bytes);
        if let Some(tag) = self.by_content.get(&key) {
            return Ok(tag.clone());
        }

        let stem = format!("sing-rules-{}", &key[..16]);
        let mut tag = stem.clone();
        let mut suffix = 1;
        while !self.used.insert(tag.clone()) {
            tag = format!("{stem}-{suffix}");
            suffix += 1;
        }
        let set = match self.format {
            Format::Inline => json!({"type":"inline", "tag":tag, "rules":source["rules"]}),
            Format::Srs { output, sing_box } => {
                let path = export_srs(output, sing_box, &bytes, &tag)?;
                json!({"type":"local", "tag":tag, "format":"binary", "path":path})
            }
        };
        self.sets.push(set);
        self.by_content.insert(key, tag.clone());
        Ok(tag)
    }
}

fn take_private(condition: &mut Map<String, Value>) -> bool {
    if condition.remove("ip_is_private").is_some() {
        return true;
    }
    // PrivateIP is only in the first, ordinary branch of a generated OR.
    if condition.get("mode").and_then(Value::as_str) != Some("or") {
        return false;
    }
    let branches = condition.get_mut("rules").unwrap().as_array_mut().unwrap();
    let ordinary = branches[0].as_object_mut().unwrap();
    if ordinary.remove("ip_is_private").is_none() {
        return false;
    }
    if ordinary.is_empty() {
        branches.remove(0);
        if branches.len() == 1 {
            let guarded = branches.pop().unwrap();
            *condition = guarded.as_object().unwrap().clone();
        }
    }
    true
}

fn export_srs(output: &Path, sing_box: &Path, source: &[u8], tag: &str) -> Result<String> {
    let directory = output
        .parent()
        .unwrap_or(Path::new(""))
        .join("sing-rules-srs");
    fs::create_dir_all(&directory).with_context(|| format!("creating {}", directory.display()))?;
    let staging = tempfile::tempdir_in(&directory)?;
    let input = staging.path().join("source.json");
    let binary = staging.path().join("compiled.srs");
    fs::write(&input, source)?;
    let result = Command::new(sing_box)
        .args(["rule-set", "compile", "-o"])
        .arg(&binary)
        .arg(&input)
        .output()
        .with_context(|| format!("running {} for {tag}", sing_box.display()))?;
    ensure!(
        result.status.success(),
        "compiling {tag}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let bytes = fs::read(&binary)?;
    ensure!(
        bytes.starts_with(b"SRS"),
        "{tag}: sing-box did not produce an SRS file"
    );
    let filename = format!("{}.srs", hash(&bytes));
    let mut staged = tempfile::NamedTempFile::new_in(&directory)?;
    staged.write_all(&bytes)?;
    staged.persist(directory.join(&filename))?;
    Ok(format!("sing-rules-srs/{filename}"))
}

fn hash(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
