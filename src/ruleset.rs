use crate::model::{self, Matcher};
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::{fs, path::Path, process::Command, time::Duration};

fn web_agent(url: &str) -> Result<ureq::Agent> {
    let scheme_variables = if url.starts_with("https://") {
        ["https_proxy", "HTTPS_PROXY"]
    } else {
        ["http_proxy", "HTTP_PROXY"]
    };
    let proxy = scheme_variables
        .into_iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
        .map(|value| -> Result<ureq::Proxy> {
            let parsed = ureq::Proxy::new(&value).context("invalid HTTP proxy configuration")?;
            let mut builder = ureq::Proxy::builder(parsed.protocol())
                .host(parsed.host())
                .port(parsed.port())
                .resolve_target(parsed.resolve_target());
            if let Some(user) = parsed.username() {
                builder = builder.username(user);
            }
            if let Some(password) = parsed.password() {
                builder = builder.password(password);
            }
            if let Ok(exclusions) = std::env::var("no_proxy").or_else(|_| std::env::var("NO_PROXY"))
            {
                for exclusion in exclusions.split(',') {
                    builder = builder.no_proxy(exclusion.trim());
                }
            }
            Ok(builder.build()?)
        })
        .transpose()?
        .or_else(ureq::Proxy::try_from_env);

    Ok(ureq::Agent::config_builder()
        .proxy(proxy)
        .timeout_global(Some(Duration::from_secs(60)))
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                .build(),
        )
        .build()
        .into())
}

pub enum Source {
    File(String),
    Url(String),
}

impl Source {
    pub fn parse(text: &str) -> Result<Self> {
        let (kind, argument) = text
            .split_once('(')
            .context("expected file(...) or url(...)")?;
        let argument = argument.strip_suffix(')').context("missing ')'")?;
        let value: String = serde_json::from_str(argument).context("expected a JSON string")?;
        ensure!(!value.is_empty(), "empty ruleset source");
        match kind {
            "file" => Ok(Self::File(value)),
            "url" if value.starts_with("https://") || value.starts_with("http://") => {
                Ok(Self::Url(value))
            }
            _ => bail!("expected file(path) or url(http[s]://...)"),
        }
    }
}

pub fn load(source: &Source, directory: &Path, sing_box: &Path) -> Result<Vec<(Matcher, String)>> {
    let (location, bytes) = match source {
        Source::File(path) => {
            let path = directory.join(path);
            let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            (path.display().to_string(), bytes)
        }
        Source::Url(url) => {
            let mut response = web_agent(url)?
                .get(url)
                .call()
                .with_context(|| format!("fetching {url}"))?;
            let bytes = response
                .body_mut()
                .with_config()
                .limit(64 * 1024 * 1024)
                .read_to_vec()
                .with_context(|| format!("reading {url}"))?;
            (url.clone(), bytes)
        }
    };

    let bytes = if bytes.starts_with(b"SRS") {
        if bytes.get(3) == Some(&1) {
            bail!(
                "{location}: SRS version 1 has legacy suffix semantics; import its JSON source instead"
            );
        }
        let temporary = tempfile::tempdir()?;
        let input = temporary.path().join("source.srs");
        let output = temporary.path().join("source.json");
        fs::write(&input, bytes)?;
        let result = Command::new(sing_box)
            .args(["rule-set", "decompile", "-o"])
            .arg(&output)
            .arg(&input)
            .output()
            .with_context(|| format!("{location}: running {}", sing_box.display()))?;
        ensure!(
            result.status.success(),
            "{location}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        fs::read(output)?
    } else {
        bytes
    };

    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("{location}: invalid ruleset JSON"))?;
    let object = value
        .as_object()
        .with_context(|| format!("{location}: expected a ruleset object"))?;
    ensure!(
        object
            .keys()
            .all(|key| matches!(key.as_str(), "version" | "rules"))
            && matches!(value["version"].as_u64(), Some(1..=5)),
        "{location}: expected a sing-box source ruleset with version 1 through 5"
    );
    let rules = value["rules"]
        .as_array()
        .with_context(|| format!("{location}: missing rules array"))?;
    let mut expanded = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        expand(rule, &format!("{location}:rules[{index}]"), &mut expanded)?;
    }
    Ok(expanded)
}

fn expand(rule: &Value, at: &str, output: &mut Vec<(Matcher, String)>) -> Result<()> {
    let object = rule
        .as_object()
        .with_context(|| format!("{at}: expected a headless rule"))?;
    ensure!(
        object.get("invert").is_none_or(|invert| invert == false),
        "{at}: unsupported invert"
    );
    match object.get("type") {
        Some(kind) if kind == "logical" => {
            for field in object.keys() {
                ensure!(
                    matches!(field.as_str(), "type" | "mode" | "rules" | "invert"),
                    "{at}: unsupported field {field}"
                );
            }
            ensure!(
                rule["mode"] == "or",
                "{at}: only logical OR rules can be expanded"
            );
            let children = rule["rules"]
                .as_array()
                .filter(|children| !children.is_empty())
                .with_context(|| format!("{at}: expected a nonempty rules list"))?;
            for (index, child) in children.iter().enumerate() {
                expand(child, &format!("{at}.rules[{index}]"), output)?;
            }
            return Ok(());
        }
        Some(kind) if kind != "default" => bail!("{at}: unsupported rule type {kind}"),
        _ => {}
    }
    let previous = output.len();
    for (field, value) in object {
        let parse: fn(&str) -> Result<Matcher> = match field.as_str() {
            "type" | "invert" => continue,
            "ip_cidr" => |text: &str| Ok(Matcher::Ip(model::ip(text)?)),
            "domain" => |text: &str| Ok(Matcher::Exact(model::domain(text)?)),
            "domain_suffix" => |text: &str| {
                let name = text.strip_prefix('.');
                Ok(Matcher::Suffix {
                    name: model::domain(name.unwrap_or(text))?,
                    subdomains_only: name.is_some(),
                })
            },
            _ => bail!("{at}: unsupported field {field}"),
        };
        let items = match value {
            Value::Array(items) => items.as_slice(),
            Value::String(_) => std::slice::from_ref(value),
            _ => bail!("{at}.{field}: expected a string or array of strings"),
        };
        for (index, item) in items.iter().enumerate() {
            let source = format!("{at}.{field}[{index}]");
            let text = item
                .as_str()
                .with_context(|| format!("{source}: expected a string"))?;
            let matcher = parse(text).with_context(|| source.clone())?;
            output.push((matcher, source));
        }
    }
    ensure!(output.len() > previous, "{at}: empty headless rule");
    Ok(())
}
