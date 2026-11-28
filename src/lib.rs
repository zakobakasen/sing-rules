pub mod cache;
pub mod compiler;
mod domain_set;
pub mod export;
mod ip_opt;
mod model;
pub mod parser;
mod ruleset;
mod set_expr;
mod srs;
mod tags;

use anyhow::Result;
use std::{collections::BTreeMap, path::Path};

pub struct Publication {
    pub config: serde_json::Value,
    pub files: BTreeMap<String, Vec<u8>>,
}

/// Compile untrusted uploads with an administrator-controlled list of import URLs.
pub fn publish(
    sr: &str,
    base: &str,
    public_url: &str,
    imports: Vec<String>,
) -> Result<Publication> {
    let cache = cache::Cache::service(imports);
    let table = parser::parse(sr, Path::new("upload.sr"), Path::new("sing-box"), &cache)?;
    let mut files = BTreeMap::new();
    let config = compiler::compile(
        &table,
        serde_json::from_str(base)?,
        compiler::BaseRules::First,
        export::Format::Remote {
            public_url,
            files: &mut files,
        },
    )?;
    Ok(Publication { config, files })
}
