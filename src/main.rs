mod cache;
mod compiler;
mod domain_set;
mod export;
mod model;
mod parser;
mod ruleset;
mod set_expr;
mod tags;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

#[derive(Parser)]
#[command(
    version,
    about = "Compile an unordered routing table into sing-box JSON"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, ValueEnum)]
enum RulesetFormat {
    Inline,
    Srs,
}

#[derive(Subcommand)]
enum Commands {
    Compile {
        input: PathBuf,
        #[arg(long)]
        base: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(
            long,
            default_value = "sing-box",
            help = "Executable used to read or write SRS files"
        )]
        sing_box: PathBuf,
        #[arg(
            long,
            value_enum,
            default_value = "inline",
            help = "Output format for generated rule sets"
        )]
        ruleset_format: RulesetFormat,
        #[arg(long, help = "Replace any existing base route.rules")]
        replace_route: bool,
        #[arg(
            long,
            conflicts_with = "replace_route",
            help = "Run existing base route.rules before generated rules"
        )]
        base_rules_first: bool,
        #[arg(long, help = "Directory for downloaded rule sets")]
        cache_dir: Option<PathBuf>,
        #[arg(long, help = "Download rule sets again even if cached")]
        refresh: bool,
    },
}

fn main() -> Result<()> {
    let Commands::Compile {
        input,
        base,
        output,
        sing_box,
        ruleset_format,
        replace_route,
        base_rules_first,
        cache_dir,
        refresh,
    } = Cli::parse().command;
    let text =
        fs::read_to_string(&input).with_context(|| format!("reading {}", input.display()))?;
    let cache = cache::Cache::new(cache_dir, refresh);
    let config = parser::parse(&text, &input, &sing_box, &cache)?;
    let base_bytes = fs::read(&base).with_context(|| format!("reading {}", base.display()))?;
    let base_config = serde_json::from_slice(&base_bytes)
        .with_context(|| format!("parsing {}", base.display()))?;
    let base_rules = if base_rules_first {
        compiler::BaseRules::First
    } else if replace_route {
        compiler::BaseRules::Replace
    } else {
        compiler::BaseRules::RequireEmpty
    };
    let format = match ruleset_format {
        RulesetFormat::Inline => export::Format::Inline,
        RulesetFormat::Srs => export::Format::Srs {
            output: output
                .as_deref()
                .context("--ruleset-format srs requires --output")?,
            sing_box: &sing_box,
        },
    };
    let config = compiler::compile(&config, base_config, base_rules, format)?;
    if let Some(output) = output {
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        write_json(&mut file, &config)?;
        file.persist(&output)
            .with_context(|| format!("writing {}", output.display()))?;
    } else {
        write_json(io::stdout().lock(), &config)?;
    }
    Ok(())
}

fn write_json(mut output: impl Write, config: &serde_json::Value) -> Result<()> {
    serde_json::to_writer_pretty(&mut output, config)?;
    writeln!(output)?;
    Ok(())
}
