mod compiler;
mod model;
mod parser;
mod ruleset;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
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
            help = "Executable used to decompile SRS imports"
        )]
        sing_box: PathBuf,
        #[arg(long, help = "Replace any existing base route.rules")]
        replace_route: bool,
    },
}

fn main() -> Result<()> {
    let Commands::Compile {
        input,
        base,
        output,
        sing_box,
        replace_route,
    } = Cli::parse().command;
    let text =
        fs::read_to_string(&input).with_context(|| format!("reading {}", input.display()))?;
    let table = parser::parse(&text, &input, &sing_box)?;
    let base_bytes = fs::read(&base).with_context(|| format!("reading {}", base.display()))?;
    let base_config = serde_json::from_slice(&base_bytes)
        .with_context(|| format!("parsing {}", base.display()))?;
    let config = compiler::compile(&table, base_config, replace_route)?;
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
