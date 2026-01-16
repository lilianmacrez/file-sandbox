use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "file-sandbox", version, about = "Offline static file analyzer (safe)")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a file (offline, static)
    Analyze {
        /// Path to the file
        path: PathBuf,

        /// Write JSON report to file (optional)
        #[arg(long)]
        json: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Analyze { path, json } => {
            let report = file_sandbox_core::analyze_file(&path)?;
            let out = serde_json::to_string_pretty(&report)?;

            if let Some(p) = json {
                std::fs::write(p, out)?;
            } else {
                println!("{out}");
            }
        }
    }

    Ok(())
}
