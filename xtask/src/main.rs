use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

/// The target the eBPF crates are compiled for.
const BPF_TARGET: &str = "bpfel-unknown-none";

/// eBPF crates that must be built with the nightly toolchain and build-std.
const EBPF_CRATES: [(&str, &str); 2] = [
    ("staticzero-offense-ebpf", "staticzero-offense"),
    ("staticzero-defense-ebpf", "staticzero-defense"),
];

#[derive(Parser, Debug)]
#[command(name = "xtask")]
#[command(about = "StaticZero workspace automation")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Compile the eBPF kernel programs for bpfel-unknown-none
    BuildEbpf {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::BuildEbpf { release } => build_ebpf(release),
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .context("CARGO_MANIFEST_DIR not set; run via `cargo xtask`")?;
    let workspace_dir = std::path::Path::new(&manifest_dir)
        .parent()
        .context("failed to locate workspace root")?
        .to_path_buf();

    for (package, bin) in EBPF_CRATES {
        eprintln!("{}: building eBPF object for {package}", bin);

        let mut cmd = Command::new("cargo");
        cmd.current_dir(&workspace_dir)
            .arg("+nightly")
            .arg("build")
            .args(["--package", package])
            .args(["--target", BPF_TARGET])
            .arg("-Z")
            .arg("build-std=core");

        if release {
            cmd.arg("--release");
        }

        let status = cmd
            .status()
            .with_context(|| format!("failed to spawn cargo for {package}"))?;

        if !status.success() {
            bail!("failed to build {package} for {BPF_TARGET}");
        }
    }

    eprintln!(
        "eBPF objects written to target/{BPF_TARGET}/{{debug,release}}/staticzero-{{offense,defense}}"
    );
    Ok(())
}
