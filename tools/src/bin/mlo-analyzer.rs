//! Thin wrapper: `mlo-analyzer` standalone binary. All logic lives in
//! [`staticzero_tools::mlo_analyzer`], shared with the multi-call
//! `staticzero` binary's `mlo-analyzer` subcommand.

use clap::Parser;
use staticzero_tools::mlo_analyzer;

fn main() -> anyhow::Result<()> {
    mlo_analyzer::run(mlo_analyzer::Cli::parse())
}
