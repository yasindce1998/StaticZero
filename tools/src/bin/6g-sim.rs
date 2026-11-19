//! Thin wrapper: `6g-sim` standalone binary. All logic lives in
//! [`staticzero_tools::sixg_sim`], shared with the multi-call `staticzero`
//! binary's `6g-sim` subcommand.

use clap::Parser;
use staticzero_tools::sixg_sim;

fn main() -> anyhow::Result<()> {
    sixg_sim::run(sixg_sim::Cli::parse())
}
