//! Thin wrapper: `staticzero-offense` standalone binary. The loader logic
//! lives in [`staticzero_offense::loader`], shared with the multi-call
//! `staticzero` binary's `offense` subcommand.

use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    staticzero_offense::loader::run(staticzero_offense::loader::Cli::parse()).await
}
