//! Thin wrapper: `staticzero-defense` standalone binary. The daemon logic
//! lives in [`defense::daemon`], shared with the multi-call `staticzero`
//! binary's `defense` subcommand.

use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    defense::daemon::run(defense::daemon::Cli::parse()).await
}
