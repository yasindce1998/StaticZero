//! Thin wrapper: `protocol-correlator` standalone binary. All logic lives in
//! [`staticzero_tools::protocol_correlator`], shared with the multi-call
//! `staticzero` binary's `protocol-correlator` subcommand.

use clap::Parser;
use staticzero_tools::protocol_correlator;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    protocol_correlator::run(protocol_correlator::Cli::parse()).await
}
