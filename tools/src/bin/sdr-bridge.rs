//! Thin wrapper: `sdr-bridge` standalone binary. All logic lives in
//! [`staticzero_tools::sdr_integration`], shared with the multi-call
//! `staticzero` binary's `sdr-bridge` subcommand.

use clap::Parser;
use staticzero_tools::sdr_integration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sdr_integration::run(sdr_integration::Cli::parse()).await
}
