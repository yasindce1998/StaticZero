//! Thin wrapper: `modem-firmware` standalone binary. All logic lives in
//! [`staticzero_tools::modem_firmware`], shared with the multi-call
//! `staticzero` binary's `modem-firmware` subcommand.

use clap::Parser;
use staticzero_tools::modem_firmware;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    modem_firmware::run(modem_firmware::Cli::parse()).await
}
