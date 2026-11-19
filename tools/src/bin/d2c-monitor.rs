//! Thin wrapper: `d2c-monitor` standalone binary. All logic lives in
//! [`staticzero_tools::d2c_monitor`], shared with the multi-call
//! `staticzero` binary's `d2c-monitor` subcommand.

use clap::Parser;
use staticzero_tools::d2c_monitor;

fn main() -> anyhow::Result<()> {
    d2c_monitor::run(d2c_monitor::Cli::parse())
}
