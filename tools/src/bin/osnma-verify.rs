//! Thin wrapper: `osnma-verify` standalone binary. All logic lives in
//! [`staticzero_tools::osnma_verify`], shared with the multi-call
//! `staticzero` binary's `osnma-verify` subcommand.

use clap::Parser;
use staticzero_tools::osnma_verify;

fn main() -> anyhow::Result<()> {
    osnma_verify::run(osnma_verify::Cli::parse())
}
