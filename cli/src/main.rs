//! StaticZero multi-call binary.
//!
//! One executable for everything: `staticzero defense`, `staticzero
//! offense`, and every tool as a subcommand. Busybox-style argv[0]
//! dispatch keeps the legacy standalone names working — a binary named
//! (or symlinked as) `staticzero-defense` runs the defense engine, so
//! existing scripts keep working against a single downloaded file.
//!
//! Building this binary requires the eBPF objects from
//! `cargo xtask build-ebpf` (embedded by the defense/offense subcommands);
//! the crate is therefore excluded from the workspace default-members.

use std::ffi::OsString;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "staticzero",
    version,
    about = "StaticZero — eBPF telecom security research toolkit (2G to 6G)",
    subcommand_negates_reqs = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Telecom network defense engine (detection modules, correlation, HTTP API)
    Defense {
        #[command(flatten)]
        args: defense::daemon::Cli,
    },
    /// Telecom exploitation research loader (authorized testing only)
    Offense {
        #[command(flatten)]
        args: offense::loader::Cli,
    },
    /// SDR bridge — hardware-abstracted radio control (HackRF, bladeRF, USRP, RTL-SDR, LimeSDR)
    SdrBridge {
        #[command(flatten)]
        args: staticzero_tools::sdr_integration::Cli,
    },
    /// Modem/baseband firmware analyzer
    ModemFirmware {
        #[command(flatten)]
        args: staticzero_tools::modem_firmware::Cli,
    },
    /// Protocol correlator — cross-layer correlation over captured traces
    ProtocolCorrelator {
        #[command(flatten)]
        args: staticzero_tools::protocol_correlator::Cli,
    },
    /// Galileo OSNMA verification — cryptographic GNSS spoofing detection
    OsnmaVerify {
        #[command(flatten)]
        args: staticzero_tools::osnma_verify::Cli,
    },
    /// Direct-to-Cell satellite cell monitor — spoofed satellite cell detection
    D2cMonitor {
        #[command(flatten)]
        args: staticzero_tools::d2c_monitor::Cli,
    },
    /// Wi-Fi 7 Multi-Link Operation analyzer
    MloAnalyzer {
        #[command(flatten)]
        args: staticzero_tools::mlo_analyzer::Cli,
    },
    /// 6G control-plane trace analyzer and scenario generator
    #[command(name = "6g-sim")]
    SixgSim {
        #[command(flatten)]
        args: staticzero_tools::sixg_sim::Cli,
    },
}

/// Map a legacy standalone binary name (argv[0] basename) to its
/// subcommand, busybox-style. Returns `None` for unknown names.
fn legacy_subcommand(argv0: &str) -> Option<&'static str> {
    let basename = argv0.rsplit('/').next().unwrap_or(argv0);
    match basename {
        "staticzero-defense" | "defense" => Some("defense"),
        "staticzero-offense" | "offense" => Some("offense"),
        "sdr-bridge" => Some("sdr-bridge"),
        "modem-firmware" => Some("modem-firmware"),
        "protocol-correlator" => Some("protocol-correlator"),
        "osnma-verify" => Some("osnma-verify"),
        "d2c-monitor" => Some("d2c-monitor"),
        "mlo-analyzer" => Some("mlo-analyzer"),
        "6g-sim" => Some("6g-sim"),
        _ => None,
    }
}

/// Build the effective argument list: when invoked under a legacy name,
/// inject the mapped subcommand in front of the user's arguments.
fn effective_args(argv: Vec<OsString>) -> Vec<OsString> {
    let mut args = argv;
    if let Some(first) = args.first() {
        if let Some(subcommand) = first.to_str().and_then(legacy_subcommand) {
            if !args.get(1).is_some_and(|arg| arg == subcommand) {
                args.insert(1, OsString::from(subcommand));
            }
            args.remove(0);
            args.insert(0, OsString::from("staticzero"));
        }
    }
    args
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = effective_args(std::env::args_os().collect());
    let cli = Cli::try_parse_from(args)?;
    match cli.command {
        Command::Defense { args } => defense::daemon::run(args).await,
        Command::Offense { args } => offense::loader::run(args).await,
        Command::SdrBridge { args } => staticzero_tools::sdr_integration::run(args).await,
        Command::ModemFirmware { args } => staticzero_tools::modem_firmware::run(args).await,
        Command::ProtocolCorrelator { args } => {
            staticzero_tools::protocol_correlator::run(args).await
        }
        Command::OsnmaVerify { args } => staticzero_tools::osnma_verify::run(args),
        Command::D2cMonitor { args } => staticzero_tools::d2c_monitor::run(args),
        Command::MloAnalyzer { args } => staticzero_tools::mlo_analyzer::run(args),
        Command::SixgSim { args } => staticzero_tools::sixg_sim::run(args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arg_vec(name: &str, rest: &[&str]) -> Vec<OsString> {
        std::iter::once(OsString::from(name))
            .chain(rest.iter().map(OsString::from))
            .collect()
    }

    #[test]
    fn legacy_names_dispatch_to_subcommands() {
        let args = effective_args(arg_vec("/usr/local/bin/staticzero-defense", &["--doctor"]));
        assert_eq!(args[0], "staticzero");
        assert_eq!(args[1], "defense");
        assert_eq!(args[2], "--doctor");
    }

    #[test]
    fn plain_staticzero_passes_through_unchanged() {
        let args = effective_args(arg_vec("staticzero", &["defense", "--doctor"]));
        assert_eq!(args[0], "staticzero");
        assert_eq!(args[1], "defense");
        assert_eq!(args[2], "--doctor");

        let args = effective_args(arg_vec("./staticzero", &["--help"]));
        assert_eq!(args[0], "./staticzero");
        assert_eq!(args.len(), 2);
    }

    #[test]
    fn unknown_names_pass_through() {
        let args = effective_args(arg_vec("something-else", &["--help"]));
        assert_eq!(args[0], "something-else");
        assert_eq!(args.len(), 2);
    }

    #[test]
    fn every_subcommand_parses_help() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
