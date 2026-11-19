//! Auxiliary telecom security tooling — protocol dissection, SDR control,
//! firmware analysis, and cross-layer correlation.
//!
//! Every tool lives as a library module with a `Cli` and a `run` entry
//! point, exposed two ways: a thin standalone binary under `src/bin/` and
//! a subcommand of the multi-call `staticzero` binary (the `cli` crate).

pub mod d2c_monitor;
pub mod mlo_analyzer;
pub mod modem_firmware;
pub mod osnma_verify;
pub mod protocol_correlator;
pub mod protocol_dissectors;
pub mod rf_selftest;
pub mod sdr_integration;
pub mod sixg_sim;
#[cfg(feature = "soapy")]
pub mod soapy;
