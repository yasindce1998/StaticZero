//! Direct-to-Cell (D2C) satellite cell monitor — detects spoofed satellite
//! cells (Starlink Direct-to-Cell/T-Mobile SCS, AST SpaceMobile, Skylo
//! NB-NTN) by physics and parameter consistency checks.
//!
//! A satellite cell is an LTE/NR base station a few hundred kilometers
//! overhead (an "eNodeB in space"). Several of its parameters are
//! physically constrained: timing advance must exceed terrestrial limits,
//! LEO doppler swings tens of kHz, SIB19 ephemeris must be present, and
//! the signal must be consistent with a moving cell. A "satellite" cell
//! violating these constraints is the direct-to-cell equivalent of an
//! IMSI catcher.
//!
//! Input: JSON lines of `D2cCellReport` (from modem status, the SDR
//! bridge, or Android's exposed satellite network state). Output: JSON
//! verdicts with a spoof score and concrete reasons.

use std::io::{BufRead, BufReader, Write};

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};

/// Terrestrial LTE/NR timing advance ceiling (TS 38.213): 1282 * 16Tc
/// corresponds to a ~100 km cell radius. Any real satellite cell must
/// exceed it by orders of magnitude.
const TA_TERRESTRIAL_MAX: u32 = 1282;
/// LEO doppler magnitude ceiling for genuine satellite signals (~±48 kHz
/// at L-band for 550-600 km altitude orbits).
const LEO_DOPPLER_MAX_HZ: i32 = 48_000;
/// Terrestrial macro doppler ceiling (UE mobility only).
const TERRESTRIAL_DOPPLER_MAX_HZ: i32 = 1_500;
/// Minimum LEO doppler magnitude expected on a live satellite beam
/// (near-zero only at closest approach, briefly).
const LEO_DOPPLER_MIN_HZ: i32 = 200;
/// Satellite RSRP ceiling: a beam from 550 km is never stronger than a
/// nearby terrestrial tower (dBm, negative values).
const SAT_RSRP_CEILING_DBM: i32 = -85;

/// A serving-cell report as observed by the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct D2cCellReport {
    /// PLMN as 6-digit string, e.g. "310260".
    pub plmn: String,
    /// NR cell global identity (or LTE ECGI) of the reported cell.
    pub cell_global_id: u64,
    pub tac: u32,
    /// True when the cell advertises the NTN/SCS satellite indicator
    /// (SIB19 / NTN-Cell in NR, or SCS capability in LTE).
    pub sat_indicator: bool,
    /// Timing advance reported by the serving cell.
    pub timing_advance: u32,
    /// Observed carrier frequency offset (Hz) against the modem clock.
    pub doppler_hz: Option<i32>,
    /// Received signal power (dBm).
    pub rsrp_dbm: Option<i32>,
    /// True when SIB19 ephemeris was broadcast for this cell.
    pub has_ephemeris: bool,
    /// True when the same cell ID is also visible as a terrestrial cell.
    pub also_seen_terrestrial: bool,
}

/// Verdict for one report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct D2cVerdict {
    pub plmn: String,
    pub cell_global_id: u64,
    pub sat_indicator: bool,
    /// 0.0 (consistent) .. 1.0 (certainly spoofed).
    pub spoof_score: f64,
    pub spoofed: bool,
    pub reasons: Vec<String>,
}

/// Apply physics and parameter consistency checks to one report.
pub fn assess(report: &D2cCellReport) -> D2cVerdict {
    let mut score = 0.0f64;
    let mut reasons = Vec::new();

    if report.sat_indicator {
        if report.timing_advance <= TA_TERRESTRIAL_MAX {
            score += 0.4;
            reasons.push(format!(
                "satellite-indicated cell has terrestrial timing advance {} (<= {})",
                report.timing_advance, TA_TERRESTRIAL_MAX
            ));
        }
        if !report.has_ephemeris {
            score += 0.2;
            reasons.push(
                "no SIB19 ephemeris broadcast — satellite cell cannot be tracked".to_string(),
            );
        }
        if let Some(doppler) = report.doppler_hz {
            let magnitude = doppler.abs();
            if magnitude <= TERRESTRIAL_DOPPLER_MAX_HZ {
                score += 0.3;
                reasons.push(format!(
                    "doppler {doppler} Hz is terrestrial-grade; LEO cells swing ±{LEO_DOPPLER_MAX_HZ} Hz"
                ));
            } else if magnitude > LEO_DOPPLER_MAX_HZ {
                score += 0.1;
                reasons.push(format!(
                    "doppler {doppler} Hz exceeds LEO physical limit ±{LEO_DOPPLER_MAX_HZ} Hz"
                ));
            }
        }
        if let Some(rsrp) = report.rsrp_dbm {
            if rsrp > SAT_RSRP_CEILING_DBM {
                score += 0.2;
                reasons.push(format!(
                    "RSRP {rsrp} dBm too strong for a beam from orbital altitude"
                ));
            }
        }
        if report.also_seen_terrestrial {
            score += 0.3;
            reasons.push(
                "same cell ID active as a terrestrial cell — impossible for a satellite"
                    .to_string(),
            );
        }
    } else {
        // No satellite indication: only flag cells that pretend to be
        // satellite-capable networks (e.g. a spoofed D2C PLMN).
        if is_known_d2c_plmn(&report.plmn) {
            score += 0.7;
            reasons.push(format!(
                "cell on D2C PLMN {} without satellite indicator — identity mismatch",
                report.plmn
            ));
        }
        if report.timing_advance > TA_TERRESTRIAL_MAX {
            score += 0.2;
            reasons.push(format!(
                "terrestrial cell reports satellite-grade timing advance {}",
                report.timing_advance
            ));
        }
        if let Some(doppler) = report.doppler_hz {
            if doppler.abs() > LEO_DOPPLER_MIN_HZ && doppler.abs() > TERRESTRIAL_DOPPLER_MAX_HZ {
                score += 0.2;
                reasons.push(format!(
                    "terrestrial cell shows satellite-grade doppler {doppler} Hz"
                ));
            }
        }
    }

    let score = score.min(1.0);
    let spoofed = score >= 0.6;
    if reasons.is_empty() {
        reasons.push("cell parameters are physically consistent".to_string());
    }

    D2cVerdict {
        plmn: report.plmn.clone(),
        cell_global_id: report.cell_global_id,
        sat_indicator: report.sat_indicator,
        spoof_score: score,
        spoofed,
        reasons,
    }
}

/// PLMNs publicly associated with direct-to-cell satellite services
/// (observed in crowdsourced D2C measurements, 2025). The table is a
/// detection aid, not an authorization list — pair with physics checks.
fn is_known_d2c_plmn(plmn: &str) -> bool {
    matches!(
        plmn,
        // T-Mobile USA — Starlink Direct-to-Cell SCS overlay
        "310260"
            // Skylo NB-NTN service partners (US)
            | "310070" | "311480"
            // Lynk Global partner deployments
            | "310240"
    )
}

#[derive(Parser, Debug)]
#[command(
    name = "d2c-monitor",
    about = "Direct-to-Cell satellite cell monitor — spoofed satellite cell (satellite IMSI catcher) detection"
)]
struct Cli {
    /// Input file with one D2cCellReport JSON object per line (stdin if omitted)
    input: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let stdin = std::io::stdin();
    let reader: Box<dyn BufRead> = match cli.input {
        Some(path) => Box::new(BufReader::new(
            std::fs::File::open(&path).with_context(|| format!("open {path}"))?,
        )),
        None => Box::new(stdin.lock()),
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for (index, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("read input line {}", index + 1))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let report: D2cCellReport = serde_json::from_str(trimmed)
            .with_context(|| format!("parse JSON record on line {}", index + 1))?;
        let verdict = assess(&report);
        serde_json::to_writer(&mut out, &verdict)?;
        writeln!(out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn genuine_satellite() -> D2cCellReport {
        D2cCellReport {
            plmn: "310260".to_string(),
            cell_global_id: 0x0000_0BAD_C0DE,
            tac: 30001,
            sat_indicator: true,
            timing_advance: 85_000,
            doppler_hz: Some(-22_000),
            rsrp_dbm: Some(-112),
            has_ephemeris: true,
            also_seen_terrestrial: false,
        }
    }

    #[test]
    fn genuine_satellite_cell_passes() {
        let verdict = assess(&genuine_satellite());
        assert!(!verdict.spoofed);
        assert!(verdict.spoof_score < 0.2, "score={}", verdict.spoof_score);
    }

    #[test]
    fn spoofed_satellite_cell_flags_every_check() {
        let report = D2cCellReport {
            timing_advance: 640,         // terrestrial TA
            doppler_hz: Some(300),       // terrestrial doppler
            rsrp_dbm: Some(-55),         // nearby transmitter
            has_ephemeris: false,        // no ephemeris
            also_seen_terrestrial: true, // impossible dual presence
            ..genuine_satellite()
        };
        let verdict = assess(&report);
        assert!(verdict.spoofed);
        assert!((verdict.spoof_score - 1.0).abs() < 1e-9);
        assert!(verdict.reasons.iter().any(|r| r.contains("timing advance")));
        assert!(verdict.reasons.iter().any(|r| r.contains("doppler")));
        assert!(verdict.reasons.iter().any(|r| r.contains("RSRP")));
    }

    #[test]
    fn terrestrial_cell_on_d2c_plmn_without_indicator_flags() {
        let report = D2cCellReport {
            plmn: "310260".to_string(),
            sat_indicator: false,
            timing_advance: 300,
            doppler_hz: Some(200),
            rsrp_dbm: Some(-70),
            has_ephemeris: false,
            also_seen_terrestrial: false,
            cell_global_id: 1,
            tac: 1,
        };
        let verdict = assess(&report);
        assert!(verdict.spoofed);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("without satellite indicator")));
    }

    #[test]
    fn ordinary_terrestrial_cell_passes() {
        let report = D2cCellReport {
            plmn: "310410".to_string(),
            sat_indicator: false,
            timing_advance: 200,
            doppler_hz: Some(150),
            rsrp_dbm: Some(-85),
            has_ephemeris: false,
            also_seen_terrestrial: false,
            cell_global_id: 2,
            tac: 2,
        };
        let verdict = assess(&report);
        assert!(!verdict.spoofed);
    }

    #[test]
    fn doppler_above_leo_limit_also_flags() {
        let report = D2cCellReport {
            doppler_hz: Some(60_000), // impossible for LEO too
            ..genuine_satellite()
        };
        let verdict = assess(&report);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("exceeds LEO physical limit")));
    }
}
