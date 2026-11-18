//! Wi-Fi 7 (802.11be) Multi-Link Operation analyzer.
//!
//! Tracks per-link state of a Multi-Link Device (MLD) from observed frame
//! records and detects the MLO attack surface documented in current
//! research:
//!
//! - **Link desynchronization**: sequence-number regression on one link
//!   of an MLO set (teardown forcing fallback to a single weaker link).
//! - **Key separation abuse**: a link accepting a key generation that
//!   belongs to another link or an older set of links. The 802.11be key
//!   hierarchy requires each link to refuse keys from a different link
//!   or generation.
//! - **Auth suite inconsistency**: MLO mandates the same AKM/cipher on
//!   every link of an MLD (WPA3-only on 6 GHz, no transition mode).
//! - **Link flapping**: rapid link add/remove cycling (DoS).
//!
//! Input: JSON lines of `MloLinkRecord`. Output: JSON findings.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};

/// Sequence regression beyond this many frames indicates link teardown.
const SEQ_REGRESSION_THRESHOLD: u32 = 64;
/// Key generations a link may fall behind before being flagged stale.
const KEY_GEN_STALENESS: u8 = 1;
/// Link state transitions per MLD per 10 s before flapping is flagged.
const FLAP_RATE_LIMIT: u32 = 6;
const FLAP_WINDOW_NS: u64 = 10_000_000_000;

/// One observed MLO link record (a management action or EAPOL exchange).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MloLinkRecord {
    /// MLD MAC address (or its hash) as a stable string key.
    pub mld_addr: String,
    /// MLO link ID (0-15).
    pub link_id: u8,
    /// Per-link sequence number at observation time.
    pub seq_num: u32,
    /// Per-link key generation counter.
    pub key_gen: u8,
    /// AKM suite selector in use on this link (e.g. 0x00-0F-AC:8 SAE).
    pub auth_suite: u16,
    /// True when the link state transitioned (link add/remove/reassoc).
    pub link_transition: bool,
    /// Observation timestamp (ns).
    pub timestamp_ns: u64,
}

/// Severity of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// One MLO analyzer finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MloFinding {
    pub mld_addr: String,
    pub link_id: u8,
    pub kind: FindingType,
    pub severity: Severity,
    pub detail: String,
    pub timestamp_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingType {
    LinkDesync,
    KeySeparationAbuse,
    AuthSuiteMismatch,
    LinkFlapping,
}

#[derive(Debug, Clone)]
struct LinkState {
    seq_num: u32,
    key_gen: u8,
    auth_suite: Option<u16>,
    transitions: Vec<u64>,
}

/// Stateful analyzer over a stream of link records.
#[derive(Debug, Default)]
pub struct MloAnalyzer {
    links: HashMap<(String, u8), LinkState>,
    /// Highest key generation observed per MLD across all links.
    mld_key_gen: HashMap<String, u8>,
}

impl MloAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest one record and return any findings it triggered.
    pub fn analyze(&mut self, record: &MloLinkRecord) -> Vec<MloFinding> {
        let mut findings = Vec::new();
        let key = (record.mld_addr.clone(), record.link_id);

        // Key separation: a generation older than the MLD-wide maximum
        // belongs to another link or a stale set of links. This applies to
        // both new and already-tracked links.
        let mld_max = self
            .mld_key_gen
            .get(&record.mld_addr)
            .copied()
            .unwrap_or(record.key_gen);
        if record.key_gen + KEY_GEN_STALENESS < mld_max {
            findings.push(MloFinding {
                mld_addr: record.mld_addr.clone(),
                link_id: record.link_id,
                kind: FindingType::KeySeparationAbuse,
                severity: Severity::Critical,
                detail: format!(
                    "link {} accepts key generation {} while MLD is at {} — key separation abuse",
                    record.link_id, record.key_gen, mld_max
                ),
                timestamp_ns: record.timestamp_ns,
            });
        }

        if let Some(state) = self.links.get_mut(&key) {
            // 1. Sequence regression = link desync / teardown attempt.
            if record.seq_num + SEQ_REGRESSION_THRESHOLD < state.seq_num {
                findings.push(MloFinding {
                    mld_addr: record.mld_addr.clone(),
                    link_id: record.link_id,
                    kind: FindingType::LinkDesync,
                    severity: Severity::Critical,
                    detail: format!(
                        "sequence regression {} -> {} on link {} — MLO link desynchronization attack",
                        state.seq_num, record.seq_num, record.link_id
                    ),
                    timestamp_ns: record.timestamp_ns,
                });
            }

            // 3. Auth suite inconsistency across links of one MLD.
            if let Some(prev_suite) = state.auth_suite {
                if prev_suite != record.auth_suite {
                    findings.push(MloFinding {
                        mld_addr: record.mld_addr.clone(),
                        link_id: record.link_id,
                        kind: FindingType::AuthSuiteMismatch,
                        severity: Severity::Warning,
                        detail: format!(
                            "link {} changed AKM suite {:04x} -> {:04x}; MLO mandates one suite per MLD",
                            record.link_id, prev_suite, record.auth_suite
                        ),
                        timestamp_ns: record.timestamp_ns,
                    });
                }
            }

            // 4. Link flapping.
            if record.link_transition {
                state.transitions.push(record.timestamp_ns);
                let cutoff = record.timestamp_ns.saturating_sub(FLAP_WINDOW_NS);
                state.transitions.retain(|t| *t >= cutoff);
                if state.transitions.len() as u32 >= FLAP_RATE_LIMIT {
                    findings.push(MloFinding {
                        mld_addr: record.mld_addr.clone(),
                        link_id: record.link_id,
                        kind: FindingType::LinkFlapping,
                        severity: Severity::Warning,
                        detail: format!(
                            "{} link transitions in the last 10s on link {} — MLO DoS",
                            state.transitions.len(),
                            record.link_id
                        ),
                        timestamp_ns: record.timestamp_ns,
                    });
                }
            }

            state.seq_num = state.seq_num.max(record.seq_num);
            state.key_gen = state.key_gen.max(record.key_gen);
            state.auth_suite = Some(record.auth_suite);
        } else {
            self.links.insert(
                key,
                LinkState {
                    seq_num: record.seq_num,
                    key_gen: record.key_gen,
                    auth_suite: Some(record.auth_suite),
                    transitions: if record.link_transition {
                        vec![record.timestamp_ns]
                    } else {
                        Vec::new()
                    },
                },
            );
        }

        let mld_max = mld_max.max(record.key_gen);
        self.mld_key_gen.insert(record.mld_addr.clone(), mld_max);

        findings
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "mlo-analyzer",
    about = "Wi-Fi 7 Multi-Link Operation analyzer — link desync, key separation abuse, suite mismatch, flapping"
)]
struct Cli {
    /// Input file with one MloLinkRecord JSON object per line (stdin if omitted)
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
    let mut analyzer = MloAnalyzer::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("read input line {}", index + 1))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let record: MloLinkRecord = serde_json::from_str(trimmed)
            .with_context(|| format!("parse JSON record on line {}", index + 1))?;
        for finding in analyzer.analyze(&record) {
            serde_json::to_writer(&mut out, &finding)?;
            writeln!(out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(mld: &str, link: u8, seq: u32, key_gen: u8, ts: u64) -> MloLinkRecord {
        MloLinkRecord {
            mld_addr: mld.to_string(),
            link_id: link,
            seq_num: seq,
            key_gen,
            auth_suite: 0x0008, // SAE
            link_transition: false,
            timestamp_ns: ts,
        }
    }

    #[test]
    fn normal_operation_produces_no_findings() {
        let mut analyzer = MloAnalyzer::new();
        for seq in [100u32, 120, 140, 160] {
            assert!(analyzer
                .analyze(&record("aa:bb", 1, seq, 3, seq as u64))
                .is_empty());
            assert!(analyzer
                .analyze(&record("aa:bb", 2, seq + 5, 3, seq as u64))
                .is_empty());
        }
    }

    #[test]
    fn sequence_regression_flags_desync() {
        let mut analyzer = MloAnalyzer::new();
        analyzer.analyze(&record("aa:bb", 0, 4000, 2, 1));
        let findings = analyzer.analyze(&record("aa:bb", 0, 3900, 2, 2));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FindingType::LinkDesync);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].detail.contains("desynchronization"));
    }

    #[test]
    fn small_regression_within_noise_is_ignored() {
        let mut analyzer = MloAnalyzer::new();
        analyzer.analyze(&record("aa:bb", 0, 4000, 2, 1));
        assert!(analyzer.analyze(&record("aa:bb", 0, 3980, 2, 2)).is_empty());
    }

    #[test]
    fn stale_key_generation_flags_separation_abuse() {
        let mut analyzer = MloAnalyzer::new();
        // Link 0 advances the MLD to generation 5.
        analyzer.analyze(&record("aa:bb", 0, 100, 5, 1));
        // Link 1 then accepts an old generation 2 key.
        let findings = analyzer.analyze(&record("aa:bb", 1, 100, 2, 2));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FindingType::KeySeparationAbuse);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn same_generation_across_links_is_fine() {
        let mut analyzer = MloAnalyzer::new();
        analyzer.analyze(&record("aa:bb", 0, 100, 4, 1));
        assert!(analyzer.analyze(&record("aa:bb", 1, 100, 4, 2)).is_empty());
    }

    #[test]
    fn auth_suite_change_flags_mismatch() {
        let mut analyzer = MloAnalyzer::new();
        analyzer.analyze(&record("aa:bb", 3, 100, 1, 1));
        let mut changed = record("aa:bb", 3, 120, 1, 2);
        changed.auth_suite = 0x0002; // downgraded suite
        let findings = analyzer.analyze(&changed);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FindingType::AuthSuiteMismatch);
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn rapid_transitions_flag_flapping() {
        let mut analyzer = MloAnalyzer::new();
        let mut saw_flap = false;
        for i in 0..8u64 {
            let mut rec = record("cc:dd", 0, 100 + i as u32, 1, i * 1_000_000_000);
            rec.link_transition = true;
            if !analyzer.analyze(&rec).is_empty() {
                saw_flap = true;
            }
        }
        assert!(saw_flap);
    }
}
