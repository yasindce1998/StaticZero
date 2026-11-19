//! 6G control-plane trace analyzer and scenario generator.
//!
//! 6G standardization (3GPP Release 20 studies) is not yet deployable, so
//! this tool works on simulation traces: Colosseum-class testbeds, digital
//! twins, and lab replay files. It ingests JSON-lines control-plane events
//! (AI-RAN model integrity, post-quantum handshakes, network-of-networks
//! credential use), applies the same invariants the defense engine expects
//! from a live 6G stack, and emits verdict lines that
//! `staticzero-defense --tool-input airan|pqc|noncred=<path>` consumes.
//!
//! Invariants enforced:
//!
//! - **AI-RAN model integrity (Module 66)**: a model's integrity hash may
//!   only change together with a version advance. A hash change without a
//!   version bump, or a version regression, is tampering.
//! - **PQC handshakes (Module 67)**: quantum-safe suites (ML-KEM class)
//!   must not silently fall back to classic crypto. Any fallback is a
//!   harvest-now-decrypt-later indicator.
//! - **Network-of-networks credentials (Module 70)**: a credential issued
//!   by one member network must not appear authorized in another without
//!   an explicit roaming/trust entry.
//!
//! `generate` mode emits synthetic trace events for lab scenarios so the
//! full tool → adapter → correlation chain can be demonstrated without a
//! testbed.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

// ── Input trace events ───────────────────────────────────────────────────────

/// One raw control-plane trace event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum TraceEvent {
    ModelIntegrity {
        model_id: String,
        version: u32,
        integrity_hash: String,
    },
    PqcHandshake {
        peer: String,
        suite: String,
        fallback: bool,
    },
    NonCredential {
        credential: String,
        source_network: String,
        target_network: String,
        authorized: bool,
    },
}

// ── Output verdicts (consumed by the defense adapters) ──────────────────────

/// Module 66 verdict: AI-RAN model integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRanVerdict {
    /// Control-plane domain the event belongs to; verdicts in one domain
    /// correlate together in the defense engine.
    pub domain: String,
    pub model_id: String,
    pub tampered: bool,
    pub version: u32,
    pub reason: String,
}

/// Module 67 verdict: PQC handshake downgrade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcVerdict {
    pub domain: String,
    pub peer: String,
    pub downgraded: bool,
    pub suite: String,
}

/// Module 70 verdict: network-of-networks credential abuse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonCredVerdict {
    pub domain: String,
    pub credential: String,
    pub source_network: String,
    pub target_network: String,
    pub crossed: bool,
}

// ── Trace analyzer ───────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct SixgAnalyzer {
    models: std::collections::HashMap<String, (u32, String)>,
}

impl SixgAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest one trace event; returns the verdict it triggered, if any.
    pub fn analyze(&mut self, event: &TraceEvent) -> Vec<Verdict> {
        // All verdicts share the default control-plane domain; events from
        // distinct domains would carry their own scope.
        let domain = "core-1".to_string();
        match event {
            TraceEvent::ModelIntegrity {
                model_id,
                version,
                integrity_hash,
            } => {
                let mut verdicts = Vec::new();
                if let Some((prev_version, prev_hash)) = self.models.get(model_id) {
                    // Invariants: a hash may only change together with a
                    // version advance, and versions never regress.
                    let tampered = if *version < *prev_version {
                        Some("version regression or replay")
                    } else if *version == *prev_version && integrity_hash != prev_hash {
                        Some("integrity hash changed without version advance")
                    } else {
                        None
                    };
                    if let Some(reason) = tampered {
                        verdicts.push(Verdict::AiRan(AiRanVerdict {
                            domain: domain.clone(),
                            model_id: model_id.clone(),
                            tampered: true,
                            version: *version,
                            reason: reason.to_string(),
                        }));
                    }
                }
                self.models
                    .insert(model_id.clone(), (*version, integrity_hash.clone()));
                verdicts
            }
            TraceEvent::PqcHandshake {
                peer,
                suite,
                fallback,
            } => {
                // A fallback to classic crypto is always a verdict; the
                // defense engine's standalone pattern escalates repeats.
                vec![Verdict::Pqc(PqcVerdict {
                    domain,
                    peer: peer.clone(),
                    downgraded: *fallback,
                    suite: suite.clone(),
                })]
            }
            TraceEvent::NonCredential {
                credential,
                source_network,
                target_network,
                authorized,
            } => {
                vec![Verdict::NonCred(NonCredVerdict {
                    domain,
                    credential: credential.clone(),
                    source_network: source_network.clone(),
                    target_network: target_network.clone(),
                    crossed: !*authorized,
                })]
            }
        }
    }
}

/// One analyzer verdict, tagged for JSON lines output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Verdict {
    AiRan(AiRanVerdict),
    Pqc(PqcVerdict),
    #[serde(rename = "non_credential")]
    NonCred(NonCredVerdict),
}

// ── Scenario generation ──────────────────────────────────────────────────────

/// Synthetic lab scenarios for `generate` mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// Clean traffic: no verdicts.
    Clean,
    /// AI-RAN model tampering: hash changes without version advance.
    AiRanTamper,
    /// PQC downgrades: quantum-safe handshakes falling back to classic.
    PqcDowngrade,
    /// Network-of-networks credential crossing without authorization.
    NonCredentialAbuse,
}

impl Scenario {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "clean" => Ok(Self::Clean),
            "ai-ran-tamper" => Ok(Self::AiRanTamper),
            "pqc-downgrade" => Ok(Self::PqcDowngrade),
            "non-credential-abuse" => Ok(Self::NonCredentialAbuse),
            other => bail!(
                "unknown scenario {other:?}; expected clean, ai-ran-tamper, pqc-downgrade, or non-credential-abuse"
            ),
        }
    }

    /// Produce `count` trace events for this scenario.
    pub fn events(self, count: usize) -> Vec<TraceEvent> {
        match self {
            Self::Clean => (0..count)
                .map(|i| TraceEvent::ModelIntegrity {
                    model_id: "airan-phy-01".into(),
                    version: i as u32 + 1,
                    integrity_hash: format!("{i:064x}"),
                })
                .chain((0..count).map(|i| TraceEvent::PqcHandshake {
                    peer: format!("amf-{i}"),
                    suite: "ml-kem-768".into(),
                    fallback: false,
                }))
                .collect(),
            Self::AiRanTamper => (0..count)
                .map(|i| {
                    // tampered: from the midpoint on, the hash changes
                    // while the version stays put
                    let tampered = i >= count / 2;
                    TraceEvent::ModelIntegrity {
                        model_id: "airan-phy-01".into(),
                        version: 4,
                        integrity_hash: if tampered {
                            "deadbeefdeadbeef".into()
                        } else {
                            "a1b2c3d4a1b2c3d4".into()
                        },
                    }
                })
                .collect(),
            Self::PqcDowngrade => (0..count)
                .map(|i| TraceEvent::PqcHandshake {
                    peer: format!("amf-{}", i % 3),
                    suite: if i % 2 == 0 {
                        "ml-kem-768".into()
                    } else {
                        "rsa-2048".into()
                    },
                    fallback: i % 2 == 1,
                })
                .collect(),
            Self::NonCredentialAbuse => (0..count)
                .map(|i| TraceEvent::NonCredential {
                    credential: format!("cred-{i:03}"),
                    source_network: "sat-net".into(),
                    target_network: if i % 2 == 0 {
                        "wlan-net".into()
                    } else {
                        "private5g-net".into()
                    },
                    authorized: false,
                })
                .collect(),
        }
    }
}

// ── CLI ──────────────────────────────────────────────────────────────────────

/// Command-line interface for `6g-sim`. Usable standalone (the thin
/// `src/bin/6g-sim.rs` wrapper) or as a subcommand of the multi-call
/// `staticzero` binary.
#[derive(Parser, Debug)]
#[command(
    name = "6g-sim",
    about = "6G control-plane trace analyzer — AI-RAN model integrity, PQC downgrade, and network-of-networks credential verdicts for the defense engine"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Analyze a JSON-lines trace file (stdin if omitted) and emit verdicts
    Analyze { input: Option<PathBuf> },
    /// Emit synthetic trace events for a lab scenario (pipe into 6g-sim analyze)
    Generate {
        /// Scenario: clean, ai-ran-tamper, pqc-downgrade, non-credential-abuse
        #[arg(long)]
        scenario: String,
        /// Number of trace events to generate
        #[arg(long, default_value_t = 10)]
        count: usize,
    },
}

/// Entry point invoked by the `6g-sim` bin and the multi-call `staticzero`
/// binary's `6g-sim` subcommand.
pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Analyze { input } => {
            let stdin = std::io::stdin();
            let reader: Box<dyn BufRead> = match input {
                Some(path) => Box::new(BufReader::new(
                    std::fs::File::open(&path).with_context(|| format!("open {path:?}"))?,
                )),
                None => Box::new(stdin.lock()),
            };
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            let mut analyzer = SixgAnalyzer::new();
            for (index, line) in reader.lines().enumerate() {
                let line = line.with_context(|| format!("read trace line {}", index + 1))?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let event: TraceEvent = serde_json::from_str(trimmed)
                    .with_context(|| format!("parse trace event on line {}", index + 1))?;
                for verdict in analyzer.analyze(&event) {
                    serde_json::to_writer(&mut out, &verdict)?;
                    writeln!(out)?;
                }
            }
            Ok(())
        }
        Command::Generate { scenario, count } => {
            let scenario = Scenario::parse(&scenario)?;
            if count == 0 || count > 100_000 {
                bail!("count must be between 1 and 100000, got {count}");
            }
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            for event in scenario.events(count) {
                serde_json::to_writer(&mut out, &event)?;
                writeln!(out)?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_model_updates_produce_no_verdicts() {
        let mut analyzer = SixgAnalyzer::new();
        for version in 1..5 {
            let verdicts = analyzer.analyze(&TraceEvent::ModelIntegrity {
                model_id: "m".into(),
                version,
                integrity_hash: "abc".into(),
            });
            assert!(verdicts.is_empty());
        }
    }

    #[test]
    fn hash_change_without_version_advance_is_tampering() {
        let mut analyzer = SixgAnalyzer::new();
        analyzer.analyze(&TraceEvent::ModelIntegrity {
            model_id: "m".into(),
            version: 4,
            integrity_hash: "aaa".into(),
        });
        let verdicts = analyzer.analyze(&TraceEvent::ModelIntegrity {
            model_id: "m".into(),
            version: 4,
            integrity_hash: "bbb".into(),
        });
        assert_eq!(verdicts.len(), 1);
        let Verdict::AiRan(v) = &verdicts[0] else {
            panic!("expected ai_ran verdict");
        };
        assert!(v.tampered);
        assert!(v.reason.contains("without version advance"));
    }

    #[test]
    fn version_regression_is_tampering() {
        let mut analyzer = SixgAnalyzer::new();
        analyzer.analyze(&TraceEvent::ModelIntegrity {
            model_id: "m".into(),
            version: 4,
            integrity_hash: "aaa".into(),
        });
        let verdicts = analyzer.analyze(&TraceEvent::ModelIntegrity {
            model_id: "m".into(),
            version: 3,
            integrity_hash: "aaa".into(),
        });
        let Verdict::AiRan(v) = &verdicts[0] else {
            panic!("expected ai_ran verdict");
        };
        assert!(v.reason.contains("regression"));
    }

    #[test]
    fn version_advance_with_new_hash_is_clean() {
        let mut analyzer = SixgAnalyzer::new();
        analyzer.analyze(&TraceEvent::ModelIntegrity {
            model_id: "m".into(),
            version: 4,
            integrity_hash: "aaa".into(),
        });
        let verdicts = analyzer.analyze(&TraceEvent::ModelIntegrity {
            model_id: "m".into(),
            version: 5,
            integrity_hash: "bbb".into(),
        });
        assert!(verdicts.is_empty());
    }

    #[test]
    fn pqc_fallback_flags_downgrade() {
        let mut analyzer = SixgAnalyzer::new();
        let verdicts = analyzer.analyze(&TraceEvent::PqcHandshake {
            peer: "amf-1".into(),
            suite: "ml-kem-768".into(),
            fallback: false,
        });
        let Verdict::Pqc(v) = &verdicts[0] else {
            panic!("expected pqc verdict");
        };
        assert!(!v.downgraded);

        let verdicts = analyzer.analyze(&TraceEvent::PqcHandshake {
            peer: "amf-1".into(),
            suite: "rsa-2048".into(),
            fallback: true,
        });
        let Verdict::Pqc(v) = &verdicts[0] else {
            panic!("expected pqc verdict");
        };
        assert!(v.downgraded);
    }

    #[test]
    fn unauthorized_cross_network_use_flags() {
        let mut analyzer = SixgAnalyzer::new();
        let verdicts = analyzer.analyze(&TraceEvent::NonCredential {
            credential: "cred-1".into(),
            source_network: "sat-net".into(),
            target_network: "wlan-net".into(),
            authorized: false,
        });
        let Verdict::NonCred(v) = &verdicts[0] else {
            panic!("expected non_credential verdict");
        };
        assert!(v.crossed);
    }

    #[test]
    fn verdicts_round_trip_through_json() {
        // The defense adapter parses these shapes; pin them.
        let verdict = Verdict::AiRan(AiRanVerdict {
            domain: "core-1".into(),
            model_id: "airan-phy-01".into(),
            tampered: true,
            version: 4,
            reason: "integrity hash changed without version advance".into(),
        });
        let json = serde_json::to_string(&verdict).unwrap();
        assert!(json.contains(r#""kind":"ai_ran""#));
        let round: Verdict = serde_json::from_str(&json).unwrap();
        assert!(matches!(round, Verdict::AiRan(_)));

        let verdict = Verdict::Pqc(PqcVerdict {
            domain: "core-1".into(),
            peer: "amf-1".into(),
            downgraded: true,
            suite: "rsa-2048".into(),
        });
        let json = serde_json::to_string(&verdict).unwrap();
        assert!(json.contains(r#""kind":"pqc""#));

        let verdict = Verdict::NonCred(NonCredVerdict {
            domain: "core-1".into(),
            credential: "cred-1".into(),
            source_network: "sat-net".into(),
            target_network: "wlan-net".into(),
            crossed: true,
        });
        let json = serde_json::to_string(&verdict).unwrap();
        assert!(json.contains(r#""kind":"non_credential""#));
    }

    #[test]
    fn generated_scenarios_produce_expected_verdicts() {
        // ai-ran-tamper: exactly one tampered model event among the events.
        let mut analyzer = SixgAnalyzer::new();
        let tampered = Scenario::AiRanTamper
            .events(5)
            .iter()
            .flat_map(|event| analyzer.analyze(event))
            .filter(|v| matches!(v, Verdict::AiRan(a) if a.tampered))
            .count();
        assert_eq!(tampered, 1);

        // pqc-downgrade: half the handshakes fall back.
        let mut analyzer = SixgAnalyzer::new();
        let downgraded = Scenario::PqcDowngrade
            .events(10)
            .iter()
            .flat_map(|event| analyzer.analyze(event))
            .filter(|v| matches!(v, Verdict::Pqc(p) if p.downgraded))
            .count();
        assert_eq!(downgraded, 5);

        // clean: no verdicts at all.
        let mut analyzer = SixgAnalyzer::new();
        let any_flagged = Scenario::Clean
            .events(10)
            .iter()
            .flat_map(|event| analyzer.analyze(event))
            .any(|v| match v {
                Verdict::AiRan(a) => a.tampered,
                Verdict::Pqc(p) => p.downgraded,
                Verdict::NonCred(n) => n.crossed,
            });
        assert!(!any_flagged);
    }
}
