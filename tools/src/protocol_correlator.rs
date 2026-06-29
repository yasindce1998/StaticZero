use anyhow::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(name = "protocol-correlator")]
#[command(about = "Cross-layer protocol correlation engine for telecom threat detection")]
struct Cli {
    /// Listen port for event ingestion (JSON lines over TCP)
    #[arg(long, default_value = "7892")]
    ingest_port: u16,

    /// Correlation time window in milliseconds
    #[arg(long, default_value = "5000")]
    window_ms: u64,

    /// Minimum confidence threshold for threat reporting (0.0 - 1.0)
    #[arg(long, default_value = "0.7")]
    threshold: f64,

    /// Output format (json, csv, syslog)
    #[arg(long, default_value = "json")]
    output: String,

    /// Maximum events held in correlation window
    #[arg(long, default_value = "10000")]
    max_events: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelecomEvent {
    pub timestamp_ns: u64,
    pub layer: TelecomLayer,
    pub event_type: String,
    pub source: String,
    pub target: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TelecomLayer {
    Radio,
    Nas,
    Transport,
    Signaling,
    Core,
    Application,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedThreat {
    pub threat_id: String,
    pub category: ThreatCategory,
    pub confidence: f64,
    pub severity: ThreatSeverity,
    pub layers_involved: Vec<TelecomLayer>,
    pub contributing_events: Vec<String>,
    pub description: String,
    pub mitre_attack_id: Option<String>,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatCategory {
    ImsiCatching,
    ManInTheMiddle,
    ProtocolDowngrade,
    SignalingAbuse,
    TollFraud,
    LocationTracking,
    DataInterception,
    ServiceDenial,
    SliceEscape,
    RoamingExploit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Critical,
    High,
    Medium,
    Low,
}

struct CorrelationEngine {
    events: VecDeque<(Instant, TelecomEvent)>,
    window: Duration,
    threshold: f64,
    max_events: usize,
    threat_counter: u64,
    rules: Vec<CorrelationRule>,
}

struct CorrelationRule {
    name: String,
    category: ThreatCategory,
    severity: ThreatSeverity,
    required_layers: Vec<TelecomLayer>,
    event_pattern: Vec<String>,
    min_events: usize,
    description: String,
    mitre_id: Option<String>,
    action: String,
}

impl CorrelationEngine {
    fn new(window_ms: u64, threshold: f64, max_events: usize) -> Self {
        let rules = Self::build_rules();
        Self {
            events: VecDeque::new(),
            window: Duration::from_millis(window_ms),
            threshold,
            max_events,
            threat_counter: 0,
            rules,
        }
    }

    fn build_rules() -> Vec<CorrelationRule> {
        vec![
            CorrelationRule {
                name: "IMSI Catcher Detection".into(),
                category: ThreatCategory::ImsiCatching,
                severity: ThreatSeverity::Critical,
                required_layers: vec![TelecomLayer::Radio, TelecomLayer::Nas],
                event_pattern: vec![
                    "identity_request".into(),
                    "cipher_mode_null".into(),
                    "cell_reselection".into(),
                ],
                min_events: 2,
                description: "Multiple identity requests with null cipher from same cell indicates IMSI catcher".into(),
                mitre_id: Some("T1617".into()),
                action: "Alert SOC, switch to alternative cell, enable SUCI if 5G".into(),
            },
            CorrelationRule {
                name: "Protocol Downgrade Attack".into(),
                category: ThreatCategory::ProtocolDowngrade,
                severity: ThreatSeverity::High,
                required_layers: vec![TelecomLayer::Radio, TelecomLayer::Nas],
                event_pattern: vec![
                    "rrc_release_redirect".into(),
                    "rat_change_down".into(),
                    "cipher_downgrade".into(),
                ],
                min_events: 2,
                description: "Forced RAT downgrade followed by cipher weakening indicates active downgrade attack".into(),
                mitre_id: Some("T1600.001".into()),
                action: "Block RAT downgrade, maintain minimum cipher strength, alert".into(),
            },
            CorrelationRule {
                name: "SS7 Location Tracking".into(),
                category: ThreatCategory::LocationTracking,
                severity: ThreatSeverity::High,
                required_layers: vec![TelecomLayer::Signaling, TelecomLayer::Core],
                event_pattern: vec![
                    "send_routing_info".into(),
                    "provide_subscriber_info".into(),
                    "any_time_interrogation".into(),
                ],
                min_events: 2,
                description: "SS7 location queries from untrusted originating point code".into(),
                mitre_id: Some("T1430".into()),
                action: "Block at STP, notify subscriber, log originating network".into(),
            },
            CorrelationRule {
                name: "GTP Tunnel Hijack".into(),
                category: ThreatCategory::DataInterception,
                severity: ThreatSeverity::Critical,
                required_layers: vec![TelecomLayer::Transport, TelecomLayer::Core],
                event_pattern: vec![
                    "gtp_create_session".into(),
                    "teid_collision".into(),
                    "unexpected_gtp_source".into(),
                ],
                min_events: 2,
                description: "GTP tunnel manipulation detected — TEID collision or unauthorized session creation".into(),
                mitre_id: None,
                action: "Drop malicious GTP-C, reset affected tunnels, alert NOC".into(),
            },
            CorrelationRule {
                name: "VoLTE Interception".into(),
                category: ThreatCategory::DataInterception,
                severity: ThreatSeverity::Critical,
                required_layers: vec![TelecomLayer::Application, TelecomLayer::Transport],
                event_pattern: vec![
                    "sip_invite".into(),
                    "srtp_key_mismatch".into(),
                    "media_redirect".into(),
                ],
                min_events: 2,
                description: "VoLTE call interception via SIP manipulation and media redirect".into(),
                mitre_id: None,
                action: "Terminate suspicious SIP session, re-register with P-CSCF, alert".into(),
            },
            CorrelationRule {
                name: "Network Slice Escape".into(),
                category: ThreatCategory::SliceEscape,
                severity: ThreatSeverity::Critical,
                required_layers: vec![TelecomLayer::Core, TelecomLayer::Transport],
                event_pattern: vec![
                    "slice_id_mismatch".into(),
                    "cross_slice_traffic".into(),
                    "nssf_manipulation".into(),
                ],
                min_events: 2,
                description: "Traffic crossing network slice boundaries indicates slice isolation failure".into(),
                mitre_id: None,
                action: "Isolate affected slice, drop cross-slice traffic, alert NMS".into(),
            },
            CorrelationRule {
                name: "Roaming Fraud".into(),
                category: ThreatCategory::RoamingExploit,
                severity: ThreatSeverity::High,
                required_layers: vec![TelecomLayer::Signaling, TelecomLayer::Core],
                event_pattern: vec![
                    "update_location".into(),
                    "insert_subscriber_data".into(),
                    "roaming_anomaly".into(),
                ],
                min_events: 2,
                description: "Fraudulent roaming via SS7/Diameter signaling manipulation".into(),
                mitre_id: None,
                action: "Block suspicious VPLMN, verify with HLR/HSS, alert fraud team".into(),
            },
            CorrelationRule {
                name: "Toll Fraud via SIP".into(),
                category: ThreatCategory::TollFraud,
                severity: ThreatSeverity::Medium,
                required_layers: vec![TelecomLayer::Application, TelecomLayer::Signaling],
                event_pattern: vec![
                    "sip_register_anomaly".into(),
                    "high_rate_invite".into(),
                    "premium_number_pattern".into(),
                ],
                min_events: 2,
                description: "Toll fraud via hijacked SIP registration and calls to premium numbers".into(),
                mitre_id: None,
                action: "Block premium destinations, deregister fraudulent endpoint, alert".into(),
            },
        ]
    }

    fn ingest(&mut self, event: TelecomEvent) {
        let now = Instant::now();
        self.events.push_back((now, event));

        // Evict old events
        while let Some((ts, _)) = self.events.front() {
            if now.duration_since(*ts) > self.window {
                self.events.pop_front();
            } else {
                break;
            }
        }

        // Enforce max capacity
        while self.events.len() > self.max_events {
            self.events.pop_front();
        }
    }

    fn correlate(&mut self) -> Vec<CorrelatedThreat> {
        let mut threats = Vec::new();

        for rule in &self.rules {
            let matching_events: Vec<&TelecomEvent> = self.events.iter()
                .map(|(_, e)| e)
                .filter(|e| {
                    rule.required_layers.contains(&e.layer) &&
                    rule.event_pattern.iter().any(|pat| e.event_type.contains(pat.as_str()))
                })
                .collect();

            if matching_events.len() >= rule.min_events {
                let layers_seen: Vec<TelecomLayer> = matching_events.iter()
                    .map(|e| e.layer)
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();

                let layer_coverage = layers_seen.len() as f64 / rule.required_layers.len() as f64;
                let pattern_coverage = matching_events.len() as f64 / rule.event_pattern.len() as f64;
                let confidence = (layer_coverage * 0.6 + pattern_coverage.min(1.0) * 0.4).min(1.0);

                if confidence >= self.threshold {
                    self.threat_counter += 1;
                    threats.push(CorrelatedThreat {
                        threat_id: format!("THR-{:06}", self.threat_counter),
                        category: rule.category,
                        confidence,
                        severity: rule.severity,
                        layers_involved: layers_seen,
                        contributing_events: matching_events.iter()
                            .map(|e| format!("{}:{}", e.event_type, e.source))
                            .collect(),
                        description: rule.description.clone(),
                        mitre_attack_id: rule.mitre_id.clone(),
                        recommended_action: rule.action.clone(),
                    });
                }
            }
        }

        threats
    }

    fn stats(&self) -> EngineStats {
        EngineStats {
            events_in_window: self.events.len(),
            threats_detected: self.threat_counter,
            rules_active: self.rules.len(),
            window_ms: self.window.as_millis() as u64,
        }
    }
}

#[derive(Debug, Serialize)]
struct EngineStats {
    events_in_window: usize,
    threats_detected: u64,
    rules_active: usize,
    window_ms: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    info!("StaticZero Protocol Correlation Engine");
    info!("  Ingest port: {}", cli.ingest_port);
    info!("  Correlation window: {}ms", cli.window_ms);
    info!("  Confidence threshold: {}", cli.threshold);
    info!("  Output format: {}", cli.output);

    let engine = Arc::new(Mutex::new(
        CorrelationEngine::new(cli.window_ms, cli.threshold, cli.max_events)
    ));

    let listener = TcpListener::bind(format!("127.0.0.1:{}", cli.ingest_port))?;
    info!("Listening for events on 127.0.0.1:{}", cli.ingest_port);

    let engine_clone = engine.clone();
    let output_format = cli.output.clone();

    // Periodic correlation check
    let correlate_engine = engine.clone();
    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(1000));
        loop {
            interval.tick().await;
            let threats = {
                let mut eng = correlate_engine.lock().unwrap();
                eng.correlate()
            };
            for threat in threats {
                match output_format.as_str() {
                    "json" => println!("{}", serde_json::to_string(&threat).unwrap()),
                    "csv" => println!("{},{},{:.2},{:?},\"{}\"",
                        threat.threat_id, format!("{:?}", threat.category),
                        threat.confidence, threat.severity, threat.description),
                    _ => println!("{}", serde_json::to_string(&threat).unwrap()),
                }
            }
        }
    });

    // Accept ingest connections
    tokio::task::spawn_blocking(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let eng = engine_clone.clone();
                    std::thread::spawn(move || {
                        let reader = BufReader::new(s);
                        for line in reader.lines() {
                            let line = match line {
                                Ok(l) => l,
                                Err(_) => break,
                            };
                            if let Ok(event) = serde_json::from_str::<TelecomEvent>(&line) {
                                eng.lock().unwrap().ingest(event);
                            }
                        }
                    });
                }
                Err(e) => warn!("Connection error: {}", e),
            }
        }
    });

    tokio::signal::ctrl_c().await?;
    let stats = engine.lock().unwrap().stats();
    info!("Shutdown — {}", serde_json::to_string(&stats).unwrap());
    Ok(())
}
