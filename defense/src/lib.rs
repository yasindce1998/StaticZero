use std::collections::{HashMap as StdHashMap, HashSet, VecDeque};

use common::{
    DefenseAlert, ALERT_CELL_ANOMALY, ALERT_DOWNGRADE_ATTACK, ALERT_ESIM_TAMPER,
    ALERT_GTP_ANOMALY, ALERT_IMSI_CATCHER, ALERT_MODEM_TAMPER, ALERT_NAS_REPLAY,
    ALERT_RF_FINGERPRINT, ALERT_ROAMING_ANOMALY, ALERT_ROGUE_TOWER, ALERT_SLICE_VIOLATION,
    ALERT_SS7_ANOMALY, ALERT_VOLTE_FRAUD,
};
use serde::{Deserialize, Serialize};

// ══════════════════════════════════════════════════════════════════════════════
// Telecom alert detail formatting
// ══════════════════════════════════════════════════════════════════════════════

pub fn format_alert_details(alert: &DefenseAlert) -> String {
    let detail_u64 = u64::from_le_bytes([
        alert.details[0],
        alert.details[1],
        alert.details[2],
        alert.details[3],
        alert.details[4],
        alert.details[5],
        alert.details[6],
        alert.details[7],
    ]);
    match alert.alert_type {
        ALERT_ROGUE_TOWER => format!("cell_id={}, signal_delta={}", alert.context, detail_u64),
        ALERT_DOWNGRADE_ATTACK => format!("cell_id={}, target_rat={}", alert.context, detail_u64),
        ALERT_IMSI_CATCHER => format!("cell_id={}, identity_reqs={}", alert.context, detail_u64),
        ALERT_CELL_ANOMALY => format!("cell_id={}, anomaly_flags={}", alert.context, detail_u64),
        ALERT_GTP_ANOMALY => format!("teid={}, rate={}", alert.context, detail_u64),
        ALERT_SS7_ANOMALY => format!("msg_type={}, source_gt={}", alert.context, detail_u64),
        ALERT_MODEM_TAMPER => format!("pid={}, access_type={}", alert.context, detail_u64),
        ALERT_NAS_REPLAY => format!("seq={}, replay_delta={}", alert.context, detail_u64),
        ALERT_VOLTE_FRAUD => format!("call_rate={}, threshold={}", alert.context, detail_u64),
        ALERT_ESIM_TAMPER => format!("eid_hash={}, op_type={}", alert.context, detail_u64),
        ALERT_SLICE_VIOLATION => format!("slice_id={}, violation={}", alert.context, detail_u64),
        ALERT_ROAMING_ANOMALY => format!("plmn={}, anomaly={}", alert.context, detail_u64),
        ALERT_RF_FINGERPRINT => format!("cell_id={}, deviation={}", alert.context, detail_u64),
        _ => format!("context={}", alert.context),
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Telecom Correlation Engine
// Cross-layer protocol correlation for advanced telecom threat detection
// ══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelecomEvent {
    pub timestamp_ns: u64,
    pub layer: TelecomLayer,
    pub event_type: u32,
    pub cell_id: u32,
    pub imsi_hash: u64,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TelecomLayer {
    Radio,
    Nas,
    Transport,
    Signaling,
    Core,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedThreat {
    pub threat_id: u64,
    pub confidence: f64,
    pub severity: u8,
    pub category: ThreatCategory,
    pub layers_involved: Vec<TelecomLayer>,
    pub events: Vec<TelecomEvent>,
    pub description: String,
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

#[derive(Debug, Clone)]
struct CellEventWindow {
    events: VecDeque<TelecomEvent>,
    window_ns: u64,
}

impl CellEventWindow {
    fn new(window_ns: u64) -> Self {
        Self {
            events: VecDeque::new(),
            window_ns,
        }
    }

    fn push(&mut self, event: TelecomEvent) {
        let cutoff = event.timestamp_ns.saturating_sub(self.window_ns);
        while let Some(front) = self.events.front() {
            if front.timestamp_ns < cutoff {
                self.events.pop_front();
            } else {
                break;
            }
        }
        self.events.push_back(event);
    }

    fn layers_active(&self) -> HashSet<TelecomLayer> {
        self.events.iter().map(|e| e.layer).collect()
    }

    fn events_in_layer(&self, layer: TelecomLayer) -> Vec<&TelecomEvent> {
        self.events.iter().filter(|e| e.layer == layer).collect()
    }
}

const TELECOM_CORRELATION_WINDOW_NS: u64 = 60_000_000_000;
const MIN_CORRELATION_CONFIDENCE: f64 = 0.6;

pub struct TelecomCorrelationEngine {
    cell_windows: StdHashMap<u32, CellEventWindow>,
    imsi_windows: StdHashMap<u64, CellEventWindow>,
    detected_threats: VecDeque<CorrelatedThreat>,
    threat_counter: u64,
    pub metrics: TelecomCorrelationMetrics,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TelecomCorrelationMetrics {
    pub events_processed: u64,
    pub threats_detected: u64,
    pub multi_layer_correlations: u64,
    pub false_positive_overrides: u64,
}

impl TelecomCorrelationEngine {
    pub fn new() -> Self {
        Self {
            cell_windows: StdHashMap::new(),
            imsi_windows: StdHashMap::new(),
            detected_threats: VecDeque::new(),
            threat_counter: 0,
            metrics: TelecomCorrelationMetrics::default(),
        }
    }

    pub fn ingest_alert(&mut self, alert: &DefenseAlert) -> Option<CorrelatedThreat> {
        self.metrics.events_processed += 1;

        let (layer, cell_id, imsi_hash) = Self::classify_alert(alert);
        let event = TelecomEvent {
            timestamp_ns: alert.timestamp_ns,
            layer,
            event_type: alert.alert_type,
            cell_id,
            imsi_hash,
            details: format_alert_details(alert),
        };

        if cell_id != 0 {
            let window = self
                .cell_windows
                .entry(cell_id)
                .or_insert_with(|| CellEventWindow::new(TELECOM_CORRELATION_WINDOW_NS));
            window.push(event.clone());
        }

        if imsi_hash != 0 {
            let window = self
                .imsi_windows
                .entry(imsi_hash)
                .or_insert_with(|| CellEventWindow::new(TELECOM_CORRELATION_WINDOW_NS));
            window.push(event.clone());
        }

        self.correlate(cell_id, imsi_hash)
    }

    fn classify_alert(alert: &DefenseAlert) -> (TelecomLayer, u32, u64) {
        let cell_id = (alert.context & 0xFFFF_FFFF) as u32;
        let imsi_hash = alert.context;

        let layer = match alert.alert_type {
            ALERT_ROGUE_TOWER | ALERT_CELL_ANOMALY | ALERT_RF_FINGERPRINT => TelecomLayer::Radio,
            ALERT_DOWNGRADE_ATTACK | ALERT_NAS_REPLAY | ALERT_IMSI_CATCHER => TelecomLayer::Nas,
            ALERT_GTP_ANOMALY | ALERT_ROAMING_ANOMALY => TelecomLayer::Transport,
            ALERT_SS7_ANOMALY | ALERT_VOLTE_FRAUD => TelecomLayer::Signaling,
            ALERT_MODEM_TAMPER | ALERT_ESIM_TAMPER | ALERT_SLICE_VIOLATION => TelecomLayer::Core,
            _ => TelecomLayer::Core,
        };

        (layer, cell_id, imsi_hash)
    }

    fn correlate(&mut self, cell_id: u32, imsi_hash: u64) -> Option<CorrelatedThreat> {
        if cell_id != 0 {
            if let Some(threat) = self.correlate_cell(cell_id) {
                return Some(threat);
            }
        }

        if imsi_hash != 0 {
            if let Some(threat) = self.correlate_imsi(imsi_hash) {
                return Some(threat);
            }
        }

        None
    }

    fn correlate_cell(&mut self, cell_id: u32) -> Option<CorrelatedThreat> {
        let window = self.cell_windows.get(&cell_id)?;
        let layers = window.layers_active();

        if layers.len() < 2 {
            return None;
        }

        self.metrics.multi_layer_correlations += 1;

        if layers.contains(&TelecomLayer::Radio) && layers.contains(&TelecomLayer::Nas) {
            let radio_events = window.events_in_layer(TelecomLayer::Radio);
            let nas_events = window.events_in_layer(TelecomLayer::Nas);

            let has_rogue = radio_events
                .iter()
                .any(|e| e.event_type == ALERT_ROGUE_TOWER || e.event_type == ALERT_RF_FINGERPRINT);
            let has_downgrade = nas_events
                .iter()
                .any(|e| e.event_type == ALERT_DOWNGRADE_ATTACK);

            if has_rogue && has_downgrade {
                let threat = self.build_threat(
                    ThreatCategory::ManInTheMiddle,
                    0.92,
                    4,
                    vec![TelecomLayer::Radio, TelecomLayer::Nas],
                    window.events.iter().cloned().collect(),
                    "Rogue base station with active protocol downgrade — likely MitM attack",
                );
                return Some(threat);
            }

            if has_rogue {
                let has_imsi_catch = nas_events
                    .iter()
                    .any(|e| e.event_type == ALERT_IMSI_CATCHER);
                if has_imsi_catch {
                    let threat = self.build_threat(
                        ThreatCategory::ImsiCatching,
                        0.88,
                        4,
                        vec![TelecomLayer::Radio, TelecomLayer::Nas],
                        window.events.iter().cloned().collect(),
                        "Fake cell with IMSI harvesting behavior detected",
                    );
                    return Some(threat);
                }
            }
        }

        if layers.contains(&TelecomLayer::Signaling) && layers.contains(&TelecomLayer::Transport) {
            let sig_events = window.events_in_layer(TelecomLayer::Signaling);
            let trans_events = window.events_in_layer(TelecomLayer::Transport);

            let has_ss7 = sig_events
                .iter()
                .any(|e| e.event_type == ALERT_SS7_ANOMALY);
            let has_gtp = trans_events
                .iter()
                .any(|e| e.event_type == ALERT_GTP_ANOMALY);

            if has_ss7 && has_gtp {
                let threat = self.build_threat(
                    ThreatCategory::SignalingAbuse,
                    0.85,
                    4,
                    vec![TelecomLayer::Signaling, TelecomLayer::Transport],
                    window.events.iter().cloned().collect(),
                    "Coordinated SS7 + GTP manipulation — possible service hijack",
                );
                return Some(threat);
            }
        }

        if layers.contains(&TelecomLayer::Radio) && layers.contains(&TelecomLayer::Core) {
            let core_events = window.events_in_layer(TelecomLayer::Core);
            let has_slice = core_events
                .iter()
                .any(|e| e.event_type == ALERT_SLICE_VIOLATION);

            if has_slice {
                let threat = self.build_threat(
                    ThreatCategory::SliceEscape,
                    0.78,
                    3,
                    vec![TelecomLayer::Radio, TelecomLayer::Core],
                    window.events.iter().cloned().collect(),
                    "Network slice isolation bypass via radio layer manipulation",
                );
                return Some(threat);
            }
        }

        None
    }

    fn correlate_imsi(&mut self, imsi_hash: u64) -> Option<CorrelatedThreat> {
        let window = self.imsi_windows.get(&imsi_hash)?;
        let layers = window.layers_active();

        if layers.len() < 2 {
            return None;
        }

        let unique_cells: HashSet<u32> = window
            .events
            .iter()
            .filter(|e| e.cell_id != 0)
            .map(|e| e.cell_id)
            .collect();

        if unique_cells.len() >= 3 {
            let threat = self.build_threat(
                ThreatCategory::LocationTracking,
                0.72,
                3,
                layers.into_iter().collect(),
                window.events.iter().cloned().collect(),
                "Subscriber tracked across multiple anomalous cells",
            );
            return Some(threat);
        }

        if layers.contains(&TelecomLayer::Transport) && layers.contains(&TelecomLayer::Signaling) {
            let has_roaming = window
                .events
                .iter()
                .any(|e| e.event_type == ALERT_ROAMING_ANOMALY);
            let has_volte = window
                .events
                .iter()
                .any(|e| e.event_type == ALERT_VOLTE_FRAUD);

            if has_roaming && has_volte {
                let threat = self.build_threat(
                    ThreatCategory::RoamingExploit,
                    0.80,
                    4,
                    vec![TelecomLayer::Transport, TelecomLayer::Signaling],
                    window.events.iter().cloned().collect(),
                    "Roaming fraud pattern — VoLTE abuse via roaming path",
                );
                return Some(threat);
            }
        }

        None
    }

    fn build_threat(
        &mut self,
        category: ThreatCategory,
        confidence: f64,
        severity: u8,
        layers: Vec<TelecomLayer>,
        events: Vec<TelecomEvent>,
        description: &str,
    ) -> CorrelatedThreat {
        if confidence < MIN_CORRELATION_CONFIDENCE {
            self.metrics.false_positive_overrides += 1;
        }
        self.threat_counter += 1;
        self.metrics.threats_detected += 1;

        let threat = CorrelatedThreat {
            threat_id: self.threat_counter,
            confidence,
            severity,
            category,
            layers_involved: layers,
            events,
            description: description.to_string(),
        };

        self.detected_threats.push_back(threat.clone());
        if self.detected_threats.len() > 128 {
            self.detected_threats.pop_front();
        }

        threat
    }

    pub fn recent_threats(&self) -> &VecDeque<CorrelatedThreat> {
        &self.detected_threats
    }

    pub fn threats_by_category(&self, category: ThreatCategory) -> Vec<&CorrelatedThreat> {
        self.detected_threats
            .iter()
            .filter(|t| t.category == category)
            .collect()
    }

    pub fn summary_json(&self) -> String {
        let summary: Vec<_> = self
            .detected_threats
            .iter()
            .map(|t| {
                serde_json::json!({
                    "id": t.threat_id,
                    "category": format!("{:?}", t.category),
                    "confidence": t.confidence,
                    "severity": t.severity,
                    "layers": t.layers_involved.iter().map(|l| format!("{:?}", l)).collect::<Vec<_>>(),
                    "description": t.description,
                })
            })
            .collect();
        serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "[]".to_string())
    }
}

impl Default for TelecomCorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}
