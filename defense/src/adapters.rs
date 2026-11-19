//! Userspace tool adapters — feed next-generation tool verdicts into the
//! defense pipeline as `DefenseAlert`s.
//!
//! Modules 56 (Wi-Fi 7 MLO integrity), 61 (D2C satellite cell
//! verification), and 62 (Galileo OSNMA authentication) are driven by the
//! `mlo-analyzer`, `d2c-monitor`, and `osnma-verify` tools instead of
//! kernel eBPF probes. Each tool emits JSON-lines verdicts; this module
//! parses those verdict streams (from a followed file or stdin), converts
//! them to alerts, and forwards them to the same correlation pipeline the
//! eBPF ring buffer feeds.
//!
//! The wire structs mirror the tool output formats exactly; tests pin
//! both sides so the formats cannot drift silently.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
use tokio::sync::mpsc;

use common::{
    DefenseAlert, ALERT_AI_RAN_INTEGRITY, ALERT_D2C_CELL_SPOOF, ALERT_GNSS_AUTH_FAILURE,
    ALERT_MLO_INTEGRITY, ALERT_NON_CREDENTIAL_ABUSE, ALERT_PQC_DOWNGRADE,
};

/// Which next-generation tool feeds a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolKind {
    /// Wi-Fi 7 MLO analyzer (Module 56).
    Mlo,
    /// Direct-to-Cell satellite cell monitor (Module 61).
    D2c,
    /// Galileo OSNMA verifier (Module 62).
    Osnma,
    /// 6G AI-RAN model integrity traces (Module 66).
    Airan,
    /// 6G PQC handshake traces (Module 67).
    Pqc,
    /// 6G network-of-networks credential traces (Module 70).
    NonCred,
}

impl ToolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mlo => "mlo",
            Self::D2c => "d2c",
            Self::Osnma => "osnma",
            Self::Airan => "airan",
            Self::Pqc => "pqc",
            Self::NonCred => "noncred",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value.trim() {
            "mlo" => Ok(Self::Mlo),
            "d2c" => Ok(Self::D2c),
            "osnma" => Ok(Self::Osnma),
            "airan" => Ok(Self::Airan),
            "pqc" => Ok(Self::Pqc),
            "noncred" => Ok(Self::NonCred),
            other => bail!(
                "unknown tool kind {other:?}; expected mlo, d2c, osnma, airan, pqc, or noncred (e.g. --tool-input mlo=/path/verdicts.jsonl)"
            ),
        }
    }
}

/// The defense module each tool drives.
pub fn tool_kind_for_module(module: u8) -> Option<ToolKind> {
    match module {
        56 => Some(ToolKind::Mlo),
        61 => Some(ToolKind::D2c),
        62 => Some(ToolKind::Osnma),
        66 => Some(ToolKind::Airan),
        67 => Some(ToolKind::Pqc),
        70 => Some(ToolKind::NonCred),
        _ => None,
    }
}

/// Parse a `--tool-input KIND=PATH` argument list.
pub fn parse_tool_inputs(specs: &[String]) -> Result<Vec<(ToolKind, PathBuf)>> {
    let mut inputs = Vec::new();
    for spec in specs {
        let Some((kind, path)) = spec.split_once('=') else {
            bail!("invalid --tool-input {spec:?}; expected KIND=PATH with kind mlo, d2c, or osnma");
        };
        let kind = ToolKind::parse(kind)?;
        if path.is_empty() {
            bail!(
                "--tool-input {}= requires a path (or - for stdin)",
                kind.as_str()
            );
        }
        inputs.push((kind, PathBuf::from(path)));
    }
    Ok(inputs)
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// FNV-1a hash used to fold string identifiers into alert contexts.
fn fnv1a64(value: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in value.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn alert(
    alert_type: u32,
    severity: u32,
    context: u64,
    detail: u64,
    timestamp_ns: u64,
) -> DefenseAlert {
    let mut details = [0u8; 16];
    details[..8].copy_from_slice(&detail.to_le_bytes());
    DefenseAlert {
        alert_type,
        severity,
        pid: 0, // userspace tool verdict, not a kernel event
        _pad: 0,
        timestamp_ns,
        context,
        details,
    }
}

// ── Wire formats (mirror the tool outputs) ───────────────────────────────────

/// One `mlo-analyzer` finding line.
#[derive(Debug, Clone, Deserialize)]
pub struct MloFindingWire {
    pub mld_addr: String,
    pub link_id: u8,
    pub kind: String,
    pub severity: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub timestamp_ns: u64,
}

/// One `d2c-monitor` verdict line.
#[derive(Debug, Clone, Deserialize)]
pub struct D2cVerdictWire {
    pub plmn: String,
    pub cell_global_id: u64,
    pub sat_indicator: bool,
    pub spoof_score: f64,
    pub spoofed: bool,
}

/// One `osnma-verify` verdict line.
#[derive(Debug, Clone, Deserialize)]
pub struct OsnmaVerdictWire {
    pub sat_svn: u8,
    pub header_parsed: bool,
    pub nma_status_ok: bool,
    pub chain_verified: Option<bool>,
    pub mac_verified: Option<bool>,
    pub spoofed: bool,
}

/// One `6g-sim` AI-RAN model integrity verdict line.
#[derive(Debug, Clone, Deserialize)]
pub struct AiRanVerdictWire {
    /// Control-plane domain; verdicts in one domain correlate together.
    #[serde(default = "default_domain")]
    pub domain: String,
    pub model_id: String,
    pub tampered: bool,
    pub version: u32,
    #[serde(default)]
    pub reason: String,
}

/// One `6g-sim` PQC handshake verdict line.
#[derive(Debug, Clone, Deserialize)]
pub struct PqcVerdictWire {
    #[serde(default = "default_domain")]
    pub domain: String,
    pub peer: String,
    pub downgraded: bool,
    pub suite: String,
}

/// One `6g-sim` network-of-networks credential verdict line.
#[derive(Debug, Clone, Deserialize)]
pub struct NonCredVerdictWire {
    #[serde(default = "default_domain")]
    pub domain: String,
    pub credential: String,
    pub source_network: String,
    pub target_network: String,
    pub crossed: bool,
}

fn default_domain() -> String {
    "core-1".to_string()
}

// ── Conversions ──────────────────────────────────────────────────────────────

fn mlo_severity(severity: &str) -> u32 {
    match severity {
        "critical" => 4,
        "warning" => 3,
        _ => 2,
    }
}

/// Convert an `mlo-analyzer` finding into a Module 56 alert.
/// The finding kind is folded into the detail word:
/// 0=link_desync, 1=key_separation_abuse, 2=auth_suite_mismatch, 3=link_flapping.
pub fn mlo_finding_to_alert(finding: &MloFindingWire) -> DefenseAlert {
    let kind_code = match finding.kind.as_str() {
        "link_desync" => 0u64,
        "key_separation_abuse" => 1,
        "auth_suite_mismatch" => 2,
        "link_flapping" => 3,
        _ => 0xF,
    };
    let detail = (finding.link_id as u64) << 36 | kind_code;
    alert(
        ALERT_MLO_INTEGRITY,
        mlo_severity(&finding.severity),
        fnv1a64(&finding.mld_addr),
        detail,
        if finding.timestamp_ns != 0 {
            finding.timestamp_ns
        } else {
            now_ns()
        },
    )
}

/// Convert a `d2c-monitor` verdict into a Module 61 alert.
/// Returns `None` for cells that passed the physics checks.
pub fn d2c_verdict_to_alert(verdict: &D2cVerdictWire) -> Option<DefenseAlert> {
    if !verdict.spoofed {
        return None;
    }
    let severity = if verdict.spoof_score >= 0.8 { 5 } else { 4 };
    Some(alert(
        ALERT_D2C_CELL_SPOOF,
        severity,
        verdict.cell_global_id,
        (verdict.spoof_score * 1000.0) as u64,
        now_ns(),
    ))
}

/// Convert an `osnma-verify` verdict into a Module 62 alert.
/// Returns `None` when the record verified cleanly.
/// The detail word packs the failure flags:
/// bit0 = chain failed, bit1 = MAC failed, bit2 = NMA status not usable,
/// bit3 = header unparseable.
pub fn osnma_verdict_to_alert(verdict: &OsnmaVerdictWire) -> Option<DefenseAlert> {
    if !verdict.spoofed {
        return None;
    }
    let mut flags = 0u64;
    if verdict.chain_verified == Some(false) {
        flags |= 1;
    }
    if verdict.mac_verified == Some(false) {
        flags |= 1 << 1;
    }
    if !verdict.nma_status_ok {
        flags |= 1 << 2;
    }
    if !verdict.header_parsed {
        flags |= 1 << 3;
    }
    let severity = if flags & 0b11 != 0 { 4 } else { 3 };
    Some(alert(
        ALERT_GNSS_AUTH_FAILURE,
        severity,
        verdict.sat_svn as u64,
        flags,
        now_ns(),
    ))
}

/// Convert a `6g-sim` AI-RAN verdict into a Module 66 alert.
/// Returns `None` for models that passed the integrity invariants.
/// The correlation context is the control-plane domain so AI-RAN and PQC
/// verdicts from one domain compound; the model hash rides in the detail.
pub fn ai_ran_verdict_to_alert(verdict: &AiRanVerdictWire) -> Option<DefenseAlert> {
    if !verdict.tampered {
        return None;
    }
    let detail = (verdict.version as u64) << 32 | fnv1a64(&verdict.model_id) & 0xFFFF_FFFF;
    Some(alert(
        ALERT_AI_RAN_INTEGRITY,
        5,
        fnv1a64(&verdict.domain),
        detail,
        now_ns(),
    ))
}

/// Convert a `6g-sim` PQC verdict into a Module 67 alert.
/// Returns `None` for handshakes that stayed quantum-safe.
pub fn pqc_verdict_to_alert(verdict: &PqcVerdictWire) -> Option<DefenseAlert> {
    if !verdict.downgraded {
        return None;
    }
    let detail = fnv1a64(&verdict.peer) & 0xFFFF_FFFF;
    Some(alert(
        ALERT_PQC_DOWNGRADE,
        4,
        fnv1a64(&verdict.domain),
        detail,
        now_ns(),
    ))
}

/// Convert a `6g-sim` network-of-networks verdict into a Module 70 alert.
/// Returns `None` for authorized credential use.
pub fn non_cred_verdict_to_alert(verdict: &NonCredVerdictWire) -> Option<DefenseAlert> {
    if !verdict.crossed {
        return None;
    }
    let detail = (fnv1a64(&verdict.credential) & 0xFFFF_FFFF)
        | (fnv1a64(&verdict.source_network) & 0xFFFF) << 48;
    Some(alert(
        ALERT_NON_CREDENTIAL_ABUSE,
        4,
        fnv1a64(&verdict.domain),
        detail,
        now_ns(),
    ))
}

fn line_to_alert(kind: ToolKind, line: &str) -> Result<Option<DefenseAlert>> {
    match kind {
        ToolKind::Mlo => {
            let finding: MloFindingWire =
                serde_json::from_str(line).context("parse mlo-analyzer finding")?;
            Ok(Some(mlo_finding_to_alert(&finding)))
        }
        ToolKind::D2c => {
            let verdict: D2cVerdictWire =
                serde_json::from_str(line).context("parse d2c-monitor verdict")?;
            Ok(d2c_verdict_to_alert(&verdict))
        }
        ToolKind::Osnma => {
            let verdict: OsnmaVerdictWire =
                serde_json::from_str(line).context("parse osnma-verify verdict")?;
            Ok(osnma_verdict_to_alert(&verdict))
        }
        ToolKind::Airan => {
            let verdict: AiRanVerdictWire =
                serde_json::from_str(line).context("parse 6g-sim ai_ran verdict")?;
            Ok(ai_ran_verdict_to_alert(&verdict))
        }
        ToolKind::Pqc => {
            let verdict: PqcVerdictWire =
                serde_json::from_str(line).context("parse 6g-sim pqc verdict")?;
            Ok(pqc_verdict_to_alert(&verdict))
        }
        ToolKind::NonCred => {
            let verdict: NonCredVerdictWire =
                serde_json::from_str(line).context("parse 6g-sim non_credential verdict")?;
            Ok(non_cred_verdict_to_alert(&verdict))
        }
    }
}

// ── Verdict stream ingestion ─────────────────────────────────────────────────

const POLL_INTERVAL_MS: u64 = 250;

/// Follow a JSON-lines verdict file, emitting alerts for each complete
/// line (existing content first, then appended lines as they arrive).
pub async fn run_tool_input_file(
    kind: ToolKind,
    path: PathBuf,
    tx: mpsc::Sender<DefenseAlert>,
    running: Arc<AtomicBool>,
) {
    let mut file = match tokio::fs::File::open(&path).await {
        Ok(file) => file,
        Err(error) => {
            tracing::error!(
                "tool adapter {}: cannot open {}: {error}",
                kind.as_str(),
                path.display()
            );
            return;
        }
    };
    tracing::info!(
        "tool adapter {}: following {}",
        kind.as_str(),
        path.display()
    );
    let mut offset: u64 = 0;
    let mut buffer: Vec<u8> = Vec::new();
    while running.load(Ordering::Relaxed) {
        match file.metadata().await {
            Ok(meta) => {
                let len = meta.len();
                if len > offset {
                    if file.seek(SeekFrom::Start(offset)).await.is_ok() {
                        let mut chunk = Vec::new();
                        let mut tail = (&mut file).take(len - offset);
                        if tail.read_to_end(&mut chunk).await.is_ok() {
                            offset = len;
                            buffer.extend_from_slice(&chunk);
                        }
                    }
                } else if len < offset {
                    // truncated/rotated: reset to the start
                    offset = 0;
                    buffer.clear();
                }
            }
            Err(error) => {
                tracing::warn!("tool adapter {}: stat failed: {error}", kind.as_str());
            }
        }
        drain_lines(kind, &mut buffer, &tx).await;
        tokio::time::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}

/// Read JSON-lines verdicts from stdin (path `-`).
pub fn run_tool_input_stdin(
    kind: ToolKind,
    tx: mpsc::Sender<DefenseAlert>,
    running: Arc<AtomicBool>,
) {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        if !running.load(Ordering::Relaxed) {
            return;
        }
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                tracing::error!("tool adapter {}: stdin read failed: {error}", kind.as_str());
                return;
            }
        };
        process_line(kind, &line, &tx);
    }
}

async fn drain_lines(kind: ToolKind, buffer: &mut Vec<u8>, tx: &mpsc::Sender<DefenseAlert>) {
    while let Some(position) = buffer.iter().position(|&byte| byte == b'\n') {
        let line: Vec<u8> = buffer.drain(..=position).collect();
        let line = String::from_utf8_lossy(&line[..line.len() - 1]).into_owned();
        if line.trim().is_empty() {
            continue;
        }
        process_line(kind, &line, tx);
        if tx.is_closed() {
            return;
        }
    }
}

fn process_line(kind: ToolKind, line: &str, tx: &mpsc::Sender<DefenseAlert>) {
    match line_to_alert(kind, line) {
        Ok(Some(alert)) => {
            if tx.try_send(alert).is_err() {
                tracing::warn!(
                    "tool adapter {}: alert channel closed or full",
                    kind.as_str()
                );
            }
        }
        Ok(None) => {}
        Err(error) => tracing::warn!(
            "tool adapter {}: skipping malformed verdict line: {error:#}",
            kind.as_str()
        ),
    }
}

/// Doctor-side check: is the configured input usable right now?
/// Stdin ("-") cannot be probed and is reported usable.
pub fn tool_input_readable(path: &Path) -> bool {
    path == Path::new("-") || std::fs::File::open(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TelecomCorrelationEngine, ThreatCategory};
    use common::{ALERT_IMSI_CATCHER, ALERT_LEO_PNT};

    fn d2c_line(spoofed: bool, score: f64) -> String {
        format!(
            r#"{{"plmn":"310260","cell_global_id":123,"sat_indicator":true,"spoof_score":{score},"spoofed":{spoofed},"reasons":["test"]}}"#
        )
    }

    fn osnma_line(spoofed: bool, mac_verified: bool) -> String {
        format!(
            r#"{{"sat_svn":19,"header_parsed":true,"nma_status_ok":true,"chain_verified":null,"mac_verified":{mac_verified},"spoofed":{spoofed},"reasons":["MAC mismatch"]}}"#
        )
    }

    #[test]
    fn tool_input_specs_parse_and_validate() {
        let inputs = parse_tool_inputs(&[
            "mlo=/tmp/findings.jsonl".to_string(),
            "d2c=-".to_string(),
            "osnma=/tmp/osnma.jsonl".to_string(),
        ])
        .unwrap();
        assert_eq!(
            inputs[0],
            (ToolKind::Mlo, PathBuf::from("/tmp/findings.jsonl"))
        );
        assert_eq!(inputs[1], (ToolKind::D2c, PathBuf::from("-")));

        assert!(parse_tool_inputs(&["bogus=/x".to_string()]).is_err());
        assert!(parse_tool_inputs(&["mlo".to_string()]).is_err());
        assert!(parse_tool_inputs(&["mlo=".to_string()]).is_err());
    }

    #[test]
    fn mlo_findings_convert_with_severity_mapping() {
        let line = r#"{"mld_addr":"aa:bb:cc:dd:ee:ff","link_id":1,"kind":"key_separation_abuse","severity":"critical","detail":"link 1 accepts key generation 2 while MLD is at 5","timestamp_ns":42}"#;
        let alert = mlo_finding_to_alert(&serde_json::from_str(line).unwrap());
        assert_eq!(alert.alert_type, ALERT_MLO_INTEGRITY);
        assert_eq!(alert.severity, 4);
        assert_eq!(alert.timestamp_ns, 42);
        assert_ne!(alert.context, 0);
        // link_id 1 << 36 | kind 1
        assert_eq!(
            u64::from_le_bytes(alert.details[..8].try_into().unwrap()),
            (1u64 << 36) | 1
        );

        let warn = r#"{"mld_addr":"x","link_id":0,"kind":"link_flapping","severity":"warning","timestamp_ns":1}"#;
        let alert = mlo_finding_to_alert(&serde_json::from_str(warn).unwrap());
        assert_eq!(alert.severity, 3);
    }

    #[test]
    fn d2c_verdicts_convert_only_when_spoofed() {
        let clean: D2cVerdictWire = serde_json::from_str(&d2c_line(false, 0.0)).unwrap();
        assert!(d2c_verdict_to_alert(&clean).is_none());

        let spoofed: D2cVerdictWire = serde_json::from_str(&d2c_line(true, 0.7)).unwrap();
        let alert = d2c_verdict_to_alert(&spoofed).unwrap();
        assert_eq!(alert.alert_type, ALERT_D2C_CELL_SPOOF);
        assert_eq!(alert.severity, 4);
        assert_eq!(alert.context, 123);

        let certain: D2cVerdictWire = serde_json::from_str(&d2c_line(true, 1.0)).unwrap();
        assert_eq!(d2c_verdict_to_alert(&certain).unwrap().severity, 5);
    }

    #[test]
    fn osnma_verdicts_convert_only_when_spoofed() {
        let clean: OsnmaVerdictWire = serde_json::from_str(&osnma_line(false, true)).unwrap();
        assert!(osnma_verdict_to_alert(&clean).is_none());

        let failed: OsnmaVerdictWire = serde_json::from_str(&osnma_line(true, false)).unwrap();
        let alert = osnma_verdict_to_alert(&failed).unwrap();
        assert_eq!(alert.alert_type, ALERT_GNSS_AUTH_FAILURE);
        assert_eq!(alert.severity, 4);
        assert_eq!(alert.context, 19);
        // MAC failure flag (bit 1)
        assert_eq!(
            u64::from_le_bytes(alert.details[..8].try_into().unwrap()),
            0b10
        );
    }

    #[test]
    fn d2c_tool_alerts_correlate_with_imsi_catcher() {
        // The end-to-end promise of the adapter: a d2c-monitor verdict fed
        // through the pipeline correlates with an IMSI catcher alert into
        // the D2cCellSpoofing compound threat.
        let spoofed: D2cVerdictWire = serde_json::from_str(&d2c_line(true, 1.0)).unwrap();
        let d2c_alert = d2c_verdict_to_alert(&spoofed).unwrap();

        let mut engine = TelecomCorrelationEngine::new(60);
        assert!(engine.ingest_alert(&d2c_alert).is_none());

        let imsi = alert(ALERT_IMSI_CATCHER, 4, 123, 0, 2_000_000_000);
        let threat = engine.ingest_alert(&imsi).expect("compound threat");
        assert_eq!(threat.category, ThreatCategory::D2cCellSpoofing);
    }

    #[test]
    fn osnma_tool_alerts_correlate_with_leo_pnt() {
        let failed: OsnmaVerdictWire = serde_json::from_str(&osnma_line(true, false)).unwrap();
        let osnma_alert = osnma_verdict_to_alert(&failed).unwrap();

        let mut engine = TelecomCorrelationEngine::new(60);
        assert!(engine.ingest_alert(&osnma_alert).is_none());

        let leo = alert(ALERT_LEO_PNT, 4, 19, 0, 2_000_000_000);
        let threat = engine.ingest_alert(&leo).expect("compound threat");
        assert_eq!(threat.category, ThreatCategory::GnssSpoofing);
    }

    fn airan_line(tampered: bool) -> String {
        format!(
            r#"{{"kind":"ai_ran","domain":"core-1","model_id":"airan-phy-01","tampered":{tampered},"version":4,"reason":"integrity hash changed without version advance"}}"#
        )
    }

    fn pqc_line(downgraded: bool) -> String {
        format!(
            r#"{{"kind":"pqc","domain":"core-1","peer":"amf-1","downgraded":{downgraded},"suite":"rsa-2048"}}"#
        )
    }

    fn noncred_line(crossed: bool) -> String {
        format!(
            r#"{{"kind":"non_credential","domain":"core-1","credential":"cred-042","source_network":"sat-net","target_network":"wlan-net","crossed":{crossed}}}"#
        )
    }

    #[test]
    fn ai_ran_verdicts_convert_only_when_tampered() {
        let clean: AiRanVerdictWire = serde_json::from_str(&airan_line(false)).unwrap();
        assert!(ai_ran_verdict_to_alert(&clean).is_none());

        let tampered: AiRanVerdictWire = serde_json::from_str(&airan_line(true)).unwrap();
        let alert = ai_ran_verdict_to_alert(&tampered).unwrap();
        assert_eq!(alert.alert_type, ALERT_AI_RAN_INTEGRITY);
        assert_eq!(alert.severity, 5);
        assert_ne!(alert.context, 0);
    }

    #[test]
    fn pqc_verdicts_convert_only_when_downgraded() {
        let clean: PqcVerdictWire = serde_json::from_str(&pqc_line(false)).unwrap();
        assert!(pqc_verdict_to_alert(&clean).is_none());

        let downgraded: PqcVerdictWire = serde_json::from_str(&pqc_line(true)).unwrap();
        let alert = pqc_verdict_to_alert(&downgraded).unwrap();
        assert_eq!(alert.alert_type, ALERT_PQC_DOWNGRADE);
        assert_eq!(alert.severity, 4);
        assert_ne!(alert.context, 0);
    }

    #[test]
    fn non_cred_verdicts_convert_only_when_crossed() {
        let clean: NonCredVerdictWire = serde_json::from_str(&noncred_line(false)).unwrap();
        assert!(non_cred_verdict_to_alert(&clean).is_none());

        let crossed: NonCredVerdictWire = serde_json::from_str(&noncred_line(true)).unwrap();
        let alert = non_cred_verdict_to_alert(&crossed).unwrap();
        assert_eq!(alert.alert_type, ALERT_NON_CREDENTIAL_ABUSE);
        assert_eq!(alert.severity, 4);
        assert_ne!(alert.context, 0);
    }

    #[test]
    fn sixg_tool_alerts_correlate_into_ai_ran_compromise() {
        // The end-to-end promise: 6g-sim verdicts fed through the pipeline
        // correlate into the AiRanCompromise compound threat.
        let tampered: AiRanVerdictWire = serde_json::from_str(&airan_line(true)).unwrap();
        let ai_ran_alert = ai_ran_verdict_to_alert(&tampered).unwrap();
        let downgraded: PqcVerdictWire = serde_json::from_str(&pqc_line(true)).unwrap();
        let pqc_alert = pqc_verdict_to_alert(&downgraded).unwrap();

        let mut engine = TelecomCorrelationEngine::new(60);
        assert!(engine.ingest_alert(&ai_ran_alert).is_none());
        let threat = engine.ingest_alert(&pqc_alert).expect("compound threat");
        assert_eq!(threat.category, ThreatCategory::AiRanCompromise);
        assert_eq!(threat.severity, 5);
    }

    #[test]
    fn repeated_pqc_tool_alerts_correlate_into_pqc_downgrade() {
        // Two downgraded handshakes in one window escalate to the
        // standalone PqcDowngrade pattern (harvest-now-decrypt-later).
        let downgraded: PqcVerdictWire = serde_json::from_str(&pqc_line(true)).unwrap();
        let pqc_alert = pqc_verdict_to_alert(&downgraded).unwrap();

        let mut engine = TelecomCorrelationEngine::new(60);
        assert!(engine.ingest_alert(&pqc_alert).is_none());
        let threat = engine.ingest_alert(&pqc_alert).expect("compound threat");
        assert_eq!(threat.category, ThreatCategory::PqcDowngrade);
        assert_eq!(threat.severity, 4);
    }

    #[test]
    fn malformed_lines_are_rejected_not_fatal() {
        assert!(line_to_alert(ToolKind::D2c, "not json").is_err());
        assert!(line_to_alert(ToolKind::Mlo, "{}").is_err()); // missing fields
        let ok = line_to_alert(ToolKind::D2c, &d2c_line(false, 0.0)).unwrap();
        assert!(ok.is_none());
    }

    #[tokio::test]
    async fn tool_input_file_streams_alerts() {
        let path = std::env::temp_dir().join(format!(
            "staticzero-adapters-test-{}.jsonl",
            std::process::id()
        ));
        std::fs::write(&path, format!("{}\n", d2c_line(false, 0.0))).unwrap();

        let (tx, mut rx) = mpsc::channel(16);
        let running = Arc::new(AtomicBool::new(true));
        let task = tokio::spawn(run_tool_input_file(
            ToolKind::D2c,
            path.clone(),
            tx,
            running.clone(),
        ));

        // The initial clean verdict (not spoofed) produces no alert.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert!(rx.try_recv().is_err());

        // Appending a spoofed verdict streams an alert through the adapter.
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            writeln!(file, "{}", d2c_line(true, 1.0)).unwrap();
        }
        let alert = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("alert within timeout")
            .expect("channel stays open");
        assert_eq!(alert.alert_type, ALERT_D2C_CELL_SPOOF);
        assert_eq!(alert.severity, 5);

        running.store(false, Ordering::SeqCst);
        let _ = task.await;
        let _ = std::fs::remove_file(&path);
    }
}
