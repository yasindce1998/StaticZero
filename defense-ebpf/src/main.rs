#![no_std]
#![no_main]
#![allow(unused_unsafe)]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{kprobe, map},
    maps::{Array, HashMap, RingBuf},
    programs::ProbeContext,
};
use common::{
    CellBaseline, CellInfo, DefenseAlert, HandoverBaseline, RanSharingState, RfFingerprint,
    SbiBaseline, SignalingCounter, ALERT_CELL_ANOMALY, ALERT_DOWNGRADE_ATTACK, ALERT_ESIM_TAMPER,
    ALERT_GTP_ANOMALY, ALERT_HANDOVER_INTEGRITY, ALERT_IMSI_CATCHER, ALERT_MODEM_TAMPER,
    ALERT_NAS_REPLAY, ALERT_RAN_SHARING_LEAK, ALERT_RF_FINGERPRINT, ALERT_ROAMING_ANOMALY,
    ALERT_ROGUE_TOWER, ALERT_SBI_ANOMALY, ALERT_SIGNALING_STORM, ALERT_SLICE_VIOLATION,
    ALERT_SS7_ANOMALY, ALERT_VOLTE_FRAUD,
};

// ══════════════════════════════════════════════════════════════════════════════
// TELECOM DEFENSE MAPS (Category 4)
// ══════════════════════════════════════════════════════════════════════════════

#[map]
static DEFENSE_ALERTS: RingBuf = RingBuf::with_byte_size(128 * 1024, 0);

#[map]
static CELL_BASELINE_MAP: HashMap<u32, CellBaseline> = HashMap::with_max_entries(64, 0);

#[map]
static CELL_CURRENT: Array<CellInfo> = Array::with_max_entries(4, 0);

#[map]
static MODEM_ACCESS_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(32, 0);

#[map]
static IDENTITY_REQ_COUNT: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

#[map]
static NAS_SEQ_TRACKER: HashMap<u32, u32> = HashMap::with_max_entries(128, 0);

#[map]
static GTP_SESSION_TRACK: HashMap<u32, u64> = HashMap::with_max_entries(64, 0);

// ══════════════════════════════════════════════════════════════════════════════
// ADVANCED TELECOM DEFENSE MAPS (Modules 24-28)
// ══════════════════════════════════════════════════════════════════════════════

#[map]
static VOLTE_CALL_RATE: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

#[map]
static ESIM_PROVISION_LOG: HashMap<u64, u64> = HashMap::with_max_entries(32, 0);

#[map]
static SLICE_ISOLATION_MAP: HashMap<u32, u32> = HashMap::with_max_entries(32, 0);

#[map]
static ROAMING_BASELINE: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

#[map]
static RF_FINGERPRINT_BASELINE: HashMap<u32, RfFingerprint> = HashMap::with_max_entries(64, 0);

// ══════════════════════════════════════════════════════════════════════════════
// 5G ADVANCED DEFENSE MAPS (Modules 29-32)
// ══════════════════════════════════════════════════════════════════════════════

#[map]
static SBI_BASELINE_MAP: HashMap<u32, SbiBaseline> = HashMap::with_max_entries(32, 0);

#[map]
static SBI_STREAM_COUNTER: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

#[map]
static HANDOVER_BASELINE_MAP: HashMap<u32, HandoverBaseline> = HashMap::with_max_entries(64, 0);

#[map]
static HANDOVER_RATE_MAP: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

#[map]
static RAN_SHARING_MAP: HashMap<u32, RanSharingState> = HashMap::with_max_entries(32, 0);

#[map]
static SIGNALING_COUNTER_MAP: HashMap<u32, SignalingCounter> = HashMap::with_max_entries(128, 0);

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 16: Rogue Tower Detection (Alert 19)
// Monitor cell changes, alert on unknown/anomalous cells.
// Hook: kprobe on modem indication handler
// ══════════════════════════════════════════════════════════════════════════════

#[kprobe]
pub fn detect_rogue_tower(ctx: ProbeContext) -> u32 {
    try_detect_rogue_tower(&ctx).unwrap_or_default()
}

fn try_detect_rogue_tower(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let cell_id: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let signal: u32 = unsafe { ctx.arg(1).unwrap_or(0) };

    if let Some(baseline) = unsafe { CELL_BASELINE_MAP.get(&cell_id) } {
        let sig_i16 = signal as i16;
        if sig_i16 > baseline.max_signal_dbm {
            let alert = DefenseAlert {
                alert_type: ALERT_ROGUE_TOWER,
                severity: 4,
                pid,
                _pad: 0,
                timestamp_ns: now,
                context: cell_id as u64,
                details: {
                    let mut d = [0u8; 16];
                    d[0..4].copy_from_slice(&cell_id.to_le_bytes());
                    d[4..8].copy_from_slice(&signal.to_le_bytes());
                    d
                },
            };
            let _ = DEFENSE_ALERTS.output(&alert, 0);
        }
    } else {
        let alert = DefenseAlert {
            alert_type: ALERT_ROGUE_TOWER,
            severity: 3,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: cell_id as u64,
            details: [0u8; 16],
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 17: Downgrade Attack Detection (Alert 20)
// Track RAT transitions, alert on unexpected downgrades.
// Hook: kprobe on network registration update
// ══════════════════════════════════════════════════════════════════════════════

#[kprobe]
pub fn detect_downgrade_attack(ctx: ProbeContext) -> u32 {
    try_detect_downgrade_attack(&ctx).unwrap_or_default()
}

fn try_detect_downgrade_attack(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let new_rat: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let new_cipher: u32 = unsafe { ctx.arg(1).unwrap_or(0) };

    // Get previous RAT from cell state
    let prev_rat = unsafe { CELL_CURRENT.get(0) }
        .map(|c| c.rat_type as u32)
        .unwrap_or(0);

    // Downgrade: higher generation -> lower (3=NR > 2=LTE > 1=UMTS > 0=GSM)
    if prev_rat > new_rat {
        let severity = if new_rat == 0 { 4 } else { 3 };

        let alert = DefenseAlert {
            alert_type: ALERT_DOWNGRADE_ATTACK,
            severity,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: ((prev_rat as u64) << 32) | new_rat as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&new_cipher.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    // Also alert on cipher downgrade (e.g. EEA2 -> EEA0)
    if new_cipher == 0 && new_rat >= 2 {
        let alert = DefenseAlert {
            alert_type: ALERT_DOWNGRADE_ATTACK,
            severity: 4,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: new_cipher as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&new_rat.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 18: IMSI Catcher Detection (Alert 21)
// Monitor Identity Request frequency from cells.
// Hook: kprobe on NAS indication path
// ══════════════════════════════════════════════════════════════════════════════

const IDENTITY_REQ_THRESHOLD: u32 = 5;

#[kprobe]
pub fn detect_imsi_catcher(ctx: ProbeContext) -> u32 {
    try_detect_imsi_catcher(&ctx).unwrap_or_default()
}

fn try_detect_imsi_catcher(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let msg_type: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };

    // NAS Identity Request = 0x55
    if msg_type != 0x55 {
        return Ok(0);
    }

    let cell_id = unsafe { CELL_CURRENT.get(0) }
        .map(|c| c.cell_id)
        .unwrap_or(0);

    let count = unsafe { IDENTITY_REQ_COUNT.get(&cell_id) }
        .copied()
        .unwrap_or(0);
    let new_count = count + 1;
    let _ = IDENTITY_REQ_COUNT.insert(&cell_id, &new_count, 0);

    if new_count >= IDENTITY_REQ_THRESHOLD {
        let alert = DefenseAlert {
            alert_type: ALERT_IMSI_CATCHER,
            severity: 4,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: cell_id as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&new_count.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 19: Cell Parameter Anomaly (Alert 22)
// Compare observed cell params against baseline.
// Hook: kprobe on SIB/MIB update path
// ══════════════════════════════════════════════════════════════════════════════

#[kprobe]
pub fn detect_cell_anomaly(ctx: ProbeContext) -> u32 {
    try_detect_cell_anomaly(&ctx).unwrap_or_default()
}

fn try_detect_cell_anomaly(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let cell_id: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let arfcn: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let lac_tac: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    if let Some(baseline) = unsafe { CELL_BASELINE_MAP.get(&cell_id) } {
        let mut anomaly = false;

        if arfcn != 0 && arfcn != baseline.expected_arfcn {
            anomaly = true;
        }
        if lac_tac != 0 && lac_tac != baseline.expected_lac_tac {
            anomaly = true;
        }

        if anomaly {
            let alert = DefenseAlert {
                alert_type: ALERT_CELL_ANOMALY,
                severity: 3,
                pid,
                _pad: 0,
                timestamp_ns: now,
                context: cell_id as u64,
                details: {
                    let mut d = [0u8; 16];
                    d[0..4].copy_from_slice(&arfcn.to_le_bytes());
                    d[4..8].copy_from_slice(&lac_tac.to_le_bytes());
                    d[8..12].copy_from_slice(&baseline.expected_arfcn.to_le_bytes());
                    d[12..16].copy_from_slice(&baseline.expected_lac_tac.to_le_bytes());
                    d
                },
            };
            let _ = DEFENSE_ALERTS.output(&alert, 0);
        }
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 20: GTP Traffic Anomaly (Alert 23)
// Monitor GTP-C messages for suspicious patterns.
// Hook: kprobe on UDP receive path (port 2152/2123)
// ══════════════════════════════════════════════════════════════════════════════

const GTP_CREATE_SESSION: u32 = 32;
const GTP_DELETE_SESSION: u32 = 36;
const GTP_RATE_THRESHOLD: u64 = 100;

#[kprobe]
pub fn detect_gtp_anomaly(ctx: ProbeContext) -> u32 {
    try_detect_gtp_anomaly(&ctx).unwrap_or_default()
}

fn try_detect_gtp_anomaly(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let msg_type: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let teid: u32 = unsafe { ctx.arg(1).unwrap_or(0) };

    if msg_type == GTP_CREATE_SESSION || msg_type == GTP_DELETE_SESSION {
        let count = unsafe { GTP_SESSION_TRACK.get(&teid) }
            .copied()
            .unwrap_or(0);
        let new_count = count + 1;
        let _ = GTP_SESSION_TRACK.insert(&teid, &new_count, 0);

        if new_count >= GTP_RATE_THRESHOLD {
            let alert = DefenseAlert {
                alert_type: ALERT_GTP_ANOMALY,
                severity: 3,
                pid,
                _pad: 0,
                timestamp_ns: now,
                context: teid as u64,
                details: {
                    let mut d = [0u8; 16];
                    d[0..4].copy_from_slice(&msg_type.to_le_bytes());
                    d[4..12].copy_from_slice(&new_count.to_le_bytes());
                    d
                },
            };
            let _ = DEFENSE_ALERTS.output(&alert, 0);
        }
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 21: SS7 Traffic Anomaly (Alert 24)
// Detect suspicious SS7 MAP operations (SRI, UpdateLocation, CancelLocation).
// Hook: kprobe on SCTP receive path
// ══════════════════════════════════════════════════════════════════════════════

const SS7_SRI: u32 = 22;
const SS7_UL: u32 = 2;
const SS7_CLR: u32 = 12;

#[kprobe]
pub fn detect_ss7_anomaly(ctx: ProbeContext) -> u32 {
    try_detect_ss7_anomaly(&ctx).unwrap_or_default()
}

fn try_detect_ss7_anomaly(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let opcode: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let src_gt_hash: u32 = unsafe { ctx.arg(1).unwrap_or(0) };

    // Alert on sensitive operations from unrecognized sources
    if opcode == SS7_SRI || opcode == SS7_UL || opcode == SS7_CLR {
        let alert = DefenseAlert {
            alert_type: ALERT_SS7_ANOMALY,
            severity: if opcode == SS7_CLR { 4 } else { 3 },
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: src_gt_hash as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&opcode.to_le_bytes());
                d[4..8].copy_from_slice(&src_gt_hash.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 22: Modem Interface Tamper Detection (Alert 25)
// Monitor access to modem device files (/dev/smd*, /dev/qmi*, /dev/at*).
// Hook: kprobe on modem device open/ioctl
// ══════════════════════════════════════════════════════════════════════════════

#[kprobe]
pub fn detect_modem_tamper(ctx: ProbeContext) -> u32 {
    try_detect_modem_tamper(&ctx).unwrap_or_default()
}

fn try_detect_modem_tamper(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let fd: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };

    // Check if this PID is authorized to access modem
    if unsafe { MODEM_ACCESS_PIDS.get(&pid) }.is_none() {
        let alert = DefenseAlert {
            alert_type: ALERT_MODEM_TAMPER,
            severity: 4,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: fd as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&pid.to_le_bytes());
                d[4..8].copy_from_slice(&fd.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 23: NAS Replay Detection (Alert 26)
// Track NAS message sequence numbers per bearer to detect replay attacks.
// Hook: kprobe on NAS decode path
// ══════════════════════════════════════════════════════════════════════════════

#[kprobe]
pub fn detect_nas_replay(ctx: ProbeContext) -> u32 {
    try_detect_nas_replay(&ctx).unwrap_or_default()
}

fn try_detect_nas_replay(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let bearer_id: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let seq_num: u32 = unsafe { ctx.arg(1).unwrap_or(0) };

    let prev_seq = unsafe { NAS_SEQ_TRACKER.get(&bearer_id) }
        .copied()
        .unwrap_or(0);

    // Duplicate or regressed sequence number = replay
    if seq_num <= prev_seq {
        let alert = DefenseAlert {
            alert_type: ALERT_NAS_REPLAY,
            severity: 4,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: bearer_id as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&seq_num.to_le_bytes());
                d[4..8].copy_from_slice(&prev_seq.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    let _ = NAS_SEQ_TRACKER.insert(&bearer_id, &seq_num, 0);

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 24: VoLTE Fraud Detection (Alert 27)
// Monitors IMS/SIP session patterns for fraud indicators:
// toll fraud, premium number calls, SIP INVITE floods
// Hook: kprobe on IMS stack SIP processing
// ══════════════════════════════════════════════════════════════════════════════

const VOLTE_CALL_RATE_THRESHOLD: u32 = 20;

#[kprobe]
pub fn detect_volte_fraud(ctx: ProbeContext) -> u32 {
    try_detect_volte_fraud(&ctx).unwrap_or_default()
}

fn try_detect_volte_fraud(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let sip_method: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let dest_hash: u32 = unsafe { ctx.arg(1).unwrap_or(0) };

    // SIP INVITE = 1, BYE = 2, REGISTER = 3
    if sip_method != 1 {
        return Ok(0);
    }

    let cell_id = unsafe { CELL_CURRENT.get(0) }
        .map(|c| c.cell_id)
        .unwrap_or(0);

    let count = unsafe { VOLTE_CALL_RATE.get(&cell_id) }
        .copied()
        .unwrap_or(0);
    let new_count = count + 1;
    let _ = VOLTE_CALL_RATE.insert(&cell_id, &new_count, 0);

    // High call rate from single cell = potential toll fraud or SIP flood
    if new_count >= VOLTE_CALL_RATE_THRESHOLD {
        let alert = DefenseAlert {
            alert_type: ALERT_VOLTE_FRAUD,
            severity: 3,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: cell_id as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&new_count.to_le_bytes());
                d[4..8].copy_from_slice(&dest_hash.to_le_bytes());
                d[8..12].copy_from_slice(&sip_method.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 25: eSIM Provisioning Monitoring (Alert 28)
// Detects unauthorized profile downloads, EID tampering,
// and SM-DP+ communication anomalies
// Hook: kprobe on eSIM LPA interface
// ══════════════════════════════════════════════════════════════════════════════

#[kprobe]
pub fn detect_esim_tamper(ctx: ProbeContext) -> u32 {
    try_detect_esim_tamper(&ctx).unwrap_or_default()
}

fn try_detect_esim_tamper(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let eid_hash: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let operation: u32 = unsafe { ctx.arg(1).unwrap_or(0) };

    // Operations: 1=download, 2=enable, 3=disable, 4=delete
    if operation == 1 || operation == 4 {
        if let Some(&prev_ts) = unsafe { ESIM_PROVISION_LOG.get(&eid_hash) } {
            let delta = now.saturating_sub(prev_ts);
            // Multiple operations within 10 seconds = suspicious
            if delta < 10_000_000_000 {
                let alert = DefenseAlert {
                    alert_type: ALERT_ESIM_TAMPER,
                    severity: 4,
                    pid,
                    _pad: 0,
                    timestamp_ns: now,
                    context: eid_hash,
                    details: {
                        let mut d = [0u8; 16];
                        d[0..4].copy_from_slice(&operation.to_le_bytes());
                        d[4..12].copy_from_slice(&delta.to_le_bytes());
                        d
                    },
                };
                let _ = DEFENSE_ALERTS.output(&alert, 0);
            }
        }
        let _ = ESIM_PROVISION_LOG.insert(&eid_hash, &now, 0);
    }

    // Any profile delete is suspicious by default
    if operation == 4 {
        let alert = DefenseAlert {
            alert_type: ALERT_ESIM_TAMPER,
            severity: 3,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: eid_hash,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&operation.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 26: Network Slice Isolation Verification (Alert 29)
// Monitors inter-slice traffic, detects S-NSSAI spoofing,
// unauthorized slice access, and QoS flow manipulation
// Hook: kprobe on NAS/NGAP slice selection
// ══════════════════════════════════════════════════════════════════════════════

#[kprobe]
pub fn detect_slice_violation(ctx: ProbeContext) -> u32 {
    try_detect_slice_violation(&ctx).unwrap_or_default()
}

fn try_detect_slice_violation(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let snssai_sst: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let src_slice_id: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let dst_slice_id: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    // Cross-slice communication detected
    if src_slice_id != 0 && dst_slice_id != 0 && src_slice_id != dst_slice_id {
        // Check if this cross-slice pair is allowed
        let pair_key = src_slice_id ^ dst_slice_id;
        if unsafe { SLICE_ISOLATION_MAP.get(&pair_key) }.is_none() {
            let alert = DefenseAlert {
                alert_type: ALERT_SLICE_VIOLATION,
                severity: 4,
                pid,
                _pad: 0,
                timestamp_ns: now,
                context: ((src_slice_id as u64) << 32) | dst_slice_id as u64,
                details: {
                    let mut d = [0u8; 16];
                    d[0..4].copy_from_slice(&snssai_sst.to_le_bytes());
                    d[4..8].copy_from_slice(&src_slice_id.to_le_bytes());
                    d[8..12].copy_from_slice(&dst_slice_id.to_le_bytes());
                    d
                },
            };
            let _ = DEFENSE_ALERTS.output(&alert, 0);
        }
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 27: Roaming Anomaly Detection (Alert 30)
// Detects impossible travel, PLMN spoofing,
// and unauthorized IPX/GRX traffic patterns
// Hook: kprobe on roaming state update path
// ══════════════════════════════════════════════════════════════════════════════

#[kprobe]
pub fn detect_roaming_anomaly(ctx: ProbeContext) -> u32 {
    try_detect_roaming_anomaly(&ctx).unwrap_or_default()
}

fn try_detect_roaming_anomaly(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let visited_plmn: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let home_plmn: u32 = unsafe { ctx.arg(1).unwrap_or(0) };

    // Check if this PLMN transition is known/expected
    if let Some(&prev_plmn) = unsafe { ROAMING_BASELINE.get(&home_plmn) } {
        if prev_plmn != visited_plmn && prev_plmn != 0 {
            // PLMN changed -- check timing for impossible travel
            let alert = DefenseAlert {
                alert_type: ALERT_ROAMING_ANOMALY,
                severity: 3,
                pid,
                _pad: 0,
                timestamp_ns: now,
                context: ((home_plmn as u64) << 32) | visited_plmn as u64,
                details: {
                    let mut d = [0u8; 16];
                    d[0..4].copy_from_slice(&visited_plmn.to_le_bytes());
                    d[4..8].copy_from_slice(&prev_plmn.to_le_bytes());
                    d[8..12].copy_from_slice(&home_plmn.to_le_bytes());
                    d
                },
            };
            let _ = DEFENSE_ALERTS.output(&alert, 0);
        }
    }

    let _ = ROAMING_BASELINE.insert(&home_plmn, &visited_plmn, 0);

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 28: RF Fingerprinting (Alert 31)
// Detects rogue base stations via RF characteristic analysis:
// IQ variance, frequency offset, power ramp profiles,
// timing advance anomalies
// Hook: kprobe on modem measurement report
// ══════════════════════════════════════════════════════════════════════════════

const RF_IQ_VARIANCE_THRESHOLD: u32 = 500;
const RF_FREQ_OFFSET_THRESHOLD: i32 = 200;

#[kprobe]
pub fn detect_rf_fingerprint(ctx: ProbeContext) -> u32 {
    try_detect_rf_fingerprint(&ctx).unwrap_or_default()
}

fn try_detect_rf_fingerprint(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let cell_id: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let iq_variance: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let freq_offset: i32 = unsafe { ctx.arg::<u32>(2).unwrap_or(0) as i32 };

    if let Some(baseline) = unsafe { RF_FINGERPRINT_BASELINE.get(&cell_id) } {
        let mut anomaly_score: u32 = 0;

        // IQ variance deviation
        let iq_diff = if iq_variance > baseline.iq_variance {
            iq_variance - baseline.iq_variance
        } else {
            baseline.iq_variance - iq_variance
        };
        if iq_diff > RF_IQ_VARIANCE_THRESHOLD {
            anomaly_score += 2;
        }

        // Frequency offset deviation
        let freq_diff = if freq_offset > baseline.freq_offset_hz {
            freq_offset - baseline.freq_offset_hz
        } else {
            baseline.freq_offset_hz - freq_offset
        };
        if freq_diff > RF_FREQ_OFFSET_THRESHOLD {
            anomaly_score += 2;
        }

        // Anomaly threshold crossed -- likely fake base station
        if anomaly_score >= 3 {
            let alert = DefenseAlert {
                alert_type: ALERT_RF_FINGERPRINT,
                severity: 4,
                pid,
                _pad: 0,
                timestamp_ns: now,
                context: cell_id as u64,
                details: {
                    let mut d = [0u8; 16];
                    d[0..4].copy_from_slice(&anomaly_score.to_le_bytes());
                    d[4..8].copy_from_slice(&iq_variance.to_le_bytes());
                    d[8..12].copy_from_slice(&(freq_offset as u32).to_le_bytes());
                    d[12..16].copy_from_slice(&cell_id.to_le_bytes());
                    d
                },
            };
            let _ = DEFENSE_ALERTS.output(&alert, 0);
        }
    } else {
        // Unknown cell -- any measurement is suspicious without baseline
        let alert = DefenseAlert {
            alert_type: ALERT_RF_FINGERPRINT,
            severity: 2,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: cell_id as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&iq_variance.to_le_bytes());
                d[4..8].copy_from_slice(&(freq_offset as u32).to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 29: SBI Anomaly Detection (Alert 32)
// Inspects HTTP/2 frames between 5G core NFs; flags unauthorized
// service discovery, token reuse, unknown NF types, excessive streams
// Hook: kprobe on tcp_sendmsg (NF SBI ports)
// ══════════════════════════════════════════════════════════════════════════════

const SBI_MAX_STREAMS_PER_NF: u32 = 100;

#[kprobe]
pub fn detect_sbi_anomaly(ctx: ProbeContext) -> u32 {
    try_detect_sbi_anomaly(&ctx).unwrap_or_default()
}

fn try_detect_sbi_anomaly(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let nf_type: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let stream_id: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let token_hash: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    // Check NF type against baseline
    if let Some(baseline) = unsafe { SBI_BASELINE_MAP.get(&nf_type) } {
        // Check stream count
        let count = unsafe { SBI_STREAM_COUNTER.get(&nf_type) }
            .copied()
            .unwrap_or(0);
        let new_count = count + 1;
        let _ = SBI_STREAM_COUNTER.insert(&nf_type, &new_count, 0);

        if new_count > SBI_MAX_STREAMS_PER_NF || new_count > baseline.max_streams {
            let alert = DefenseAlert {
                alert_type: ALERT_SBI_ANOMALY,
                severity: 3,
                pid,
                _pad: 0,
                timestamp_ns: now,
                context: nf_type as u64,
                details: {
                    let mut d = [0u8; 16];
                    d[0..4].copy_from_slice(&nf_type.to_le_bytes());
                    d[4..8].copy_from_slice(&new_count.to_le_bytes());
                    d[8..12].copy_from_slice(&stream_id.to_le_bytes());
                    d
                },
            };
            let _ = DEFENSE_ALERTS.output(&alert, 0);
        }

        // Token fingerprint mismatch = potential token theft/reuse
        let token_fp = baseline.token_fingerprint as u32;
        if token_hash != 0 && token_fp != 0 && token_hash != token_fp {
            let alert = DefenseAlert {
                alert_type: ALERT_SBI_ANOMALY,
                severity: 4,
                pid,
                _pad: 0,
                timestamp_ns: now,
                context: nf_type as u64,
                details: {
                    let mut d = [0u8; 16];
                    d[0..4].copy_from_slice(&token_hash.to_le_bytes());
                    d[4..8].copy_from_slice(&token_fp.to_le_bytes());
                    d[8..12].copy_from_slice(&nf_type.to_le_bytes());
                    d
                },
            };
            let _ = DEFENSE_ALERTS.output(&alert, 0);
        }
    } else {
        // Unknown NF type communicating on SBI -- always suspicious
        let alert = DefenseAlert {
            alert_type: ALERT_SBI_ANOMALY,
            severity: 4,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: nf_type as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&nf_type.to_le_bytes());
                d[4..8].copy_from_slice(&stream_id.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 30: Handover Integrity Monitoring (Alert 33)
// Validates measurement reports against known cell topology;
// flags implausible RSRP/PCI combinations and excessive handover rates
// Hook: kprobe on RRC measurement report processing
// ══════════════════════════════════════════════════════════════════════════════

const HANDOVER_RATE_THRESHOLD: u32 = 10;

#[kprobe]
pub fn detect_handover_integrity(ctx: ProbeContext) -> u32 {
    try_detect_handover_integrity(&ctx).unwrap_or_default()
}

fn try_detect_handover_integrity(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let source_pci: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let target_pci: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let rsrp: i32 = unsafe { ctx.arg::<u32>(2).unwrap_or(0) as i32 };

    // Rate limiting: count handovers per source cell
    let rate = unsafe { HANDOVER_RATE_MAP.get(&source_pci) }
        .copied()
        .unwrap_or(0);
    let new_rate = rate + 1;
    let _ = HANDOVER_RATE_MAP.insert(&source_pci, &new_rate, 0);

    if new_rate > HANDOVER_RATE_THRESHOLD {
        let alert = DefenseAlert {
            alert_type: ALERT_HANDOVER_INTEGRITY,
            severity: 3,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: source_pci as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&source_pci.to_le_bytes());
                d[4..8].copy_from_slice(&target_pci.to_le_bytes());
                d[8..12].copy_from_slice(&new_rate.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    // Validate against topology baseline
    if let Some(baseline) = unsafe { HANDOVER_BASELINE_MAP.get(&source_pci) } {
        let rsrp_i16 = rsrp as i16;

        // Check if target PCI is an expected neighbor
        if target_pci != baseline.target_pci as u32 {
            let alert = DefenseAlert {
                alert_type: ALERT_HANDOVER_INTEGRITY,
                severity: 4,
                pid,
                _pad: 0,
                timestamp_ns: now,
                context: ((source_pci as u64) << 32) | target_pci as u64,
                details: {
                    let mut d = [0u8; 16];
                    d[0..4].copy_from_slice(&source_pci.to_le_bytes());
                    d[4..8].copy_from_slice(&target_pci.to_le_bytes());
                    d[8..12].copy_from_slice(&(rsrp as u32).to_le_bytes());
                    d
                },
            };
            let _ = DEFENSE_ALERTS.output(&alert, 0);
        }

        // Check RSRP plausibility
        if rsrp_i16 < baseline.min_rsrp || rsrp_i16 > baseline.max_rsrp {
            let alert = DefenseAlert {
                alert_type: ALERT_HANDOVER_INTEGRITY,
                severity: 3,
                pid,
                _pad: 0,
                timestamp_ns: now,
                context: source_pci as u64,
                details: {
                    let mut d = [0u8; 16];
                    d[0..4].copy_from_slice(&(rsrp as u32).to_le_bytes());
                    d[4..6].copy_from_slice(&baseline.min_rsrp.to_le_bytes());
                    d[6..8].copy_from_slice(&baseline.max_rsrp.to_le_bytes());
                    d[8..12].copy_from_slice(&target_pci.to_le_bytes());
                    d
                },
            };
            let _ = DEFENSE_ALERTS.output(&alert, 0);
        }
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 31: RAN Sharing Isolation Detection (Alert 34)
// Detects cross-PLMN leakage in MOCN/MORAN deployments;
// monitors UE-to-PLMN mappings for isolation violations
// Hook: kprobe on PLMN selection / RRC connection setup
// ══════════════════════════════════════════════════════════════════════════════

const RAN_SHARING_ISOLATION_THRESHOLD: u32 = 3;

#[kprobe]
pub fn detect_ran_sharing_leak(ctx: ProbeContext) -> u32 {
    try_detect_ran_sharing_leak(&ctx).unwrap_or_default()
}

fn try_detect_ran_sharing_leak(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let plmn_id: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let slice_id: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let ue_context_hash: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    if let Some(state) = unsafe { RAN_SHARING_MAP.get(&plmn_id) } {
        // Check if this UE context belongs to a different PLMN's slice
        if state.slice_id != 0 && slice_id != 0 && state.slice_id != slice_id {
            let violations = (state.isolation_violations as u32) + 1;

            // Update violation count
            let new_state = RanSharingState {
                plmn_id,
                slice_id: state.slice_id,
                ue_count: state.ue_count,
                _pad: 0,
                isolation_violations: violations as u64,
            };
            let _ = RAN_SHARING_MAP.insert(&plmn_id, &new_state, 0);

            if violations >= RAN_SHARING_ISOLATION_THRESHOLD {
                let alert = DefenseAlert {
                    alert_type: ALERT_RAN_SHARING_LEAK,
                    severity: 4,
                    pid,
                    _pad: 0,
                    timestamp_ns: now,
                    context: plmn_id as u64,
                    details: {
                        let mut d = [0u8; 16];
                        d[0..4].copy_from_slice(&plmn_id.to_le_bytes());
                        d[4..8].copy_from_slice(&violations.to_le_bytes());
                        d[8..12].copy_from_slice(&slice_id.to_le_bytes());
                        d[12..16].copy_from_slice(&ue_context_hash.to_le_bytes());
                        d
                    },
                };
                let _ = DEFENSE_ALERTS.output(&alert, 0);
            }
        }
    } else {
        // First time seeing this PLMN -- register baseline
        let new_state = RanSharingState {
            plmn_id,
            slice_id,
            ue_count: 1,
            _pad: 0,
            isolation_violations: 0,
        };
        let _ = RAN_SHARING_MAP.insert(&plmn_id, &new_state, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 32: Signaling Storm Detection (Alert 35)
// Volumetric analysis of attach/detach/TAU/service-request floods;
// fires when any message type exceeds threshold per time window
// Hook: kprobe on NAS/NGAP message processing
// ══════════════════════════════════════════════════════════════════════════════

const SIGNALING_STORM_ATTACH_THRESHOLD: u32 = 50;
const SIGNALING_STORM_TAU_THRESHOLD: u32 = 100;
const SIGNALING_WINDOW_NS: u64 = 10_000_000_000; // 10 seconds

#[kprobe]
pub fn detect_signaling_storm(ctx: ProbeContext) -> u32 {
    try_detect_signaling_storm(&ctx).unwrap_or_default()
}

fn try_detect_signaling_storm(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let msg_type: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let cell_id: u32 = unsafe { ctx.arg(1).unwrap_or(0) };

    let counter = unsafe { SIGNALING_COUNTER_MAP.get(&cell_id) }.copied();

    let mut counters = match counter {
        Some(c) => {
            // Reset window if expired
            if now.saturating_sub(c.window_start_ns) > SIGNALING_WINDOW_NS {
                SignalingCounter {
                    attach_count: 0,
                    detach_count: 0,
                    tau_count: 0,
                    service_req_count: 0,
                    window_start_ns: now,
                }
            } else {
                c
            }
        }
        None => SignalingCounter {
            attach_count: 0,
            detach_count: 0,
            tau_count: 0,
            service_req_count: 0,
            window_start_ns: now,
        },
    };

    // NAS message types: 0x41=Attach, 0x45=Detach, 0x48=TAU, 0x4C=ServiceReq
    match msg_type {
        0x41 => counters.attach_count += 1,
        0x45 => counters.detach_count += 1,
        0x48 => counters.tau_count += 1,
        0x4C => counters.service_req_count += 1,
        _ => {}
    }

    let _ = SIGNALING_COUNTER_MAP.insert(&cell_id, &counters, 0);

    // Check thresholds
    let storm_detected = counters.attach_count >= SIGNALING_STORM_ATTACH_THRESHOLD
        || counters.detach_count >= SIGNALING_STORM_ATTACH_THRESHOLD
        || counters.tau_count >= SIGNALING_STORM_TAU_THRESHOLD
        || counters.service_req_count >= SIGNALING_STORM_TAU_THRESHOLD;

    if storm_detected {
        let total_rate = counters.attach_count
            + counters.detach_count
            + counters.tau_count
            + counters.service_req_count;

        let alert = DefenseAlert {
            alert_type: ALERT_SIGNALING_STORM,
            severity: 4,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: cell_id as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&msg_type.to_le_bytes());
                d[4..8].copy_from_slice(&total_rate.to_le_bytes());
                d[8..12].copy_from_slice(&counters.attach_count.to_le_bytes());
                d[12..16].copy_from_slice(&counters.tau_count.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// Panic Handler
// ══════════════════════════════════════════════════════════════════════════════

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
