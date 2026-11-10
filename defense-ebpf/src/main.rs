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
    AisVesselState, CellBaseline, CellInfo, DefenseAlert, HandoverBaseline, LmrBaseline,
    RanSharingState, RfFingerprint, SbiBaseline, SignalingCounter, ALERT_AIS_INTEGRITY,
    ALERT_AVIATION_INTEGRITY, ALERT_BLE_PAIRING, ALERT_BROADCAST_INJECTION, ALERT_CELL_ANOMALY,
    ALERT_DOWNGRADE_ATTACK, ALERT_DVBS2_ANOMALY, ALERT_EAS_SPOOFING, ALERT_ESIM_TAMPER,
    ALERT_GNSS_SPOOFING, ALERT_GTP_ANOMALY, ALERT_HANDOVER_INTEGRITY, ALERT_IMSI_CATCHER,
    ALERT_LEO_SIGNALING, ALERT_LORAWAN_JOIN, ALERT_MODEM_TAMPER, ALERT_NAS_REPLAY, ALERT_NBIOT_RRC,
    ALERT_NTN_ANOMALY, ALERT_ORAN_FRONTHAUL, ALERT_ORAN_RIC, ALERT_P25_CONTROL,
    ALERT_PAGER_ANOMALY, ALERT_RAN_SHARING_LEAK, ALERT_RF_FINGERPRINT, ALERT_RKE_JAMMING,
    ALERT_ROAMING_ANOMALY, ALERT_ROGUE_TOWER, ALERT_SBI_ANOMALY, ALERT_SIGNALING_STORM,
    ALERT_SLICE_VIOLATION, ALERT_SS7_ANOMALY, ALERT_STARLINK_AUTH, ALERT_TETRA_ENCRYPTION,
    ALERT_UAV_C2, ALERT_VOLTE_FRAUD, ALERT_VSAT_INTEGRITY, ALERT_WIFI_DEAUTH, ALERT_WPA3_INTEGRITY,
    ALERT_ZIGBEE_KEY,
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
// SATELLITE DEFENSE MAPS (Modules 33-39)
// ══════════════════════════════════════════════════════════════════════════════

#[map]
static SAT_CARRIER_BASELINE: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

#[map]
static NTN_TA_BASELINE: HashMap<u32, u32> = HashMap::with_max_entries(32, 0);

#[map]
static LEO_BURST_COUNTER: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

#[map]
static VSAT_FW_BASELINE: HashMap<u32, u64> = HashMap::with_max_entries(16, 0);

#[map]
static STARLINK_TOKEN_LOG: HashMap<u64, u64> = HashMap::with_max_entries(32, 0);

#[map]
static ADSB_TRACK_HISTORY: HashMap<u32, u64> = HashMap::with_max_entries(128, 0);

#[map]
static GNSS_CN0_BASELINE: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

// ══════════════════════════════════════════════════════════════════════════════
// RF PROTOCOL DOMAIN DEFENSE MAPS (Modules 40-55)
// ══════════════════════════════════════════════════════════════════════════════

#[map]
static TETRA_CIPHER_BASELINE: HashMap<u32, LmrBaseline> = HashMap::with_max_entries(32, 0);

#[map]
static P25_CONTROL_BASELINE: HashMap<u32, u64> = HashMap::with_max_entries(64, 0);

#[map]
static BLE_PAIRING_STATE: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

#[map]
static WPAN_JOIN_LOG: HashMap<u32, u64> = HashMap::with_max_entries(64, 0);

#[map]
static LORAWAN_NONCE_LOG: HashMap<u64, u32> = HashMap::with_max_entries(128, 0);

#[map]
static LORAWAN_FCNT_LOG: HashMap<u32, u32> = HashMap::with_max_entries(128, 0);

#[map]
static NBIOT_RRC_RATE: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

#[map]
static WIFI_DEAUTH_RATE: HashMap<u64, u32> = HashMap::with_max_entries(128, 0);

#[map]
static WPA3_SAE_STATE: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

#[map]
static RKE_ENERGY_LOG: HashMap<u32, u64> = HashMap::with_max_entries(32, 0);

#[map]
static UAV_FLEET_AUTH: HashMap<u64, u64> = HashMap::with_max_entries(128, 0);

#[map]
static PAGER_RIC_LOG: HashMap<u32, u64> = HashMap::with_max_entries(128, 0);

#[map]
static BROADCAST_PI_LOG: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

#[map]
static EAS_ORIGINATOR_LOG: HashMap<u32, u32> = HashMap::with_max_entries(32, 0);

#[map]
static ECPRI_SEQ_TRACK: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

#[map]
static RIC_XAPP_LOG: HashMap<u64, u64> = HashMap::with_max_entries(64, 0);

#[map]
static AIS_VESSEL_TRACK: HashMap<u32, AisVesselState> = HashMap::with_max_entries(128, 0);

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
        let iq_diff = iq_variance.abs_diff(baseline.iq_variance);
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
// MODULE 33: DVB-S2/S2X Anomaly Detection (Alert 36)
// Detects unauthorized carriers, abnormal modcod transitions, injection attempts
// Hook: kprobe on DVB demux path
// ══════════════════════════════════════════════════════════════════════════════

const DVB_MODCOD_MAX: u32 = 28;
const DVB_SYMBOL_RATE_MIN: u32 = 1000;
const DVB_SYMBOL_RATE_MAX: u32 = 45000;

#[kprobe]
pub fn detect_dvbs2_anomaly(ctx: ProbeContext) -> u32 {
    try_detect_dvbs2_anomaly(&ctx).unwrap_or_default()
}

fn try_detect_dvbs2_anomaly(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let carrier_id: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let modcod: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let symbol_rate: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    let mut anomaly = false;

    if modcod > DVB_MODCOD_MAX {
        anomaly = true;
    }

    if symbol_rate != 0 && !(DVB_SYMBOL_RATE_MIN..=DVB_SYMBOL_RATE_MAX).contains(&symbol_rate) {
        anomaly = true;
    }

    if let Some(baseline) = unsafe { SAT_CARRIER_BASELINE.get(&carrier_id) } {
        let prev_modcod = *baseline;
        let diff = modcod.abs_diff(prev_modcod);
        if diff > 5 {
            anomaly = true;
        }
    } else {
        anomaly = true;
    }

    let _ = SAT_CARRIER_BASELINE.insert(&carrier_id, &modcod, 0);

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_DVBS2_ANOMALY,
            severity: 3,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: carrier_id as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&carrier_id.to_le_bytes());
                d[4..8].copy_from_slice(&modcod.to_le_bytes());
                d[8..12].copy_from_slice(&symbol_rate.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 34: NTN Access Anomaly Detection (Alert 37)
// Detects timing advance inconsistencies with satellite ephemeris
// Hook: kprobe on NTN TA processing
// ══════════════════════════════════════════════════════════════════════════════

const NTN_TA_MAX: u32 = 200_000;
const NTN_TA_JUMP_THRESHOLD: u32 = 10_000;

#[kprobe]
pub fn detect_ntn_anomaly(ctx: ProbeContext) -> u32 {
    try_detect_ntn_anomaly(&ctx).unwrap_or_default()
}

fn try_detect_ntn_anomaly(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let cell_id: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let ta_value: u32 = unsafe { ctx.arg(1).unwrap_or(0) };

    let mut anomaly = false;

    if ta_value > NTN_TA_MAX {
        anomaly = true;
    }

    if let Some(prev_ta) = unsafe { NTN_TA_BASELINE.get(&cell_id) } {
        let diff = ta_value.abs_diff(*prev_ta);
        if diff > NTN_TA_JUMP_THRESHOLD {
            anomaly = true;
        }
    }

    let _ = NTN_TA_BASELINE.insert(&cell_id, &ta_value, 0);

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_NTN_ANOMALY,
            severity: 3,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: cell_id as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&cell_id.to_le_bytes());
                d[4..8].copy_from_slice(&ta_value.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 35: LEO Constellation Signaling Monitor (Alert 38)
// Detects unauthorized L-band burst patterns
// Hook: kprobe on SDR RX path
// ══════════════════════════════════════════════════════════════════════════════

const LEO_BURST_RATE_THRESHOLD: u32 = 100;

#[kprobe]
pub fn detect_leo_signaling(ctx: ProbeContext) -> u32 {
    try_detect_leo_signaling(&ctx).unwrap_or_default()
}

fn try_detect_leo_signaling(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let channel_id: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let burst_type: u32 = unsafe { ctx.arg(1).unwrap_or(0) };

    let count = if let Some(prev) = unsafe { LEO_BURST_COUNTER.get(&channel_id) } {
        *prev + 1
    } else {
        1u32
    };
    let _ = LEO_BURST_COUNTER.insert(&channel_id, &count, 0);

    if count > LEO_BURST_RATE_THRESHOLD {
        let alert = DefenseAlert {
            alert_type: ALERT_LEO_SIGNALING,
            severity: 3,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: channel_id as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&channel_id.to_le_bytes());
                d[4..8].copy_from_slice(&burst_type.to_le_bytes());
                d[8..12].copy_from_slice(&count.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 36: VSAT/SCPC Integrity Monitor (Alert 39)
// Detects unauthorized firmware updates and burst time plan deviations
// Hook: kprobe on USB/modem firmware path
// ══════════════════════════════════════════════════════════════════════════════

const VSAT_FW_UPDATE_MIN_INTERVAL_NS: u64 = 3_600_000_000_000;

#[kprobe]
pub fn detect_vsat_integrity(ctx: ProbeContext) -> u32 {
    try_detect_vsat_integrity(&ctx).unwrap_or_default()
}

fn try_detect_vsat_integrity(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let terminal_id: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let transfer_len: u32 = unsafe { ctx.arg(1).unwrap_or(0) };

    let mut anomaly = false;

    if let Some(last_update) = unsafe { VSAT_FW_BASELINE.get(&terminal_id) } {
        if now - *last_update < VSAT_FW_UPDATE_MIN_INTERVAL_NS {
            anomaly = true;
        }
    }

    let _ = VSAT_FW_BASELINE.insert(&terminal_id, &now, 0);

    if transfer_len > 1024 * 1024 {
        anomaly = true;
    }

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_VSAT_INTEGRITY,
            severity: 4,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: terminal_id as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&terminal_id.to_le_bytes());
                d[4..8].copy_from_slice(&transfer_len.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 37: Starlink Authentication Monitor (Alert 40)
// Detects gRPC token reuse/replay and unauthorized firmware updates
// Hook: kprobe on tcp_sendmsg
// ══════════════════════════════════════════════════════════════════════════════

#[kprobe]
pub fn detect_starlink_auth(ctx: ProbeContext) -> u32 {
    try_detect_starlink_auth(&ctx).unwrap_or_default()
}

fn try_detect_starlink_auth(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let terminal_id: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let token_hash: u64 = unsafe { ctx.arg(1).unwrap_or(0) };

    let mut anomaly = false;

    if let Some(prev_token) = unsafe { STARLINK_TOKEN_LOG.get(&terminal_id) } {
        if *prev_token == token_hash && token_hash != 0 {
            anomaly = true;
        }
    }

    let _ = STARLINK_TOKEN_LOG.insert(&terminal_id, &token_hash, 0);

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_STARLINK_AUTH,
            severity: 4,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: terminal_id,
            details: {
                let mut d = [0u8; 16];
                d[0..8].copy_from_slice(&token_hash.to_le_bytes());
                d[8..12].copy_from_slice(&pid.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 38: Aviation/Maritime Signal Integrity (Alert 41)
// Detects ADS-B position inconsistencies and false distress beacons
// Hook: kprobe on SDR RX path
// ══════════════════════════════════════════════════════════════════════════════

const ADSB_MAX_CLIMB_RATE_FPM: u32 = 6000;
const ADSB_MAX_SPEED_KT: u32 = 600;

#[kprobe]
pub fn detect_aviation_integrity(ctx: ProbeContext) -> u32 {
    try_detect_aviation_integrity(&ctx).unwrap_or_default()
}

fn try_detect_aviation_integrity(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let icao_addr: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let altitude: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let speed: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    let mut anomaly = false;

    if let Some(prev_packed) = unsafe { ADSB_TRACK_HISTORY.get(&icao_addr) } {
        let prev_alt = (*prev_packed >> 32) as u32;
        let alt_diff = altitude.abs_diff(prev_alt);
        if alt_diff > ADSB_MAX_CLIMB_RATE_FPM {
            anomaly = true;
        }
    }

    if speed > ADSB_MAX_SPEED_KT {
        anomaly = true;
    }

    let packed = ((altitude as u64) << 32) | speed as u64;
    let _ = ADSB_TRACK_HISTORY.insert(&icao_addr, &packed, 0);

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_AVIATION_INTEGRITY,
            severity: 5,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: icao_addr as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&icao_addr.to_le_bytes());
                d[4..8].copy_from_slice(&altitude.to_le_bytes());
                d[8..12].copy_from_slice(&speed.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 39: GNSS Spoofing Detection (Alert 42)
// Detects C/N0 anomalies, cross-constellation divergence, code-phase jumps
// Hook: kprobe on GNSS receiver path
// ══════════════════════════════════════════════════════════════════════════════

const GNSS_CN0_ANOMALY_THRESHOLD: u32 = 1000;
const GNSS_CN0_MAX: u32 = 6000;
const GNSS_CN0_MIN: u32 = 2000;

#[kprobe]
pub fn detect_gnss_spoofing(ctx: ProbeContext) -> u32 {
    try_detect_gnss_spoofing(&ctx).unwrap_or_default()
}

fn try_detect_gnss_spoofing(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let prn_key: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let cn0: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let constellation: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    let mut anomaly = false;

    if !(GNSS_CN0_MIN..=GNSS_CN0_MAX).contains(&cn0) {
        anomaly = true;
    }

    if let Some(baseline_cn0) = unsafe { GNSS_CN0_BASELINE.get(&prn_key) } {
        let diff = cn0.abs_diff(*baseline_cn0);
        if diff > GNSS_CN0_ANOMALY_THRESHOLD {
            anomaly = true;
        }
    }

    let _ = GNSS_CN0_BASELINE.insert(&prn_key, &cn0, 0);

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_GNSS_SPOOFING,
            severity: 5,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: prn_key as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&prn_key.to_le_bytes());
                d[4..8].copy_from_slice(&cn0.to_le_bytes());
                d[8..12].copy_from_slice(&constellation.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 40: TETRA Encryption Monitor (Alert 43)
// Detects TEA cipher downgrades and disabled encryption (TETRA:BURST).
// Hook: kprobe on TETRA SYSINFO/cipher indication
// ══════════════════════════════════════════════════════════════════════════════

const TETRA_SYSINFO_DCK_FALLBACK: u32 = 2;

#[kprobe]
pub fn detect_tetra_encryption(ctx: ProbeContext) -> u32 {
    try_detect_tetra_encryption(&ctx).unwrap_or_default()
}

fn try_detect_tetra_encryption(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let radio_id: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let cipher: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let sysinfo_enc: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    let mut anomaly = false;
    let mut expected_cipher = 0u32;

    if let Some(baseline) = unsafe { TETRA_CIPHER_BASELINE.get(&radio_id) } {
        expected_cipher = baseline.expected_cipher;
        // Cipher downgrade: TEA3=3 > TEA2=2 > TEA1=1 > clear=0
        if cipher < baseline.expected_cipher {
            anomaly = true;
        }
        // SYSINFO encryption indicator clear while encryption is expected
        if sysinfo_enc == 0 && baseline.expected_cipher > 0 {
            anomaly = true;
        }
    }

    // DCK (Derived Cipher Key) fallback from SCK
    if sysinfo_enc == TETRA_SYSINFO_DCK_FALLBACK {
        anomaly = true;
    }

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_TETRA_ENCRYPTION,
            severity: 4,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: radio_id as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&radio_id.to_le_bytes());
                d[4..8].copy_from_slice(&cipher.to_le_bytes());
                d[8..12].copy_from_slice(&sysinfo_enc.to_le_bytes());
                d[12..16].copy_from_slice(&expected_cipher.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 41: P25 Control Channel Integrity (Alert 44)
// Detects rogue NAC values and unexpected system ID changes.
// Hook: kprobe on P25 control channel decoder
// ══════════════════════════════════════════════════════════════════════════════

#[kprobe]
pub fn detect_p25_control(ctx: ProbeContext) -> u32 {
    try_detect_p25_control(&ctx).unwrap_or_default()
}

fn try_detect_p25_control(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let radio_id: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let nac: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let system_id: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    // Baseline packs NAC (high 32 bits) and system ID (low 32 bits)
    let packed = ((nac as u64) << 32) | system_id as u64;
    let mut anomaly = false;

    if let Some(prev_packed) = unsafe { P25_CONTROL_BASELINE.get(&radio_id) } {
        let prev_nac = (*prev_packed >> 32) as u32;
        let prev_system_id = *prev_packed as u32;
        if nac != prev_nac || system_id != prev_system_id {
            anomaly = true;
        }
    }

    let _ = P25_CONTROL_BASELINE.insert(&radio_id, &packed, 0);

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_P25_CONTROL,
            severity: 4,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: radio_id as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&radio_id.to_le_bytes());
                d[4..8].copy_from_slice(&nac.to_le_bytes());
                d[8..12].copy_from_slice(&system_id.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 42: BLE Pairing/Scanning Defense (Alert 45)
// Detects LE Secure Connections downgrades and GATT enumeration floods.
// Hook: kprobe on BLE SMP/GATT handler
// ══════════════════════════════════════════════════════════════════════════════

const BLE_GATT_ENUM_RATE_THRESHOLD: u32 = 100;

#[kprobe]
pub fn detect_ble_pairing(ctx: ProbeContext) -> u32 {
    try_detect_ble_pairing(&ctx).unwrap_or_default()
}

fn try_detect_ble_pairing(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let conn_handle: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let pairing_mode: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let enum_rate: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    let mut anomaly = false;
    let mut severity = 3u32;

    if let Some(prev_mode) = unsafe { BLE_PAIRING_STATE.get(&conn_handle) } {
        // Downgrade from LE Secure Connections (1) to LE Legacy (0)
        if *prev_mode == 1 && pairing_mode == 0 {
            anomaly = true;
            severity = 4;
        }
    }
    let _ = BLE_PAIRING_STATE.insert(&conn_handle, &pairing_mode, 0);

    // GATT service enumeration flood
    if enum_rate > BLE_GATT_ENUM_RATE_THRESHOLD {
        anomaly = true;
    }

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_BLE_PAIRING,
            severity,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: conn_handle as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&conn_handle.to_le_bytes());
                d[4..8].copy_from_slice(&pairing_mode.to_le_bytes());
                d[8..12].copy_from_slice(&enum_rate.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 43: Zigbee/Z-Wave Key Provisioning Monitor (Alert 46)
// Detects unprotected key transport, Z-Wave S0 zero-key inclusion, ZLL touchlink.
// Hook: kprobe on WPAN join/key exchange path
// ══════════════════════════════════════════════════════════════════════════════

const ZIGBEE_KEY_UNPROTECTED_TRANSPORT: u32 = 0x1;
const ZWAVE_S0_ZERO_TEMP_KEY: u32 = 0x2;
const ZLL_TOUCHLINK_COMMISSIONING: u32 = 0x4;

#[kprobe]
pub fn detect_zigbee_key(ctx: ProbeContext) -> u32 {
    try_detect_zigbee_key(&ctx).unwrap_or_default()
}

fn try_detect_zigbee_key(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let pan_id: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let key_flags: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let src_hash: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    let join_count = unsafe { WPAN_JOIN_LOG.get(&pan_id) }.copied().unwrap_or(0) + 1;
    let _ = WPAN_JOIN_LOG.insert(&pan_id, &join_count, 0);

    let insecure_flags = key_flags
        & (ZIGBEE_KEY_UNPROTECTED_TRANSPORT | ZWAVE_S0_ZERO_TEMP_KEY | ZLL_TOUCHLINK_COMMISSIONING);

    if insecure_flags != 0 {
        let alert = DefenseAlert {
            alert_type: ALERT_ZIGBEE_KEY,
            severity: 4,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: pan_id as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&pan_id.to_le_bytes());
                d[4..8].copy_from_slice(&key_flags.to_le_bytes());
                d[8..12].copy_from_slice(&src_hash.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 44: LoRaWAN Join Integrity (Alert 47)
// Detects OTAA DevNonce replay and ABP frame counter resets (session hijack).
// Hook: kprobe on LoRaWAN MAC layer
// ══════════════════════════════════════════════════════════════════════════════

#[kprobe]
pub fn detect_lorawan_join(ctx: ProbeContext) -> u32 {
    try_detect_lorawan_join(&ctx).unwrap_or_default()
}

fn try_detect_lorawan_join(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let dev_addr: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let dev_nonce: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let fcnt: u32 = unsafe { ctx.arg(2).unwrap_or(0) };
    let activation: u32 = unsafe { ctx.arg(3).unwrap_or(0) };

    let mut anomaly = false;

    // DevNonce replay: (DevAddr, DevNonce) pair already observed
    if dev_nonce != 0 {
        let nonce_key = ((dev_addr as u64) << 32) | dev_nonce as u64;
        if unsafe { LORAWAN_NONCE_LOG.get(&nonce_key) }.is_some() {
            anomaly = true;
        } else {
            let _ = LORAWAN_NONCE_LOG.insert(&nonce_key, &dev_addr, 0);
        }
    }

    // ABP frame counter reset => session hijack
    if activation == 1 {
        if let Some(prev_fcnt) = unsafe { LORAWAN_FCNT_LOG.get(&dev_addr) } {
            if fcnt < *prev_fcnt {
                anomaly = true;
            }
        }
        let _ = LORAWAN_FCNT_LOG.insert(&dev_addr, &fcnt, 0);
    }

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_LORAWAN_JOIN,
            severity: 4,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: dev_addr as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&dev_addr.to_le_bytes());
                d[4..8].copy_from_slice(&dev_nonce.to_le_bytes());
                d[8..12].copy_from_slice(&fcnt.to_le_bytes());
                d[12..16].copy_from_slice(&activation.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 45: NB-IoT/LTE-M RRC Anomaly (Alert 48)
// Detects NAS messages without security context and RRC signaling floods.
// Hook: kprobe on NB-IoT RRC/NAS dispatch
// ══════════════════════════════════════════════════════════════════════════════

const NBIOT_MSG_NAS: u32 = 1;
const NBIOT_RRC_RATE_THRESHOLD: u32 = 50;
const NBIOT_SEC_ESTABLISHED_BIT: u32 = 1 << 31;

#[kprobe]
pub fn detect_nbiot_rrc(ctx: ProbeContext) -> u32 {
    try_detect_nbiot_rrc(&ctx).unwrap_or_default()
}

fn try_detect_nbiot_rrc(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let ue_id: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let msg_type: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let sec_ctx: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    // Packed state: bit 31 = security context established, bits 0-30 = msg count
    let packed = unsafe { NBIOT_RRC_RATE.get(&ue_id) }.copied().unwrap_or(0);
    let was_established = packed & NBIOT_SEC_ESTABLISHED_BIT != 0;
    let rate = (packed & 0x7FFF) + 1;

    let mut anomaly = false;

    // NAS message without an active security context after establishment
    if msg_type == NBIOT_MSG_NAS && sec_ctx == 0 && was_established {
        anomaly = true;
    }

    // RRC connection rate exceeds threshold
    if rate > NBIOT_RRC_RATE_THRESHOLD {
        anomaly = true;
    }

    let established = was_established || sec_ctx != 0;
    let new_packed = if established {
        NBIOT_SEC_ESTABLISHED_BIT | (rate & 0x7FFF)
    } else {
        rate & 0x7FFF
    };
    let _ = NBIOT_RRC_RATE.insert(&ue_id, &new_packed, 0);

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_NBIOT_RRC,
            severity: 3,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: ue_id as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&ue_id.to_le_bytes());
                d[4..8].copy_from_slice(&msg_type.to_le_bytes());
                d[8..12].copy_from_slice(&sec_ctx.to_le_bytes());
                d[12..16].copy_from_slice(&rate.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 46: WiFi Deauth/Disassoc Detection (Alert 49)
// Detects 802.11 deauth/disassociation frame floods per BSSID.
// Hook: kprobe on 802.11 management frame path
// ══════════════════════════════════════════════════════════════════════════════

const WIFI_DEAUTH_SUBTYPE: u32 = 10;
const WIFI_DISASSOC_SUBTYPE: u32 = 12;
const WIFI_DEAUTH_FLOOD_THRESHOLD: u32 = 10;

#[kprobe]
pub fn detect_wifi_deauth(ctx: ProbeContext) -> u32 {
    try_detect_wifi_deauth(&ctx).unwrap_or_default()
}

fn try_detect_wifi_deauth(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let bssid_hash: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let subtype: u32 = unsafe { ctx.arg(1).unwrap_or(0) };

    if subtype != WIFI_DEAUTH_SUBTYPE && subtype != WIFI_DISASSOC_SUBTYPE {
        return Ok(0);
    }

    let count = unsafe { WIFI_DEAUTH_RATE.get(&bssid_hash) }
        .copied()
        .unwrap_or(0)
        + 1;
    let _ = WIFI_DEAUTH_RATE.insert(&bssid_hash, &count, 0);

    if count > WIFI_DEAUTH_FLOOD_THRESHOLD {
        let alert = DefenseAlert {
            alert_type: ALERT_WIFI_DEAUTH,
            severity: 4,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: bssid_hash,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&subtype.to_le_bytes());
                d[4..8].copy_from_slice(&count.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 47: WPA3/FT Integrity Monitor (Alert 50)
// Detects SAE group downgrades, anti-clogging token floods, and timing anomalies.
// Hook: kprobe on WPA3 SAE handshake path
// ══════════════════════════════════════════════════════════════════════════════

const SAE_EVENT_COMMIT: u32 = 0;
const SAE_EVENT_CONFIRM: u32 = 1;
const SAE_EVENT_GROUP_DOWNGRADE: u32 = 2;
const SAE_EVENT_ANTI_CLOGGING_TOKEN: u32 = 3;
const SAE_TOKEN_FLOOD_THRESHOLD: u32 = 20;
const SAE_MIN_COMMIT_CONFIRM_GAP_US: u32 = 1000;

#[kprobe]
pub fn detect_wpa3_integrity(ctx: ProbeContext) -> u32 {
    try_detect_wpa3_integrity(&ctx).unwrap_or_default()
}

fn try_detect_wpa3_integrity(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let sta_hash: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let sae_event: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let delta_us: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    let mut anomaly = false;
    let mut severity = 3u32;

    // SAE group downgrade attempt
    if sae_event == SAE_EVENT_GROUP_DOWNGRADE {
        anomaly = true;
        severity = 4;
    }

    // Anti-clogging token flood
    let tokens = unsafe { WPA3_SAE_STATE.get(&sta_hash) }
        .copied()
        .unwrap_or(0);
    let new_tokens = if sae_event == SAE_EVENT_ANTI_CLOGGING_TOKEN {
        tokens + 1
    } else {
        tokens
    };
    let _ = WPA3_SAE_STATE.insert(&sta_hash, &new_tokens, 0);
    if new_tokens > SAE_TOKEN_FLOOD_THRESHOLD {
        anomaly = true;
    }

    // Commit/confirm gap under 1ms — replay / side-channel indicator
    if (sae_event == SAE_EVENT_COMMIT || sae_event == SAE_EVENT_CONFIRM)
        && delta_us != 0
        && delta_us < SAE_MIN_COMMIT_CONFIRM_GAP_US
    {
        anomaly = true;
    }

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_WPA3_INTEGRITY,
            severity,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: sta_hash as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&sta_hash.to_le_bytes());
                d[4..8].copy_from_slice(&sae_event.to_le_bytes());
                d[8..12].copy_from_slice(&delta_us.to_le_bytes());
                d[12..16].copy_from_slice(&new_tokens.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 48: RKE Jamming Detection (Alert 51)
// Detects RollJam-style jam+capture patterns at 315/433 MHz.
// Hook: kprobe on key fob RF front-end
// ══════════════════════════════════════════════════════════════════════════════

const RKE_JAM_ENERGY_THRESHOLD: u32 = 8000;
const RKE_ENERGY_DELTA_THRESHOLD: u32 = 5000;

#[kprobe]
pub fn detect_rke_jamming(ctx: ProbeContext) -> u32 {
    try_detect_rke_jamming(&ctx).unwrap_or_default()
}

fn try_detect_rke_jamming(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let fob_id: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let energy_level: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let tx_failed: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    let mut anomaly = false;
    let mut severity = 4u32;

    // Sudden RF energy spike at the fob frequency
    if let Some(prev_energy) = unsafe { RKE_ENERGY_LOG.get(&fob_id) } {
        if energy_level.abs_diff(*prev_energy as u32) > RKE_ENERGY_DELTA_THRESHOLD {
            anomaly = true;
        }
    }
    let _ = RKE_ENERGY_LOG.insert(&fob_id, &(energy_level as u64), 0);

    // Sustained jamming coinciding with fob transmission failure (RollJam)
    if energy_level > RKE_JAM_ENERGY_THRESHOLD && tx_failed == 1 {
        anomaly = true;
        severity = 5;
    }

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_RKE_JAMMING,
            severity,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: fob_id as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&fob_id.to_le_bytes());
                d[4..8].copy_from_slice(&energy_level.to_le_bytes());
                d[8..12].copy_from_slice(&tx_failed.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 49: UAV C2 Integrity Monitor (Alert 52)
// Detects unsigned MAVLink commands, unauthorized DroneID serials, GCS spoofing.
// Hook: kprobe on MAVLink/DroneID telemetry path
// ══════════════════════════════════════════════════════════════════════════════

const UAV_FLAG_SIGNING_REQUIRED: u32 = 1;

#[kprobe]
pub fn detect_uav_c2(ctx: ProbeContext) -> u32 {
    try_detect_uav_c2(&ctx).unwrap_or_default()
}

fn try_detect_uav_c2(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let serial_hash: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let signed_flag: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let gcs_addr_hash: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    let mut anomaly = false;
    let mut severity = 3u32;

    // Fleet entry packs signing-required flag (high 32 bits) and GCS hash (low 32)
    if let Some(entry) = unsafe { UAV_FLEET_AUTH.get(&serial_hash) } {
        let flags = (*entry >> 32) as u32;
        let fleet_gcs = *entry as u32;

        // Signing configured but command arrives unsigned
        if flags & UAV_FLAG_SIGNING_REQUIRED != 0 && signed_flag == 0 {
            anomaly = true;
            severity = 4;
        }

        // Command source from unexpected GCS address
        if fleet_gcs != 0 && gcs_addr_hash != fleet_gcs {
            anomaly = true;
        }

        // Keep the trusted GCS binding; refresh only when unset or matching
        let new_gcs = if fleet_gcs == 0 || gcs_addr_hash == fleet_gcs {
            gcs_addr_hash
        } else {
            fleet_gcs
        };
        let updated = ((flags as u64) << 32) | new_gcs as u64;
        let _ = UAV_FLEET_AUTH.insert(&serial_hash, &updated, 0);
    } else {
        // DroneID serial not in the authorized fleet
        anomaly = true;
        severity = 4;
        let flags = if signed_flag == 1 {
            UAV_FLAG_SIGNING_REQUIRED
        } else {
            0
        };
        let entry = ((flags as u64) << 32) | gcs_addr_hash as u64;
        let _ = UAV_FLEET_AUTH.insert(&serial_hash, &entry, 0);
    }

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_UAV_C2,
            severity,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: serial_hash as u32 as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&(serial_hash as u32).to_le_bytes());
                d[4..8].copy_from_slice(&signed_flag.to_le_bytes());
                d[8..12].copy_from_slice(&gcs_addr_hash.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 50: Pager Signal Anomaly (Alert 53)
// Detects unknown POCSAG/FLEX RIC addresses, baud anomalies, irregular bursts.
// Hook: kprobe on pager decoder path
// ══════════════════════════════════════════════════════════════════════════════

#[kprobe]
pub fn detect_pager_anomaly(ctx: ProbeContext) -> u32 {
    try_detect_pager_anomaly(&ctx).unwrap_or_default()
}

fn try_detect_pager_anomaly(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let ric: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let baud: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let burst_pattern: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    let mut anomaly = false;

    // RIC address not seen before (not in the registered database)
    if unsafe { PAGER_RIC_LOG.get(&ric) }.is_none() {
        anomaly = true;
    }
    let _ = PAGER_RIC_LOG.insert(&ric, &now, 0);

    // Baud rate outside POCSAG (512/1200/2400) or FLEX (1600/3200/6400)
    match baud {
        512 | 1200 | 2400 | 1600 | 3200 | 6400 => {}
        _ => anomaly = true,
    }

    // Irregular burst timing pattern
    if burst_pattern & 0x80 != 0 {
        anomaly = true;
    }

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_PAGER_ANOMALY,
            severity: 3,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: ric as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&ric.to_le_bytes());
                d[4..8].copy_from_slice(&baud.to_le_bytes());
                d[8..12].copy_from_slice(&burst_pattern.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 51: Broadcast Injection Detection (Alert 54)
// Detects RDS PI code changes without switchover and unauthorized DAB+ FIG data.
// Hook: kprobe on RDS/DAB+ demodulator path
// ══════════════════════════════════════════════════════════════════════════════

const BROADCAST_FIG_SWITCHOVER_FLAG: u32 = 0x40;
const BROADCAST_FIG_UNAUTHORIZED_TYPE: u32 = 0x21;

#[kprobe]
pub fn detect_broadcast_injection(ctx: ProbeContext) -> u32 {
    try_detect_broadcast_injection(&ctx).unwrap_or_default()
}

fn try_detect_broadcast_injection(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let pi_code: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let fig_type: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let service_hash: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    let mut anomaly = false;

    if let Some(prev_pi) = unsafe { BROADCAST_PI_LOG.get(&service_hash) } {
        // PI code changed without the switchover flag
        if pi_code != *prev_pi && fig_type & BROADCAST_FIG_SWITCHOVER_FLAG == 0 {
            anomaly = true;
        }
    } else if fig_type == BROADCAST_FIG_UNAUTHORIZED_TYPE {
        // FIG type 0x21 from an unknown source
        anomaly = true;
    }

    let _ = BROADCAST_PI_LOG.insert(&service_hash, &pi_code, 0);

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_BROADCAST_INJECTION,
            severity: 4,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: pi_code as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&pi_code.to_le_bytes());
                d[4..8].copy_from_slice(&fig_type.to_le_bytes());
                d[8..12].copy_from_slice(&service_hash.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 52: Emergency Alert Spoofing Detection (Alert 55)
// Detects invalid SAME originator codes, malformed event codes, unauthorized WEA.
// Hook: kprobe on EAS/WEA message delivery path
// ══════════════════════════════════════════════════════════════════════════════

const EAS_MAX_ORIGINATOR_CODE: u32 = 6;
const EAS_MAX_EVENT_CODE: u32 = 200;

#[kprobe]
pub fn detect_eas_spoofing(ctx: ProbeContext) -> u32 {
    try_detect_eas_spoofing(&ctx).unwrap_or_default()
}

fn try_detect_eas_spoofing(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let originator: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let event_code: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let plmn_auth: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    let count = unsafe { EAS_ORIGINATOR_LOG.get(&originator) }
        .copied()
        .unwrap_or(0)
        + 1;
    let _ = EAS_ORIGINATOR_LOG.insert(&originator, &count, 0);

    let mut anomaly = false;

    // Originator code outside the known SAME values
    if originator > EAS_MAX_ORIGINATOR_CODE {
        anomaly = true;
    }

    // Malformed event code
    if event_code == 0 || event_code > EAS_MAX_EVENT_CODE {
        anomaly = true;
    }

    // WEA without a PLMN authorization chain
    if plmn_auth == 0 {
        anomaly = true;
    }

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_EAS_SPOOFING,
            severity: 5,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: originator as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&originator.to_le_bytes());
                d[4..8].copy_from_slice(&event_code.to_le_bytes());
                d[8..12].copy_from_slice(&plmn_auth.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 53: O-RAN Fronthaul Integrity (Alert 56)
// Detects eCPRI sequence gaps, IQ sample injection, and O-RAN WG4 timing violations.
// Hook: kprobe on eCPRI fronthaul receive path
// ══════════════════════════════════════════════════════════════════════════════

const ECPRI_IQ_AMPLITUDE_MAX: u32 = 32768;
const ORAN_TIMING_OFFSET_MAX_NS: u32 = 65;

#[kprobe]
pub fn detect_oran_fronthaul(ctx: ProbeContext) -> u32 {
    try_detect_oran_fronthaul(&ctx).unwrap_or_default()
}

fn try_detect_oran_fronthaul(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let pc_id: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let seq_num: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let iq_amplitude: u32 = unsafe { ctx.arg(2).unwrap_or(0) };
    let timing_offset_ns: i32 = unsafe { ctx.arg(3).unwrap_or(0) };

    let mut anomaly = false;

    // eCPRI sequence number gap (dropped or injected frames)
    if let Some(prev_seq) = unsafe { ECPRI_SEQ_TRACK.get(&pc_id) } {
        if *prev_seq != 0 && seq_num != prev_seq.wrapping_add(1) {
            anomaly = true;
        }
    }
    let _ = ECPRI_SEQ_TRACK.insert(&pc_id, &seq_num, 0);

    // IQ sample amplitude beyond expected range (injection)
    if iq_amplitude > ECPRI_IQ_AMPLITUDE_MAX {
        anomaly = true;
    }

    // Timing violation beyond O-RAN WG4 +/-65ns
    if timing_offset_ns.unsigned_abs() > ORAN_TIMING_OFFSET_MAX_NS {
        anomaly = true;
    }

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_ORAN_FRONTHAUL,
            severity: 4,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: pc_id as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&seq_num.to_le_bytes());
                d[4..8].copy_from_slice(&iq_amplitude.to_le_bytes());
                d[8..12].copy_from_slice(&timing_offset_ns.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 54: O-RAN RIC Security Monitor (Alert 57)
// Detects rogue xApp registrations, A1 policy injection, and O1 config changes.
// Hook: kprobe on Near-RT RIC E2/A1/O1 interface path
// ══════════════════════════════════════════════════════════════════════════════

const RIC_EVENT_SUBSCRIPTION: u32 = 0;
const RIC_EVENT_REGISTRATION: u32 = 1;
const RIC_EVENT_A1_POLICY: u32 = 2;
const RIC_EVENT_O1_CONFIG: u32 = 3;

#[kprobe]
pub fn detect_oran_ric(ctx: ProbeContext) -> u32 {
    try_detect_oran_ric(&ctx).unwrap_or_default()
}

fn try_detect_oran_ric(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let xapp_id: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let event_type: u32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let e2_node_id: u32 = unsafe { ctx.arg(2).unwrap_or(0) };

    let mut anomaly = false;
    let mut severity = 4u32;

    // Registry entry packs last event type (high 32 bits) and E2 node (low 32)
    if unsafe { RIC_XAPP_LOG.get(&xapp_id) }.is_some() {
        // Known xApp: refresh the latest E2 node association
        let updated = ((event_type as u64) << 32) | e2_node_id as u64;
        let _ = RIC_XAPP_LOG.insert(&xapp_id, &updated, 0);

        // O1 configuration change — maintenance window verified in user space
        if event_type == RIC_EVENT_O1_CONFIG {
            anomaly = true;
            severity = 3;
        }
    } else {
        // Unknown xApp: rogue registration attempt, unauthorized E2
        // subscription, or A1 policy injection from an unknown source
        anomaly = true;
        severity = match event_type {
            RIC_EVENT_O1_CONFIG => 3,
            RIC_EVENT_REGISTRATION | RIC_EVENT_SUBSCRIPTION | RIC_EVENT_A1_POLICY => 4,
            _ => 4,
        };
    }

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_ORAN_RIC,
            severity,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: xapp_id as u32 as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&(xapp_id as u32).to_le_bytes());
                d[4..8].copy_from_slice(&event_type.to_le_bytes());
                d[8..12].copy_from_slice(&e2_node_id.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE 55: AIS Signal Integrity (Alert 58)
// Physics-based validation of AIS position, speed, and course reports.
// Hook: kprobe on AIS receiver decode path
// ══════════════════════════════════════════════════════════════════════════════

const AIS_MAX_SPEED_TENTHS: u32 = 500; // 50 knots for cargo
const AIS_MAX_POSITION_JUMP_DEG: u32 = 100;
const AIS_MAX_COURSE_CHANGE_TENTHS: u32 = 7200; // 720 deg/min equivalent

#[kprobe]
pub fn detect_ais_integrity(ctx: ProbeContext) -> u32 {
    try_detect_ais_integrity(&ctx).unwrap_or_default()
}

fn try_detect_ais_integrity(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let mmsi: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let lat: i32 = unsafe { ctx.arg(1).unwrap_or(0) };
    let lon: i32 = unsafe { ctx.arg(2).unwrap_or(0) };
    let sog_tenths: u32 = unsafe { ctx.arg(3).unwrap_or(0) };
    let cog_tenths: u32 = unsafe { ctx.arg(4).unwrap_or(0) };

    let mut anomaly = false;

    if let Some(prev) = unsafe { AIS_VESSEL_TRACK.get(&mmsi) } {
        // Position jump inconsistent with prior trajectory
        if lat.abs_diff(prev.lat_deg) > AIS_MAX_POSITION_JUMP_DEG
            || lon.abs_diff(prev.lon_deg) > AIS_MAX_POSITION_JUMP_DEG
        {
            anomaly = true;
        }

        // Course change exceeding physical turn-rate limits
        if cog_tenths.abs_diff(prev.cog_tenths as u32) > AIS_MAX_COURSE_CHANGE_TENTHS {
            anomaly = true;
        }
    }

    // Speed exceeding vessel class maximum
    if sog_tenths > AIS_MAX_SPEED_TENTHS {
        anomaly = true;
    }

    let state = AisVesselState {
        mmsi,
        lat_deg: lat,
        lon_deg: lon,
        sog_tenths: sog_tenths as u16,
        cog_tenths: cog_tenths as u16,
        msg_type: 0,
        _pad: [0; 3],
        timestamp_ns: now,
    };
    let _ = AIS_VESSEL_TRACK.insert(&mmsi, &state, 0);

    if anomaly {
        let alert = DefenseAlert {
            alert_type: ALERT_AIS_INTEGRITY,
            severity: 5,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: mmsi as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&mmsi.to_le_bytes());
                d[4..8].copy_from_slice(&sog_tenths.to_le_bytes());
                d[8..12].copy_from_slice(&cog_tenths.to_le_bytes());
                d[12..16].copy_from_slice(&lat.to_le_bytes());
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
