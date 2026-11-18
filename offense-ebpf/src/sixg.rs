//! 6G horizon capabilities (3GPP Release 20+ studies) — AI-native air
//! interface, reconfigurable intelligent surfaces (RIS), THz beams,
//! post-quantum cryptography, network-of-networks integration, and
//! integrated sensing and communication (ISAC).
//!
//! Features F195-F200. 6G standardization is in progress (TR 22.870 use
//! cases); these probes catalog the attack surfaces the studies expose.

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{classifier, kprobe, xdp},
    programs::{ProbeContext, TcContext, XdpContext},
};
use common::{
    AiRanModelState, EventHeader, PqcHandshakeState, EVENT_6G_AI_PERTURB, EVENT_6G_ISAC_ABUSE,
    EVENT_6G_NON_CRED_ABUSE, EVENT_6G_PQC_DOWNGRADE, EVENT_6G_RIS_MANIP, EVENT_6G_THZ_BLOCKAGE,
};

use crate::maps::*;

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;

const AI_RAN_INFERENCE_MARKER: u32 = 0x494E4652; // "INFR" — AI/ML inference request magic
const AI_RAN_PERTURBATION_NORM: u32 = 0x40; // adversarial perturbation L-inf budget
const RIS_CONTROL_MAGIC: u32 = 0x52495300; // "RIS\0" — reflection control API marker
const RIS_PHASE_SHIFT_DELTA: i32 = 90; // degrees of unwanted phase steering
const THZ_BEAM_CODEBOOK_MARKER: u8 = 0x66; // THz beam codebook update opcode
const THZ_BLOCKAGE_SEQ_THRESHOLD: u32 = 4; // consecutive blocked beams before alert
const PQC_SUITE_KYBER: u32 = 1; // ML-KEM (Kyber) class suite id
const PQC_FALLBACK_MARKER: u8 = 0x01; // classic-crypto fallback indication
const NON_CRED_MARKER: u32 = 0x4E4F4E00; // "NON\0" — network-of-networks credential API
const ISAC_SENSING_REQUEST: u8 = 0x3C; // cellular ISAC sensing request opcode

// ──────────────────────────────────────────────
// FEATURE 195: AI-Native Air Interface Adversarial Perturbation
// Crafts adversarial perturbations against learned receivers of the
// 6G AI/ML air interface — model inversion and inference confusion
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_6g_ai_perturb(ctx: XdpContext) -> u32 {
    try_6g_ai_perturb(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_6g_ai_perturb(ctx: &XdpContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 16 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    let marker = u32::from_be(unsafe { *((data + payload_offset) as *const u32) });

    if marker == AI_RAN_INFERENCE_MARKER {
        let model_id_hash = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 4) as *const u8) },
            unsafe { *((data + payload_offset + 5) as *const u8) },
            unsafe { *((data + payload_offset + 6) as *const u8) },
            unsafe { *((data + payload_offset + 7) as *const u8) },
        ]);
        let perturbation_norm =
            u32::from_be(unsafe { *((data + payload_offset + 8) as *const u32) });

        let state = AiRanModelState {
            model_id_hash,
            version: 0,
            integrity_hash: perturbation_norm as u64,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = AI_RAN_MODEL_STATE.insert(&model_id_hash, &state, 0);

        if perturbation_norm > AI_RAN_PERTURBATION_NORM {
            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            let event = EventHeader {
                event_type: EVENT_6G_AI_PERTURB,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((perturbation_norm as u64) << 32) | model_id_hash as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// FEATURE 196: RIS Reflection Manipulation
// Hijacks reconfigurable intelligent surface phase-shift control to steer
// reflections away from legitimate receivers — a physical-layer MitM
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_6g_ris_manip(ctx: ProbeContext) -> u32 {
    try_6g_ris_manip(&ctx).unwrap_or(0)
}

fn try_6g_ris_manip(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 12] =
        unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 12])? };

    let marker = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    if marker & 0xFFFF_FF00 == RIS_CONTROL_MAGIC {
        let element_id = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let phase_shift_deg = i32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);

        let manip = phase_shift_deg.abs() > RIS_PHASE_SHIFT_DELTA;

        if manip {
            let state = AiRanModelState {
                model_id_hash: element_id, // RIS element tracked in the model table
                version: phase_shift_deg as u32,
                integrity_hash: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
            };
            let _ = AI_RAN_MODEL_STATE.insert(&element_id, &state, 0);

            let event = EventHeader {
                event_type: EVENT_6G_RIS_MANIP,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((phase_shift_deg as u32 as u64) << 32) | element_id as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 197: THz Beam Blockage Attack
// Selectively blocks THz narrow beams via codebook manipulation to force
// beam-training exhaustion and denial of ultra-massive connectivity
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_6g_thz_blockage(ctx: XdpContext) -> u32 {
    try_6g_thz_blockage(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_6g_thz_blockage(ctx: &XdpContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 12 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    let codebook_opcode = unsafe { *((data + payload_offset) as *const u8) };

    if codebook_opcode == THZ_BEAM_CODEBOOK_MARKER {
        let beam_id = u16::from_be(unsafe { *((data + payload_offset + 1) as *const u16) });
        let blocked_seq = u32::from_be(unsafe { *((data + payload_offset + 3) as *const u32) });

        if blocked_seq > THZ_BLOCKAGE_SEQ_THRESHOLD {
            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            let event = EventHeader {
                event_type: EVENT_6G_THZ_BLOCKAGE,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((blocked_seq as u64) << 32) | beam_id as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// FEATURE 198: PQC Handshake Downgrade
// Forces quantum-safe handshakes (ML-KEM/Dilithium class) back to classic
// crypto — harvest-now-decrypt-later enabler against long-lived telecom keys
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_6g_pqc_downgrade(ctx: ProbeContext) -> u32 {
    try_6g_pqc_downgrade(&ctx).unwrap_or(0)
}

fn try_6g_pqc_downgrade(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 12] =
        unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 12])? };

    let suite_id = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    if suite_id == PQC_SUITE_KYBER {
        let peer_hash = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let fallback = hdr[8];

        if fallback == PQC_FALLBACK_MARKER {
            let state = PqcHandshakeState {
                suite_id,
                peer_hash,
                classic_fallback: 1,
                _pad: [0; 3],
                _pad2: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
            };
            let _ = PQC_HANDSHAKE_STATE.insert(&peer_hash, &state, 0);

            let event = EventHeader {
                event_type: EVENT_6G_PQC_DOWNGRADE,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((suite_id as u64) << 32) | peer_hash as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 199: Network-of-Networks Credential Abuse
// Crosses credentials between 6G integrated non-3GPP networks (satellite,
// WLAN, private 5G) — the expanded trust fabric of Release 20
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_6g_non_cred_abuse(ctx: TcContext) -> i32 {
    try_6g_non_cred_abuse(&ctx).unwrap_or(0)
}

fn try_6g_non_cred_abuse(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 16 > data_end {
        return Ok(0);
    }

    let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    let marker = u32::from_be(unsafe { *((data + payload_offset) as *const u32) });

    if marker & 0xFFFF_FF00 == NON_CRED_MARKER {
        let credential_hash = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 4) as *const u8) },
            unsafe { *((data + payload_offset + 5) as *const u8) },
            unsafe { *((data + payload_offset + 6) as *const u8) },
            unsafe { *((data + payload_offset + 7) as *const u8) },
        ]);
        let source_network = u32::from_be(unsafe { *((data + payload_offset + 8) as *const u32) });

        let state = PqcHandshakeState {
            suite_id: source_network, // credential network tracked in the PQC table
            peer_hash: credential_hash,
            classic_fallback: 0,
            _pad: [0; 3],
            _pad2: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = PQC_HANDSHAKE_STATE.insert(&credential_hash, &state, 0);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_6G_NON_CRED_ABUSE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((source_network as u64) << 32) | credential_hash as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 200: ISAC Sensing Abuse
// Abuses integrated sensing and communication to track subscribers —
// 6G cellular radar as a mass surveillance side channel
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_6g_isac_abuse(ctx: TcContext) -> i32 {
    try_6g_isac_abuse(&ctx).unwrap_or(0)
}

fn try_6g_isac_abuse(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 12 > data_end {
        return Ok(0);
    }

    let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    let sensing_opcode = unsafe { *((data + payload_offset) as *const u8) };

    if sensing_opcode == ISAC_SENSING_REQUEST {
        let target_id_hash = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 1) as *const u8) },
            unsafe { *((data + payload_offset + 2) as *const u8) },
            unsafe { *((data + payload_offset + 3) as *const u8) },
            unsafe { *((data + payload_offset + 4) as *const u8) },
        ]);
        let sensing_interval_ms =
            u32::from_be(unsafe { *((data + payload_offset + 5) as *const u32) });

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_6G_ISAC_ABUSE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((sensing_interval_ms as u64) << 32) | target_id_hash as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}
