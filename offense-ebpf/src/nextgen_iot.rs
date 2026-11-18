//! Next-generation IoT and critical-infrastructure protocols — Matter
//! smart home, 3GPP Release 19 Ambient IoT, DECT-2020 NR, FRMCS railway,
//! and LDACS aeronautical datalinks.
//!
//! Features F189-F194.

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{classifier, kprobe, xdp},
    programs::{ProbeContext, TcContext, XdpContext},
};
use common::{
    AmbientIotState, EventHeader, MatterSessionState, EVENT_AMBIENT_IOT_CLONE,
    EVENT_DECT2020_INJECT, EVENT_FRMCS_INJECT, EVENT_LDACS_INJECT, EVENT_MATTER_ACL_MANIP,
    EVENT_MATTER_PASSCODE_ATTACK,
};

use crate::maps::*;

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;

const MATTER_ONTCP_PASSCODE_MARKER: u32 = 0x35; // PASE session establishment opcode
const MATTER_PASSCODE_ATTEMPT_LIMIT: u32 = 5; // commissioning window guess budget
const MATTER_ACL_WRITE_MARKER: u8 = 0x0B; // ACL cluster write attribute opcode
const AMBIENT_IOT_BACKSCATTER_CLASS: u8 = 0; // Rel-19 device class A (backscatter)
const AMBIENT_IOT_CLONE_RSSI_DELTA: i16 = 20; // dB delta indicating a second transmitter
const DECT2020_NWK_ID_MARKER: u32 = 0x2020_DE07; // DECT-2020 NR network ID magic
const FRMCS_SCTP_PORT: u16 = 38422; // FRMCS rail signaling SCTP port (5G-based)
const LDACS_FRAMING_MARKER: u8 = 0x5A; // LDACS L-band datalink framing marker

// ──────────────────────────────────────────────
// FEATURE 189: Matter Onboarding Passcode Attack
// Brute-forces the low-entropy SPAKE2+ setup passcode during Matter
// commissioning (weak PBKDF2 parameters and static salts widen the window)
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_matter_passcode_attack(ctx: ProbeContext) -> u32 {
    try_matter_passcode_attack(&ctx).unwrap_or(0)
}

fn try_matter_passcode_attack(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 16] =
        unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 16])? };

    let opcode = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    if opcode == MATTER_ONTCP_PASSCODE_MARKER {
        let node_id_hash = u64::from_le_bytes([
            hdr[4], hdr[5], hdr[6], hdr[7], hdr[8], hdr[9], hdr[10], hdr[11],
        ]);

        let mut attempts = 1;
        if let Some(prev) = unsafe { MATTER_SESSION_STATE.get(&node_id_hash) } {
            attempts = prev.passcode_attempts + 1;
        }

        let state = MatterSessionState {
            node_id_hash,
            passcode_attempts: attempts,
            acl_version: 0,
            commissioning_state: 1, // PASE in progress
            _pad: [0; 3],
            _pad2: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = MATTER_SESSION_STATE.insert(&node_id_hash, &state, 0);

        if attempts > MATTER_PASSCODE_ATTEMPT_LIMIT {
            let event = EventHeader {
                event_type: EVENT_MATTER_PASSCODE_ATTACK,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((attempts as u64) << 32) | (node_id_hash & 0xFFFF_FFFF),
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 190: Matter ACL Manipulation
// Exploits non-atomic ACL updates (CVE-2024-56317 class) to grant
// persistent controller access from temporary privileges
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_matter_acl_manip(ctx: TcContext) -> i32 {
    try_matter_acl_manip(&ctx).unwrap_or(0)
}

fn try_matter_acl_manip(ctx: &TcContext) -> Result<i32, i64> {
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
    let acl_opcode = unsafe { *((data + payload_offset) as *const u8) };

    if acl_opcode == MATTER_ACL_WRITE_MARKER {
        let node_id_hash = u64::from_le_bytes([
            unsafe { *((data + payload_offset + 1) as *const u8) },
            unsafe { *((data + payload_offset + 2) as *const u8) },
            unsafe { *((data + payload_offset + 3) as *const u8) },
            unsafe { *((data + payload_offset + 4) as *const u8) },
            unsafe { *((data + payload_offset + 5) as *const u8) },
            unsafe { *((data + payload_offset + 6) as *const u8) },
            unsafe { *((data + payload_offset + 7) as *const u8) },
            unsafe { *((data + payload_offset + 8) as *const u8) },
        ]);
        let acl_version = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 9) as *const u8) },
            unsafe { *((data + payload_offset + 10) as *const u8) },
            unsafe { *((data + payload_offset + 11) as *const u8) },
            unsafe { *((data + payload_offset + 12) as *const u8) },
        ]);

        let mut version_regression = false;
        if let Some(prev) = unsafe { MATTER_SESSION_STATE.get(&node_id_hash) } {
            // an ACL write that does not advance the version = non-atomic update
            version_regression = acl_version <= prev.acl_version;
        }

        let state = MatterSessionState {
            node_id_hash,
            passcode_attempts: 0,
            acl_version,
            commissioning_state: 2, // operational
            _pad: [0; 3],
            _pad2: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = MATTER_SESSION_STATE.insert(&node_id_hash, &state, 0);

        if version_regression {
            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            let event = EventHeader {
                event_type: EVENT_MATTER_ACL_MANIP,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((acl_version as u64) << 32) | (node_id_hash & 0xFFFF_FFFF),
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 191: Ambient IoT Device Cloning
// Clones 3GPP Release 19 batteryless Ambient IoT device identities
// (class-A backscatter, ~1µW, envelope-detector receivers) to inject
// forged sensor reports
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_ambient_iot_clone(ctx: TcContext) -> i32 {
    try_ambient_iot_clone(&ctx).unwrap_or(0)
}

fn try_ambient_iot_clone(ctx: &TcContext) -> Result<i32, i64> {
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
    let device_class = unsafe { *((data + payload_offset) as *const u8) };

    if device_class == AMBIENT_IOT_BACKSCATTER_CLASS {
        let device_id_hash = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 1) as *const u8) },
            unsafe { *((data + payload_offset + 2) as *const u8) },
            unsafe { *((data + payload_offset + 3) as *const u8) },
            unsafe { *((data + payload_offset + 4) as *const u8) },
        ]);
        let signal_dbm = i16::from_le_bytes([
            unsafe { *((data + payload_offset + 5) as *const u8) },
            unsafe { *((data + payload_offset + 6) as *const u8) },
        ]);

        let mut clone = false;
        if let Some(prev) = unsafe { AMBIENT_IOT_STATE.get(&device_id_hash) } {
            // same batteryless ID transmitting at a very different power —
            // a second (active) transmitter is impersonating the device
            clone = (prev.signal_dbm - signal_dbm).abs() > AMBIENT_IOT_CLONE_RSSI_DELTA;
        }

        let report_count = 1 + unsafe { AMBIENT_IOT_STATE.get(&device_id_hash) }
            .map(|prev| prev.report_count)
            .unwrap_or(0);

        let state = AmbientIotState {
            device_id_hash,
            device_class,
            _pad: [0; 3],
            report_count,
            signal_dbm,
            _pad2: 0,
            _pad3: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = AMBIENT_IOT_STATE.insert(&device_id_hash, &state, 0);

        if clone {
            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            let event = EventHeader {
                event_type: EVENT_AMBIENT_IOT_CLONE,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((signal_dbm as u16 as u64) << 32) | device_id_hash as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 192: DECT-2020 NR Mesh Injection
// Injects into ETSI DECT-2020 NR massive-mesh networks (ITU-R IMT-2020
// technology, 1.9 GHz) before its new security framework fully lands
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_dect2020_inject(ctx: XdpContext) -> u32 {
    try_dect2020_inject(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_dect2020_inject(ctx: &XdpContext) -> Result<u32, i64> {
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
    let nwk_id = u32::from_be(unsafe { *((data + payload_offset) as *const u32) });

    if nwk_id == DECT2020_NWK_ID_MARKER {
        let cluster_size = u16::from_be(unsafe { *((data + payload_offset + 4) as *const u16) });
        let relay_hash = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 6) as *const u8) },
            unsafe { *((data + payload_offset + 7) as *const u8) },
            unsafe { *((data + payload_offset + 8) as *const u8) },
            unsafe { *((data + payload_offset + 9) as *const u8) },
        ]);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_DECT2020_INJECT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((cluster_size as u64) << 32) | relay_hash as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// FEATURE 193: FRMCS Railway Signaling Injection
// Injects into Future Railway Mobile Communication System — the 5G-based
// GSM-R successor carrying train control and signaling
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_frmcs_inject(ctx: TcContext) -> i32 {
    try_frmcs_inject(&ctx).unwrap_or(0)
}

fn try_frmcs_inject(ctx: &TcContext) -> Result<i32, i64> {
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

    let dst_port = u16::from_be(unsafe { *((data + ETH_HDR_LEN + IP_HDR_LEN + 4) as *const u16) });
    if dst_port == FRMCS_SCTP_PORT {
        let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
        let train_id_hash = u32::from_le_bytes([
            unsafe { *((data + payload_offset) as *const u8) },
            unsafe { *((data + payload_offset + 1) as *const u8) },
            unsafe { *((data + payload_offset + 2) as *const u8) },
            unsafe { *((data + payload_offset + 3) as *const u8) },
        ]);
        let procedure_code = unsafe { *((data + payload_offset + 4) as *const u8) };

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_FRMCS_INJECT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((procedure_code as u64) << 32) | train_id_hash as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 194: LDACS Aviation Datalink Injection
// Injects into the L-band Digital Aeronautical Communications System —
// the planned ATC/OPS successor to VHF datalink mode 2
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_ldacs_inject(ctx: TcContext) -> i32 {
    try_ldacs_inject(&ctx).unwrap_or(0)
}

fn try_ldacs_inject(ctx: &TcContext) -> Result<i32, i64> {
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
    let framing = unsafe { *((data + payload_offset) as *const u8) };

    if framing == LDACS_FRAMING_MARKER {
        let aircraft_addr = u32::from_be(unsafe { *((data + payload_offset + 1) as *const u32) });
        let procedure_code = unsafe { *((data + payload_offset + 5) as *const u8) };

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_LDACS_INJECT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((procedure_code as u64) << 32) | aircraft_addr as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}
