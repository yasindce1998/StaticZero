//! Satellite Direct-to-Cell (D2C), NTN Release 19 regenerative payloads,
//! and LEO PNT / GNSS authentication attacks.
//!
//! Features F180-F184. Starlink Direct-to-Cell, AST SpaceMobile, and Skylo
//! NB-NTN put LTE/NR base stations in orbit; these probes target the
//! device-side indicators and feeder-link signaling they depend on.

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{classifier, kprobe, xdp},
    programs::{ProbeContext, TcContext, XdpContext},
};
use common::{
    D2cCellState, EventHeader, LeoPntState, EVENT_D2C_CELL_SPOOF, EVENT_GNSS_AUTH_BYPASS,
    EVENT_LEO_PNT_SPOOF, EVENT_NBNTN_SAF_ABUSE, EVENT_NTN_REGEN_INJECT,
};

use crate::maps::*;

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;

const D2C_SAT_INDICATOR: u8 = 0x01; // SIB19 NTN/satellite-neighbor indicator
const D2C_TA_THRESHOLD: u32 = 1282; // NTN timing advance far exceeds terrestrial
const NGAP_PORT: u16 = 38412; // SCTP port for NGAP between gNB and AMF
const NTN_REGEN_PAYLOAD_FLAG: u8 = 0x01; // gNB-on-board (Rel-19 regenerative)
const LEO_PNT_CN0_MAX: u32 = 55; // nominal LEO signal C/N0 ceiling (dB-Hz)
const LEO_PNT_DOPPLER_MAX: i32 = 48_000; // LEO doppler swing exceeds GNSS by 10x
const OSNMA_HEADER_TAG: u8 = 0x0A; // Galileo I/NAV OSNMA header marker
const OSNMA_AUTH_FAILED: u8 = 0x02; // tesla chain verification failure marker
const NBNTN_STORE_FORWARD_FLAG: u8 = 0x01; // store-and-forward queueing marker

// ──────────────────────────────────────────────
// FEATURE 180: Direct-to-Cell Spoofed Satellite Cell
// Impersonates a satellite D2C cell (T-Mobile/Starlink SCS, AST SpaceMobile,
// Skylo) to harvest registrations from satellite-capable handsets
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_d2c_cell_spoof(ctx: TcContext) -> i32 {
    try_d2c_cell_spoof(&ctx).unwrap_or(0)
}

fn try_d2c_cell_spoof(ctx: &TcContext) -> Result<i32, i64> {
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
    let sat_indicator = unsafe { *((data + payload_offset) as *const u8) };

    if sat_indicator == D2C_SAT_INDICATOR {
        let plmn = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 1) as *const u8) },
            unsafe { *((data + payload_offset + 2) as *const u8) },
            unsafe { *((data + payload_offset + 3) as *const u8) },
            unsafe { *((data + payload_offset + 4) as *const u8) },
        ]);
        let cell_global_id = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 5) as *const u8) },
            unsafe { *((data + payload_offset + 6) as *const u8) },
            unsafe { *((data + payload_offset + 7) as *const u8) },
            unsafe { *((data + payload_offset + 8) as *const u8) },
        ]);
        let timing_advance = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 9) as *const u8) },
            unsafe { *((data + payload_offset + 10) as *const u8) },
            unsafe { *((data + payload_offset + 11) as *const u8) },
            unsafe { *((data + payload_offset + 12) as *const u8) },
        ]);

        // A "satellite" cell advertising a terrestrial-range timing advance
        // is the D2C equivalent of an IMSI catcher — physically impossible.
        if timing_advance < D2C_TA_THRESHOLD {
            let state = D2cCellState {
                plmn,
                cell_global_id,
                tac: 0,
                sat_indicator,
                regen_payload: 0,
                _pad: [0; 2],
                timing_advance,
                _pad2: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
            };
            let _ = D2C_CELL_STATE.insert(&cell_global_id, &state, 0);

            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            let event = EventHeader {
                event_type: EVENT_D2C_CELL_SPOOF,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((timing_advance as u64) << 32) | cell_global_id as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 181: NTN Regenerative gNB Injection
// Injects NGAP signaling through a Release 19 regenerative feeder link
// where the gNB rides on the satellite itself
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_ntn_regen_inject(ctx: TcContext) -> i32 {
    try_ntn_regen_inject(&ctx).unwrap_or(0)
}

fn try_ntn_regen_inject(ctx: &TcContext) -> Result<i32, i64> {
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

    // verify the SCTP destination port carries NGAP (AMF↔gNB feeder link)
    let dst_port = u16::from_be(unsafe { *((data + ETH_HDR_LEN + IP_HDR_LEN + 4) as *const u16) });
    if dst_port == NGAP_PORT {
        let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
        let regen_flag = unsafe { *((data + payload_offset) as *const u8) };

        if regen_flag == NTN_REGEN_PAYLOAD_FLAG {
            let amf_ue_id = u64::from_le_bytes([
                unsafe { *((data + payload_offset + 2) as *const u8) },
                unsafe { *((data + payload_offset + 3) as *const u8) },
                unsafe { *((data + payload_offset + 4) as *const u8) },
                unsafe { *((data + payload_offset + 5) as *const u8) },
                unsafe { *((data + payload_offset + 6) as *const u8) },
                unsafe { *((data + payload_offset + 7) as *const u8) },
                unsafe { *((data + payload_offset + 8) as *const u8) },
                unsafe { *((data + payload_offset + 9) as *const u8) },
            ]);

            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            let event = EventHeader {
                event_type: EVENT_NTN_REGEN_INJECT,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: amf_ue_id,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 182: LEO PNT Signal Spoofing
// Forges Xona Pulsar-class LEO positioning signals — narrow beams, no
// authentication, high doppler slopes that receivers trust
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_leo_pnt_spoof(ctx: XdpContext) -> u32 {
    try_leo_pnt_spoof(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_leo_pnt_spoof(ctx: &XdpContext) -> Result<u32, i64> {
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
    let sat_id = u16::from_be(unsafe { *((data + payload_offset) as *const u16) });
    let beam_id = u16::from_be(unsafe { *((data + payload_offset + 2) as *const u16) });
    let cn0_dbhz = u32::from_be(unsafe { *((data + payload_offset + 4) as *const u32) });
    let doppler_hz = i32::from_be(unsafe { *((data + payload_offset + 8) as *const i32) });

    // physically implausible C/N0 or doppler for a genuine LEO PNT beam
    let implausible = cn0_dbhz > LEO_PNT_CN0_MAX || doppler_hz.abs() > LEO_PNT_DOPPLER_MAX;

    let state = LeoPntState {
        sat_id,
        beam_id,
        cn0_dbhz,
        doppler_hz,
        auth_status: 0,
        _pad: [0; 3],
        _pad2: 0,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    };
    let _ = LEO_PNT_STATE.insert(&(sat_id as u32), &state, 0);

    if implausible {
        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_LEO_PNT_SPOOF,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((sat_id as u64) << 32) | cn0_dbhz as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// FEATURE 183: Galileo OSNMA Authentication Bypass Probe
// Probes receivers that skip OSNMA navigation-message authentication
// (operational since 2025) by injecting forged Galileo I/NAV words
// with absent or inconsistent OSNMA tesla chains
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_gnss_auth_bypass(ctx: ProbeContext) -> u32 {
    try_gnss_auth_bypass(&ctx).unwrap_or(0)
}

fn try_gnss_auth_bypass(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8])? };

    if hdr[0] == OSNMA_HEADER_TAG {
        let sat_id = u16::from_le_bytes([hdr[1], hdr[2]]);
        let auth_status = hdr[3];

        let state = LeoPntState {
            sat_id,
            beam_id: 0,
            cn0_dbhz: 0,
            doppler_hz: 0,
            auth_status,
            _pad: [0; 3],
            _pad2: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = LEO_PNT_STATE.insert(&(sat_id as u32), &state, 0);

        if auth_status == OSNMA_AUTH_FAILED {
            let event = EventHeader {
                event_type: EVENT_GNSS_AUTH_BYPASS,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((sat_id as u64) << 32) | auth_status as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 184: NB-NTN Store-and-Forward Abuse
// Abuses Release 19 store-and-forward satellite IoT queueing to replay
// or delay-inject NB-IoT uplink reports (Skylo-class service)
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_nbntn_saf_abuse(ctx: TcContext) -> i32 {
    try_nbntn_saf_abuse(&ctx).unwrap_or(0)
}

fn try_nbntn_saf_abuse(ctx: &TcContext) -> Result<i32, i64> {
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
    let store_forward_flag = unsafe { *((data + payload_offset) as *const u8) };

    if store_forward_flag == NBNTN_STORE_FORWARD_FLAG {
        let device_id_hash = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 1) as *const u8) },
            unsafe { *((data + payload_offset + 2) as *const u8) },
            unsafe { *((data + payload_offset + 3) as *const u8) },
            unsafe { *((data + payload_offset + 4) as *const u8) },
        ]);
        let queue_delay_ms = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 5) as *const u8) },
            unsafe { *((data + payload_offset + 6) as *const u8) },
            unsafe { *((data + payload_offset + 7) as *const u8) },
            unsafe { *((data + payload_offset + 8) as *const u8) },
        ]);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_NBNTN_SAF_ABUSE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((queue_delay_ms as u64) << 32) | device_id_hash as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}
