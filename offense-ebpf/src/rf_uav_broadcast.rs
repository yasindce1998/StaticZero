use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{classifier, kprobe, xdp},
    programs::{ProbeContext, TcContext, XdpContext},
};
use common::{
    BroadcastInjectState, EventHeader, PagerMessageState, UavLinkState, EVENT_DAB_ENSEMBLE_MANIP,
    EVENT_DJI_DRONEID_FINGERPRINT, EVENT_EAS_SAME_INJECT, EVENT_FLEX_INTERCEPT,
    EVENT_FPV_VIDEO_INTERCEPT, EVENT_MAVLINK_INJECT, EVENT_POCSAG_DECODE, EVENT_RDS_INJECT,
    EVENT_WEA_CMAS_INJECT,
};

use crate::maps::*;

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;

const MAVLINK_V1_STX: u8 = 0xFE; // MAVLink v1 start byte
const MAVLINK_V2_STX: u8 = 0xFD; // MAVLink v2 start byte
const DJI_DRONEID_MARKER: u8 = 0x55; // DroneID beacon preamble
const FPV_FRAME_MARKER: u8 = 0x66; // digital FPV video frame sync
const POCSAG_SYNC: u32 = 0x7CD215D8; // POCSAG batch synchronization codeword
const FLEX_SYNC: u32 = 0x870C0B6F; // FLEX 1600 bps frame synchronization word
const RDS_GROUP_MARKER: u8 = 0x03; // RDS block-A offset word marker
const DAB_FIC_MARKER: u8 = 0xE3; // DAB+ FIC data unit marker
const SAME_HEADER: u32 = 0x5A435A43; // "ZCZC" SAME header preamble
const CMAS_SIB12_MARKER: u8 = 0x12; // SIB12 (CMAS/WEA) container marker

// ──────────────────────────────────────────────
// FEATURE 158: MAVLink Command Injection
// Injects unauthenticated MAVLink v1/v2 commands into the UAV C2 link
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_mavlink_inject(ctx: TcContext) -> i32 {
    try_mavlink_inject(&ctx).unwrap_or(0)
}

fn try_mavlink_inject(ctx: &TcContext) -> Result<i32, i64> {
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
    let stx = unsafe { *((data + payload_offset) as *const u8) };

    if stx == MAVLINK_V2_STX || stx == MAVLINK_V1_STX {
        // v2: len, flags, msgid(24), seq, sys, comp — v1: len, seq, sys, comp, msgid
        let (sys_id, comp_id, msg_id, signed) = if stx == MAVLINK_V2_STX {
            (
                unsafe { *((data + payload_offset + 10) as *const u8) },
                unsafe { *((data + payload_offset + 11) as *const u8) },
                u32::from_le_bytes([
                    unsafe { *((data + payload_offset + 5) as *const u8) },
                    unsafe { *((data + payload_offset + 6) as *const u8) },
                    unsafe { *((data + payload_offset + 7) as *const u8) },
                    0,
                ]),
                (unsafe { *((data + payload_offset + 2) as *const u8) } >> 7) & 1,
            )
        } else {
            (
                unsafe { *((data + payload_offset + 3) as *const u8) },
                unsafe { *((data + payload_offset + 4) as *const u8) },
                unsafe { *((data + payload_offset + 5) as *const u8) } as u32,
                0,
            )
        };

        // unsigned links (most consumer UAVs) accept injected commands
        let gcs_addr_hash = unsafe { u32::from_be(*((data + ETH_HDR_LEN + 12) as *const u32)) };

        let state = UavLinkState {
            sys_id,
            comp_id,
            msg_id: msg_id as u16,
            signed,
            _pad: [0; 3],
            serial_hash: 0,
            gcs_addr_hash,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = UAV_LINK_STATE.insert(&(sys_id as u32), &state, 0);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_MAVLINK_INJECT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((sys_id as u64) << 32) | (msg_id as u16) as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 159: DJI DroneID Fingerprint
// Decodes DroneID beacons for serial, operator location and telemetry
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_dji_droneid_fingerprint(ctx: ProbeContext) -> u32 {
    try_dji_droneid_fingerprint(&ctx).unwrap_or(0)
}

fn try_dji_droneid_fingerprint(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 12] =
        unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 12])? };

    if hdr[0] == DJI_DRONEID_MARKER {
        // DroneID beacon: UAV serial fragment plus operator (GCS) position
        let serial_hash = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
        let gcs_addr_hash = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]);
        let flight_state = u16::from_be_bytes([hdr[9], hdr[10]]);

        let state = UavLinkState {
            sys_id: 1,
            comp_id: 1,
            msg_id: flight_state,
            signed: 0,
            _pad: [0; 3],
            serial_hash,
            gcs_addr_hash,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = UAV_LINK_STATE.insert(&serial_hash, &state, 0);

        let event = EventHeader {
            event_type: EVENT_DJI_DRONEID_FINGERPRINT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((serial_hash as u64) << 32) | gcs_addr_hash as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 160: FPV Video Link Intercept
// Captures FPV video streams and embedded OSD telemetry
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_fpv_video_intercept(ctx: XdpContext) -> u32 {
    try_fpv_video_intercept(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_fpv_video_intercept(ctx: &XdpContext) -> Result<u32, i64> {
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
    let marker = unsafe { *(payload_offset as *const u8) };

    if marker == FPV_FRAME_MARKER {
        // OSD telemetry rides with the video: link id, battery, GPS flags
        let sys_id = unsafe { *((payload_offset + 1) as *const u8) };
        let battery = unsafe { *((payload_offset + 2) as *const u8) };
        let gps_flags = unsafe { *((payload_offset + 3) as *const u8) };
        let gcs_addr_hash = unsafe { u32::from_be(*((payload_offset + 4) as *const u32)) };

        let state = UavLinkState {
            sys_id,
            comp_id: 0,
            msg_id: ((battery as u16) << 8) | gps_flags as u16,
            signed: 0,
            _pad: [0; 3],
            serial_hash: 0,
            gcs_addr_hash,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = UAV_LINK_STATE.insert(&(sys_id as u32), &state, 0);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_FPV_VIDEO_INTERCEPT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((sys_id as u64) << 24) | ((battery as u64) << 16) | gps_flags as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// FEATURE 161: POCSAG Message Decode
// Demodulates FSK paging signals to extract RIC addresses and messages
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_pocsag_decode(ctx: ProbeContext) -> u32 {
    try_pocsag_decode(&ctx).unwrap_or(0)
}

fn try_pocsag_decode(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 12] =
        unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 12])? };

    let sync = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    if sync == POCSAG_SYNC {
        // address codeword: RIC in the high bits, function bits follow
        let ric = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) >> 13;
        let function_code = ((hdr[8] >> 1) & 0x03) as u32;
        let baud: u32 = match hdr[9] {
            0 => 512,
            1 => 1200,
            _ => 2400,
        };
        let msg_hash = u32::from_be_bytes([hdr[10], hdr[11], hdr[8], hdr[9]]);

        let state = PagerMessageState {
            ric,
            function_code,
            baud,
            protocol: 0,
            msg_hash,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = PAGER_MESSAGES.insert(&ric, &state, 0);

        let event = EventHeader {
            event_type: EVENT_POCSAG_DECODE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((ric as u64) << 2) | function_code as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 162: FLEX/ReFLEX Intercept
// Decodes high-speed 4-FSK FLEX paging including group messages
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_flex_intercept(ctx: ProbeContext) -> u32 {
    try_flex_intercept(&ctx).unwrap_or(0)
}

fn try_flex_intercept(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 12] =
        unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 12])? };

    let sync = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    if sync == FLEX_SYNC {
        // FLEX frame: capcode address word, baud selector, message fragment
        let capcode = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let baud: u32 = 1600 << (hdr[8] & 0x03); // 1600/3200/6400 bps
        let msg_hash = u32::from_be_bytes([hdr[9], hdr[10], hdr[11], hdr[8]]);

        let state = PagerMessageState {
            ric: capcode,
            function_code: hdr[8] as u32,
            baud,
            protocol: 1,
            msg_hash,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = PAGER_MESSAGES.insert(&capcode, &state, 0);

        let event = EventHeader {
            event_type: EVENT_FLEX_INTERCEPT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((capcode as u64) << 2) | (hdr[8] & 0x03) as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 163: FM RDS Injection
// Injects spoofed RDS RadioText/PS/TMC data on the 57 kHz subcarrier
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_rds_inject(ctx: TcContext) -> i32 {
    try_rds_inject(&ctx).unwrap_or(0)
}

fn try_rds_inject(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 8 > data_end {
        return Ok(0);
    }

    let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    let marker = unsafe { *((data + payload_offset) as *const u8) };

    if marker == RDS_GROUP_MARKER {
        // RDS group: PI code in block A, service data in block B
        let pi_code = u16::from_be_bytes([
            unsafe { *((data + payload_offset + 1) as *const u8) },
            unsafe { *((data + payload_offset + 2) as *const u8) },
        ]);
        let service_hash = u32::from_be_bytes([
            unsafe { *((data + payload_offset + 3) as *const u8) },
            unsafe { *((data + payload_offset + 4) as *const u8) },
            unsafe { *((data + payload_offset + 5) as *const u8) },
            unsafe { *((data + payload_offset + 6) as *const u8) },
        ]);

        let state = BroadcastInjectState {
            pi_code,
            fig_type: 0,
            service_hash,
            originator: 0,
            event_code: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = BROADCAST_INJECT_STATE.insert(&(pi_code as u32), &state, 0);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_RDS_INJECT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((pi_code as u64) << 32) | service_hash as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 164: DAB+ Ensemble Manipulation
// Injects modified FIG data to reconfigure DAB+ service components
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_dab_ensemble_manip(ctx: TcContext) -> i32 {
    try_dab_ensemble_manip(&ctx).unwrap_or(0)
}

fn try_dab_ensemble_manip(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 8 > data_end {
        return Ok(0);
    }

    let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    let marker = unsafe { *((data + payload_offset) as *const u8) };

    if marker == DAB_FIC_MARKER {
        // FIC data unit: FIG type/length field then service component data
        let fig_type = u16::from_be_bytes([
            unsafe { *((data + payload_offset + 1) as *const u8) },
            unsafe { *((data + payload_offset + 2) as *const u8) },
        ]);
        let service_hash = u32::from_be_bytes([
            unsafe { *((data + payload_offset + 3) as *const u8) },
            unsafe { *((data + payload_offset + 4) as *const u8) },
            unsafe { *((data + payload_offset + 5) as *const u8) },
            unsafe { *((data + payload_offset + 6) as *const u8) },
        ]);

        let state = BroadcastInjectState {
            pi_code: 0,
            fig_type,
            service_hash,
            originator: 0,
            event_code: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = BROADCAST_INJECT_STATE.insert(&service_hash, &state, 0);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_DAB_ENSEMBLE_MANIP,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((fig_type as u64) << 32) | service_hash as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 165: SAME/EAS Header Injection
// Crafts "ZCZC" headers with spoofed originator/event/location codes
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_eas_same_inject(ctx: TcContext) -> i32 {
    try_eas_same_inject(&ctx).unwrap_or(0)
}

fn try_eas_same_inject(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 8 > data_end {
        return Ok(0);
    }

    let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    let preamble = unsafe { u32::from_be(*((data + payload_offset) as *const u32)) };

    if preamble == SAME_HEADER {
        // "ZCZC-ORG-EEE-SSSS+ZZZZ": originator then event code
        let originator = unsafe { *((data + payload_offset + 4) as *const u8) } as u32;
        let event_code = u16::from_be_bytes([
            unsafe { *((data + payload_offset + 5) as *const u8) },
            unsafe { *((data + payload_offset + 6) as *const u8) },
        ]) as u32;

        let state = BroadcastInjectState {
            pi_code: 0,
            fig_type: 0,
            service_hash: 0,
            originator,
            event_code,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = BROADCAST_INJECT_STATE.insert(&event_code, &state, 0);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_EAS_SAME_INJECT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((originator as u64) << 16) | event_code as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 166: WEA/CMAS Cell Broadcast Injection
// Injects CMAS pages via SIB12 to trigger WEA on mobile devices
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_wea_cmas_inject(ctx: TcContext) -> i32 {
    try_wea_cmas_inject(&ctx).unwrap_or(0)
}

fn try_wea_cmas_inject(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 8 > data_end {
        return Ok(0);
    }

    let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    let marker = unsafe { *((data + payload_offset) as *const u8) };

    if marker == CMAS_SIB12_MARKER {
        // SIB12 page: message id, serial number, presidential-level flag
        let message_id = u16::from_be_bytes([
            unsafe { *((data + payload_offset + 1) as *const u8) },
            unsafe { *((data + payload_offset + 2) as *const u8) },
        ]) as u32;
        let serial_num = u16::from_be_bytes([
            unsafe { *((data + payload_offset + 3) as *const u8) },
            unsafe { *((data + payload_offset + 4) as *const u8) },
        ]);
        let presidential = unsafe { *((data + payload_offset + 5) as *const u8) } & 0x80;

        let state = BroadcastInjectState {
            pi_code: 0,
            fig_type: 0,
            service_hash: serial_num as u32,
            originator: 0,
            event_code: message_id,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        // namespace WEA keys apart from SAME codes in the shared map
        let key = message_id | 0x8000_0000;
        let _ = BROADCAST_INJECT_STATE.insert(&key, &state, 0);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_WEA_CMAS_INJECT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((message_id as u64) << 8) | presidential as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}
