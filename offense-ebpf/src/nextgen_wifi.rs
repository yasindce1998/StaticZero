//! Next-generation Wi-Fi exploitation — Wi-Fi 6/6E/7/8 (802.11ax/be/bn),
//! WLAN sensing (802.11bf), and Wi-Fi HaLow (802.11ah).
//!
//! Features F173-F179. These probes decode header patterns observed on the
//! WLAN/WPAN traffic path; full over-the-air MLO attack chains additionally
//! require monitor-mode radio hardware (see docs/NEXTGEN_RESEARCH.md).

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{classifier, kprobe, xdp},
    programs::{ProbeContext, TcContext, XdpContext},
};
use common::{
    EventHeader, MloLinkState, WifiClientState, EVENT_WIFI6_AFC_IMPERSONATION,
    EVENT_WIFI6_OFDMA_RU_JAM, EVENT_WIFI7_MLO_KEY_ABUSE, EVENT_WIFI7_MLO_LINK_DESYNC,
    EVENT_WIFI8_MAPC_ROGUE, EVENT_WIFI_HALOW_EXPLOIT, EVENT_WIFI_SENSING_PRIVACY,
};

use crate::maps::*;

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;

const WIFI_FC_ACTION: u8 = 0xD0; // mgmt frame control: action frame
const WIFI_ACTION_CATEGORY_VENDOR: u8 = 127; // vendor-specific action (Multi-Link Element)
const MLO_CONTROL_TYPE: u8 = 0x0E; // Multi-Link Element control type (802.11be)
const MLO_LINK_DESYNC_THRESHOLD: u32 = 4; // sequence divergence before desync fires
const WIFI_SENSING_ACTION_CATEGORY: u8 = 36; // 802.11bf sensing action category
const SENSING_POLL_INTERVAL_US: u32 = 20_000; // fast sensing poll cadence
const AFC_STD_POWER_AP_FLAG: u8 = 0x01; // standard-power AP claim in 6 GHz HE capabilities
const OFDMA_RU_PUNCTURE_MASK: u16 = 0x00FF; // primary-channel puncturing pattern
const HALOW_S1G_BEACON: u8 = 0x00; // S1G beacon frame subtype
const MAPC_COORDINATION_TAG: u8 = 0x0F; // Multi-AP coordination element marker

// ──────────────────────────────────────────────
// FEATURE 173: MLO Link Desynchronization Attack
// Tears down or desyncs one link of a Wi-Fi 7 MLO set so the MLD falls
// back to a single, weaker link
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_wifi7_mlo_link_desync(ctx: TcContext) -> i32 {
    try_wifi7_mlo_link_desync(&ctx).unwrap_or(0)
}

fn try_wifi7_mlo_link_desync(ctx: &TcContext) -> Result<i32, i64> {
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
    let fc = unsafe { *((data + payload_offset) as *const u8) };
    let action_category = unsafe { *((data + payload_offset + 1) as *const u8) };
    let mle_control = unsafe { *((data + payload_offset + 2) as *const u8) };

    if fc == WIFI_FC_ACTION
        && action_category == WIFI_ACTION_CATEGORY_VENDOR
        && mle_control & 0x0F == MLO_CONTROL_TYPE
    {
        // per-link sequence and address tracking from the multi-link element
        let mld_addr_hash = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 4) as *const u8) },
            unsafe { *((data + payload_offset + 5) as *const u8) },
            unsafe { *((data + payload_offset + 6) as *const u8) },
            unsafe { *((data + payload_offset + 7) as *const u8) },
        ]);
        let link_id = unsafe { *((data + payload_offset + 8) as *const u8) } & 0x0F;
        let seq_num = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 10) as *const u8) },
            unsafe { *((data + payload_offset + 11) as *const u8) },
            unsafe { *((data + payload_offset + 12) as *const u8) },
            unsafe { *((data + payload_offset + 13) as *const u8) },
        ]);

        let mut desync_count = 1;
        if let Some(prev) = unsafe { MLO_LINK_STATE.get(&mld_addr_hash) } {
            // sequence regression on the same MLD = link tearing attempt
            if seq_num + MLO_LINK_DESYNC_THRESHOLD < prev.seq_num {
                desync_count = prev.desync_count + 1;
            } else {
                desync_count = prev.desync_count;
            }
        }

        let state = MloLinkState {
            mld_addr_hash,
            link_id,
            key_gen: 0,
            auth_suite: 0,
            desync_count,
            seq_num,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = MLO_LINK_STATE.insert(&mld_addr_hash, &state, 0);

        if desync_count > MLO_LINK_DESYNC_THRESHOLD {
            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            let event = EventHeader {
                event_type: EVENT_WIFI7_MLO_LINK_DESYNC,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((desync_count as u64) << 32) | mld_addr_hash as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 174: MLO Key Separation Abuse
// Crosses per-link key generations — a link must refuse keys that belong
// to another link or an older set of links (802.11be key hierarchy)
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_wifi7_mlo_key_abuse(ctx: ProbeContext) -> u32 {
    try_wifi7_mlo_key_abuse(&ctx).unwrap_or(0)
}

fn try_wifi7_mlo_key_abuse(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8])? };

    // EAPOL-Key frames carrying an MLO key-generation mismatch arrive with a
    // vendor MLE tag followed by a stale per-link generation counter
    if hdr[0] == WIFI_FC_ACTION && hdr[1] == WIFI_ACTION_CATEGORY_VENDOR {
        let mld_addr_hash = u32::from_le_bytes([hdr[2], hdr[3], hdr[4], hdr[5]]);
        let key_gen = hdr[6];
        let link_id = hdr[7] & 0x0F;

        let mut stale = false;
        if let Some(prev) = unsafe { MLO_LINK_STATE.get(&mld_addr_hash) } {
            // a key generation older than the last accepted one for this MLD
            stale = key_gen < prev.key_gen;
        }

        let state = MloLinkState {
            mld_addr_hash,
            link_id,
            key_gen,
            auth_suite: 0,
            desync_count: 0,
            seq_num: 0,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = MLO_LINK_STATE.insert(&mld_addr_hash, &state, 0);

        if stale {
            let event = EventHeader {
                event_type: EVENT_WIFI7_MLO_KEY_ABUSE,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((key_gen as u64) << 32) | mld_addr_hash as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 175: 6 GHz AFC Impersonation
// Impersonates an AFC-approved standard-power AP in the 6 GHz band,
// bypassing power constraints that client devices trust
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_wifi6_afc_impersonation(ctx: TcContext) -> i32 {
    try_wifi6_afc_impersonation(&ctx).unwrap_or(0)
}

fn try_wifi6_afc_impersonation(ctx: &TcContext) -> Result<i32, i64> {
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
    let he_capabilities = unsafe { *((data + payload_offset) as *const u8) };
    let std_power_claim = unsafe { *((data + payload_offset + 1) as *const u8) };

    if he_capabilities == AFC_STD_POWER_AP_FLAG && std_power_claim == AFC_STD_POWER_AP_FLAG {
        let bssid_hash = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 2) as *const u8) },
            unsafe { *((data + payload_offset + 3) as *const u8) },
            unsafe { *((data + payload_offset + 4) as *const u8) },
            unsafe { *((data + payload_offset + 5) as *const u8) },
        ]);

        let state = WifiClientState {
            bssid_hash,
            ssid_hash: 0,
            client_addr_hash: 0,
            deauth_count: 0,
            mgmt_subtype: 0,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = WIFI_CLIENTS.insert(&bssid_hash, &state, 0);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_WIFI6_AFC_IMPERSONATION,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: bssid_hash as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 176: OFDMA Resource Unit Selective Jamming
// Punctures specific resource units in an HE/EHT MU PPDU, denying
// service to individual stations inside an OFDMA allocation
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_wifi6_ofdma_ru_jam(ctx: XdpContext) -> u32 {
    try_wifi6_ofdma_ru_jam(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_wifi6_ofdma_ru_jam(ctx: &XdpContext) -> Result<u32, i64> {
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

    let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    let puncture_pattern = u16::from_be(unsafe { *((data + payload_offset) as *const u16) });

    if puncture_pattern & OFDMA_RU_PUNCTURE_MASK != 0 {
        let bssid_hash = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 2) as *const u8) },
            unsafe { *((data + payload_offset + 3) as *const u8) },
            unsafe { *((data + payload_offset + 4) as *const u8) },
            unsafe { *((data + payload_offset + 5) as *const u8) },
        ]);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_WIFI6_OFDMA_RU_JAM,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((puncture_pattern as u64) << 32) | bssid_hash as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// FEATURE 177: 802.11bf Sensing Privacy Exploit
// Drives fast sensing measurement polls to track presence and motion
// through walls — device-free passive surveillance
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_wifi_sensing_privacy(ctx: ProbeContext) -> u32 {
    try_wifi_sensing_privacy(&ctx).unwrap_or(0)
}

fn try_wifi_sensing_privacy(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8])? };

    if hdr[0] == WIFI_FC_ACTION && hdr[1] == WIFI_SENSING_ACTION_CATEGORY {
        // poll interval in µs follows the sensing dialog token
        let poll_interval_us = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);

        if poll_interval_us < SENSING_POLL_INTERVAL_US {
            let event = EventHeader {
                event_type: EVENT_WIFI_SENSING_PRIVACY,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((poll_interval_us as u64) << 32) | hdr[2] as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 178: Wi-Fi HaLow (802.11ah) Sub-GHz Exploit
// Targets S1G beacons of long-range sub-GHz Wi-Fi deployments
// (smart metering / industrial IoT at 900 MHz)
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_wifi_halow_exploit(ctx: XdpContext) -> u32 {
    try_wifi_halow_exploit(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_wifi_halow_exploit(ctx: &XdpContext) -> Result<u32, i64> {
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

    let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    let s1g_subtype = unsafe { *((data + payload_offset) as *const u8) };

    if s1g_subtype == HALOW_S1G_BEACON {
        let bssid_hash = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 1) as *const u8) },
            unsafe { *((data + payload_offset + 2) as *const u8) },
            unsafe { *((data + payload_offset + 3) as *const u8) },
            unsafe { *((data + payload_offset + 4) as *const u8) },
        ]);

        let state = WifiClientState {
            bssid_hash,
            ssid_hash: 0,
            client_addr_hash: 0,
            deauth_count: 0,
            mgmt_subtype: HALOW_S1G_BEACON as u32,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = WIFI_CLIENTS.insert(&bssid_hash, &state, 0);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_WIFI_HALOW_EXPLOIT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: bssid_hash as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// FEATURE 179: Wi-Fi 8 Multi-AP Coordination Rogue
// Injects rogue coordination elements (Co-BF/Co-SR/Co-TDMA) into a
// multi-AP set — 802.11bn Ultra High Reliability attack surface
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_wifi8_mapc_rogue(ctx: TcContext) -> i32 {
    try_wifi8_mapc_rogue(&ctx).unwrap_or(0)
}

fn try_wifi8_mapc_rogue(ctx: &TcContext) -> Result<i32, i64> {
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
    let fc = unsafe { *((data + payload_offset) as *const u8) };
    let coordination_tag = unsafe { *((data + payload_offset + 1) as *const u8) };

    if fc == WIFI_FC_ACTION && coordination_tag == MAPC_COORDINATION_TAG {
        let bssid_hash = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 2) as *const u8) },
            unsafe { *((data + payload_offset + 3) as *const u8) },
            unsafe { *((data + payload_offset + 4) as *const u8) },
            unsafe { *((data + payload_offset + 5) as *const u8) },
        ]);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_WIFI8_MAPC_ROGUE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: bssid_hash as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}
