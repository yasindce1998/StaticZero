#![no_std]

// ══════════════════════════════════════════════════════════════════════════════
// Core Infrastructure Types (self-contained, no external dependency)
// ══════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RootkitConfig {
    pub self_pid: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EventHeader {
    pub event_type: u32,
    pub pid: u32,
    pub timestamp_ns: u64,
    pub context: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DefenseAlert {
    pub alert_type: u32,
    pub severity: u32,
    pub pid: u32,
    pub _pad: u32,
    pub timestamp_ns: u64,
    pub context: u64,
    pub details: [u8; 16],
}

// ══════════════════════════════════════════════════════════════════════════════
// Telecom Event Constants — Offense (Features 89-100)
// ══════════════════════════════════════════════════════════════════════════════

pub const EVENT_AT_CMD_INJECT: u32 = 150;
pub const EVENT_BASEBAND_EXPLOIT: u32 = 151;
pub const EVENT_SIM_CLONE: u32 = 152;
pub const EVENT_IMSI_INTERCEPT: u32 = 153;
pub const EVENT_PROTOCOL_DOWNGRADE: u32 = 154;
pub const EVENT_GTP_TUNNEL_HIJACK: u32 = 155;
pub const EVENT_SS7_MAP_INJECT: u32 = 156;
pub const EVENT_DIAMETER_EXPLOIT: u32 = 157;
pub const EVENT_RRC_REDIRECT: u32 = 158;
pub const EVENT_NAS_INTERCEPT: u32 = 159;
pub const EVENT_SUPI_DECONCEAL: u32 = 160;
pub const EVENT_N2_INTERFACE_INJECT: u32 = 161;

// ══════════════════════════════════════════════════════════════════════════════
// Telecom Event Constants — Offense Advanced (Features 101-108)
// ══════════════════════════════════════════════════════════════════════════════

pub const EVENT_VOLTE_INTERCEPT: u32 = 162;
pub const EVENT_SIP_HIJACK: u32 = 163;
pub const EVENT_RTP_CAPTURE: u32 = 164;
pub const EVENT_ESIM_PROFILE_INJECT: u32 = 165;
pub const EVENT_SMDP_EXPLOIT: u32 = 166;
pub const EVENT_SLICE_ISOLATION_BYPASS: u32 = 167;
pub const EVENT_NSSF_MANIPULATE: u32 = 168;
pub const EVENT_VOWIFI_DOWNGRADE: u32 = 169;
pub const EVENT_EPDG_EXPLOIT: u32 = 170;
pub const EVENT_LI_X1_INJECT: u32 = 171;
pub const EVENT_LI_X2_INTERCEPT: u32 = 172;
pub const EVENT_FEMTOCELL_PIVOT: u32 = 173;
pub const EVENT_HENB_GW_EXPLOIT: u32 = 174;
pub const EVENT_SUPL_SPOOF: u32 = 175;
pub const EVENT_LPP_MANIPULATE: u32 = 176;
pub const EVENT_ROAMING_IPX_PIVOT: u32 = 177;
pub const EVENT_GRX_LATERAL: u32 = 178;

// ══════════════════════════════════════════════════════════════════════════════
// Telecom Defense Alert Constants
// ══════════════════════════════════════════════════════════════════════════════

pub const ALERT_ROGUE_TOWER: u32 = 19;
pub const ALERT_DOWNGRADE_ATTACK: u32 = 20;
pub const ALERT_IMSI_CATCHER: u32 = 21;
pub const ALERT_CELL_ANOMALY: u32 = 22;
pub const ALERT_GTP_ANOMALY: u32 = 23;
pub const ALERT_SS7_ANOMALY: u32 = 24;
pub const ALERT_MODEM_TAMPER: u32 = 25;
pub const ALERT_NAS_REPLAY: u32 = 26;
pub const ALERT_VOLTE_FRAUD: u32 = 27;
pub const ALERT_ESIM_TAMPER: u32 = 28;
pub const ALERT_SLICE_VIOLATION: u32 = 29;
pub const ALERT_ROAMING_ANOMALY: u32 = 30;
pub const ALERT_RF_FINGERPRINT: u32 = 31;

// ══════════════════════════════════════════════════════════════════════════════
// Telecom Structs (eBPF map values)
// ══════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CellInfo {
    pub mcc: u16,
    pub mnc: u16,
    pub lac: u16,
    pub cell_id: u32,
    pub arfcn: u16,
    pub signal_dbm: i16,
    pub timing_advance: u16,
    pub rat_type: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AtCommandCtx {
    pub fd: i32,
    pub cmd_type: u32,
    pub cmd_len: u32,
    pub _pad: u32,
    pub cmd_buf: [u8; 64],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GtpTunnelState {
    pub teid_in: u32,
    pub teid_out: u32,
    pub peer_ip: u32,
    pub local_ip: u32,
    pub qfi: u8,
    pub state: u8,
    pub _pad: [u8; 2],
    pub byte_count: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SignalingState {
    pub protocol: u32,
    pub msg_type: u32,
    pub seq_num: u32,
    pub _pad: u32,
    pub imsi_hash: u64,
    pub timestamp_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CellBaseline {
    pub cell_id: u32,
    pub expected_mcc: u16,
    pub expected_mnc: u16,
    pub expected_lac_tac: u32,
    pub min_signal_dbm: i16,
    pub max_signal_dbm: i16,
    pub expected_arfcn: u32,
    pub max_timing_advance: u16,
    pub _pad: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ImsSipSession {
    pub call_id_hash: u64,
    pub from_uri_hash: u64,
    pub to_uri_hash: u64,
    pub state: u32,
    pub codec: u32,
    pub srtp_key_len: u32,
    pub _pad: u32,
    pub srtp_master_key: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RtpStreamState {
    pub ssrc: u32,
    pub seq_num: u16,
    pub payload_type: u8,
    pub _pad: u8,
    pub packet_count: u64,
    pub byte_count: u64,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EsimProvisionCtx {
    pub eid: [u8; 32],
    pub iccid: [u8; 20],
    pub smdp_addr_hash: u64,
    pub state: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NetworkSliceInfo {
    pub snssai_sst: u8,
    pub snssai_sd: [u8; 3],
    pub nsi_id_hash: u32,
    pub max_ues: u32,
    pub current_ues: u32,
    pub isolation_level: u32,
    pub _pad: u32,
    pub allowed_nssai_hash: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VoWiFiTunnelState {
    pub ike_spi_i: u64,
    pub ike_spi_r: u64,
    pub epdg_ip: u32,
    pub ue_ip: u32,
    pub state: u32,
    pub _pad: u32,
    pub child_sa_spi: u32,
    pub _pad2: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LiInterfaceState {
    pub target_id_hash: u64,
    pub li_id: u32,
    pub interface_type: u32,
    pub x2_endpoint: u32,
    pub x3_endpoint: u32,
    pub intercept_count: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FemtocellCtx {
    pub local_gw_ip: u32,
    pub henb_gw_ip: u32,
    pub access_mode: u32,
    pub security_mode: u32,
    pub ipsec_tunnel_id: u32,
    pub _pad: u32,
    pub last_heartbeat_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SuplSpoofState {
    pub slp_ip: u32,
    pub session_id: u32,
    pub fake_lat: i32,
    pub fake_lon: i32,
    pub target_imsi_hash: u64,
    pub inject_count: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RoamingState {
    pub home_plmn: u32,
    pub visited_plmn: u32,
    pub roaming_type: u32,
    pub _pad: u32,
    pub ipx_provider_hash: u64,
    pub session_count: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RfFingerprint {
    pub freq_offset_hz: i32,
    pub iq_variance: u32,
    pub timing_offset_ns: i32,
    pub power_ramp_us: u32,
    pub cell_id: u32,
    pub _pad: u32,
    pub fingerprint_hash: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TelecomCorrelationEvent {
    pub event_type: u32,
    pub layer: u32,
    pub cell_id: u32,
    pub _pad: u32,
    pub imsi_hash: u64,
    pub timestamp_ns: u64,
    pub correlation_id: u64,
}

// ══════════════════════════════════════════════════════════════════════════════
// Pod trait — required for eBPF map value types
// ══════════════════════════════════════════════════════════════════════════════

/// # Safety
/// Implementors must ensure the type has no padding bytes and is valid for any bit pattern.
pub unsafe trait Pod: Copy + 'static {}

unsafe impl Pod for RootkitConfig {}
unsafe impl Pod for EventHeader {}
unsafe impl Pod for DefenseAlert {}
unsafe impl Pod for CellInfo {}
unsafe impl Pod for AtCommandCtx {}
unsafe impl Pod for GtpTunnelState {}
unsafe impl Pod for SignalingState {}
unsafe impl Pod for CellBaseline {}
unsafe impl Pod for ImsSipSession {}
unsafe impl Pod for RtpStreamState {}
unsafe impl Pod for EsimProvisionCtx {}
unsafe impl Pod for NetworkSliceInfo {}
unsafe impl Pod for VoWiFiTunnelState {}
unsafe impl Pod for LiInterfaceState {}
unsafe impl Pod for FemtocellCtx {}
unsafe impl Pod for SuplSpoofState {}
unsafe impl Pod for RoamingState {}
unsafe impl Pod for RfFingerprint {}
unsafe impl Pod for TelecomCorrelationEvent {}
