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
// Telecom Event Constants — Offense 5G Advanced (Features 109-120)
// ══════════════════════════════════════════════════════════════════════════════

pub const EVENT_PBCH_SIB_SPOOF: u32 = 179;
pub const EVENT_RRC_MEAS_MANIPULATE: u32 = 180;
pub const EVENT_HANDOVER_HIJACK: u32 = 181;
pub const EVENT_SBI_EXPLOIT: u32 = 182;
pub const EVENT_NRF_ABUSE: u32 = 183;
pub const EVENT_OAUTH2_THEFT: u32 = 184;
pub const EVENT_JAMMING_EVASION: u32 = 185;
pub const EVENT_MIMO_FINGERPRINT: u32 = 186;
pub const EVENT_SIDELINK_EXPLOIT: u32 = 187;
pub const EVENT_AKA_DOWNGRADE: u32 = 188;
pub const EVENT_SUCI_REPLAY: u32 = 189;
pub const EVENT_ARPF_PROBE: u32 = 190;

// ══════════════════════════════════════════════════════════════════════════════
// Satellite Event Constants — Offense (Features 121-134)
// ══════════════════════════════════════════════════════════════════════════════

pub const EVENT_DVBS2_INTERCEPT: u32 = 191;
pub const EVENT_TRANSPONDER_HIJACK: u32 = 192;
pub const EVENT_NTN_TIMING_EXPLOIT: u32 = 193;
pub const EVENT_NTN_GATEWAY_INJECT: u32 = 194;
pub const EVENT_IRIDIUM_CAPTURE: u32 = 195;
pub const EVENT_LEO_SIGNALING_INJECT: u32 = 196;
pub const EVENT_VSAT_FIRMWARE_EXTRACT: u32 = 197;
pub const EVENT_SCPC_CARRIER_MANIP: u32 = 198;
pub const EVENT_STARLINK_AUTH_PROBE: u32 = 199;
pub const EVENT_ISL_FINGERPRINT: u32 = 200;
pub const EVENT_ADSB_INJECT: u32 = 201;
pub const EVENT_SARSAT_BEACON_SPOOF: u32 = 202;
pub const EVENT_GNSS_L1_SPOOF: u32 = 203;
pub const EVENT_GNSS_L5_SPOOF: u32 = 204;

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
pub const ALERT_SBI_ANOMALY: u32 = 32;
pub const ALERT_HANDOVER_INTEGRITY: u32 = 33;
pub const ALERT_RAN_SHARING_LEAK: u32 = 34;
pub const ALERT_SIGNALING_STORM: u32 = 35;

// ══════════════════════════════════════════════════════════════════════════════
// Satellite Defense Alert Constants (Modules 33-39)
// ══════════════════════════════════════════════════════════════════════════════

pub const ALERT_DVBS2_ANOMALY: u32 = 36;
pub const ALERT_NTN_ANOMALY: u32 = 37;
pub const ALERT_LEO_SIGNALING: u32 = 38;
pub const ALERT_VSAT_INTEGRITY: u32 = 39;
pub const ALERT_STARLINK_AUTH: u32 = 40;
pub const ALERT_AVIATION_INTEGRITY: u32 = 41;
pub const ALERT_GNSS_SPOOFING: u32 = 42;

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
// 5G Advanced / SBI / RAN Structs (Features 109-120, Modules 29-32)
// ══════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SbiSessionState {
    pub stream_id: u32,
    pub method_hash: u32,
    pub path_hash: u64,
    pub nf_src: u32,
    pub nf_dst: u32,
    pub token_hash: u64,
    pub timestamp_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NrfRegistration {
    pub nf_instance_id: u64,
    pub nf_type: u32,
    pub status: u32,
    pub service_hash: u64,
    pub token_expiry_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AkaAuthState {
    pub suci_hash: u64,
    pub rand: [u8; 16],
    pub autn: [u8; 16],
    pub res_star: [u8; 16],
    pub kausf_hash: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SidelinkCtx {
    pub src_l2_id: u32,
    pub dst_l2_id: u32,
    pub freq: u32,
    pub sl_rnti: u16,
    pub cast_type: u16,
    pub resource_pool: u32,
    pub _pad: u32,
    pub timestamp_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HandoverCtx {
    pub source_pci: u16,
    pub target_pci: u16,
    pub earfcn: u32,
    pub meas_rsrp: i16,
    pub meas_rsrq: i16,
    pub event_type: u32,
    pub timestamp_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MimoBeamState {
    pub beam_id: u32,
    pub ssb_index: u8,
    pub num_layers: u8,
    pub _pad: [u8; 2],
    pub precoder_hash: u64,
    pub csi_report_hash: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SbiBaseline {
    pub nf_type: u32,
    pub expected_services: u32,
    pub max_streams: u32,
    pub _pad: u32,
    pub token_fingerprint: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HandoverBaseline {
    pub source_pci: u16,
    pub target_pci: u16,
    pub min_rsrp: i16,
    pub max_rsrp: i16,
    pub expected_earfcn: u32,
    pub max_rate_per_min: u32,
    pub _pad: u32,
    pub _pad2: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RanSharingState {
    pub plmn_id: u32,
    pub slice_id: u32,
    pub ue_count: u32,
    pub _pad: u32,
    pub isolation_violations: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SignalingCounter {
    pub attach_count: u32,
    pub detach_count: u32,
    pub tau_count: u32,
    pub service_req_count: u32,
    pub window_start_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PfcpSessionState {
    pub seid_local: u64,
    pub seid_remote: u64,
    pub node_ip: u32,
    pub _pad: u32,
    pub pdr_count: u32,
    pub far_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NgapContext {
    pub amf_ue_id: u64,
    pub ran_ue_id: u32,
    pub procedure_code: u32,
    pub criticality: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct XnApContext {
    pub source_gnb: u32,
    pub target_gnb: u32,
    pub old_ue_xnap_id: u32,
    pub new_ue_xnap_id: u32,
    pub sn_status_hash: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IqSampleMeta {
    pub center_freq_hz: u64,
    pub sample_rate_hz: u32,
    pub gain_db: u16,
    pub bits_per_sample: u8,
    pub _pad: u8,
    pub timestamp_ns: u64,
}

// ══════════════════════════════════════════════════════════════════════════════
// Satellite Structs (Features 121-134, Modules 33-39)
// ══════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SatelliteLinkState {
    pub carrier_id: u32,
    pub symbol_rate: u32,
    pub modcod: u16,
    pub roll_off: u16,
    pub frequency_khz: u32,
    pub polarization: u8,
    pub _pad: [u8; 3],
    pub timestamp_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GnssSignalState {
    pub prn: u8,
    pub constellation: u8,
    pub signal_band: u8,
    pub _pad: u8,
    pub cn0_dbhz: u32,
    pub pseudorange_m: u64,
    pub doppler_hz: i32,
    pub code_phase: u32,
    pub timestamp_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NtnTimingState {
    pub ta_value: u32,
    pub ephem_offset_ms: u32,
    pub sat_elevation_deg: u16,
    pub feeder_link_id: u16,
    pub propagation_delay_us: u32,
    pub timestamp_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct StarlinkSessionState {
    pub terminal_id: u64,
    pub grpc_token_hash: u64,
    pub ground_station: u32,
    pub sat_id: u32,
    pub handover_count: u16,
    pub firmware_ver: u16,
    pub _pad: u32,
    pub timestamp_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AdsbAircraftState {
    pub icao_addr: u32,
    pub altitude_ft: i32,
    pub lat_deg: i32,
    pub lon_deg: i32,
    pub velocity_kt: u16,
    pub heading_deg: u16,
    pub squawk: u16,
    pub _pad: u16,
    pub timestamp_ns: u64,
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
unsafe impl Pod for SbiSessionState {}
unsafe impl Pod for NrfRegistration {}
unsafe impl Pod for AkaAuthState {}
unsafe impl Pod for SidelinkCtx {}
unsafe impl Pod for HandoverCtx {}
unsafe impl Pod for MimoBeamState {}
unsafe impl Pod for SbiBaseline {}
unsafe impl Pod for HandoverBaseline {}
unsafe impl Pod for RanSharingState {}
unsafe impl Pod for SignalingCounter {}
unsafe impl Pod for PfcpSessionState {}
unsafe impl Pod for NgapContext {}
unsafe impl Pod for XnApContext {}
unsafe impl Pod for IqSampleMeta {}
unsafe impl Pod for SatelliteLinkState {}
unsafe impl Pod for GnssSignalState {}
unsafe impl Pod for NtnTimingState {}
unsafe impl Pod for StarlinkSessionState {}
unsafe impl Pod for AdsbAircraftState {}
