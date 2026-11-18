//! Shared types between eBPF kernel programs and user-space components.
//!
//! All types are `#[repr(C)]` and `Copy` to satisfy eBPF map value constraints.
//! This crate is `no_std` so it can be linked into both `*-ebpf` (kernel) and
//! user-space crates. The optional `user` feature enables `serde` derives for
//! JSON serialization in the defense and tools binaries.

#![no_std]

pub mod modem;

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
// RF Protocol Domain Event Constants — Offense (Features 135-172)
// ══════════════════════════════════════════════════════════════════════════════

// TETRA/P25 — Public Safety LMR (F135-F138)
pub const EVENT_TETRA_INTERCEPT: u32 = 205;
pub const EVENT_TETRA_DOWNGRADE: u32 = 206;
pub const EVENT_P25_CONTROL_HARVEST: u32 = 207;
pub const EVENT_P25_IMBE_INTERCEPT: u32 = 208;
// Bluetooth/BLE (F139-F142)
pub const EVENT_BLE_GATT_ENUM: u32 = 209;
pub const EVENT_BLE_PAIRING_DOWNGRADE: u32 = 210;
pub const EVENT_BLUEBORNE_PROBE: u32 = 211;
pub const EVENT_BLE_ADV_SPOOF: u32 = 212;
// Zigbee/Z-Wave/Thread (F143-F145)
pub const EVENT_ZIGBEE_KEY_SNIFF: u32 = 213;
pub const EVENT_ZWAVE_S0_EXTRACT: u32 = 214;
pub const EVENT_THREAD_MLE_EXPLOIT: u32 = 215;
// LoRa/LoRaWAN (F146-F148)
pub const EVENT_LORAWAN_JOIN_REPLAY: u32 = 216;
pub const EVENT_LORAWAN_ABP_HIJACK: u32 = 217;
pub const EVENT_LORA_PHY_JAM: u32 = 218;
// NB-IoT/LTE-M (F149-F150)
pub const EVENT_NBIOT_RRC_EXPLOIT: u32 = 219;
pub const EVENT_LTEM_EDRX_TIMING: u32 = 220;
// WiFi 802.11 (F151-F155)
pub const EVENT_WIFI_DEAUTH_FLOOD: u32 = 221;
pub const EVENT_WPA3_DRAGONBLOOD: u32 = 222;
pub const EVENT_EVIL_TWIN_KARMA: u32 = 223;
pub const EVENT_FT_ROAMING_ABUSE: u32 = 224;
pub const EVENT_PMKID_CAPTURE: u32 = 225;
// Remote Keyless Entry (F156-F157)
pub const EVENT_ROLLJAM_ATTACK: u32 = 226;
pub const EVENT_RKE_RELAY_ATTACK: u32 = 227;
// Drone/UAV C2 (F158-F160)
pub const EVENT_MAVLINK_INJECT: u32 = 228;
pub const EVENT_DJI_DRONEID_FINGERPRINT: u32 = 229;
pub const EVENT_FPV_VIDEO_INTERCEPT: u32 = 230;
// POCSAG/FLEX Paging (F161-F162)
pub const EVENT_POCSAG_DECODE: u32 = 231;
pub const EVENT_FLEX_INTERCEPT: u32 = 232;
// RDS/DAB+ Broadcast (F163-F164)
pub const EVENT_RDS_INJECT: u32 = 233;
pub const EVENT_DAB_ENSEMBLE_MANIP: u32 = 234;
// EAS/WEA Emergency Alert (F165-F166)
pub const EVENT_EAS_SAME_INJECT: u32 = 235;
pub const EVENT_WEA_CMAS_INJECT: u32 = 236;
// O-RAN Fronthaul (F167-F170)
pub const EVENT_ECPRI_IQ_INTERCEPT: u32 = 237;
pub const EVENT_FRONTHAUL_MITM_INJECT: u32 = 238;
pub const EVENT_ORAN_XAPP_EXPLOIT: u32 = 239;
pub const EVENT_F1AP_CU_DU_EXPLOIT: u32 = 240;
// AIS Maritime (F171-F172)
pub const EVENT_AIS_POSITION_SPOOF: u32 = 241;
pub const EVENT_AIS_CPA_ABUSE: u32 = 242;

// ══════════════════════════════════════════════════════════════════════════════
// Next-Generation Wireless Event Constants — Offense (Features 173-200)
// Wi-Fi 6/6E/7/8 + sensing (F173-F179), satellite D2C/PNT (F180-F184),
// UWB/BT 6.0 secure ranging (F185-F188), Matter/Ambient IoT/DECT-2020/
// FRMCS/LDACS (F189-F194), 6G horizon (F195-F200)
// ══════════════════════════════════════════════════════════════════════════════

// Wi-Fi 6/6E/7/8 & WLAN Sensing (F173-F179)
pub const EVENT_WIFI7_MLO_LINK_DESYNC: u32 = 243;
pub const EVENT_WIFI7_MLO_KEY_ABUSE: u32 = 244;
pub const EVENT_WIFI6_AFC_IMPERSONATION: u32 = 245;
pub const EVENT_WIFI6_OFDMA_RU_JAM: u32 = 246;
pub const EVENT_WIFI_SENSING_PRIVACY: u32 = 247;
pub const EVENT_WIFI_HALOW_EXPLOIT: u32 = 248;
pub const EVENT_WIFI8_MAPC_ROGUE: u32 = 249;
// Satellite Direct-to-Cell & PNT (F180-F184)
pub const EVENT_D2C_CELL_SPOOF: u32 = 250;
pub const EVENT_NTN_REGEN_INJECT: u32 = 251;
pub const EVENT_LEO_PNT_SPOOF: u32 = 252;
pub const EVENT_GNSS_AUTH_BYPASS: u32 = 253;
pub const EVENT_NBNTN_SAF_ABUSE: u32 = 254;
// UWB / Secure Ranging / Bluetooth 6.0 (F185-F188)
pub const EVENT_UWB_RANGING_MANIP: u32 = 255;
pub const EVENT_UWB_KEY_RELAY: u32 = 256;
pub const EVENT_BT_CS_SPOOF: u32 = 257;
pub const EVENT_BT_AURACAST_ABUSE: u32 = 258;
// Matter / Ambient IoT / DECT-2020 NR / FRMCS / LDACS (F189-F194)
pub const EVENT_MATTER_PASSCODE_ATTACK: u32 = 259;
pub const EVENT_MATTER_ACL_MANIP: u32 = 260;
pub const EVENT_AMBIENT_IOT_CLONE: u32 = 261;
pub const EVENT_DECT2020_INJECT: u32 = 262;
pub const EVENT_FRMCS_INJECT: u32 = 263;
pub const EVENT_LDACS_INJECT: u32 = 264;
// 6G horizon (F195-F200)
pub const EVENT_6G_AI_PERTURB: u32 = 265;
pub const EVENT_6G_RIS_MANIP: u32 = 266;
pub const EVENT_6G_THZ_BLOCKAGE: u32 = 267;
pub const EVENT_6G_PQC_DOWNGRADE: u32 = 268;
pub const EVENT_6G_NON_CRED_ABUSE: u32 = 269;
pub const EVENT_6G_ISAC_ABUSE: u32 = 270;

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
// RF Protocol Domain Alert Constants (Modules 40-55)
// ══════════════════════════════════════════════════════════════════════════════

// Public Safety LMR Defense (Modules 40-41)
pub const ALERT_TETRA_ENCRYPTION: u32 = 43;
pub const ALERT_P25_CONTROL: u32 = 44;
// IoT Radio Defense (Modules 42-45)
pub const ALERT_BLE_PAIRING: u32 = 45;
pub const ALERT_ZIGBEE_KEY: u32 = 46;
pub const ALERT_LORAWAN_JOIN: u32 = 47;
pub const ALERT_NBIOT_RRC: u32 = 48;
// WiFi Defense (Modules 46-47)
pub const ALERT_WIFI_DEAUTH: u32 = 49;
pub const ALERT_WPA3_INTEGRITY: u32 = 50;
// RF Control Defense (Modules 48-49)
pub const ALERT_RKE_JAMMING: u32 = 51;
pub const ALERT_UAV_C2: u32 = 52;
// Broadcast/Paging Defense (Modules 50-52)
pub const ALERT_PAGER_ANOMALY: u32 = 53;
pub const ALERT_BROADCAST_INJECTION: u32 = 54;
pub const ALERT_EAS_SPOOFING: u32 = 55;
// O-RAN Defense (Modules 53-54)
pub const ALERT_ORAN_FRONTHAUL: u32 = 56;
pub const ALERT_ORAN_RIC: u32 = 57;
// AIS Maritime Defense (Module 55)
pub const ALERT_AIS_INTEGRITY: u32 = 58;

// ══════════════════════════════════════════════════════════════════════════════
// Next-Generation Wireless Alert Constants (Modules 56-70)
// ══════════════════════════════════════════════════════════════════════════════

// Wi-Fi 6/7/8 Defense (Modules 56, 64, 69)
pub const ALERT_MLO_INTEGRITY: u32 = 59;
pub const ALERT_WIFI_SENSING: u32 = 67;
pub const ALERT_MAPC_INTEGRITY: u32 = 72;
// Secure Ranging Defense (Module 57)
pub const ALERT_SECURE_RANGING: u32 = 60;
// Smart Home / IoT Defense (Modules 58-60)
pub const ALERT_MATTER_COMMISSIONING: u32 = 61;
pub const ALERT_AMBIENT_IOT: u32 = 62;
pub const ALERT_DECT2020_INTEGRITY: u32 = 63;
// Satellite D2C / PNT Defense (Modules 61-63, 68)
pub const ALERT_D2C_CELL_SPOOF: u32 = 64;
pub const ALERT_GNSS_AUTH_FAILURE: u32 = 65;
pub const ALERT_NTN_REGEN_ANOMALY: u32 = 66;
pub const ALERT_LEO_PNT: u32 = 71;
// Transport Signaling Defense (Module 65)
pub const ALERT_FRMCS_LDACS: u32 = 68;
// 6G Horizon Defense (Modules 66-67, 70)
pub const ALERT_AI_RAN_INTEGRITY: u32 = 69;
pub const ALERT_PQC_DOWNGRADE: u32 = 70;
pub const ALERT_NON_CREDENTIAL_ABUSE: u32 = 73;

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
// RF Protocol Domain Structs (Features 135-172, Modules 40-55)
// ══════════════════════════════════════════════════════════════════════════════

/// TETRA/P25 land mobile radio state (F135-F138, Modules 40-41)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LmrRadioState {
    pub nac: u16,        // P25 Network Access Code
    pub wacn: u16,       // P25 Wide Area Communication Network ID (low 16 bits)
    pub color_code: u16, // TETRA color code
    pub mcc: u16,        // TETRA Mobile Country Code
    pub system_id: u32,  // P25 system ID
    pub tgid: u32,       // P25 Talk Group ID
    pub cipher: u32,     // TEA cipher suite in use (0=clear, 1=TEA1, 2=TEA2, 3=TEA3)
    pub timestamp_ns: u64,
}

/// Baseline for LMR defense modules (Modules 40-41)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LmrBaseline {
    pub expected_cipher: u32,
    pub expected_nac: u32,
    pub expected_wacn: u32,
    pub expected_system_id: u32,
    pub _pad: u32,
}

/// Bluetooth/BLE link state (F139-F142, Module 42)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BleLinkState {
    pub conn_handle: u32,
    pub pairing_mode: u32, // 0=LE Legacy, 1=LE Secure Connections
    pub addr_hash: u32,
    pub gatt_handle_count: u32,
    pub l2cap_len: u32,
    pub _pad: u32,
    pub timestamp_ns: u64,
}

/// Zigbee/Z-Wave/Thread WPAN network state (F143-F145, Module 43)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WpanNetworkState {
    pub pan_id: u16,
    pub protocol: u8, // 0=zigbee, 1=z-wave, 2=thread
    pub _pad: u8,
    pub channel: u16,
    pub join_count: u16,
    pub key_hash: u32,
    pub timestamp_ns: u64,
}

/// LoRaWAN session state (F146-F148, Module 44)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LoRaSessionState {
    pub dev_addr: u32,
    pub dev_nonce: u16,
    pub spreading_factor: u8,
    pub activation: u8, // 0=OTAA, 1=ABP
    pub fcnt_up: u32,
    pub fcnt_down: u32,
    pub timestamp_ns: u64,
}

/// WiFi 802.11 client/AP state (F151-F155, Modules 46-47)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WifiClientState {
    pub bssid_hash: u32,
    pub ssid_hash: u32,
    pub client_addr_hash: u32,
    pub deauth_count: u32,
    pub mgmt_subtype: u32,
    pub _pad: u32,
    pub timestamp_ns: u64,
}

/// Remote keyless entry fob state (F156-F157, Module 48)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RkeFobState {
    pub fob_id: u32,
    pub frequency_khz: u32, // 315000 or 433920
    pub code_count: u32,
    pub last_code: u32,
    pub _pad: u32,
    pub timestamp_ns: u64,
}

/// UAV command-and-control link state (F158-F160, Module 49)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UavLinkState {
    pub sys_id: u8,  // MAVLink system ID
    pub comp_id: u8, // MAVLink component ID
    pub msg_id: u16, // MAVLink message ID
    pub signed: u8,  // 1 if MAVLink v2 signing present
    pub _pad: [u8; 3],
    pub serial_hash: u32, // DJI DroneID serial hash
    pub gcs_addr_hash: u32,
    pub timestamp_ns: u64,
}

/// POCSAG/FLEX pager message state (F161-F162, Module 50)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PagerMessageState {
    pub ric: u32, // Radio Identity Code / FLEX capcode
    pub function_code: u32,
    pub baud: u32,     // 512/1200/2400 POCSAG, 1600/3200/6400 FLEX
    pub protocol: u32, // 0=POCSAG, 1=FLEX
    pub msg_hash: u32,
    pub _pad: u32,
    pub timestamp_ns: u64,
}

/// RDS/DAB+/EAS broadcast injection state (F163-F166, Modules 51-52)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BroadcastInjectState {
    pub pi_code: u16,  // RDS Programme Identification
    pub fig_type: u16, // DAB+ Fast Information Group type
    pub service_hash: u32,
    pub originator: u32, // SAME originator code
    pub event_code: u32, // SAME/WEA event code
    pub timestamp_ns: u64,
}

/// eCPRI/O-RAN fronthaul state (F167-F170, Modules 53-54)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EcpriFronthaulState {
    pub seq_num: u32,
    pub pc_id: u16,   // eCPRI PC_ID / antenna-carrier ID
    pub msg_type: u8, // eCPRI message type (0=IQ data plane)
    pub _pad: u8,
    pub iq_amplitude: u32, // peak IQ magnitude observed
    pub timestamp_ns: u64,
}

/// O-RAN Near-RT RIC / E2 state (F169, Module 54)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OranRicState {
    pub xapp_id: u32,
    pub e2_node_id: u32,
    pub subscription_hash: u32,
    pub policy_id: u32, // A1 policy ID
    pub _pad: u32,
    pub timestamp_ns: u64,
}

/// AIS vessel tracking state (F171-F172, Module 55)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AisVesselState {
    pub mmsi: u32,
    pub lat_deg: i32, // position, degrees
    pub lon_deg: i32,
    pub sog_tenths: u16, // speed over ground (0.1 kn units)
    pub cog_tenths: u16, // course over ground (0.1 deg units)
    pub msg_type: u8,    // AIS message type (1-3 position, 18 Class B)
    pub _pad: [u8; 3],
    pub timestamp_ns: u64,
}

// ══════════════════════════════════════════════════════════════════════════════
// Next-Generation Wireless Structs (Features 173-200, Modules 56-70)
// ══════════════════════════════════════════════════════════════════════════════

/// Wi-Fi 6/7 Multi-Link Operation link state (F173-F174, Module 56)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MloLinkState {
    pub mld_addr_hash: u32, // MLD MAC address hash
    pub link_id: u8,        // MLO link identifier
    pub key_gen: u8,        // per-link key generation counter
    pub auth_suite: u16,    // WPA3/SAE suite selector
    pub desync_count: u32,  // observed link desynchronization events
    pub seq_num: u32,       // per-link sequence number
    pub _pad: u32,
    pub timestamp_ns: u64,
}

/// Direct-to-Cell satellite cell state (F180-F181, F184, Module 61)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct D2cCellState {
    pub plmn: u32,           // PLMN ID (MCC/MNC packed)
    pub cell_global_id: u32, // NCGI of the serving satellite cell
    pub tac: u32,
    pub sat_indicator: u8, // NTN/SCS indicator from SIB19
    pub regen_payload: u8, // 1 = regenerative gNB on board (Rel-19 NTN)
    pub _pad: [u8; 2],
    pub timing_advance: u32,
    pub _pad2: u32,
    pub timestamp_ns: u64,
}

/// Secure ranging state for UWB 802.15.4z / Bluetooth 6.0 CS (F185-F187, Module 57)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SecureRangingState {
    pub ranging_type: u8, // 0=UWB HRP, 1=BT channel sounding
    pub auth_level: u8,   // STS/DRBG security level in use
    pub _pad: [u8; 2],
    pub session_hash: u32, // ranging session identifier hash
    pub measured_dist_cm: u32,
    pub sts_hash: u32, // scrambled timestamp sequence hash
    pub _pad2: u32,
    pub timestamp_ns: u64,
}

/// Matter smart-home session state (F189-F190, Module 58)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MatterSessionState {
    pub node_id_hash: u64, // Matter operational node ID hash
    pub passcode_attempts: u32,
    pub acl_version: u32, // access control list version
    pub commissioning_state: u8,
    pub _pad: [u8; 3],
    pub _pad2: u32,
    pub timestamp_ns: u64,
}

/// Ambient IoT device state — 3GPP Rel-19 batteryless classes (F191, Module 59)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AmbientIotState {
    pub device_id_hash: u32,
    pub device_class: u8, // 0=A (backscatter), 1=B, 2=C (±20 dBm)
    pub _pad: [u8; 3],
    pub report_count: u32,
    pub signal_dbm: i16,
    pub _pad2: u16,
    pub _pad3: u32,
    pub timestamp_ns: u64,
}

/// LEO PNT signal state — Xona Pulsar-class / Galileo OSNMA (F182-F183, Modules 62/68)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LeoPntState {
    pub sat_id: u16,
    pub beam_id: u16,
    pub cn0_dbhz: u32,
    pub doppler_hz: i32,
    pub auth_status: u8, // 0=unauthenticated, 1=OSNMA verified, 2=OSNMA failed
    pub _pad: [u8; 3],
    pub _pad2: u32,
    pub timestamp_ns: u64,
}

/// AI-native RAN model integrity state (F195-F196, Module 66)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AiRanModelState {
    pub model_id_hash: u32,
    pub version: u32,
    pub integrity_hash: u64,
    pub timestamp_ns: u64,
}

/// Post-quantum cryptography handshake state (F198, Module 67)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PqcHandshakeState {
    pub suite_id: u32, // NIST PQC suite (Kyber/Dilithium class)
    pub peer_hash: u32,
    pub classic_fallback: u8, // 1 = downgraded to classic crypto
    pub _pad: [u8; 3],
    pub _pad2: u32,
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
unsafe impl Pod for LmrRadioState {}
unsafe impl Pod for LmrBaseline {}
unsafe impl Pod for BleLinkState {}
unsafe impl Pod for WpanNetworkState {}
unsafe impl Pod for LoRaSessionState {}
unsafe impl Pod for WifiClientState {}
unsafe impl Pod for RkeFobState {}
unsafe impl Pod for UavLinkState {}
unsafe impl Pod for PagerMessageState {}
unsafe impl Pod for BroadcastInjectState {}
unsafe impl Pod for EcpriFronthaulState {}
unsafe impl Pod for OranRicState {}
unsafe impl Pod for AisVesselState {}
unsafe impl Pod for MloLinkState {}
unsafe impl Pod for D2cCellState {}
unsafe impl Pod for SecureRangingState {}
unsafe impl Pod for MatterSessionState {}
unsafe impl Pod for AmbientIotState {}
unsafe impl Pod for LeoPntState {}
unsafe impl Pod for AiRanModelState {}
unsafe impl Pod for PqcHandshakeState {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn struct_sizes_are_stable() {
        assert_eq!(mem::size_of::<RootkitConfig>(), 8);
        assert_eq!(mem::size_of::<EventHeader>(), 24);
        assert_eq!(mem::size_of::<DefenseAlert>(), 48);
        assert_eq!(mem::size_of::<CellInfo>(), 20);
        assert_eq!(mem::size_of::<AtCommandCtx>(), 80);
        assert_eq!(mem::size_of::<GtpTunnelState>(), 32);
        assert_eq!(mem::size_of::<SignalingState>(), 32);
        assert_eq!(mem::size_of::<CellBaseline>(), 24);
        assert_eq!(mem::size_of::<TelecomCorrelationEvent>(), 40);
    }

    #[test]
    fn struct_alignment_is_repr_c() {
        assert_eq!(mem::align_of::<RootkitConfig>(), 4);
        assert_eq!(mem::align_of::<EventHeader>(), 8);
        assert_eq!(mem::align_of::<DefenseAlert>(), 8);
        assert_eq!(mem::align_of::<CellInfo>(), 4);
        assert_eq!(mem::align_of::<GtpTunnelState>(), 8);
    }

    #[test]
    fn event_constants_are_unique() {
        let offense_events = [
            EVENT_AT_CMD_INJECT,
            EVENT_BASEBAND_EXPLOIT,
            EVENT_SIM_CLONE,
            EVENT_IMSI_INTERCEPT,
            EVENT_PROTOCOL_DOWNGRADE,
            EVENT_GTP_TUNNEL_HIJACK,
            EVENT_SS7_MAP_INJECT,
            EVENT_DIAMETER_EXPLOIT,
            EVENT_RRC_REDIRECT,
            EVENT_NAS_INTERCEPT,
            EVENT_SUPI_DECONCEAL,
            EVENT_N2_INTERFACE_INJECT,
            EVENT_VOLTE_INTERCEPT,
            EVENT_SIP_HIJACK,
            EVENT_RTP_CAPTURE,
            EVENT_ESIM_PROFILE_INJECT,
            EVENT_SMDP_EXPLOIT,
            EVENT_SLICE_ISOLATION_BYPASS,
            EVENT_NSSF_MANIPULATE,
            EVENT_VOWIFI_DOWNGRADE,
            EVENT_EPDG_EXPLOIT,
            EVENT_LI_X1_INJECT,
            EVENT_LI_X2_INTERCEPT,
            EVENT_FEMTOCELL_PIVOT,
            EVENT_HENB_GW_EXPLOIT,
            EVENT_SUPL_SPOOF,
            EVENT_LPP_MANIPULATE,
            EVENT_ROAMING_IPX_PIVOT,
            EVENT_GRX_LATERAL,
            EVENT_PBCH_SIB_SPOOF,
            EVENT_RRC_MEAS_MANIPULATE,
            EVENT_HANDOVER_HIJACK,
            EVENT_SBI_EXPLOIT,
            EVENT_NRF_ABUSE,
            EVENT_OAUTH2_THEFT,
            EVENT_JAMMING_EVASION,
            EVENT_MIMO_FINGERPRINT,
            EVENT_SIDELINK_EXPLOIT,
            EVENT_AKA_DOWNGRADE,
            EVENT_SUCI_REPLAY,
            EVENT_ARPF_PROBE,
            EVENT_DVBS2_INTERCEPT,
            EVENT_TRANSPONDER_HIJACK,
            EVENT_NTN_TIMING_EXPLOIT,
            EVENT_NTN_GATEWAY_INJECT,
            EVENT_IRIDIUM_CAPTURE,
            EVENT_LEO_SIGNALING_INJECT,
            EVENT_VSAT_FIRMWARE_EXTRACT,
            EVENT_SCPC_CARRIER_MANIP,
            EVENT_STARLINK_AUTH_PROBE,
            EVENT_ISL_FINGERPRINT,
            EVENT_ADSB_INJECT,
            EVENT_SARSAT_BEACON_SPOOF,
            EVENT_GNSS_L1_SPOOF,
            EVENT_GNSS_L5_SPOOF,
            EVENT_TETRA_INTERCEPT,
            EVENT_TETRA_DOWNGRADE,
            EVENT_P25_CONTROL_HARVEST,
            EVENT_P25_IMBE_INTERCEPT,
            EVENT_BLE_GATT_ENUM,
            EVENT_BLE_PAIRING_DOWNGRADE,
            EVENT_BLUEBORNE_PROBE,
            EVENT_BLE_ADV_SPOOF,
            EVENT_ZIGBEE_KEY_SNIFF,
            EVENT_ZWAVE_S0_EXTRACT,
            EVENT_THREAD_MLE_EXPLOIT,
            EVENT_LORAWAN_JOIN_REPLAY,
            EVENT_LORAWAN_ABP_HIJACK,
            EVENT_LORA_PHY_JAM,
            EVENT_NBIOT_RRC_EXPLOIT,
            EVENT_LTEM_EDRX_TIMING,
            EVENT_WIFI_DEAUTH_FLOOD,
            EVENT_WPA3_DRAGONBLOOD,
            EVENT_EVIL_TWIN_KARMA,
            EVENT_FT_ROAMING_ABUSE,
            EVENT_PMKID_CAPTURE,
            EVENT_ROLLJAM_ATTACK,
            EVENT_RKE_RELAY_ATTACK,
            EVENT_MAVLINK_INJECT,
            EVENT_DJI_DRONEID_FINGERPRINT,
            EVENT_FPV_VIDEO_INTERCEPT,
            EVENT_POCSAG_DECODE,
            EVENT_FLEX_INTERCEPT,
            EVENT_RDS_INJECT,
            EVENT_DAB_ENSEMBLE_MANIP,
            EVENT_EAS_SAME_INJECT,
            EVENT_WEA_CMAS_INJECT,
            EVENT_ECPRI_IQ_INTERCEPT,
            EVENT_FRONTHAUL_MITM_INJECT,
            EVENT_ORAN_XAPP_EXPLOIT,
            EVENT_F1AP_CU_DU_EXPLOIT,
            EVENT_AIS_POSITION_SPOOF,
            EVENT_AIS_CPA_ABUSE,
            EVENT_WIFI7_MLO_LINK_DESYNC,
            EVENT_WIFI7_MLO_KEY_ABUSE,
            EVENT_WIFI6_AFC_IMPERSONATION,
            EVENT_WIFI6_OFDMA_RU_JAM,
            EVENT_WIFI_SENSING_PRIVACY,
            EVENT_WIFI_HALOW_EXPLOIT,
            EVENT_WIFI8_MAPC_ROGUE,
            EVENT_D2C_CELL_SPOOF,
            EVENT_NTN_REGEN_INJECT,
            EVENT_LEO_PNT_SPOOF,
            EVENT_GNSS_AUTH_BYPASS,
            EVENT_NBNTN_SAF_ABUSE,
            EVENT_UWB_RANGING_MANIP,
            EVENT_UWB_KEY_RELAY,
            EVENT_BT_CS_SPOOF,
            EVENT_BT_AURACAST_ABUSE,
            EVENT_MATTER_PASSCODE_ATTACK,
            EVENT_MATTER_ACL_MANIP,
            EVENT_AMBIENT_IOT_CLONE,
            EVENT_DECT2020_INJECT,
            EVENT_FRMCS_INJECT,
            EVENT_LDACS_INJECT,
            EVENT_6G_AI_PERTURB,
            EVENT_6G_RIS_MANIP,
            EVENT_6G_THZ_BLOCKAGE,
            EVENT_6G_PQC_DOWNGRADE,
            EVENT_6G_NON_CRED_ABUSE,
            EVENT_6G_ISAC_ABUSE,
        ];
        for i in 0..offense_events.len() {
            for j in (i + 1)..offense_events.len() {
                assert_ne!(
                    offense_events[i], offense_events[j],
                    "Duplicate event constant at indices {} and {}",
                    i, j
                );
            }
        }
    }

    #[test]
    fn alert_constants_are_unique() {
        let alerts = [
            ALERT_ROGUE_TOWER,
            ALERT_DOWNGRADE_ATTACK,
            ALERT_IMSI_CATCHER,
            ALERT_CELL_ANOMALY,
            ALERT_GTP_ANOMALY,
            ALERT_SS7_ANOMALY,
            ALERT_MODEM_TAMPER,
            ALERT_NAS_REPLAY,
            ALERT_VOLTE_FRAUD,
            ALERT_ESIM_TAMPER,
            ALERT_SLICE_VIOLATION,
            ALERT_ROAMING_ANOMALY,
            ALERT_RF_FINGERPRINT,
            ALERT_SBI_ANOMALY,
            ALERT_HANDOVER_INTEGRITY,
            ALERT_RAN_SHARING_LEAK,
            ALERT_SIGNALING_STORM,
            ALERT_DVBS2_ANOMALY,
            ALERT_NTN_ANOMALY,
            ALERT_LEO_SIGNALING,
            ALERT_VSAT_INTEGRITY,
            ALERT_STARLINK_AUTH,
            ALERT_AVIATION_INTEGRITY,
            ALERT_GNSS_SPOOFING,
            ALERT_TETRA_ENCRYPTION,
            ALERT_P25_CONTROL,
            ALERT_BLE_PAIRING,
            ALERT_ZIGBEE_KEY,
            ALERT_LORAWAN_JOIN,
            ALERT_NBIOT_RRC,
            ALERT_WIFI_DEAUTH,
            ALERT_WPA3_INTEGRITY,
            ALERT_RKE_JAMMING,
            ALERT_UAV_C2,
            ALERT_PAGER_ANOMALY,
            ALERT_BROADCAST_INJECTION,
            ALERT_EAS_SPOOFING,
            ALERT_ORAN_FRONTHAUL,
            ALERT_ORAN_RIC,
            ALERT_AIS_INTEGRITY,
            ALERT_MLO_INTEGRITY,
            ALERT_SECURE_RANGING,
            ALERT_MATTER_COMMISSIONING,
            ALERT_AMBIENT_IOT,
            ALERT_DECT2020_INTEGRITY,
            ALERT_D2C_CELL_SPOOF,
            ALERT_GNSS_AUTH_FAILURE,
            ALERT_NTN_REGEN_ANOMALY,
            ALERT_WIFI_SENSING,
            ALERT_FRMCS_LDACS,
            ALERT_AI_RAN_INTEGRITY,
            ALERT_PQC_DOWNGRADE,
            ALERT_LEO_PNT,
            ALERT_MAPC_INTEGRITY,
            ALERT_NON_CREDENTIAL_ABUSE,
        ];
        for i in 0..alerts.len() {
            for j in (i + 1)..alerts.len() {
                assert_ne!(
                    alerts[i], alerts[j],
                    "Duplicate alert constant at indices {} and {}",
                    i, j
                );
            }
        }
    }

    #[test]
    fn event_and_alert_ranges_dont_overlap() {
        let min_event = EVENT_AT_CMD_INJECT;
        let max_event = EVENT_6G_ISAC_ABUSE;
        let min_alert = ALERT_ROGUE_TOWER;
        let max_alert = ALERT_NON_CREDENTIAL_ABUSE;
        assert!(
            max_alert < min_event || max_event < min_alert,
            "Event range [{min_event},{max_event}] overlaps alert range [{min_alert},{max_alert}]"
        );
    }

    #[test]
    fn pod_types_have_no_padding_invariant() {
        // Verify structs where we can calculate expected size from fields
        // RootkitConfig: u32 + u32 = 8
        assert_eq!(mem::size_of::<RootkitConfig>(), 4 + 4);
        // EventHeader: u32 + u32 + u64 + u64 = 24
        assert_eq!(mem::size_of::<EventHeader>(), 4 + 4 + 8 + 8);
        // SignalingState: u32*4 + u64*2 = 32
        assert_eq!(mem::size_of::<SignalingState>(), 4 * 4 + 8 * 2);
    }

    #[test]
    fn satellite_struct_sizes() {
        assert_eq!(mem::size_of::<SatelliteLinkState>(), 32);
        assert_eq!(mem::size_of::<GnssSignalState>(), 32);
        assert_eq!(mem::size_of::<NtnTimingState>(), 24);
        assert_eq!(mem::size_of::<StarlinkSessionState>(), 40);
        assert_eq!(mem::size_of::<AdsbAircraftState>(), 32);
    }

    #[test]
    fn rf_domain_struct_sizes() {
        assert_eq!(mem::size_of::<LmrRadioState>(), 32);
        assert_eq!(mem::size_of::<LmrBaseline>(), 20);
        assert_eq!(mem::size_of::<BleLinkState>(), 32);
        assert_eq!(mem::size_of::<WpanNetworkState>(), 24);
        assert_eq!(mem::size_of::<LoRaSessionState>(), 24);
        assert_eq!(mem::size_of::<WifiClientState>(), 32);
        assert_eq!(mem::size_of::<RkeFobState>(), 32);
        assert_eq!(mem::size_of::<UavLinkState>(), 24);
        assert_eq!(mem::size_of::<PagerMessageState>(), 32);
        assert_eq!(mem::size_of::<BroadcastInjectState>(), 24);
        assert_eq!(mem::size_of::<EcpriFronthaulState>(), 24);
        assert_eq!(mem::size_of::<OranRicState>(), 32);
        assert_eq!(mem::size_of::<AisVesselState>(), 32);
    }

    #[test]
    fn fiveg_struct_sizes() {
        assert_eq!(mem::size_of::<SbiSessionState>(), 40);
        assert_eq!(mem::size_of::<NrfRegistration>(), 32);
        assert_eq!(mem::size_of::<AkaAuthState>(), 64);
        assert_eq!(mem::size_of::<HandoverCtx>(), 24);
        assert_eq!(mem::size_of::<SidelinkCtx>(), 32);
    }

    #[test]
    fn nextgen_struct_sizes() {
        assert_eq!(mem::size_of::<MloLinkState>(), 32);
        assert_eq!(mem::size_of::<D2cCellState>(), 32);
        assert_eq!(mem::size_of::<SecureRangingState>(), 32);
        assert_eq!(mem::size_of::<MatterSessionState>(), 32);
        assert_eq!(mem::size_of::<AmbientIotState>(), 32);
        assert_eq!(mem::size_of::<LeoPntState>(), 32);
        assert_eq!(mem::size_of::<AiRanModelState>(), 24);
        assert_eq!(mem::size_of::<PqcHandshakeState>(), 24);
    }
}
