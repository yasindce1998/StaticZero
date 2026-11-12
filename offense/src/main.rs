use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::{SchedClassifier, Xdp, XdpFlags};
use aya::BpfLoader;
use clap::Parser;
use tokio::signal;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use common::EventHeader;
use staticzero_offense::attach_kprobe;

// The compiled eBPF object is embedded so release binaries are
// self-contained. `cargo xtask build-ebpf` must run before building this
// binary (enforced by the ebpf-bin feature requirement).
#[cfg(debug_assertions)]
const EMBEDDED_BPF: &[u8] =
    include_bytes!("../../target/bpfel-unknown-none/debug/staticzero-offense");
#[cfg(not(debug_assertions))]
const EMBEDDED_BPF: &[u8] =
    include_bytes!("../../target/bpfel-unknown-none/release/staticzero-offense");

#[derive(Parser, Debug)]
#[command(name = "staticzero-offense")]
#[command(about = "StaticZero Telecom Exploitation Research Loader")]
struct Cli {
    /// Path to an external eBPF object file; overrides the embedded object
    #[arg(short, long)]
    bpf_path: Option<PathBuf>,

    /// Enable telecom interception (F89-F100: AT cmd, baseband, SIM, IMSI, downgrade, GTP, SS7, Diameter, RRC, NAS, SUPI, N2)
    #[arg(long)]
    enable_telecom: bool,

    /// Enable advanced telecom (F101-F108: VoLTE, eSIM, slicing, WiFi calling, LI, femtocell, SUPL, roaming)
    #[arg(long)]
    enable_telecom_advanced: bool,

    /// Enable all features
    #[arg(long)]
    all: bool,

    /// Target IMSI for interception (15-digit string)
    #[arg(long)]
    target_imsi: Option<String>,

    /// GTP tunnel interface for core network interception
    #[arg(long, default_value = "gtp0")]
    gtp_iface: String,

    /// IMS/SIP interface for VoLTE interception
    #[arg(long, default_value = "ims0")]
    ims_iface: String,

    /// WiFi calling interface
    #[arg(long, default_value = "wlan0")]
    wifi_iface: String,

    /// Enable 5G advanced exploitation (F109-F120: RAN, SBI, radio, identity)
    #[arg(long)]
    enable_5g_advanced: bool,

    /// Enable satellite exploitation (F121-F134: DVB-S2, NTN, Iridium, VSAT, Starlink, ADS-B, GNSS)
    #[arg(long)]
    enable_satellite: bool,

    /// Enable RF protocol domain exploitation (F135-F172: TETRA/P25, BLE, Zigbee, LoRaWAN, NB-IoT, WiFi, RKE, UAV, paging, broadcast, O-RAN, AIS)
    #[arg(long)]
    enable_rf: bool,

    /// SBI/core network interface for NF interception
    #[arg(long, default_value = "sbi0")]
    sbi_iface: String,

    /// SDR interface for radio-layer attacks
    #[arg(long, default_value = "sdr0")]
    sdr_iface: String,

    /// Satellite ground segment interface
    #[arg(long, default_value = "sat0")]
    sat_iface: String,

    /// WPAN (Zigbee/Z-Wave/Thread) interface
    #[arg(long, default_value = "wpan0")]
    wpan_iface: String,

    /// UAV telemetry / command-and-control interface
    #[arg(long, default_value = "uav0")]
    uav_iface: String,

    /// O-RAN fronthaul Ethernet interface (eCPRI/F1AP)
    #[arg(long, default_value = "eth0")]
    fronthaul_iface: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    tokio::spawn(async move {
        signal::ctrl_c().await.expect("failed to listen for ctrl+c");
        r.store(false, Ordering::SeqCst);
    });

    info!("StaticZero Telecom Offense Loader starting");

    // An explicit --bpf-path overrides the object embedded at build time.
    let (bpf_bytes, bpf_source) = match &cli.bpf_path {
        Some(path) => (
            std::fs::read(path).with_context(|| format!("read eBPF object {}", path.display()))?,
            path.display().to_string(),
        ),
        None => (
            EMBEDDED_BPF.to_vec(),
            format!("embedded object ({} bytes)", EMBEDDED_BPF.len()),
        ),
    };
    info!("Loading eBPF programs from {}", bpf_source);

    let mut bpf = BpfLoader::new()
        .load(&bpf_bytes)
        .context("failed to load eBPF object")?;

    // Attached kprobe symbol names (informational; the aya links live in the
    // Bpf object and detach when it drops).
    let mut attachments = Vec::new();

    /// Attach a kprobe; a missing kernel symbol or a verifier rejection
    /// disables that one feature, never the whole loader.
    macro_rules! attach_kprobes {
        ($probes:expr) => {
            for (name, attach_point, desc) in &$probes {
                match attach_kprobe(&mut bpf, name, attach_point) {
                    Ok(()) => {
                        info!(
                            "{} enabled via {} (probe runs on all CPUs)",
                            desc, attach_point
                        );
                        attachments.push(*attach_point);
                    }
                    Err(error) => {
                        warn!("{} ({}) not attached, skipping: {:#}", desc, name, error)
                    }
                }
            }
        };
    }

    let enable_telecom = cli.all || cli.enable_telecom;
    let enable_advanced = cli.all || cli.enable_telecom_advanced;
    let enable_5g = cli.all || cli.enable_5g_advanced;
    let enable_satellite = cli.all || cli.enable_satellite;
    let enable_rf = cli.all || cli.enable_rf;

    // ── Features 89-100: Telecom Interception ────────────────────────────────
    if enable_telecom {
        // Kprobes for modem/baseband/SIM/NAS interception
        let kprobes = [
            (
                "shadow_at_cmd_inject",
                "tty_write",
                "F89: AT Command Injection",
            ),
            (
                "shadow_baseband_exploit",
                "usb_submit_urb",
                "F90: Baseband Exploitation",
            ),
            ("shadow_sim_clone", "vfs_read", "F91: SIM Data Extraction"),
            (
                "shadow_imsi_intercept",
                "qmi_wwan_rx_fixup",
                "F92: IMSI Interception",
            ),
            (
                "shadow_rrc_redirect",
                "tty_write",
                "F93: RRC Connection Redirect",
            ),
            (
                "shadow_nas_intercept",
                "qmi_wwan_rx_fixup",
                "F98: NAS Message Interception",
            ),
            (
                "shadow_supi_deconceal",
                "ecies_decrypt",
                "F99: 5G SUPI De-concealment",
            ),
        ];

        attach_kprobes!(kprobes);

        // XDP on GTP interface for tunnel hijacking
        if let Some(prog) = bpf.program_mut("shadow_gtp_hijack") {
            let xdp: &mut Xdp = prog.try_into()?;
            xdp.load()?;
            xdp.attach(&cli.gtp_iface, XdpFlags::default())?;
            info!("F94: GTP Tunnel Hijacking enabled on {}", cli.gtp_iface);
        }

        // TC classifiers for SS7/Diameter/NGAP/protocol downgrade
        let tc_progs = [
            ("shadow_protocol_downgrade", "F93: Protocol Downgrade"),
            ("shadow_ss7_inject", "F95: SS7 MAP Injection"),
            ("shadow_diameter_exploit", "F96: Diameter AVP Manipulation"),
            ("shadow_n2_inject", "F100: 5G N2 Interface Injection"),
        ];

        for (name, desc) in &tc_progs {
            if let Some(prog) = bpf.program_mut(name) {
                let tc: &mut SchedClassifier = prog.try_into()?;
                tc.load()?;
                info!("{} loaded (attach to interface manually)", desc);
            }
        }
    }

    // ── Features 101-108: Advanced Telecom ───────────────────────────────────
    if enable_advanced {
        let advanced_kprobes = [
            (
                "shadow_volte_intercept",
                "sip_msg_send",
                "F101: VoLTE/VoNR Interception",
            ),
            (
                "shadow_esim_exploit",
                "tty_write",
                "F102: eSIM Provisioning Attack",
            ),
            (
                "shadow_femtocell_exploit",
                "ipsec_output",
                "F106: Femtocell Exploitation",
            ),
        ];

        attach_kprobes!(advanced_kprobes);

        // XDP for WiFi calling exploitation
        if let Some(prog) = bpf.program_mut("shadow_wifi_calling_exploit") {
            let xdp: &mut Xdp = prog.try_into()?;
            xdp.load()?;
            xdp.attach(&cli.wifi_iface, XdpFlags::default())?;
            info!(
                "F104: WiFi Calling Exploitation enabled on {}",
                cli.wifi_iface
            );
        }

        // TC classifiers for advanced telecom
        let tc_advanced = [
            ("shadow_slice_exploit", "F103: Network Slicing Exploit"),
            ("shadow_li_abuse", "F105: Lawful Intercept Abuse"),
            ("shadow_supl_spoof", "F107: SUPL/Location Spoofing"),
            ("shadow_roaming_pivot", "F108: Roaming/IPX Pivoting"),
        ];

        for (name, desc) in &tc_advanced {
            if let Some(prog) = bpf.program_mut(name) {
                let tc: &mut SchedClassifier = prog.try_into()?;
                tc.load()?;
                info!("{} loaded", desc);
            }
        }
    }

    // ── Features 109-120: 5G Advanced / RAN / SBI / Identity ──────────────────
    if enable_5g {
        let kprobes_5g = [
            (
                "shadow_pbch_sib_spoof",
                "tty_write",
                "F109: PBCH/SIB Broadcast Spoofing",
            ),
            (
                "shadow_rrc_meas_manipulate",
                "qmi_wwan_rx_fixup",
                "F110: RRC Measurement Report Manipulation",
            ),
            (
                "shadow_oauth2_theft",
                "tcp_sendmsg",
                "F114: OAuth2 Token Theft (NF-to-NF)",
            ),
            (
                "shadow_mimo_fingerprint",
                "qmi_wwan_rx_fixup",
                "F116: MIMO Beamforming Fingerprinting",
            ),
            (
                "shadow_aka_downgrade",
                "tcp_sendmsg",
                "F118: 5G-AKA Downgrade to EAP-AKA'",
            ),
            (
                "shadow_suci_replay",
                "tcp_sendmsg",
                "F119: SUCI Replay Attack",
            ),
            (
                "shadow_arpf_probe",
                "tcp_sendmsg",
                "F120: ARPF Key Extraction Probe",
            ),
        ];

        attach_kprobes!(kprobes_5g);

        // XDP on SDR interface for jamming evasion
        if let Some(prog) = bpf.program_mut("shadow_jamming_evasion") {
            let xdp: &mut Xdp = prog.try_into()?;
            xdp.load()?;
            xdp.attach(&cli.sdr_iface, XdpFlags::default())?;
            info!(
                "F115: Jamming Detection Evasion enabled on {}",
                cli.sdr_iface
            );
        }

        // TC classifiers for SBI/RAN/sidelink exploitation
        let tc_5g = [
            ("shadow_handover_hijack", "F111: Handover Hijacking"),
            ("shadow_sbi_exploit", "F112: HTTP/2 SBI Exploitation"),
            ("shadow_nrf_abuse", "F113: NRF API Abuse"),
            ("shadow_sidelink_exploit", "F117: Sidelink PC5/V2X Exploit"),
        ];

        for (name, desc) in &tc_5g {
            if let Some(prog) = bpf.program_mut(name) {
                let tc: &mut SchedClassifier = prog.try_into()?;
                tc.load()?;
                info!("{} loaded (attach to {} manually)", desc, cli.sbi_iface);
            }
        }
    }

    // ── Features 121-134: Satellite Communications ────────────────────────────
    if enable_satellite {
        let sat_kprobes = [
            (
                "shadow_dvbs2_intercept",
                "dvb_dmx_swfilter_packets",
                "F121: DVB-S2 Downlink Interception",
            ),
            (
                "shadow_ntn_timing_exploit",
                "tcp_sendmsg",
                "F123: NTN Timing Advance Exploitation",
            ),
            (
                "shadow_iridium_capture",
                "sdr_rx_callback",
                "F125: Iridium L-Band Frame Capture",
            ),
            (
                "shadow_vsat_firmware_extract",
                "usb_submit_urb",
                "F127: VSAT Terminal Firmware Extraction",
            ),
            (
                "shadow_starlink_auth_probe",
                "tcp_sendmsg",
                "F129: Starlink Dishy Auth Probe",
            ),
            (
                "shadow_sarsat_beacon_spoof",
                "sdr_rx_callback",
                "F132: COSPAS-SARSAT Beacon Spoofing",
            ),
        ];

        attach_kprobes!(sat_kprobes);

        // XDP on satellite interface for ISL fingerprinting and GNSS spoofing
        let sat_xdp_progs = [
            ("shadow_isl_fingerprint", "F130: ISL Laser Link Fingerprint"),
            ("shadow_gnss_l1_spoof", "F133: GPS L1 C/A Code Spoofing"),
            (
                "shadow_gnss_l5_spoof",
                "F134: Multi-Constellation L5/E5 Spoofing",
            ),
        ];

        for (name, desc) in &sat_xdp_progs {
            if let Some(prog) = bpf.program_mut(name) {
                let xdp: &mut Xdp = prog.try_into()?;
                xdp.load()?;
                xdp.attach(&cli.sat_iface, XdpFlags::default())?;
                info!("{} enabled on {}", desc, cli.sat_iface);
            }
        }

        // TC classifiers for satellite injection
        let tc_sat = [
            (
                "shadow_transponder_hijack",
                "F122: Transponder Hijack Injection",
            ),
            (
                "shadow_ntn_gateway_inject",
                "F124: NTN-5G Core Gateway Injection",
            ),
            (
                "shadow_leo_signaling_inject",
                "F126: LEO Constellation Signaling Injection",
            ),
            (
                "shadow_scpc_carrier_manip",
                "F128: SCPC Carrier Manipulation",
            ),
            ("shadow_adsb_inject", "F131: ADS-B/ACARS Frame Injection"),
        ];

        for (name, desc) in &tc_sat {
            if let Some(prog) = bpf.program_mut(name) {
                let tc: &mut SchedClassifier = prog.try_into()?;
                tc.load()?;
                info!("{} loaded (attach to {} manually)", desc, cli.sat_iface);
            }
        }
    }

    // ── Features 135-172: RF Protocol Domains ────────────────────────────────
    if enable_rf {
        let rf_kprobes = [
            (
                "shadow_tetra_intercept",
                "sdr_rx_callback",
                "F135: TETRA Air Interface Intercept",
            ),
            (
                "shadow_p25_control_harvest",
                "sdr_rx_callback",
                "F137: P25 Control Channel Harvest",
            ),
            (
                "shadow_ble_gatt_enum",
                "hci_send_frame",
                "F139: BLE GATT Enumeration",
            ),
            (
                "shadow_ble_pairing_downgrade",
                "smp_send_cmd",
                "F140: BLE Pairing Downgrade",
            ),
            (
                "shadow_blueborne_probe",
                "l2cap_recv_frame",
                "F141: BlueBorne-style RCE Probe",
            ),
            (
                "shadow_zigbee_key_sniff",
                "sdr_rx_callback",
                "F143: Zigbee Network Key Sniff",
            ),
            (
                "shadow_zwave_s0_extract",
                "sdr_rx_callback",
                "F144: Z-Wave S0 Key Extraction",
            ),
            (
                "shadow_lorawan_join_replay",
                "sdr_rx_callback",
                "F146: LoRaWAN Join Replay",
            ),
            (
                "shadow_lora_phy_jam",
                "sdr_rx_callback",
                "F148: LoRa PHY Jamming/Capture",
            ),
            (
                "shadow_nbiot_rrc_exploit",
                "qmi_wwan_rx_fixup",
                "F149: NB-IoT RRC/NAS Exploit",
            ),
            (
                "shadow_wpa3_dragonblood",
                "cfg80211_rx_mgmt",
                "F152: WPA3 Dragonblood Exploit",
            ),
            (
                "shadow_evil_twin_karma",
                "cfg80211_rx_mgmt",
                "F153: Evil Twin/Karma Attack",
            ),
            (
                "shadow_pmkid_capture",
                "cfg80211_rx_mgmt",
                "F155: PMKID Capture",
            ),
            (
                "shadow_rolljam_attack",
                "sdr_rx_callback",
                "F156: RollJam Rolling Code Attack",
            ),
            (
                "shadow_dji_droneid_fingerprint",
                "sdr_rx_callback",
                "F159: DJI OcuSync Fingerprint",
            ),
            (
                "shadow_pocsag_decode",
                "sdr_rx_callback",
                "F161: POCSAG Message Decode",
            ),
            (
                "shadow_flex_intercept",
                "sdr_rx_callback",
                "F162: FLEX/ReFLEX Intercept",
            ),
            (
                "shadow_oran_xapp_exploit",
                "tcp_sendmsg",
                "F169: O-RAN xApp Exploitation",
            ),
            (
                "shadow_ais_cpa_abuse",
                "sdr_rx_callback",
                "F172: AIS Collision Avoidance Abuse",
            ),
        ];

        attach_kprobes!(rf_kprobes);

        // XDP programs for RF domains (SDR + fronthaul interfaces)
        let rf_xdp_progs = [
            (
                "shadow_p25_imbe_intercept",
                "F138: P25 IMBE Voice Interception",
                &cli.sdr_iface,
            ),
            (
                "shadow_lorawan_abp_hijack",
                "F147: LoRaWAN ABP Session Hijack",
                &cli.sdr_iface,
            ),
            (
                "shadow_rke_relay_attack",
                "F157: RKE Relay/Amplification Attack",
                &cli.sdr_iface,
            ),
            (
                "shadow_fpv_video_intercept",
                "F160: FPV Video Link Intercept",
                &cli.sdr_iface,
            ),
            (
                "shadow_ecpri_iq_intercept",
                "F167: eCPRI IQ Sample Intercept",
                &cli.fronthaul_iface,
            ),
        ];

        for (name, desc, iface) in &rf_xdp_progs {
            if let Some(prog) = bpf.program_mut(name) {
                let xdp: &mut Xdp = prog.try_into()?;
                xdp.load()?;
                xdp.attach(iface, XdpFlags::default())?;
                info!("{} enabled on {}", desc, iface);
            }
        }

        // TC classifiers for RF domain injection
        let tc_rf = [
            ("shadow_tetra_downgrade", "F136: TETRA Encryption Downgrade"),
            ("shadow_ble_adv_spoof", "F142: BLE Advertisement Spoofing"),
            (
                "shadow_thread_mle_exploit",
                "F145: Thread/6LoWPAN MLE Exploit",
            ),
            (
                "shadow_ltem_edrx_timing",
                "F150: LTE-M eDRX/PSM Timing Attack",
            ),
            (
                "shadow_wifi_deauth_flood",
                "F151: WiFi Deauth/Disassoc Flood",
            ),
            ("shadow_ft_roaming_abuse", "F154: FT Roaming Abuse"),
            ("shadow_mavlink_inject", "F158: MAVLink Command Injection"),
            ("shadow_rds_inject", "F163: FM RDS Injection"),
            (
                "shadow_dab_ensemble_manip",
                "F164: DAB+ Ensemble Manipulation",
            ),
            ("shadow_eas_same_inject", "F165: SAME/EAS Header Injection"),
            ("shadow_wea_cmas_inject", "F166: WEA/CMAS Cell Broadcast"),
            (
                "shadow_fronthaul_mitm_inject",
                "F168: Fronthaul MitM Injection",
            ),
            (
                "shadow_f1ap_cu_du_exploit",
                "F170: CU/DU Split Exploitation",
            ),
            ("shadow_ais_position_spoof", "F171: AIS Position Spoofing"),
        ];

        for (name, desc) in &tc_rf {
            if let Some(prog) = bpf.program_mut(name) {
                let tc: &mut SchedClassifier = prog.try_into()?;
                tc.load()?;
                info!(
                    "{} loaded (attach to {}/{} manually)",
                    desc, cli.sdr_iface, cli.fronthaul_iface
                );
            }
        }
    }

    // ── Event loop (ring buffer) ─────────────────────────────────────────────
    let events_map = bpf
        .take_map("EVENTS")
        .context("EVENTS map not found in eBPF object")?;
    let mut ring_buf =
        RingBuf::try_from(events_map).context("failed to open EVENTS ring buffer")?;

    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<EventHeader>(1024);
    let rb_running = running.clone();

    tokio::task::spawn_blocking(move || {
        while rb_running.load(Ordering::Relaxed) {
            while let Some(item) = ring_buf.next() {
                let ptr = item.as_ptr() as *const EventHeader;
                let header = unsafe { ptr.read_unaligned() };
                if event_tx.blocking_send(header).is_err() {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });

    tokio::spawn(async move {
        while let Some(header) = event_rx.recv().await {
            info!(
                "EVENT type={} pid={} ts={}",
                header.event_type, header.pid, header.timestamp_ns
            );
        }
    });

    info!(
        "StaticZero Offense Engine running ({} attached probe group(s)). Press Ctrl+C to stop.",
        attachments.len()
    );
    signal::ctrl_c().await?;
    running.store(false, Ordering::SeqCst);
    info!("Shutting down.");
    Ok(())
}
