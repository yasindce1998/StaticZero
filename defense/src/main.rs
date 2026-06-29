use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use aya::programs::{KProbe, TracePoint};
use aya::{Ebpf, EbpfLoader};
use aya::maps::AsyncPerfEventArray;
use aya::util::online_cpus;
use bytes::BytesMut;
use clap::Parser;
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use common::DefenseAlert;
use defense::TelecomCorrelationEngine;

#[derive(Parser, Debug)]
#[command(name = "staticzero-defense")]
#[command(about = "StaticZero Telecom Network Defense Engine")]
struct Cli {
    /// Path to compiled eBPF object file
    #[arg(short, long, default_value = "target/bpfel-unknown-none/release/staticzero-defense")]
    bpf_path: PathBuf,

    /// Enable basic telecom detection (modules 16-23: rogue tower, downgrade, IMSI catcher, etc.)
    #[arg(long, default_value_t = true)]
    telecom_detect: bool,

    /// Enable advanced telecom detection (modules 24-28: VoLTE fraud, eSIM, slicing, roaming, RF)
    #[arg(long)]
    telecom_advanced: bool,

    /// Enable all detection modules
    #[arg(long)]
    all: bool,

    /// JSON output mode for SIEM integration
    #[arg(long)]
    json: bool,

    /// Correlation window in seconds
    #[arg(long, default_value_t = 30)]
    correlation_window: u64,
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

    info!("StaticZero Telecom Defense Engine starting");
    info!("Loading eBPF programs from {:?}", cli.bpf_path);

    let mut bpf = EbpfLoader::new()
        .load_file(&cli.bpf_path)
        .context("failed to load eBPF object")?;

    let enable_telecom = cli.all || cli.telecom_detect;
    let enable_advanced = cli.all || cli.telecom_advanced;

    // ── Modules 16-23: Basic Telecom Detection ───────────────────────────────
    if enable_telecom {
        let probes = [
            ("detect_rogue_tower", "Module 16: Rogue Tower Detection"),
            ("detect_downgrade_attack", "Module 17: Downgrade Attack Detection"),
            ("detect_imsi_catcher", "Module 18: IMSI Catcher Detection"),
            ("detect_cell_param_anomaly", "Module 19: Cell Parameter Anomaly"),
            ("detect_gtp_anomaly", "Module 20: GTP Traffic Anomaly"),
            ("detect_ss7_anomaly", "Module 21: SS7/SIGTRAN Anomaly"),
            ("detect_modem_tamper", "Module 22: Modem Tamper Detection"),
            ("detect_nas_replay", "Module 23: NAS Replay/Injection Detection"),
        ];

        for (name, desc) in &probes {
            match bpf.program_mut(name) {
                Some(prog) => {
                    let kprobe: &mut KProbe = prog.try_into()?;
                    kprobe.load()?;
                    kprobe.attach(name.trim_start_matches("detect_"), 0)?;
                    info!("{} enabled", desc);
                }
                None => warn!("{} not found in eBPF object, skipping", name),
            }
        }
    }

    // ── Modules 24-28: Advanced Telecom Detection ────────────────────────────
    if enable_advanced {
        let probes = [
            ("detect_volte_fraud", "Module 24: VoLTE Fraud Detection"),
            ("detect_esim_tamper", "Module 25: eSIM Provisioning Monitor"),
            ("detect_slice_violation", "Module 26: Slice Isolation Verification"),
            ("detect_roaming_anomaly", "Module 27: Roaming Anomaly Detection"),
            ("detect_rf_fingerprint", "Module 28: RF Fingerprint Analysis"),
        ];

        for (name, desc) in &probes {
            match bpf.program_mut(name) {
                Some(prog) => {
                    let kprobe: &mut KProbe = prog.try_into()?;
                    kprobe.load()?;
                    kprobe.attach(name.trim_start_matches("detect_"), 0)?;
                    info!("{} enabled", desc);
                }
                None => warn!("{} not found in eBPF object, skipping", name),
            }
        }
    }

    // ── Alert event loop ─────────────────────────────────────────────────────
    let mut correlation_engine = TelecomCorrelationEngine::new(cli.correlation_window);

    let mut perf_array = AsyncPerfEventArray::try_from(
        bpf.take_map("DEFENSE_ALERTS").context("DEFENSE_ALERTS map not found")?,
    )?;

    let cpus = online_cpus().map_err(|e| anyhow::anyhow!("failed to get online CPUs: {}", e))?;
    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;
        let json_mode = cli.json;
        let running = running.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<DefenseAlert>()))
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
                    let ptr = buffers[i].as_ptr() as *const DefenseAlert;
                    let alert = unsafe { ptr.read_unaligned() };

                    let details = defense::format_alert_details(&alert);
                    if json_mode {
                        println!(
                            r#"{{"timestamp_ns":{},"alert_type":{},"severity":{},"details":"{}"}}"#,
                            alert.timestamp_ns, alert.alert_type, alert.severity, details
                        );
                    } else {
                        info!(
                            "ALERT type={} severity={} {}",
                            alert.alert_type, alert.severity, details
                        );
                    }
                }
            }
        });
    }

    info!("StaticZero Defense Engine running. Press Ctrl+C to stop.");
    signal::ctrl_c().await?;
    running.store(false, Ordering::SeqCst);
    info!("Shutting down.");
    Ok(())
}
