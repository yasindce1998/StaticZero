use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{ensure, Context, Result};
use aya::maps::RingBuf;
use aya::BpfLoader;
use clap::Parser;
use tokio::signal;
use tokio::sync::{mpsc, watch, Mutex, RwLock};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use common::DefenseAlert;
use defense::adaptive::AdaptiveThresholds;
use defense::bus::{BusMessage, InProcessBus};
use defense::config::{Config, ConfigWatcher};
use defense::metrics::Metrics;
use defense::persistence::AlertStore;
use defense::pipeline::{decode_alert, AlertPipeline};
use defense::probes::{
    attach_probes, configure_modem_probe, select_probes, ProbeGroup, ProbeStatus,
};
use defense::security::{harden_process, validate_environment, SecurityConfig};
use defense::server::{build_router, AppState};
use defense::TelecomCorrelationMetrics;

#[derive(Parser, Debug)]
#[command(name = "staticzero-defense")]
#[command(about = "StaticZero Telecom Network Defense Engine")]
struct Cli {
    /// Path to compiled eBPF object file
    #[arg(
        short,
        long,
        default_value = "target/bpfel-unknown-none/release/staticzero-defense"
    )]
    bpf_path: PathBuf,

    /// Configuration file path
    #[arg(short, long, default_value = "/etc/staticzero/config.toml")]
    config: PathBuf,

    /// Read-only platform, privilege, ELF, and attachment preflight; then exit
    #[arg(long)]
    doctor: bool,

    /// Select modules explicitly (comma-separated IDs); overrides group flags
    #[arg(long, value_delimiter = ',')]
    modules: Vec<u8>,

    /// Exact absolute pathname to observe in native openat attempts (Module 22)
    #[arg(long, default_value = "/dev/cdc-wdm0")]
    modem_path: PathBuf,

    /// Authorized process IDs for Module 22 (comma-separated; at most 32)
    #[arg(long, value_delimiter = ',')]
    allow_modem_pid: Vec<u32>,

    /// Enable basic telecom detection (modules 16-23)
    #[arg(long, default_value_t = true)]
    telecom_detect: bool,

    /// Enable advanced telecom detection (modules 24-28)
    #[arg(long)]
    telecom_advanced: bool,

    /// Enable 5G core defense modules (29-32)
    #[arg(long)]
    telecom_5g_defense: bool,

    /// Enable satellite defense modules (33-39)
    #[arg(long)]
    satellite_defense: bool,

    /// Enable RF protocol domain defense modules (40-55)
    #[arg(long)]
    rf_defense: bool,

    /// Enable all detection modules
    #[arg(long)]
    all: bool,

    /// JSON output mode for SIEM integration
    #[arg(long)]
    json: bool,

    /// Correlation window in seconds (overrides config)
    #[arg(long)]
    correlation_window: Option<u64>,

    /// Skip security hardening (for development)
    #[arg(long)]
    no_harden: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let mut groups = Vec::new();
    for (enabled, group) in [
        (cli.all || cli.telecom_detect, ProbeGroup::Telecom),
        (cli.all || cli.telecom_advanced, ProbeGroup::Advanced),
        (cli.all || cli.telecom_5g_defense, ProbeGroup::Core),
        (cli.all || cli.satellite_defense, ProbeGroup::Satellite),
        (cli.all || cli.rf_defense, ProbeGroup::Rf),
    ] {
        if enabled {
            groups.push(group);
        }
    }
    let selected = select_probes(&cli.modules, &groups)?;
    let preflight = defense::doctor::inspect(
        &cli.bpf_path,
        &selected,
        &cli.modem_path,
        &cli.allow_modem_pid,
    );
    if cli.doctor || !preflight.passed() {
        preflight.print(cli.json)?;
    }
    ensure!(
        preflight.passed(),
        "defense preflight failed; use --doctor for details"
    );
    if cli.doctor {
        return Ok(());
    }
    let running = Arc::new(AtomicBool::new(true));

    // ── Phase 4: Load configuration ─────────────────────────────────────────
    let config = Config::load_or_default(&cli.config);
    let config_arc = Arc::new(config.clone());
    let (config_tx, _config_rx) = watch::channel(config_arc.clone());

    let _config_watcher = if cli.config.exists() {
        match ConfigWatcher::start(cli.config.clone(), config_tx) {
            Ok(w) => {
                info!("Config hot-reload enabled for {:?}", cli.config);
                Some(w)
            }
            Err(e) => {
                warn!(
                    "Config watcher failed to start: {}. Hot-reload disabled.",
                    e
                );
                None
            }
        }
    } else {
        info!("No config file at {:?}, using defaults", cli.config);
        None
    };

    let correlation_window = cli
        .correlation_window
        .unwrap_or(config.engine.correlation_window_secs);
    let json_mode = cli.json || config.engine.json_output;

    // ── Phase 3: Observability — metrics ────────────────────────────────────
    let metrics = Metrics::new()?;
    let start_time = Instant::now();

    // ── Phase 2: Persistence layer ──────────────────────────────────────────
    let store = if config.persistence.enabled {
        match AlertStore::open(&config.persistence.db_path) {
            Ok(s) => {
                info!(
                    "SQLite persistence enabled at {:?}",
                    config.persistence.db_path
                );
                Some(s)
            }
            Err(e) => {
                warn!("Failed to open alert store: {}. Persistence disabled.", e);
                None
            }
        }
    } else {
        None
    };

    // ── Phase 7: Adaptive thresholds ────────────────────────────────────────
    let adaptive = Arc::new(tokio::sync::Mutex::new(AdaptiveThresholds::new(
        config.thresholds.min_confidence,
    )));

    // ── Phase 5: Message bus ────────────────────────────────────────────────
    let bus = Arc::new(InProcessBus::new(4096));

    // ── Phase 3: HTTP server ────────────────────────────────────────────────
    let app_state = Arc::new(AppState {
        metrics: metrics.clone(),
        store: store.map(Mutex::new),
        correlation_metrics: RwLock::new(TelecomCorrelationMetrics::default()),
        start_time,
    });

    // ── eBPF loading ────────────────────────────────────────────────────────
    info!("StaticZero Telecom Defense Engine starting");
    info!("Loading eBPF programs from {:?}", cli.bpf_path);

    let mut bpf = BpfLoader::new()
        .load_file(&cli.bpf_path)
        .context("failed to load eBPF object")?;

    let (_, filename_offset) = defense::doctor::openat_layout()?;
    configure_modem_probe(
        &mut bpf,
        &cli.modem_path,
        &cli.allow_modem_pid,
        filename_offset,
    )?;
    let attached = attach_probes(&mut bpf, &selected);
    for report in &attached.reports {
        match report.status {
            ProbeStatus::Active => info!(module = report.module, "active: {}", report.detail),
            _ => warn!(module = report.module, status = ?report.status, "{}", report.detail),
        }
    }
    ensure!(
        attached
            .reports
            .iter()
            .any(|report| report.status == ProbeStatus::Active),
        "no defense modules attached"
    );

    // ── Alert event loop with full integration ──────────────────────────────
    let mut pipeline = AlertPipeline::new(
        correlation_window,
        app_state.clone(),
        adaptive.clone(),
        bus.clone(),
    );
    let (alert_tx, mut alert_rx) = mpsc::channel::<DefenseAlert>(4096);

    let correlation_running = running.clone();

    tokio::spawn(async move {
        while let Some(alert) = alert_rx.recv().await {
            if !correlation_running.load(Ordering::Relaxed) {
                break;
            }

            let details = defense::format_alert_details(&alert);
            let threat = match pipeline.process(&alert).await {
                Ok(threat) => threat,
                Err(error) => {
                    warn!("Alert processing failed: {error:#}");
                    continue;
                }
            };

            // Output
            if json_mode {
                println!(
                    "{}",
                    serde_json::json!({
                        "timestamp_ns": alert.timestamp_ns, "alert_type": alert.alert_type,
                        "severity": alert.severity, "pid": alert.pid, "context": alert.context,
                        "details": details, "threat": threat,
                    })
                );
            } else {
                info!(
                    "ALERT type={} severity={} {}",
                    alert.alert_type, alert.severity, details
                );
                if let Some(ref t) = threat {
                    info!(
                        "THREAT id={} category={:?} confidence={:.2} severity={} — {}",
                        t.threat_id, t.category, t.confidence, t.severity, t.description
                    );
                }
            }
        }
    });

    // ── Feedback consumer (bus → adaptive thresholds) ───────────────────────
    let feedback_bus = bus.clone();
    let feedback_metrics = metrics.clone();
    tokio::spawn(async move {
        while let Some(msg) = feedback_bus.recv_feedback().await {
            if let BusMessage::FeedbackOverride {
                threat_id: _,
                is_false_positive,
                reason,
            } = msg
            {
                info!(
                    "Operator feedback: false_positive={} reason={}",
                    is_false_positive, reason
                );
                // For now we don't look up the category from the threat_id,
                // but in production you'd fetch the threat and get its category.
                feedback_metrics.record_false_positive_override();
            }
        }
    });

    // ── Alert reader (ring buffer → correlation pipeline) ────────────────────
    let alerts_map = bpf
        .take_map("DEFENSE_ALERTS")
        .context("DEFENSE_ALERTS map not found in eBPF object")?;
    let mut ring_buf =
        RingBuf::try_from(alerts_map).context("failed to open DEFENSE_ALERTS ring buffer")?;

    // Attach programs and open maps before privilege reduction.
    if !cli.no_harden {
        for warning in validate_environment() {
            warn!("{}", warning);
        }
        harden_process(&SecurityConfig::default())?;
    }

    // Bind before starting the blocking reader, so bind failures cannot leave
    // an unbounded reader alive while the Tokio runtime shuts down.
    let listener = if config.server.enabled {
        Some(
            tokio::net::TcpListener::bind(&config.server.listen_addr)
                .await
                .context("failed to bind HTTP server")?,
        )
    } else {
        None
    };

    let rb_tx = alert_tx.clone();
    let rb_running = running.clone();

    tokio::task::spawn_blocking(move || {
        while rb_running.load(Ordering::Relaxed) {
            while let Some(item) = ring_buf.next() {
                let alert = match decode_alert(&item) {
                    Ok(alert) => alert,
                    Err(error) => {
                        warn!("Discarding malformed ring buffer record: {error}");
                        continue;
                    }
                };
                if rb_tx.blocking_send(alert).is_err() {
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    });
    drop(alert_tx);

    // Do not expose the API until attachment and ring-buffer setup succeed.
    if let Some(listener) = listener {
        let router = build_router(app_state.clone());
        info!("HTTP server listening on {}", config.server.listen_addr);
        tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, router).await {
                warn!("HTTP server stopped: {error}");
            }
        });
    }

    info!("StaticZero Defense Engine running. Press Ctrl+C to stop.");
    let shutdown = signal::ctrl_c().await;
    running.store(false, Ordering::SeqCst);
    shutdown?;
    info!("Shutting down.");
    Ok(())
}
