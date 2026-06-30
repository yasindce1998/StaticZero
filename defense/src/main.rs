use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use aya::maps::AsyncPerfEventArray;
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::EbpfLoader;
use bytes::BytesMut;
use clap::Parser;
use tokio::signal;
use tokio::sync::{mpsc, watch, Mutex, RwLock};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use common::DefenseAlert;
use defense::adaptive::AdaptiveThresholds;
use defense::bus::{BusMessage, InProcessBus, MessagePublisher, ThreatEnvelope};
use defense::config::{Config, ConfigWatcher};
use defense::metrics::Metrics;
use defense::persistence::AlertStore;
use defense::security::{harden_process, validate_environment, SecurityConfig};
use defense::server::{build_router, AppState};
use defense::{TelecomCorrelationEngine, TelecomCorrelationMetrics};

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

    /// Enable basic telecom detection (modules 16-23)
    #[arg(long, default_value_t = true)]
    telecom_detect: bool,

    /// Enable advanced telecom detection (modules 24-28)
    #[arg(long)]
    telecom_advanced: bool,

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
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let running = Arc::new(AtomicBool::new(true));

    // ── Phase 6: Security hardening ─────────────────────────────────────────
    if !cli.no_harden {
        let warnings = validate_environment();
        for w in &warnings {
            warn!("{}", w);
        }
        harden_process(&SecurityConfig::default())?;
    }

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
    let metrics = Metrics::new();
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

    if config.server.enabled {
        let router = build_router(app_state.clone());
        let listen_addr = config.server.listen_addr.clone();
        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(&listen_addr)
                .await
                .expect("failed to bind HTTP server");
            info!("HTTP server listening on {}", listen_addr);
            axum::serve(listener, router).await.ok();
        });
    }

    // ── eBPF loading ────────────────────────────────────────────────────────
    info!("StaticZero Telecom Defense Engine starting");
    info!("Loading eBPF programs from {:?}", cli.bpf_path);

    let mut bpf = EbpfLoader::new()
        .load_file(&cli.bpf_path)
        .context("failed to load eBPF object")?;

    let enable_telecom = cli.all || cli.telecom_detect;
    let enable_advanced = cli.all || cli.telecom_advanced;

    if enable_telecom {
        let probes = [
            ("detect_rogue_tower", "Module 16: Rogue Tower Detection"),
            (
                "detect_downgrade_attack",
                "Module 17: Downgrade Attack Detection",
            ),
            ("detect_imsi_catcher", "Module 18: IMSI Catcher Detection"),
            (
                "detect_cell_param_anomaly",
                "Module 19: Cell Parameter Anomaly",
            ),
            ("detect_gtp_anomaly", "Module 20: GTP Traffic Anomaly"),
            ("detect_ss7_anomaly", "Module 21: SS7/SIGTRAN Anomaly"),
            ("detect_modem_tamper", "Module 22: Modem Tamper Detection"),
            (
                "detect_nas_replay",
                "Module 23: NAS Replay/Injection Detection",
            ),
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

    if enable_advanced {
        let probes = [
            ("detect_volte_fraud", "Module 24: VoLTE Fraud Detection"),
            ("detect_esim_tamper", "Module 25: eSIM Provisioning Monitor"),
            (
                "detect_slice_violation",
                "Module 26: Slice Isolation Verification",
            ),
            (
                "detect_roaming_anomaly",
                "Module 27: Roaming Anomaly Detection",
            ),
            (
                "detect_rf_fingerprint",
                "Module 28: RF Fingerprint Analysis",
            ),
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

    // ── Alert event loop with full integration ──────────────────────────────
    let mut correlation_engine = TelecomCorrelationEngine::new(correlation_window);
    let (alert_tx, mut alert_rx) = mpsc::channel::<DefenseAlert>(4096);

    let correlation_running = running.clone();
    let correlation_metrics = metrics.clone();
    let correlation_bus = bus.clone();
    let correlation_adaptive = adaptive.clone();
    let correlation_store = app_state.clone();

    tokio::spawn(async move {
        while let Some(alert) = alert_rx.recv().await {
            if !correlation_running.load(Ordering::Relaxed) {
                break;
            }

            correlation_metrics.record_alert(alert.alert_type, alert.severity);
            let details = defense::format_alert_details(&alert);

            // Persist raw alert
            if let Some(ref store) = correlation_store.store {
                let store = store.lock().await;
                let _ = store.insert_alert(
                    alert.timestamp_ns,
                    alert.alert_type,
                    alert.severity,
                    alert.pid,
                    alert.context,
                    &details,
                );
            }

            // Correlate
            let threat = correlation_engine.ingest_alert(&alert);

            if let Some(ref threat) = threat {
                let adaptive_lock = correlation_adaptive.lock().await;
                if !adaptive_lock.should_fire(&threat.category, threat.confidence) {
                    continue;
                }
                drop(adaptive_lock);

                correlation_metrics.record_threat(&format!("{:?}", threat.category));

                // Persist threat
                if let Some(ref store) = correlation_store.store {
                    let store = store.lock().await;
                    let _ = store.insert_threat(threat);
                }

                // Publish to bus
                let envelope = ThreatEnvelope::from(threat);
                let _ = correlation_bus
                    .publish("threats", &BusMessage::Threat(envelope))
                    .await;
            }

            // Output
            if json_mode {
                let threat_json = threat
                    .as_ref()
                    .map(|t| serde_json::to_string(t).unwrap_or_default());
                println!(
                    r#"{{"timestamp_ns":{},"alert_type":{},"severity":{},"details":"{}","threat":{}}}"#,
                    alert.timestamp_ns,
                    alert.alert_type,
                    alert.severity,
                    details,
                    threat_json.as_deref().unwrap_or("null")
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

            // Update shared metrics for HTTP endpoints
            let mut cm = correlation_store.correlation_metrics.write().await;
            *cm = correlation_engine.metrics.clone();
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

    // ── Per-CPU perf event readers ──────────────────────────────────────────
    let mut perf_array = AsyncPerfEventArray::try_from(
        bpf.take_map("DEFENSE_ALERTS")
            .context("DEFENSE_ALERTS map not found")?,
    )?;

    let cpus = online_cpus().map_err(|e| anyhow::anyhow!("failed to get online CPUs: {}", e))?;
    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;
        let running = running.clone();
        let tx = alert_tx.clone();

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
                    if tx.send(alert).await.is_err() {
                        return;
                    }
                }
            }
        });
    }
    drop(alert_tx);

    info!("StaticZero Defense Engine running. Press Ctrl+C to stop.");
    signal::ctrl_c().await?;
    running.store(false, Ordering::SeqCst);
    info!("Shutting down.");
    Ok(())
}
