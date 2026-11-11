//! Offline policy/pipeline coverage plus an opt-in real-kernel smoke test.
//! The privileged test is deliberately ignored, not silently skipped.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Context, Result};
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use common::modem::{modem_access_alert, MODEM_ACCESS_OPENAT};
use common::{DefenseAlert, ALERT_MODEM_TAMPER};
use defense::adaptive::AdaptiveThresholds;
use defense::bus::InProcessBus;
use defense::metrics::Metrics;
use defense::persistence::AlertStore;
use defense::pipeline::{decode_alert, AlertPipeline};
use defense::probes::encode_modem_path;
use defense::server::{build_router, AppState};
use defense::TelecomCorrelationMetrics;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt;

struct Fixture {
    directory: PathBuf,
}

impl Fixture {
    fn new() -> Result<Self> {
        let base = if std::path::Path::new("/tmp/opencode").is_dir() {
            PathBuf::from("/tmp/opencode")
        } else {
            std::env::temp_dir()
        };
        let directory = base.join(format!(
            "sz-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        std::fs::create_dir(&directory)?;
        std::fs::write(
            directory.join("modem"),
            b"ordinary test file; no radio hardware",
        )?;
        std::fs::write(directory.join("benign"), b"benign control")?;
        Ok(Self { directory })
    }
    fn watched(&self) -> PathBuf {
        self.directory.join("modem")
    }
    fn database(&self) -> PathBuf {
        self.directory.join("alerts.sqlite")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for name in [
            "modem",
            "benign",
            "alerts.sqlite",
            "alerts.sqlite-wal",
            "alerts.sqlite-shm",
        ] {
            let _ = std::fs::remove_file(self.directory.join(name));
        }
        let _ = std::fs::remove_dir(&self.directory);
    }
}

/// Encode the native ring-buffer ABI without assuming the source is aligned.
fn record(alert: &DefenseAlert) -> Vec<u8> {
    let mut bytes = vec![0]; // Deliberately unaligned start in offline smoke test.
    for value in [alert.alert_type, alert.severity, alert.pid, alert._pad] {
        bytes.extend(value.to_ne_bytes());
    }
    bytes.extend(alert.timestamp_ns.to_ne_bytes());
    bytes.extend(alert.context.to_ne_bytes());
    bytes.extend(alert.details);
    bytes
}

async fn assert_pipeline(fixture: &Fixture, alert: DefenseAlert) -> Result<()> {
    ensure!(alert.alert_type == ALERT_MODEM_TAMPER);
    ensure!(alert.pid == std::process::id());
    ensure!(alert.context == alert.pid as u64);
    ensure!(u32::from_le_bytes(alert.details[..4].try_into()?) == MODEM_ACCESS_OPENAT);
    let state = Arc::new(AppState {
        metrics: Metrics::new()?,
        store: Some(Mutex::new(AlertStore::open(&fixture.database())?)),
        correlation_metrics: RwLock::new(TelecomCorrelationMetrics::default()),
        start_time: Instant::now(),
    });
    let mut pipeline = AlertPipeline::new(
        60,
        state.clone(),
        Arc::new(Mutex::new(AdaptiveThresholds::new(0.6))),
        Arc::new(InProcessBus::new(16)),
    );
    // One access alert is not evidence of a compound telecom attack.
    ensure!(pipeline.process(&alert).await?.is_none());
    ensure!(state.metrics.events_processed.get() == 1);
    ensure!(state.correlation_metrics.read().await.events_processed == 1);
    ensure!(state.correlation_metrics.read().await.threats_detected == 0);
    let router = build_router(state);
    for endpoint in ["/api/v1/alerts", "/api/v1/stats", "/metrics"] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(endpoint).body(Body::empty())?)
            .await?;
        ensure!(response.status() == StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        if endpoint == "/api/v1/alerts" {
            let json: serde_json::Value = serde_json::from_slice(&body)?;
            ensure!(json.as_array().unwrap().len() == 1);
            ensure!(json[0]["alert_type"] == ALERT_MODEM_TAMPER);
            ensure!(json[0]["pid"] == alert.pid);
        } else if endpoint == "/api/v1/stats" {
            let json: serde_json::Value = serde_json::from_slice(&body)?;
            ensure!(json["events_processed"] == 1);
        } else {
            let text = std::str::from_utf8(&body)?;
            ensure!(text.contains("staticzero_events_processed_total 1"));
            ensure!(text.contains(&format!(
                "staticzero_alerts_total{{alert_type=\"{ALERT_MODEM_TAMPER}\",severity=\"4\"}} 1"
            )));
        }
    }
    drop(router);
    drop(pipeline);
    let reopened = AlertStore::open(&fixture.database())?;
    ensure!(reopened.recent_alerts(10)?.len() == 1);
    ensure!(reopened.recent_threats(10)?.is_empty());
    Ok(())
}

#[tokio::test]
async fn offline_modem_policy_pipeline_smoke() -> Result<()> {
    let fixture = Fixture::new()?;
    let watched = encode_modem_path(&fixture.watched())?;
    let benign = encode_modem_path(&fixture.directory.join("benign"))?;
    let pid = std::process::id();
    ensure!(modem_access_alert(&benign, &watched, false, pid, 1).is_none());
    ensure!(modem_access_alert(&watched, &watched, true, pid, 1).is_none());
    ensure!(modem_access_alert(&watched, &[0; 128], false, pid, 1).is_none());
    let prefix_collision = encode_modem_path(&fixture.directory.join("modem-extra"))?;
    ensure!(modem_access_alert(&prefix_collision, &watched, false, pid, 1).is_none());
    let alert = modem_access_alert(&watched, &watched, false, pid, 1).unwrap();
    let bytes = record(&alert);
    assert_pipeline(&fixture, decode_alert(&bytes[1..])?).await
}

#[tokio::test]
async fn shared_pipeline_preserves_correlated_threat_delivery() -> Result<()> {
    use defense::bus::BusMessage;
    use defense::ThreatCategory;
    let state = Arc::new(AppState {
        metrics: Metrics::new()?,
        store: Some(Mutex::new(AlertStore::open_in_memory()?)),
        correlation_metrics: RwLock::new(TelecomCorrelationMetrics::default()),
        start_time: Instant::now(),
    });
    let bus = Arc::new(InProcessBus::new(16));
    let mut threats = bus.subscribe_threats();
    let mut pipeline = AlertPipeline::new(
        60,
        state.clone(),
        Arc::new(Mutex::new(AdaptiveThresholds::new(0.6))),
        bus,
    );
    let mut alert = DefenseAlert {
        alert_type: common::ALERT_ROGUE_TOWER,
        severity: 4,
        pid: 1,
        _pad: 0,
        timestamp_ns: 1_000_000_000,
        context: 42,
        details: [0; 16],
    };
    ensure!(pipeline.process(&alert).await?.is_none());
    alert.alert_type = common::ALERT_DOWNGRADE_ATTACK;
    alert.timestamp_ns += 1_000_000_000;
    let threat = pipeline.process(&alert).await?.unwrap();
    ensure!(threat.category == ThreatCategory::ManInTheMiddle);
    let message = tokio::time::timeout(Duration::from_secs(1), threats.recv()).await??;
    ensure!(matches!(message, BusMessage::Threat(_)));
    ensure!(state.metrics.events_processed.get() == 2);
    ensure!(state.correlation_metrics.read().await.events_processed == 2);
    let store = state.store.as_ref().unwrap().lock().await;
    ensure!(store.recent_alerts(10)?.len() == 2);
    ensure!(store.recent_threats(10)?.len() == 1);
    Ok(())
}

#[cfg(target_os = "linux")]
fn openat(path: &std::path::Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // Explicit native syscall makes this test independent of libc's open/openat2 choice.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
            0,
        )
    };
    ensure!(
        fd >= 0,
        "openat failed: {}",
        std::io::Error::last_os_error()
    );
    unsafe {
        libc::close(fd as i32);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn collect(
    ring: &mut aya::maps::RingBuf<aya::maps::MapData>,
    duration: Duration,
) -> Result<Vec<DefenseAlert>> {
    let deadline = Instant::now() + duration;
    let mut alerts = Vec::new();
    loop {
        while let Some(item) = ring.next() {
            alerts.push(decode_alert(&item)?);
        }
        if Instant::now() >= deadline {
            return Ok(alerts);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires a built defense eBPF object, tracefs, and BPF/perf privileges in an isolated VM"]
async fn privileged_modem_openat_smoke() -> Result<()> {
    use aya::maps::{HashMap, RingBuf};
    use defense::probes::{attach_probes, configure_modem_probe, select_probes, ProbeStatus};
    let fixture = Fixture::new()?;
    let object = std::env::var_os("STATICZERO_BPF_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../target/bpfel-unknown-none/release/staticzero-defense")
        });
    let selected = select_probes(&[22], &[])?;
    let report = defense::doctor::inspect(&object, &selected, &fixture.watched(), &[]);
    report.print(false)?;
    ensure!(
        report.passed(),
        "privileged smoke preflight failed (this test does not skip failures)"
    );
    let mut bpf = aya::BpfLoader::new().load_file(object)?;
    configure_modem_probe(
        &mut bpf,
        &fixture.watched(),
        &[],
        defense::doctor::openat_layout()?.1,
    )?;
    let mut ring = RingBuf::try_from(bpf.take_map("DEFENSE_ALERTS").unwrap())?;
    let attached = attach_probes(&mut bpf, &selected);
    ensure!(
        attached.reports[0].status == ProbeStatus::Active,
        "attach failed: {:?}",
        attached.reports[0]
    );

    openat(&fixture.directory.join("benign"))?;
    ensure!(
        collect(&mut ring, Duration::from_millis(250))
            .await?
            .is_empty(),
        "benign path emitted an alert"
    );
    openat(&fixture.watched())?;
    let alerts = collect(&mut ring, Duration::from_secs(1)).await?;
    ensure!(
        alerts.len() == 1,
        "expected exactly one kernel alert, got {}",
        alerts.len()
    );
    ensure!(alerts[0].timestamp_ns > 0);
    HashMap::<_, u32, u8>::try_from(bpf.map_mut("MODEM_ACCESS_PIDS").unwrap())?.insert(
        std::process::id(),
        1,
        0,
    )?;
    openat(&fixture.watched())?;
    ensure!(
        collect(&mut ring, Duration::from_millis(250))
            .await?
            .is_empty(),
        "allowlisted PID emitted an alert"
    );
    drop(ring);
    drop(attached); // Detaches per-CPU perf events before unloading programs.
    drop(bpf); // Detaches before fixture/database cleanup.
    assert_pipeline(&fixture, alerts[0]).await
}

/// A real character device node (PTY slave in /dev/pts) instead of a plain
/// file, so the monitored path is an actual device the kernel resolves
/// through devtmpfs.
struct Pty {
    master: libc::c_int,
    slave_path: PathBuf,
}

impl Pty {
    fn new() -> Result<Self> {
        let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        ensure!(
            master >= 0,
            "posix_openpt failed: {}",
            std::io::Error::last_os_error()
        );
        unsafe {
            libc::grantpt(master);
            libc::unlockpt(master);
        }
        let mut name = [0u8; 64];
        let rc =
            unsafe { libc::ptsname_r(master, name.as_mut_ptr() as *mut libc::c_char, name.len()) };
        ensure!(
            rc == 0,
            "ptsname_r failed: {}",
            std::io::Error::from_raw_os_error(rc)
        );
        let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        Ok(Self {
            master,
            slave_path: PathBuf::from(String::from_utf8_lossy(&name[..len]).into_owned()),
        })
    }

    fn slave(&self) -> &PathBuf {
        &self.slave_path
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.master);
        }
    }
}

#[cfg(target_os = "linux")]
async fn modem_device_smoke(device: &std::path::Path) -> Result<()> {
    use aya::maps::RingBuf;
    use defense::probes::{attach_probes, configure_modem_probe, select_probes, ProbeStatus};
    let fixture = Fixture::new()?;
    let object = std::env::var_os("STATICZERO_BPF_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../target/bpfel-unknown-none/release/staticzero-defense")
        });
    let selected = select_probes(&[22], &[])?;
    let report = defense::doctor::inspect(&object, &selected, device, &[]);
    report.print(false)?;
    ensure!(
        report.passed(),
        "privileged smoke preflight failed (this test does not skip failures)"
    );
    let mut bpf = aya::BpfLoader::new().load_file(object)?;
    configure_modem_probe(&mut bpf, device, &[], defense::doctor::openat_layout()?.1)?;
    let mut ring = RingBuf::try_from(bpf.take_map("DEFENSE_ALERTS").unwrap())?;
    let attached = attach_probes(&mut bpf, &selected);
    ensure!(
        attached.reports[0].status == ProbeStatus::Active,
        "attach failed: {:?}",
        attached.reports[0]
    );

    openat(&fixture.directory.join("benign"))?;
    ensure!(
        collect(&mut ring, Duration::from_millis(250))
            .await?
            .is_empty(),
        "benign path emitted an alert"
    );
    // O_NONBLOCK: a real modem port must never block the test; O_NOCTTY: the
    // test must not steal the PTY as its controlling terminal.
    openat_flags(device, libc::O_RDONLY | libc::O_NOCTTY | libc::O_NONBLOCK)?;
    let alerts = collect(&mut ring, Duration::from_secs(1)).await?;
    ensure!(
        alerts.len() == 1,
        "expected exactly one kernel alert from opening {}, got {}",
        device.display(),
        alerts.len()
    );
    ensure!(alerts[0].pid == std::process::id());
    drop(ring);
    drop(attached);
    drop(bpf);
    assert_pipeline(&fixture, alerts[0]).await
}

#[cfg(target_os = "linux")]
fn openat_flags(path: &std::path::Path, flags: libc::c_int) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let fd = unsafe { libc::syscall(libc::SYS_openat, libc::AT_FDCWD, path.as_ptr(), flags, 0) };
    ensure!(
        fd >= 0,
        "openat({}) failed: {}",
        path.to_string_lossy(),
        std::io::Error::last_os_error()
    );
    unsafe {
        libc::close(fd as i32);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires a built defense eBPF object, tracefs, and BPF/perf privileges in an isolated VM"]
async fn privileged_modem_pty_smoke() -> Result<()> {
    let pty = Pty::new()?;
    ensure!(pty.slave().is_absolute(), "pty slave path must be absolute");
    modem_device_smoke(pty.slave()).await
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "opt-in: set STATICZERO_MODEM_DEVICE=/dev/ttyUSB0 (or /dev/cdc-wdm0) against real lab hardware"]
async fn privileged_real_modem_smoke() -> Result<()> {
    let device = std::env::var_os("STATICZERO_MODEM_DEVICE").context(
        "STATICZERO_MODEM_DEVICE is not set; point it at a real modem device node \
         (for example /dev/ttyUSB0 or /dev/cdc-wdm0) to run the real modem access smoke test",
    )?;
    let device = PathBuf::from(device);
    ensure!(
        device.is_absolute(),
        "STATICZERO_MODEM_DEVICE must be absolute"
    );
    std::fs::metadata(&device)
        .with_context(|| format!("configured modem device {} is missing", device.display()))?;
    modem_device_smoke(&device).await
}
