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
/// Attach the diagnostic liveness probe alongside the modem probe so that a
/// failed assertion can distinguish "tracepoint never fired" from "filename
/// read or path match failed". The diagnostic writes no alerts.
fn configure_diagnostics(bpf: &mut aya::Bpf, pid: u32) -> Result<()> {
    use aya::maps::HashMap;
    use aya::programs::TracePoint;
    HashMap::<_, u32, u32>::try_from(
        bpf.map_mut("DIAG_PID")
            .context("DIAG_PID map missing from eBPF object")?,
    )?
    .insert(0, pid, 0)?;
    let diag: &mut TracePoint = bpf
        .program_mut("diag_openat")
        .context("diag_openat missing from eBPF object")?
        .try_into()?;
    diag.load().context("verifier rejected diag_openat")?;
    diag.attach("syscalls", "sys_enter_openat")
        .context("attaching diag_openat")?;
    Ok(())
}

#[cfg(target_os = "linux")]
/// Human-readable state of the diagnostic maps and the tracepoint, for
/// inclusion in test failure messages.
fn diagnostics(bpf: &aya::Bpf) -> String {
    use aya::maps::HashMap;
    let count: Option<u64> = bpf
        .map("DIAG_COUNT")
        .and_then(|map| HashMap::<_, u32, u64>::try_from(map).ok())
        .and_then(|map| map.get(&0, 0).ok());
    let read_rc: Option<i64> = bpf
        .map("DIAG_READ_RC")
        .and_then(|map| HashMap::<_, u32, i64>::try_from(map).ok())
        .and_then(|map| map.get(&0, 0).ok());
    let path: Option<[u8; common::modem::MODEM_PATH_BYTES]> = bpf
        .map("DIAG_PATH")
        .and_then(|map| {
            HashMap::<_, u32, [u8; common::modem::MODEM_PATH_BYTES]>::try_from(map).ok()
        })
        .and_then(|map| map.get(&0, 0).ok());

    let mut out = match count {
        Some(count) => format!("diag_openat invocations for this pid: {count}"),
        None => "diag_openat state unreadable".to_string(),
    };
    match read_rc {
        Some(rc) => {
            out.push_str(&format!(", last filename read rc: {rc}"));
            if let Some(path) = path {
                let end = path
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(path.len())
                    .min(48);
                out.push_str(&format!(
                    ", last requested path: {:?}",
                    String::from_utf8_lossy(&path[..end])
                ));
            }
        }
        None => out.push_str(", no filename read attempted"),
    }
    if let Ok(id) =
        std::fs::read_to_string("/sys/kernel/tracing/events/syscalls/sys_enter_openat/id")
    {
        out.push_str(&format!("; tracepoint id {}", id.trim_matches('\n')));
    }
    out
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
    configure_diagnostics(&mut bpf, std::process::id())?;

    openat(&fixture.directory.join("benign"))?;
    ensure!(
        collect(&mut ring, Duration::from_millis(250))
            .await?
            .is_empty(),
        "benign path emitted an alert ({})",
        diagnostics(&bpf)
    );
    openat(&fixture.watched())?;
    let alerts = collect(&mut ring, Duration::from_secs(1)).await?;
    if alerts.len() != 1 {
        anyhow::bail!(
            "expected exactly one kernel alert, got {} ({})",
            alerts.len(),
            diagnostics(&bpf)
        );
    }
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
        "allowlisted PID emitted an alert ({})",
        diagnostics(&bpf)
    );
    drop(ring);
    drop(attached);
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
    configure_diagnostics(&mut bpf, std::process::id())?;

    let diag_count = |bpf: &aya::Bpf| -> Option<u64> {
        let map = bpf.map("DIAG_COUNT")?;
        let map = aya::maps::HashMap::<_, u32, u64>::try_from(map).ok()?;
        map.get(&0, 0).ok()
    };

    // Three opens with the diagnostic counter and CPU read after each: a
    // regular file, an ordinary character device (/dev/null, same flag set as
    // the device under test), and the device itself. On failure the counts
    // bisect between "tracepoint machinery died after the first open" and
    // "the device open specifically skipped the syscall-enter BPF run"; the
    // CPU numbers expose per-CPU breakage in the kernel's syscall-enter
    // handling (the failure has behaved like a scheduler lottery).
    openat(&fixture.directory.join("benign"))?;
    let after_benign = (diag_count(&bpf), unsafe { libc::sched_getcpu() });
    ensure!(
        collect(&mut ring, Duration::from_millis(250))
            .await?
            .is_empty(),
        "benign path emitted an alert ({})",
        diagnostics(&bpf)
    );
    // O_NONBLOCK: a real modem port must never block the test; O_NOCTTY: the
    // test must not steal the PTY as its controlling terminal.
    let device_flags = libc::O_RDONLY | libc::O_NOCTTY | libc::O_NONBLOCK;
    openat_flags(std::path::Path::new("/dev/null"), device_flags)?;
    let after_null = (diag_count(&bpf), unsafe { libc::sched_getcpu() });
    ensure!(
        collect(&mut ring, Duration::from_millis(250))
            .await?
            .is_empty(),
        "/dev/null control emitted an alert ({})",
        diagnostics(&bpf)
    );
    openat_flags(device, device_flags)?;
    let after_device = (diag_count(&bpf), unsafe { libc::sched_getcpu() });
    let alerts = collect(&mut ring, Duration::from_secs(1)).await?;
    // Machinery recheck: a regular-file open must still fire after the device
    // open; if it does not, the tracepoint died at (or before) the device open.
    openat(&fixture.directory.join("benign"))?;
    let after_recheck = (diag_count(&bpf), unsafe { libc::sched_getcpu() });
    if alerts.len() != 1 {
        anyhow::bail!(
            "expected exactly one kernel alert from opening {}, got {} \
             (diag counts/cpu: benign={:?}, /dev/null={:?}, device={:?}, recheck={:?}; {})",
            device.display(),
            alerts.len(),
            after_benign,
            after_null,
            after_device,
            after_recheck,
            diagnostics(&bpf)
        );
    }
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
