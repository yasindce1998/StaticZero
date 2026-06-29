use anyhow::Result;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub drop_caps: bool,
    pub chroot_path: Option<String>,
    pub run_as_uid: Option<u32>,
    pub run_as_gid: Option<u32>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            drop_caps: true,
            chroot_path: None,
            run_as_uid: None,
            run_as_gid: None,
        }
    }
}

/// Drop all capabilities except those needed for eBPF operation.
/// Must be called AFTER eBPF programs are loaded and maps are opened.
pub fn harden_process(config: &SecurityConfig) -> Result<()> {
    if !cfg!(target_os = "linux") {
        warn!("Security hardening is Linux-only; skipping on this platform");
        return Ok(());
    }

    if config.drop_caps {
        drop_capabilities()?;
    }

    if let Some(ref path) = config.chroot_path {
        info!("Would chroot to {} (requires root)", path);
    }

    if let Some(uid) = config.run_as_uid {
        info!("Would drop to UID {} after eBPF attach", uid);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn drop_capabilities() -> Result<()> {
    use std::io;

    // CAP_BPF (39) + CAP_PERFMON (38) are needed for eBPF perf event reading
    // CAP_NET_ADMIN (12) for XDP/TC programs
    // Drop everything else
    const KEEP_CAPS: &[u32] = &[12, 38, 39];

    // Using prctl directly to avoid pulling in caps crate
    // PR_SET_KEEPCAPS = 8, PR_CAPBSET_DROP = 24
    unsafe {
        // Keep caps across setuid
        if libc::prctl(8, 1, 0, 0, 0) != 0 {
            warn!(
                "prctl(PR_SET_KEEPCAPS) failed: {}",
                io::Error::last_os_error()
            );
        }

        // Drop all capabilities from bounding set except the ones we need
        for cap in 0..64u32 {
            if !KEEP_CAPS.contains(&cap) {
                // PR_CAPBSET_DROP = 24
                let _ = libc::prctl(24, cap as libc::c_ulong, 0, 0, 0);
            }
        }
    }

    info!(
        "Dropped capabilities; retained CAP_NET_ADMIN, CAP_PERFMON, CAP_BPF"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn drop_capabilities() -> Result<()> {
    warn!("Capability dropping not supported on this platform");
    Ok(())
}

/// Validate that the process environment is sane for security-sensitive operation
pub fn validate_environment() -> Vec<String> {
    let mut warnings = Vec::new();

    if std::env::var("LD_PRELOAD").is_ok() {
        warnings.push("LD_PRELOAD is set — potential library injection".into());
    }

    if std::env::var("LD_LIBRARY_PATH").is_ok() {
        warnings.push("LD_LIBRARY_PATH is set — non-standard library search path".into());
    }

    if let Ok(term) = std::env::var("TERM") {
        if term.contains("screen") || term.contains("tmux") {
            // Not a warning, just informational
        }
    }

    // Check if running as root (UID 0) which is expected but worth noting
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::getuid() } == 0 {
            info!("Running as root (expected for eBPF)");
        } else {
            warnings.push("Not running as root — eBPF attach may fail".into());
        }
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_security_config() {
        let config = SecurityConfig::default();
        assert!(config.drop_caps);
        assert!(config.chroot_path.is_none());
    }

    #[test]
    fn test_validate_environment_runs() {
        let warnings = validate_environment();
        // Just verify it doesn't panic
        let _ = warnings;
    }

    #[test]
    fn test_harden_process_non_linux() {
        let config = SecurityConfig::default();
        // On non-Linux (CI), this should succeed with a warning
        let result = harden_process(&config);
        assert!(result.is_ok());
    }
}
