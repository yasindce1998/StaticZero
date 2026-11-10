//! Read-only preflight: never calls BPF load, attaches a probe, or changes privileges.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use aya_obj::{Object, ProgramSection};
use serde::Serialize;

use crate::probes::{encode_modem_path, Attachment, ProbeReport, ProbeSpec, ProbeStatus};

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Warning,
    Fail,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub checks: Vec<Check>,
    pub modules: Vec<ProbeReport>,
}

impl DoctorReport {
    pub fn passed(&self) -> bool {
        !self
            .checks
            .iter()
            .any(|check| matches!(check.status, CheckStatus::Fail))
            && self
                .modules
                .iter()
                .any(|module| module.status == ProbeStatus::Available)
            && !self
                .modules
                .iter()
                .any(|module| module.status == ProbeStatus::Failed)
    }

    pub fn print(&self, json: bool) -> Result<()> {
        if json {
            println!("{}", serde_json::to_string_pretty(self)?);
        } else {
            println!("StaticZero defense preflight (read-only; no probes loaded)");
            for check in &self.checks {
                println!("{:?}: {} — {}", check.status, check.name, check.detail);
            }
            for module in &self.modules {
                println!(
                    "Module {} [{}]: {:?} — {}",
                    module.module, module.program, module.status, module.detail
                );
            }
            println!("Preflight {}. Availability is not proof of verifier acceptance or successful attachment.", if self.passed() { "passed" } else { "failed" });
        }
        Ok(())
    }
}

fn check(name: &'static str, result: Result<String>) -> Check {
    match result {
        Ok(detail) => Check {
            name,
            status: CheckStatus::Pass,
            detail,
        },
        Err(error) => Check {
            name,
            status: CheckStatus::Fail,
            detail: format!("{error:#}"),
        },
    }
}

fn kernel_supported(release: &str) -> bool {
    let mut numbers = release.split('.');
    let major = numbers
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = numbers
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    (major, minor) >= (5, 15)
}

fn has_bpf_caps(status: &str) -> bool {
    let caps = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
        .unwrap_or(0);
    caps & (1 << 21) != 0 || (caps & (1 << 38) != 0 && caps & (1 << 39) != 0)
}

/// Validate the actual running kernel's ABI rather than assuming an offset.
pub fn filename_offset(format: &str) -> Result<u32> {
    for line in format.lines() {
        let fields: Vec<_> = line.split(';').map(str::trim).collect();
        let Some(declaration) = fields
            .first()
            .and_then(|field| field.strip_prefix("field:"))
        else {
            continue;
        };
        if declaration.split_whitespace().last() != Some("filename") {
            continue;
        }
        if !declaration.contains("char") || !declaration.contains('*') {
            bail!("filename is not a char pointer");
        }
        let number = |key: &str| -> Option<u32> {
            fields
                .iter()
                .find_map(|field| field.strip_prefix(key))
                .and_then(|value| value.trim().parse().ok())
        };
        let offset = number("offset:").context("filename offset missing")?;
        if number("size:") != Some(8) || !(8..=256).contains(&offset) || !offset.is_multiple_of(8) {
            bail!(
                "unsupported filename layout: requires an aligned 64-bit pointer at offset 8-256"
            );
        }
        return Ok(offset);
    }
    bail!("filename field missing from openat tracepoint format")
}

pub fn openat_layout() -> Result<(PathBuf, u32)> {
    let mut errors = Vec::new();
    for root in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
        let event = Path::new(root).join("events/syscalls/sys_enter_openat");
        let result = (|| -> Result<u32> {
            fs::read_to_string(event.join("id"))?
                .trim()
                .parse::<u32>()
                .context("invalid tracepoint ID")?;
            filename_offset(&fs::read_to_string(event.join("format"))?)
        })();
        match result {
            Ok(offset) => return Ok((event, offset)),
            Err(error) => errors.push(format!("{}: {error:#}", event.display())),
        }
    }
    bail!("openat tracepoint unavailable; mount tracefs and check CONFIG_FTRACE_SYSCALLS/permissions: {}", errors.join("; "))
}

pub fn inspect(
    bpf_path: &Path,
    selected: &[&ProbeSpec],
    modem_path: &Path,
    allowed_pids: &[u32],
) -> DoctorReport {
    let mut checks = vec![check(
        "platform",
        if cfg!(target_os = "linux") && cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
            Ok(format!(
                "Linux {} (64-bit native openat only)",
                std::env::consts::ARCH
            ))
        } else {
            Err(anyhow::anyhow!(
                "unsupported platform; use Linux x86_64 or aarch64"
            ))
        },
    )];
    checks.push(check(
        "kernel",
        (|| {
            let release = fs::read_to_string("/proc/sys/kernel/osrelease")?;
            if !kernel_supported(release.trim()) {
                bail!("requires Linux 5.15+; found {}", release.trim());
            }
            Ok(release.trim().to_owned())
        })(),
    ));
    checks.push(check("privileges", (|| {
        if !has_bpf_caps(&fs::read_to_string("/proc/self/status")?) {
            bail!("requires effective CAP_BPF + CAP_PERFMON (or CAP_SYS_ADMIN); run with sudo in an isolated VM; root alone in a restricted container may not suffice");
        }
        Ok("effective capabilities permit attempting BPF/perf loading; LSM/lockdown may still deny it".into())
    })()));
    checks.push(Check {
        name: "kernel_btf",
        status: if Path::new("/sys/kernel/btf/vmlinux").is_file() {
            CheckStatus::Pass
        } else {
            CheckStatus::Warning
        },
        detail: "vmlinux BTF is optional for the openat adapter; it does not use CO-RE relocations"
            .into(),
    });
    for (name, path) in [
        (
            "unprivileged_bpf_disabled",
            "/proc/sys/kernel/unprivileged_bpf_disabled",
        ),
        (
            "perf_event_paranoid",
            "/proc/sys/kernel/perf_event_paranoid",
        ),
    ] {
        checks.push(Check {
            name,
            status: CheckStatus::Warning,
            detail: format!(
                "{} (informational; capabilities/LSM determine actual access)",
                fs::read_to_string(path)
                    .unwrap_or_else(|_| "unreadable".into())
                    .trim()
            ),
        });
    }
    let object = fs::read(bpf_path)
        .with_context(|| {
            format!(
                "read {}; build with cargo xtask build-ebpf --release",
                bpf_path.display()
            )
        })
        .and_then(|bytes| Object::parse(&bytes).context("parse eBPF ELF object"));
    checks.push(check(
        "ebpf_object",
        object
            .as_ref()
            .map(|_| bpf_path.display().to_string())
            .map_err(|e| anyhow::anyhow!("{e:#}")),
    ));
    let modules = selected.iter().map(|spec| {
        let Attachment::TracePoint { category, event } = spec.attachment else {
            let Attachment::Unsupported(reason) = spec.attachment else { unreachable!() };
            return ProbeReport::new(spec, ProbeStatus::Unsupported, reason);
        };
        let result = (|| -> Result<String> {
            encode_modem_path(modem_path)?;
            if allowed_pids.len() > 32 || allowed_pids.contains(&0) { bail!("at most 32 nonzero allowed PIDs are supported"); }
            let object = object.as_ref().map_err(|e| anyhow::anyhow!("{e:#}"))?;
            if !matches!(object.programs.get(spec.program).map(|program| &program.section), Some(ProgramSection::TracePoint)) {
                bail!("{} missing or wrong program type; rebuild defense eBPF object", spec.program);
            }
            for map in ["DEFENSE_ALERTS", "MODEM_MONITORED_PATH", "MODEM_FILENAME_OFFSET", "MODEM_ACCESS_PIDS"] {
                if !object.maps.contains_key(map) { bail!("required map {map} missing; rebuild defense eBPF object"); }
            }
            let (_, offset) = openat_layout()?;
            Ok(format!("tracepoint {category}/{event}, filename offset {offset}; exact pathname {} (attempts only, no path resolution)", modem_path.display()))
        })();
        match result {
            Ok(detail) => ProbeReport::new(spec, ProbeStatus::Available, detail),
            Err(error) => ProbeReport::new(spec, ProbeStatus::Failed, format!("{error:#}")),
        }
    }).collect();
    DoctorReport { checks, modules }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracepoint_layout_is_validated() {
        assert_eq!(
            filename_offset("field:const char * filename; offset:24; size:8; signed:0;").unwrap(),
            24
        );
        assert!(filename_offset("field:const char * filename; offset:24; size:4;").is_err());
        assert!(filename_offset("field:unsigned long filename; offset:24; size:8;").is_err());
        assert!(filename_offset("field:const char * filename; offset:999; size:8;").is_err());
        assert!(filename_offset("").is_err());
    }

    #[test]
    fn kernel_and_privilege_checks_are_not_uid_checks() {
        assert!(kernel_supported("5.15.0-generic"));
        assert!(kernel_supported("7.2.9-arch1-1"));
        assert!(!kernel_supported("5.14.99"));
        assert!(!kernel_supported("invalid"));
        assert!(!has_bpf_caps("Uid:\t0\nCapEff:\t0000000000000000"));
        assert!(has_bpf_caps("CapEff:\t000000c000000000"));
        assert!(has_bpf_caps("CapEff:\t0000000000200000"));
        assert!(!has_bpf_caps("CapEff:\t0000008000000000"));
    }

    #[test]
    fn preflight_needs_one_available_module_and_no_failures() {
        let spec = &crate::probes::PROBES[6];
        let mut report = DoctorReport {
            checks: Vec::new(),
            modules: Vec::new(),
        };
        assert!(!report.passed());
        report.modules.push(ProbeReport::new(
            spec,
            ProbeStatus::Unsupported,
            "no adapter",
        ));
        assert!(!report.passed());
        report.modules.push(ProbeReport::new(
            spec,
            ProbeStatus::Available,
            "tracepoint found",
        ));
        assert!(report.passed());
        report.modules.push(ProbeReport::new(
            spec,
            ProbeStatus::Failed,
            "missing program",
        ));
        assert!(!report.passed());
        report.modules.pop();
        report.checks.push(Check {
            name: "privileges",
            status: CheckStatus::Fail,
            detail: "missing capabilities".into(),
        });
        assert!(!report.passed());
    }
}
