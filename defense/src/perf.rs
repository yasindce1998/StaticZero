//! Per-CPU perf event attachment for eBPF programs.
//!
//! aya's `TracePoint::attach` opens a single perf event with `cpu = 0`
//! (`perf_event_open_trace_point` in aya's `sys` module), so a program
//! attached that way only fires for events that execute on CPU 0 and
//! silently misses every other CPU. The helpers here open one perf event
//! per online CPU and pin the loaded program with `PERF_EVENT_IOC_SET_BPF`,
//! which is what libbpf and BCC do for tracepoints and kprobes.

use std::fs;
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};

/// `PERF_ATTR_SIZE_VER1` (72 bytes): the kernel accepts truncated
/// `perf_event_attr` structs and treats this size as a stable ABI boundary.
/// Field layout: type, size, config, sample_period, sample_type, read_format,
/// flags bitfield (u64), wakeup (u32 + pad), config1, config2.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup: u32,
    _pad: u32,
    config1: u64,
    config2: u64,
}

impl PerfEventAttr {
    fn new(type_: u32, config: u64) -> Self {
        Self {
            type_,
            size: std::mem::size_of::<PerfEventAttr>() as u32,
            config,
            sample_period: 0,
            sample_type: 0,
            read_format: 0,
            flags: 0,
            wakeup: 0,
            _pad: 0,
            config1: 0,
            config2: 0,
        }
    }
}

const PERF_TYPE_TRACEPOINT: u32 = 2;
const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 8;
/// `_IO('$', 0)`
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
/// `_IO('$', 1)`
const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;
/// `_IOW('$', 8, __u32)` — ioctl number 8; 5 is SET_OUTPUT, which the kernel
/// answers with ENOTTY. Values cross-checked against aya-obj's generated
/// UAPI bindings (`AYA_PERF_EVENT_IOC_*`).
const PERF_EVENT_IOC_SET_BPF: libc::c_ulong = 0x4004_2408;

/// Owned perf event file descriptors holding an attached program. Dropping
/// disables the events and closes the descriptors, which detaches the program.
#[derive(Debug)]
pub struct PerfEvents {
    fds: Vec<libc::c_int>,
}

impl PerfEvents {
    pub fn len(&self) -> usize {
        self.fds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fds.is_empty()
    }
}

impl Drop for PerfEvents {
    fn drop(&mut self) {
        for fd in self.fds.drain(..) {
            unsafe {
                libc::ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
                libc::close(fd);
            }
        }
    }
}

/// Online CPU numbers parsed from `/sys/devices/system/cpu/online`
/// (for example `0-3,8`).
pub fn online_cpus() -> Result<Vec<u32>> {
    let text =
        fs::read_to_string("/sys/devices/system/cpu/online").context("reading online CPU list")?;
    parse_cpu_list(&text)
}

fn parse_cpu_list(text: &str) -> Result<Vec<u32>> {
    let mut cpus = Vec::new();
    for part in text.trim().split(',') {
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let start: u32 = start
                .trim()
                .parse()
                .with_context(|| format!("invalid CPU range start in {part:?}"))?;
            let end: u32 = end
                .trim()
                .parse()
                .with_context(|| format!("invalid CPU range end in {part:?}"))?;
            ensure!(start <= end, "inverted CPU range {part:?}");
            cpus.extend(start..=end);
        } else {
            let cpu: u32 = part
                .trim()
                .parse()
                .with_context(|| format!("invalid CPU number {part:?}"))?;
            cpus.push(cpu);
        }
    }
    ensure!(!cpus.is_empty(), "online CPU list is empty");
    Ok(cpus)
}

/// Resolve a tracepoint id from tracefs, validating that the event exists.
pub fn tracepoint_id(category: &str, event: &str) -> Result<u32> {
    let mut errors = Vec::new();
    for root in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
        let dir = Path::new(root).join("events").join(category).join(event);
        let result = (|| -> Result<u32> {
            fs::read_to_string(dir.join("id"))
                .with_context(|| format!("reading {}", dir.join("id").display()))?
                .trim()
                .parse::<u32>()
                .context("invalid tracepoint id")
        })();
        match result {
            Ok(id) => return Ok(id),
            Err(error) => errors.push(format!("{}: {error:#}", dir.display())),
        }
    }
    bail!(
        "tracepoint {category}/{event} unavailable: {}",
        errors.join("; ")
    )
}

fn open_perf_event(attr: &PerfEventAttr, cpu: u32) -> Result<libc::c_int> {
    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            attr,
            -1 as libc::pid_t,
            cpu as libc::c_int,
            -1 as libc::c_int,
            PERF_FLAG_FD_CLOEXEC,
        )
    };
    if fd < 0 {
        bail!(
            "perf_event_open on cpu {cpu} failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(fd as libc::c_int)
}

/// Open one perf event per online CPU for `tp_id` (`PERF_TYPE_TRACEPOINT`)
/// and pin `prog_fd` to each one. Every event fires immediately.
pub fn attach_tracepoint_all_cpus(prog_fd: libc::c_int, tp_id: u32) -> Result<PerfEvents> {
    let cpus = online_cpus()?;
    let attr = PerfEventAttr::new(PERF_TYPE_TRACEPOINT, tp_id as u64);
    let mut fds = Vec::with_capacity(cpus.len());
    let mut attach = || -> Result<()> {
        for cpu in &cpus {
            let fd = open_perf_event(&attr, *cpu)?;
            let pinned = unsafe { libc::ioctl(fd, PERF_EVENT_IOC_SET_BPF, prog_fd as libc::c_int) };
            if pinned < 0 {
                let error = std::io::Error::last_os_error();
                unsafe { libc::close(fd) };
                bail!("PERF_EVENT_IOC_SET_BPF on cpu {cpu} failed: {error}");
            }
            let enabled = unsafe { libc::ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) };
            if enabled < 0 {
                let error = std::io::Error::last_os_error();
                unsafe { libc::close(fd) };
                bail!("PERF_EVENT_IOC_ENABLE on cpu {cpu} failed: {error}");
            }
            fds.push(fd);
        }
        Ok(())
    };
    match attach() {
        Ok(()) => Ok(PerfEvents { fds }),
        Err(error) => {
            for fd in fds.drain(..) {
                unsafe { libc::close(fd) };
            }
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_cpu() {
        assert_eq!(parse_cpu_list("2\n").unwrap(), vec![2]);
    }

    #[test]
    fn parses_ranges_and_lists() {
        assert_eq!(parse_cpu_list("0-3\n").unwrap(), vec![0, 1, 2, 3]);
        assert_eq!(parse_cpu_list("0-1,4\n").unwrap(), vec![0, 1, 4]);
        assert_eq!(parse_cpu_list(" 0 - 2 , 5 \n").unwrap(), vec![0, 1, 2, 5]);
    }

    #[test]
    fn rejects_invalid_lists() {
        assert!(parse_cpu_list("").is_err());
        assert!(parse_cpu_list("x\n").is_err());
        assert!(parse_cpu_list("3-1\n").is_err());
        assert!(parse_cpu_list("1-2,x\n").is_err());
    }

    #[test]
    fn attr_layout_matches_perf_attr_size_ver1() {
        assert_eq!(std::mem::size_of::<PerfEventAttr>(), 72);
        assert_eq!(std::mem::align_of::<PerfEventAttr>(), 8);
        let attr = PerfEventAttr::new(PERF_TYPE_TRACEPOINT, 42);
        assert_eq!(attr.size, 72);
        assert_eq!(attr.type_, 2);
        assert_eq!(attr.config, 42);
    }

    /// Regression test: an earlier revision used ioctl number 5 (SET_OUTPUT)
    /// for SET_BPF, which every kernel answers with ENOTTY.
    #[test]
    fn ioctl_numbers_match_the_kernel_uapi() {
        assert_eq!(PERF_EVENT_IOC_ENABLE, 0x2400); // _IO('$', 0)
        assert_eq!(PERF_EVENT_IOC_DISABLE, 0x2401); // _IO('$', 1)
        assert_eq!(PERF_EVENT_IOC_SET_BPF, 0x4004_2408); // _IOW('$', 8, __u32)
    }
}
