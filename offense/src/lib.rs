//! Loader helpers for StaticZero offense eBPF programs.
//!
//! aya's `KProbe::attach` opens a single perf event with `cpu = 0`, so a
//! program attached that way only observes calls that execute on CPU 0 and
//! silently misses every other CPU. [`attach_kprobe_all_cpus`] instead opens
//! one perf event per online CPU through the kprobe PMU (the same
//! `perf_event_open` path libbpf and BCC use) and pins the loaded program to
//! each one.

use std::ffi::CString;
use std::fs;
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use aya::programs::KProbe;
use aya::Bpf;

/// `PERF_ATTR_SIZE_VER1` (72 bytes): the kernel accepts truncated
/// `perf_event_attr` structs and treats this size as a stable ABI boundary.
#[repr(C)]
#[derive(Clone, Copy)]
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

const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 8;
/// `_IO('$', 0)`
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
/// `_IO('$', 1)`
const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;
/// `_IOW('$', 8, __u32)` — ioctl number 8; 5 is SET_OUTPUT, which the kernel
/// answers with ENOTTY. Values cross-checked against aya-obj's generated
/// UAPI bindings (`AYA_PERF_EVENT_IOC_*`).
const PERF_EVENT_IOC_SET_BPF: libc::c_ulong = 0x4004_2408;

/// Owned perf event descriptors holding a kprobe program attached on every
/// online CPU. Dropping disables the events and closes the descriptors, which
/// detaches (and unregisters the per-CPU probe events).
#[derive(Debug)]
pub struct ProbeAttachment {
    symbol: String,
    fds: Vec<libc::c_int>,
}

impl ProbeAttachment {
    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    pub fn len(&self) -> usize {
        self.fds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fds.is_empty()
    }
}

impl Drop for ProbeAttachment {
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

/// The kprobe PMU type id (`/sys/bus/event_source/devices/kprobe/type`).
/// Requires `CONFIG_KPROBE_EVENTS`; present in every mainstream distro kernel.
fn kprobe_pmu_type() -> Result<u32> {
    let text = fs::read_to_string("/sys/bus/event_source/devices/kprobe/type")
        .context("reading kprobe PMU type (requires CONFIG_KPROBE_EVENTS)")?;
    text.trim()
        .parse::<u32>()
        .context("invalid kprobe PMU type")
}

/// Load `program` from the eBPF object and attach it as a kprobe on `symbol`
/// with one perf event per online CPU. The returned guard must stay alive for
/// as long as the probe should run.
pub fn attach_kprobe_all_cpus(
    bpf: &mut Bpf,
    program: &str,
    symbol: &str,
) -> Result<ProbeAttachment> {
    let kprobe: &mut KProbe = bpf
        .program_mut(program)
        .with_context(|| format!("program {program} missing from eBPF object"))?
        .try_into()
        .with_context(|| format!("program {program} is not a kprobe"))?;
    kprobe.load().context("verifier rejected program")?;
    let prog_fd = kprobe
        .fd()
        .context("retrieving loaded program fd")?
        .as_fd()
        .as_raw_fd();
    let pmu_type = kprobe_pmu_type()?;
    let symbol_c = CString::new(symbol).context("kprobe symbol contains a NUL byte")?;
    let cpus = online_cpus()?;

    let attr = PerfEventAttr {
        type_: pmu_type,
        size: std::mem::size_of::<PerfEventAttr>() as u32,
        config: 0, // bit 0 would request a kretprobe
        sample_period: 0,
        sample_type: 0,
        read_format: 0,
        flags: 0,
        wakeup: 0,
        _pad: 0,
        config1: symbol_c.as_ptr() as u64,
        config2: 0,
    };

    let mut fds = Vec::with_capacity(cpus.len());
    let mut attach = || -> Result<()> {
        for cpu in &cpus {
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_perf_event_open,
                    &attr,
                    -1 as libc::pid_t,
                    *cpu as libc::c_int,
                    -1 as libc::c_int,
                    PERF_FLAG_FD_CLOEXEC,
                )
            };
            if fd < 0 {
                bail!(
                    "perf_event_open(kprobe {symbol}) on cpu {cpu} failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let fd = fd as libc::c_int;
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
        Ok(()) => Ok(ProbeAttachment {
            symbol: symbol.to_string(),
            fds,
        }),
        Err(error) => {
            for fd in fds.drain(..) {
                unsafe { libc::close(fd) };
            }
            Err(error)
        }
    }
}

/// Whether a kernel symbol is visible in kallsyms (and therefore attachable).
/// Offensive loaders must not assume every documented hook point exists on
/// the running kernel: `sdr_rx_callback` or `ecies_decrypt`, for example, are
/// not mainline symbols.
pub fn kernel_symbol_exists(symbol: &str) -> bool {
    let Ok(kallsyms) = fs::read_to_string(Path::new("/proc/kallsyms")) else {
        return false;
    };
    kallsyms
        .lines()
        .any(|line| line.split_whitespace().nth(2) == Some(symbol))
}

/// Decode an [`common::EventHeader`] from a ring-buffer record without
/// assuming the record is aligned.
pub fn decode_event(record: &[u8]) -> Result<common::EventHeader> {
    const HEADER_BYTES: usize = std::mem::size_of::<common::EventHeader>();
    ensure!(
        record.len() >= HEADER_BYTES,
        "ring record too short: {} bytes",
        record.len()
    );
    Ok(common::EventHeader {
        event_type: u32::from_ne_bytes(record[0..4].try_into()?),
        pid: u32::from_ne_bytes(record[4..8].try_into()?),
        timestamp_ns: u64::from_ne_bytes(record[8..16].try_into()?),
        context: u64::from_ne_bytes(record[16..24].try_into()?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cpu_lists() {
        assert_eq!(parse_cpu_list("2\n").unwrap(), vec![2]);
        assert_eq!(parse_cpu_list("0-3\n").unwrap(), vec![0, 1, 2, 3]);
        assert_eq!(parse_cpu_list("0-1,4\n").unwrap(), vec![0, 1, 4]);
        assert!(parse_cpu_list("").is_err());
        assert!(parse_cpu_list("3-1\n").is_err());
    }

    #[test]
    fn attr_layout_matches_perf_attr_size_ver1() {
        assert_eq!(std::mem::size_of::<PerfEventAttr>(), 72);
    }

    /// Regression test: an earlier revision used ioctl number 5 (SET_OUTPUT)
    /// for SET_BPF, which every kernel answers with ENOTTY.
    #[test]
    fn ioctl_numbers_match_the_kernel_uapi() {
        assert_eq!(PERF_EVENT_IOC_ENABLE, 0x2400); // _IO('$', 0)
        assert_eq!(PERF_EVENT_IOC_DISABLE, 0x2401); // _IO('$', 1)
        assert_eq!(PERF_EVENT_IOC_SET_BPF, 0x4004_2408); // _IOW('$', 8, __u32)
    }

    #[test]
    fn decodes_event_header_from_unaligned_bytes() {
        let header = common::EventHeader {
            event_type: 158,
            pid: 4242,
            timestamp_ns: 1_700_000_000_000_000_000,
            context: 0x1122_3344,
        };
        let mut bytes = Vec::new();
        bytes.extend(header.event_type.to_ne_bytes());
        bytes.extend(header.pid.to_ne_bytes());
        bytes.extend(header.timestamp_ns.to_ne_bytes());
        bytes.extend(header.context.to_ne_bytes());
        bytes.push(0xAA); // trailing padding byte must be ignored
        let decoded = decode_event(&bytes).unwrap();
        assert_eq!(decoded.event_type, header.event_type);
        assert_eq!(decoded.pid, header.pid);
        assert_eq!(decoded.timestamp_ns, header.timestamp_ns);
        assert_eq!(decoded.context, header.context);
    }

    #[test]
    fn rejects_short_event_records() {
        assert!(decode_event(&[0u8; 8]).is_err());
    }
}
