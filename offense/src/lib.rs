//! Attachment helpers for StaticZero eBPF programs.
//!
//! One perf event per probe is the canonical attachment model, matching aya
//! and libbpf: the loaded program is placed in the *tracepoint's shared
//! program array* (`event->tp_event->prog_array`), which the kernel executes
//! on every CPU where the tracepoint or kprobe fires. Opening one perf event
//! per CPU and pinning the same program to each is rejected by the kernel
//! with EEXIST (`bpf_prog_array_copy` refuses duplicate programs), so per-CPU
//! attachment of a single program is impossible by design and unnecessary.

use anyhow::{Context, Result};
use aya::programs::KProbe;
use aya::Bpf;

/// Load `program` from the eBPF object and attach it as a kprobe on
/// `symbol`. The attachment lives as long as the `Bpf` object.
///
/// Returns an error when the symbol is not present in the running kernel's
/// kallsyms (for example `sdr_rx_callback` or `ecies_decrypt`, which are not
/// mainline symbols) — callers should treat that as "feature unavailable",
/// never as a crash.
pub fn attach_kprobe(bpf: &mut Bpf, program: &str, symbol: &str) -> Result<()> {
    let kprobe: &mut KProbe = bpf
        .program_mut(program)
        .with_context(|| format!("program {program} missing from eBPF object"))?
        .try_into()
        .with_context(|| format!("program {program} is not a kprobe"))?;
    kprobe.load().context("verifier rejected program")?;
    kprobe
        .attach(symbol, 0)
        .with_context(|| format!("attaching kprobe {program} to kernel symbol {symbol}"))?;
    // The probe runs on every CPU via the tracepoint program array; the perf
    // event opened by aya only keeps the event registered.
    Ok(())
}

/// Decode an [`common::EventHeader`] from a ring-buffer record without
/// assuming the record is aligned.
pub fn decode_event(record: &[u8]) -> Result<common::EventHeader> {
    const HEADER_BYTES: usize = std::mem::size_of::<common::EventHeader>();
    anyhow::ensure!(
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
