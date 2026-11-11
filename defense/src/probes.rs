//! Explicit defense attachment registry. Decoded-value probes are not kernel ABIs.

use std::path::Path;

use anyhow::{bail, Context, Result};
use aya::maps::{Array, HashMap};
use aya::programs::TracePoint;
use aya::Bpf;
use common::modem::MODEM_PATH_BYTES;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeGroup {
    Telecom,
    Advanced,
    Core,
    Satellite,
    Rf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attachment {
    TracePoint {
        category: &'static str,
        event: &'static str,
    },
    Unsupported(&'static str),
}

#[derive(Debug)]
pub struct ProbeSpec {
    pub module: u8,
    pub program: &'static str,
    pub description: &'static str,
    pub group: ProbeGroup,
    pub attachment: Attachment,
}

const DECODED_ABI: &str =
    "expects decoded protocol arguments; no validated kernel or userspace adapter";

macro_rules! pending {
    ($id:literal, $program:literal, $description:literal, $group:ident) => {
        ProbeSpec {
            module: $id,
            program: $program,
            description: $description,
            group: ProbeGroup::$group,
            attachment: Attachment::Unsupported(DECODED_ABI),
        }
    };
}

pub static PROBES: &[ProbeSpec] = &[
    pending!(16, "detect_rogue_tower", "Rogue Tower Detection", Telecom),
    pending!(
        17,
        "detect_downgrade_attack",
        "Downgrade Attack Detection",
        Telecom
    ),
    pending!(18, "detect_imsi_catcher", "IMSI Catcher Detection", Telecom),
    pending!(
        19,
        "detect_cell_param_anomaly",
        "Cell Parameter Anomaly",
        Telecom
    ),
    pending!(20, "detect_gtp_anomaly", "GTP Traffic Anomaly", Telecom),
    pending!(21, "detect_ss7_anomaly", "SS7/SIGTRAN Anomaly", Telecom),
    ProbeSpec {
        module: 22,
        program: "detect_modem_tamper",
        description: "Modem openat Access Monitor (experimental)",
        group: ProbeGroup::Telecom,
        attachment: Attachment::TracePoint {
            category: "syscalls",
            event: "sys_enter_openat",
        },
    },
    pending!(
        23,
        "detect_nas_replay",
        "NAS Replay/Injection Detection",
        Telecom
    ),
    pending!(24, "detect_volte_fraud", "VoLTE Fraud Detection", Advanced),
    pending!(
        25,
        "detect_esim_tamper",
        "eSIM Provisioning Monitor",
        Advanced
    ),
    pending!(
        26,
        "detect_slice_violation",
        "Slice Isolation Verification",
        Advanced
    ),
    pending!(
        27,
        "detect_roaming_anomaly",
        "Roaming Anomaly Detection",
        Advanced
    ),
    pending!(
        28,
        "detect_rf_fingerprint",
        "RF Fingerprint Analysis",
        Advanced
    ),
    pending!(29, "detect_sbi_anomaly", "SBI Anomaly Detection", Core),
    pending!(
        30,
        "detect_handover_integrity",
        "Handover Integrity Monitoring",
        Core
    ),
    pending!(31, "detect_ran_sharing_leak", "RAN Sharing Isolation", Core),
    pending!(
        32,
        "detect_signaling_storm",
        "Signaling Storm Detection",
        Core
    ),
    pending!(
        33,
        "detect_dvbs2_anomaly",
        "DVB-S2/S2X Anomaly Detection",
        Satellite
    ),
    pending!(34, "detect_ntn_anomaly", "NTN Access Anomaly", Satellite),
    pending!(
        35,
        "detect_leo_signaling",
        "LEO Constellation Monitor",
        Satellite
    ),
    pending!(
        36,
        "detect_vsat_integrity",
        "VSAT/SCPC Integrity Monitor",
        Satellite
    ),
    pending!(
        37,
        "detect_starlink_auth",
        "Starlink Auth Monitor",
        Satellite
    ),
    pending!(
        38,
        "detect_aviation_integrity",
        "Aviation Signal Integrity",
        Satellite
    ),
    pending!(
        39,
        "detect_gnss_spoofing",
        "GNSS Spoofing Detection",
        Satellite
    ),
    pending!(
        40,
        "detect_tetra_encryption",
        "TETRA Encryption Monitor",
        Rf
    ),
    pending!(
        41,
        "detect_p25_control",
        "P25 Control Channel Integrity",
        Rf
    ),
    pending!(42, "detect_ble_pairing", "BLE Pairing/Scanning Defense", Rf),
    pending!(
        43,
        "detect_zigbee_key",
        "Zigbee/Z-Wave Key Provisioning Monitor",
        Rf
    ),
    pending!(44, "detect_lorawan_join", "LoRaWAN Join Integrity", Rf),
    pending!(45, "detect_nbiot_rrc", "NB-IoT/LTE-M RRC Anomaly", Rf),
    pending!(
        46,
        "detect_wifi_deauth",
        "WiFi Deauth/Disassoc Detection",
        Rf
    ),
    pending!(47, "detect_wpa3_integrity", "WPA3/FT Integrity Monitor", Rf),
    pending!(48, "detect_rke_jamming", "RKE Jamming Detection", Rf),
    pending!(49, "detect_uav_c2", "UAV C2 Integrity Monitor", Rf),
    pending!(50, "detect_pager_anomaly", "Pager Signal Anomaly", Rf),
    pending!(
        51,
        "detect_broadcast_injection",
        "Broadcast Injection Detection",
        Rf
    ),
    pending!(
        52,
        "detect_eas_spoofing",
        "Emergency Alert Spoofing Detection",
        Rf
    ),
    pending!(53, "detect_oran_fronthaul", "O-RAN Fronthaul Integrity", Rf),
    pending!(54, "detect_oran_ric", "O-RAN RIC Security Monitor", Rf),
    pending!(55, "detect_ais_integrity", "AIS Signal Integrity", Rf),
];

pub fn select_probes(modules: &[u8], groups: &[ProbeGroup]) -> Result<Vec<&'static ProbeSpec>> {
    for module in modules {
        if !PROBES.iter().any(|probe| probe.module == *module) {
            bail!("unknown defense module {module}; expected 16-55");
        }
    }
    Ok(PROBES
        .iter()
        .filter(|probe| {
            if modules.is_empty() {
                groups.contains(&probe.group)
            } else {
                modules.contains(&probe.module)
            }
        })
        .collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Available,
    Active,
    Unsupported,
    Failed,
}

#[derive(Debug, Serialize)]
pub struct ProbeReport {
    pub module: u8,
    pub program: &'static str,
    pub description: &'static str,
    pub status: ProbeStatus,
    pub detail: String,
}

impl ProbeReport {
    pub fn new(spec: &ProbeSpec, status: ProbeStatus, detail: impl Into<String>) -> Self {
        Self {
            module: spec.module,
            program: spec.program,
            description: spec.description,
            status,
            detail: detail.into(),
        }
    }
}

pub fn encode_modem_path(path: &Path) -> Result<[u8; MODEM_PATH_BYTES]> {
    let text = path.to_str().context("modem path must be UTF-8")?;
    if !path.is_absolute() || text.as_bytes().contains(&0) || text.len() > MODEM_PATH_BYTES - 2 {
        bail!(
            "modem path must be absolute, NUL-free, and at most {} bytes",
            MODEM_PATH_BYTES - 2
        );
    }
    let mut encoded = [0; MODEM_PATH_BYTES];
    encoded[..text.len()].copy_from_slice(text.as_bytes());
    Ok(encoded)
}

/// Must run before attaching the tracepoint; an empty path disables the policy.
pub fn configure_modem_probe(
    bpf: &mut Bpf,
    path: &Path,
    allowed_pids: &[u32],
    filename_offset: u32,
) -> Result<()> {
    if !(8..=256).contains(&filename_offset) || !filename_offset.is_multiple_of(8) {
        bail!("invalid openat filename offset; validate the running tracepoint layout first");
    }
    if allowed_pids.len() > 32 || allowed_pids.contains(&0) {
        bail!("at most 32 nonzero modem PID allowlist entries are supported");
    }
    let encoded = encode_modem_path(path)?;
    Array::<_, [u8; MODEM_PATH_BYTES]>::try_from(
        bpf.map_mut("MODEM_MONITORED_PATH")
            .context("MODEM_MONITORED_PATH missing")?,
    )?
    .set(0, encoded, 0)?;
    Array::<_, u32>::try_from(
        bpf.map_mut("MODEM_FILENAME_OFFSET")
            .context("MODEM_FILENAME_OFFSET missing")?,
    )?
    .set(0, filename_offset, 0)?;
    let mut pids = HashMap::<_, u32, u8>::try_from(
        bpf.map_mut("MODEM_ACCESS_PIDS")
            .context("MODEM_ACCESS_PIDS missing")?,
    )?;
    for pid in allowed_pids {
        pids.insert(*pid, 1, 0)?;
    }
    Ok(())
}

/// Loaded defense probes. Dropping the value is a no-op beyond dropping the
/// reports; the aya links live in the `Bpf` object and detach when it drops.
#[derive(Debug)]
pub struct AttachedProbes {
    pub reports: Vec<ProbeReport>,
}

/// A module is only active after both verifier loading and attachment succeed.
///
/// One perf event per tracepoint is the canonical model (aya, libbpf): the
/// program is pinned into the tracepoint's *shared* program array and then
/// executes on every CPU where the tracepoint fires, regardless of which CPU
/// the perf event itself was opened on. The kernel rejects pinning the same
/// program into additional per-CPU perf events with EEXIST, so per-CPU
/// attachment of a single program is impossible by design.
pub fn attach_probes(bpf: &mut Bpf, selected: &[&'static ProbeSpec]) -> AttachedProbes {
    let reports = selected
        .iter()
        .map(|spec| {
            let Attachment::TracePoint { category, event } = spec.attachment else {
                let Attachment::Unsupported(reason) = spec.attachment else {
                    unreachable!()
                };
                return ProbeReport::new(spec, ProbeStatus::Unsupported, reason);
            };
            let result = (|| -> Result<()> {
                let program: &mut TracePoint = bpf
                    .program_mut(spec.program)
                    .context("program missing from eBPF object")?
                    .try_into()?;
                program.load().context("verifier rejected program")?;
                program
                    .attach(category, event)
                    .context("tracepoint attachment failed")?;
                Ok(())
            })();
            match result {
                Ok(()) => ProbeReport::new(
                    spec,
                    ProbeStatus::Active,
                    format!(
                        "tracepoint {category}/{event} (probe runs on all CPUs \
                         via the tracepoint program array)"
                    ),
                ),
                Err(error) => ProbeReport::new(spec, ProbeStatus::Failed, format!("{error:#}")),
            }
        })
        .collect();
    AttachedProbes { reports }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_complete_and_unique() {
        assert_eq!(PROBES.len(), 40);
        for (index, spec) in PROBES.iter().enumerate() {
            assert_eq!(spec.module as usize, index + 16);
            assert_eq!(
                PROBES
                    .iter()
                    .filter(|other| other.program == spec.program)
                    .count(),
                1
            );
            assert_eq!(
                matches!(spec.attachment, Attachment::TracePoint { .. }),
                spec.module == 22
            );
        }
    }

    #[test]
    fn explicit_selection_overrides_groups_and_deduplicates() {
        let selected = select_probes(&[46, 46], &[ProbeGroup::Telecom]).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].module, 46);
        assert!(select_probes(&[15], &[]).is_err());
        assert_eq!(select_probes(&[], &[ProbeGroup::Telecom]).unwrap().len(), 8);
    }

    #[test]
    fn modem_paths_are_bounded_and_absolute() {
        assert!(encode_modem_path(Path::new("relative")).is_err());
        assert!(encode_modem_path(Path::new("/dev/a\0b")).is_err());
        assert!(encode_modem_path(Path::new(&format!("/{}", "a".repeat(126)))).is_err());
        assert!(encode_modem_path(Path::new(&format!("/{}", "a".repeat(125)))).is_ok());
    }
}
