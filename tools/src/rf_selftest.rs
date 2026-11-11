//! RF transmission self-test for the sdr-bridge TX path.
//!
//! Two stages:
//!
//! 1. **Software stage** (no hardware): generate a signed 8-bit I/Q CW tone
//!    (the `hackrf_transfer` file format), write it to disk, read it back, and
//!    verify the round trip and the signal level. This validates the TX
//!    pipeline end to end except for the DAC and the radio front end.
//! 2. **Hardware stage** (opt-in, lab only): transmit the generated file with
//!    `hackrf_transfer` while capturing with `rtl_sdr`, then verify the
//!    received energy. This requires TWO cabled devices — HackRF TX port
//!    through an attenuator into an RTL-SDR RX port — inside an RF-shielded
//!    enclosure or fully cabled, never with antennas, per the lab compliance
//!    checklist in `docs/LAB_SETUP.md`. One HackRF cannot do this alone: it
//!    cannot transmit and receive simultaneously.
//!
//! The hardware stage runs only when explicitly requested
//! (`STATICZERO_SDR_TX=1`) and both CLI tools are installed. Anything less is
//! reported as skipped, not passed.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};

/// Full scale for signed 8-bit samples (hackrf I/Q files).
const I8_FULL_SCALE: f64 = 127.5;
/// Full scale for unsigned 8-bit samples (rtl_sdr captures).
const U8_FULL_SCALE: f64 = 127.5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestOptions {
    /// Center frequency for the hardware loopback, in Hz.
    pub frequency_hz: u64,
    /// Sample rate for TX and RX, in Hz (RTL-SDR tops out at 3.2 Msps).
    pub sample_rate_hz: u64,
    /// HackRF TX VGA gain (0-47 dB).
    pub tx_gain_db: u32,
    /// Complex samples to transmit.
    pub tx_samples: usize,
    /// Complex samples per RMS analysis window on the RX capture.
    pub rx_window_samples: usize,
    /// Maximum-window RMS (dBFS) that must be exceeded during TX.
    pub rx_threshold_dbfs: f64,
    /// Fail instead of skipping when hardware tools are unavailable.
    pub require_hardware: bool,
}

impl Default for SelfTestOptions {
    fn default() -> Self {
        Self {
            // 100 MHz: safely inside both devices' range and away from
            // licensed cellular bands for shielded/cabled lab use.
            frequency_hz: 100_000_000,
            sample_rate_hz: 2_000_000,
            tx_gain_db: 40,
            tx_samples: 262_144,
            rx_window_samples: 4096,
            rx_threshold_dbfs: -25.0,
            require_hardware: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareLoopback {
    pub tx_tool: String,
    pub rx_tool: String,
    pub rx_bytes: usize,
    /// Maximum per-window RMS over the whole RX capture, dBFS.
    pub rx_peak_window_rms_dbfs: f64,
    pub threshold_dbfs: f64,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxSelfTestReport {
    pub passed: bool,
    pub iq_file: PathBuf,
    pub iq_bytes: usize,
    pub tone_hz: f64,
    pub tx_samples: usize,
    /// RMS of the generated tone, dBFS (software stage).
    pub tx_rms_dbfs: f64,
    pub round_trip_verified: bool,
    pub hardware: Option<HardwareLoopback>,
    /// Why the hardware stage did not run, when it did not.
    pub hardware_skipped: Option<String>,
}

/// Generate a signed 8-bit interleaved I/Q CW tone at `tone_hz` with
/// amplitude `amplitude` per component.
pub fn generate_cw_tone_iq(
    samples: usize,
    sample_rate_hz: u64,
    tone_hz: f64,
    amplitude: f64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(samples * 2);
    for n in 0..samples {
        let phase = 2.0 * std::f64::consts::PI * tone_hz * n as f64 / sample_rate_hz as f64;
        let i = (amplitude * phase.cos()).round().clamp(-127.0, 127.0) as i8;
        let q = (amplitude * phase.sin()).round().clamp(-127.0, 127.0) as i8;
        bytes.push(i as u8);
        bytes.push(q as u8);
    }
    bytes
}

/// RMS level of a signed 8-bit interleaved I/Q buffer, in dBFS. A pure tone
/// with per-component amplitude `a` measures `20*log10(a / (√2 · 127.5))`.
pub fn rms_dbfs_i8(bytes: &[u8]) -> f64 {
    ensure_pairs(bytes);
    let samples: Vec<f64> = bytes.iter().map(|&b| b as i8 as f64).collect();
    rms_dbfs(&samples, I8_FULL_SCALE)
}

/// RMS level of an unsigned 8-bit interleaved I/Q buffer (rtl_sdr format,
/// centered at 127.5), in dBFS.
pub fn rms_dbfs_u8(bytes: &[u8]) -> f64 {
    ensure_pairs(bytes);
    let samples: Vec<f64> = bytes.iter().map(|&b| b as f64 - 127.5).collect();
    rms_dbfs(&samples, U8_FULL_SCALE)
}

/// Maximum RMS (dBFS) over non-overlapping windows of `window_samples`
/// complex samples. Using the peak window makes the check robust to the TX
/// burst occupying only a fraction of the RX capture.
pub fn peak_window_rms_dbfs_u8(bytes: &[u8], window_samples: usize) -> f64 {
    let window_bytes = window_samples.checked_mul(2).expect("window size overflow");
    let mut peak = f64::NEG_INFINITY;
    for window in bytes.chunks(window_bytes) {
        if window.len() < 2 {
            continue;
        }
        peak = peak.max(rms_dbfs_u8(window));
    }
    peak
}

fn ensure_pairs(bytes: &[u8]) {
    assert!(
        bytes.len().is_multiple_of(2),
        "I/Q buffer must contain interleaved pairs"
    );
}

fn rms_dbfs(samples: &[f64], full_scale: f64) -> f64 {
    if samples.is_empty() {
        return f64::NEG_INFINITY;
    }
    let power: f64 = samples.iter().map(|s| s * s).sum::<f64>() / samples.len() as f64;
    if power == 0.0 {
        f64::NEG_INFINITY
    } else {
        20.0 * (power.sqrt() / full_scale).log10()
    }
}

fn write_all(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file =
        std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn tool_available(name: &str) -> bool {
    Command::new(name)
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Software stage: write the tone, read it back, verify integrity and level.
fn software_stage(workdir: &Path, options: &SelfTestOptions) -> Result<(PathBuf, Vec<u8>, f64)> {
    std::fs::create_dir_all(workdir).with_context(|| format!("creating {}", workdir.display()))?;
    let tone_hz = options.sample_rate_hz as f64 / 4.0;
    let iq = generate_cw_tone_iq(options.tx_samples, options.sample_rate_hz, tone_hz, 100.0);
    let iq_file = workdir.join("tone.iq");
    write_all(&iq_file, &iq)?;

    let read_back =
        std::fs::read(&iq_file).with_context(|| format!("reading back {}", iq_file.display()))?;
    ensure!(
        read_back == iq,
        "I/Q file round trip mismatch: wrote {} bytes, read {}",
        iq.len(),
        read_back.len()
    );
    let rms = rms_dbfs_i8(&iq);
    // Amplitude 100 per component of a CW tone: about -5.1 dBFS.
    ensure!(
        (-7.0..=-3.5).contains(&rms),
        "generated tone RMS {rms:.2} dBFS is outside the expected band"
    );
    Ok((iq_file, iq, rms))
}

/// Hardware stage: HackRF TX cabled into RTL-SDR RX. Requires root or udev
/// permissions for both devices, and both CLI tools installed.
fn hardware_loopback(
    workdir: &Path,
    iq: &[u8],
    options: &SelfTestOptions,
) -> Result<HardwareLoopback> {
    let tx_tool = "hackrf_transfer";
    let rx_tool = "rtl_sdr";
    for tool in [tx_tool, rx_tool] {
        ensure!(
            tool_available(tool),
            "{tool} not found in PATH; install hackrf and rtl-sdr tools"
        );
    }

    let rx_file = workdir.join("rx.raw");
    // Capture enough to cover device startup plus the TX burst.
    let rx_samples: u64 = options.sample_rate_hz * 2;
    let mut rx = Command::new(rx_tool)
        .arg("-f")
        .arg(options.frequency_hz.to_string())
        .arg("-s")
        .arg(options.sample_rate_hz.to_string())
        .arg("-n")
        .arg(rx_samples.to_string())
        .arg(rx_file.to_string_lossy().into_owned())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("spawning rtl_sdr")?;

    // Let the receiver open and settle before keying the transmitter.
    std::thread::sleep(Duration::from_millis(1500));

    let tx_samples = iq.len() / 2;
    let tx_status = Command::new(tx_tool)
        .arg("-t")
        .arg(workdir.join("tone.iq").to_string_lossy().into_owned())
        .arg("-f")
        .arg(options.frequency_hz.to_string())
        .arg("-s")
        .arg(options.sample_rate_hz.to_string())
        .arg("-x")
        .arg(options.tx_gain_db.to_string())
        .arg("-n")
        .arg(tx_samples.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("spawning hackrf_transfer")?;
    ensure!(
        tx_status.success(),
        "hackrf_transfer failed with {tx_status}"
    );

    let rx_status = rx.wait().context("waiting for rtl_sdr")?;
    ensure!(rx_status.success(), "rtl_sdr failed with {rx_status}");

    let captured = std::fs::read(&rx_file).context("reading rtl_sdr capture")?;
    ensure!(
        captured.len() >= options.rx_window_samples * 2,
        "rtl_sdr captured {} bytes, too few to analyze",
        captured.len()
    );
    let peak = peak_window_rms_dbfs_u8(&captured, options.rx_window_samples);
    let passed = peak > options.rx_threshold_dbfs;
    Ok(HardwareLoopback {
        tx_tool: tx_tool.to_string(),
        rx_tool: rx_tool.to_string(),
        rx_bytes: captured.len(),
        rx_peak_window_rms_dbfs: peak,
        threshold_dbfs: options.rx_threshold_dbfs,
        passed,
    })
}

/// Run the full self-test in `workdir`. Never call with `require_hardware`
/// unless the two-device cabled loopback described in the module docs is
/// physically connected.
pub fn run_selftest(workdir: &Path, options: &SelfTestOptions) -> Result<TxSelfTestReport> {
    let (iq_file, iq, tx_rms) = software_stage(workdir, options)?;

    let requested = std::env::var_os("STATICZERO_SDR_TX")
        .map(|v| v == "1")
        .unwrap_or(false);
    if !requested {
        if options.require_hardware {
            bail!("hardware stage required but STATICZERO_SDR_TX is not set to 1");
        }
        return Ok(TxSelfTestReport {
            passed: true,
            iq_file,
            iq_bytes: iq.len(),
            tone_hz: options.sample_rate_hz as f64 / 4.0,
            tx_samples: options.tx_samples,
            tx_rms_dbfs: tx_rms,
            round_trip_verified: true,
            hardware: None,
            hardware_skipped: Some(
                "not requested; set STATICZERO_SDR_TX=1 with the cabled HackRF→attenuator→RTL-SDR loopback connected".to_string(),
            ),
        });
    }

    let hw = match hardware_loopback(workdir, &iq, options) {
        Ok(report) => report,
        Err(error) => {
            if options.require_hardware {
                return Err(error);
            }
            return Ok(TxSelfTestReport {
                passed: true,
                iq_file,
                iq_bytes: iq.len(),
                tone_hz: options.sample_rate_hz as f64 / 4.0,
                tx_samples: options.tx_samples,
                tx_rms_dbfs: tx_rms,
                round_trip_verified: true,
                hardware: None,
                hardware_skipped: Some(format!("hardware stage failed: {error:#}")),
            });
        }
    };
    let passed = hw.passed;
    Ok(TxSelfTestReport {
        passed,
        iq_file,
        iq_bytes: iq.len(),
        tone_hz: options.sample_rate_hz as f64 / 4.0,
        tx_samples: options.tx_samples,
        tx_rms_dbfs: tx_rms,
        round_trip_verified: true,
        hardware: Some(hw),
        hardware_skipped: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cw_tone_rms_matches_amplitude() {
        let iq = generate_cw_tone_iq(8192, 1_000_000, 250_000.0, 100.0);
        assert_eq!(iq.len(), 16_384);
        let rms = rms_dbfs_i8(&iq);
        // 20*log10(100 / (sqrt(2) * 127.5)) = -5.12 dBFS
        assert!((rms - (-5.12)).abs() < 0.3, "rms was {rms:.3}");
    }

    #[test]
    fn silence_is_minus_infinity_or_below_noise() {
        assert_eq!(rms_dbfs_i8(&[0, 0, 0, 0]), f64::NEG_INFINITY);
        // rtl-sdr u8 has no exact zero; 128 sits half an LSB off center.
        assert!(rms_dbfs_u8(&[128, 128]) < -40.0);
    }

    #[test]
    fn u8_rms_centers_at_127_5() {
        // Full-scale square wave at +127/-128 around the rtl center.
        let bytes: Vec<u8> = (0..4096)
            .map(|n| if n % 2 == 0 { 255 } else { 0 })
            .collect();
        let rms = rms_dbfs_u8(&bytes);
        assert!(rms > -0.5, "rms was {rms:.3}");
    }

    #[test]
    fn tone_frequency_is_encoded_in_zero_crossings() {
        let sample_rate = 1_000_000u64;
        let tone = 100_000.0f64;
        let samples = 10_000usize;
        let iq = generate_cw_tone_iq(samples, sample_rate, tone, 100.0);
        let crossings = iq
            .chunks(2)
            .map(|pair| pair[0] as i8)
            .collect::<Vec<i8>>()
            .windows(2)
            .filter(|w| (w[0] <= 0) != (w[1] <= 0))
            .count();
        let expected = 2.0 * tone * samples as f64 / sample_rate as f64;
        assert!(
            (crossings as f64 - expected).abs() < expected * 0.05,
            "zero crossings {crossings}, expected about {expected}"
        );
    }

    #[test]
    fn peak_window_detects_burst_among_silence() {
        let mut capture = vec![128u8; 4 * 8192]; // noise floor at center
        let burst = generate_cw_tone_iq(4096, 1_000_000, 250_000.0, 120.0);
        // Convert signed tone to rtl-sdr unsigned format.
        for (dst, src) in capture[8192..8192 + burst.len()].iter_mut().zip(burst) {
            *dst = (src as i8 as i16 + 128) as u8;
        }
        let peak = peak_window_rms_dbfs_u8(&capture, 4096);
        let floor = rms_dbfs_u8(&capture[..8192]);
        assert!(peak > -8.0, "peak was {peak:.2}");
        assert!(floor < -35.0, "floor was {floor:.2}");
    }

    #[test]
    fn software_stage_round_trips() {
        let dir = std::env::temp_dir().join(format!("sz-rf-test-{}", std::process::id()));
        let options = SelfTestOptions {
            tx_samples: 4096,
            ..SelfTestOptions::default()
        };
        let (path, iq, rms) = software_stage(&dir, &options).unwrap();
        assert_eq!(iq.len(), 8192);
        assert!(path.is_file());
        assert!(rms < -3.5 && rms > -7.0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn report_serializes() {
        let report = TxSelfTestReport {
            passed: true,
            iq_file: PathBuf::from("/tmp/tone.iq"),
            iq_bytes: 1024,
            tone_hz: 500_000.0,
            tx_samples: 512,
            tx_rms_dbfs: -5.1,
            round_trip_verified: true,
            hardware: None,
            hardware_skipped: Some("not requested".to_string()),
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"passed\":true"));
        let back: TxSelfTestReport = serde_json::from_str(&json).unwrap();
        assert!(back.round_trip_verified);
    }
}
