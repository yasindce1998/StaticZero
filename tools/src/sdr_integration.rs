//! SDR (Software Defined Radio) bridge for real-time RF signal capture and injection.

use anyhow::{ensure, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Channels measured above this CF32 power level are reported by the scan
/// summary (rough noise-floor separation; RF environments vary).
const POWER_SCAN_THRESHOLD_DBFS: f32 = -70.0;

/// Read a CF32 IQ file: interleaved native-endian f32 I/Q pairs.
fn read_cf32_file(path: &std::path::Path) -> Result<Vec<f32>> {
    let bytes =
        std::fs::read(path).map_err(|e| anyhow::anyhow!("read IQ file {}: {e}", path.display()))?;
    ensure!(
        bytes.len() % 8 == 0,
        "CF32 file {} has a partial sample ({} bytes); expected 8 bytes per I/Q pair",
        path.display(),
        bytes.len()
    );
    Ok(bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| f32::from_ne_bytes(*chunk))
        .collect())
}
use tokio::sync::mpsc;
use tracing::{error, info, warn};

#[derive(Debug, Parser)]
#[command(name = "sdr-bridge")]
#[command(about = "SDR Integration Layer — bridges SDR hardware to StaticZero telecom modules")]
pub struct Cli {
    /// SDR device type (hackrf, bladerf, usrp, rtlsdr, limesdr)
    #[arg(long, default_value = "hackrf")]
    sdr_type: String,

    /// SDR device serial or index
    #[arg(long)]
    device_id: Option<String>,

    /// Center frequency in Hz (default: LTE Band 7 downlink = 2620 MHz)
    #[arg(long, default_value = "2620000000")]
    frequency: u64,

    /// Sample rate in Hz
    #[arg(long, default_value = "20000000")]
    sample_rate: u64,

    /// RF gain in dB
    #[arg(long, default_value = "40")]
    gain: u32,

    /// Bandwidth in Hz
    #[arg(long, default_value = "20000000")]
    bandwidth: u64,

    /// IQ output pipe/file path (for feeding to gr-lte, srsRAN, etc.)
    #[arg(long)]
    iq_output: Option<PathBuf>,

    /// Listen port for control API (JSON over TCP)
    #[arg(long, default_value = "7890")]
    control_port: u16,

    /// Feed decoded frames to defense engine via this port
    #[arg(long, default_value = "7891")]
    defense_port: u16,

    /// Operating mode: scan, capture, inject, relay, list, selftest-tx
    #[arg(long, default_value = "scan")]
    mode: String,

    /// CF32 IQ file to transmit in inject mode (interleaved f32 I/Q pairs)
    #[arg(long)]
    iq_input: Option<PathBuf>,

    /// Band scan range (comma-separated EARFCN list or "all-lte")
    #[arg(long)]
    scan_bands: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdrConfig {
    pub device_type: String,
    pub device_id: Option<String>,
    pub frequency_hz: u64,
    pub sample_rate_hz: u64,
    pub gain_db: u32,
    pub bandwidth_hz: u64,
    pub mode: SdrMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SdrMode {
    Scan,
    Capture,
    Inject,
    Relay,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellScanResult {
    pub earfcn: u32,
    pub pci: u16,
    pub rsrp_dbm: f32,
    pub rsrq_db: f32,
    pub frequency_offset_hz: f32,
    pub mib_decoded: bool,
    pub sib1_decoded: bool,
    pub mcc: Option<u16>,
    pub mnc: Option<u16>,
    pub tac: Option<u32>,
    pub cell_id: Option<u32>,
    pub bandwidth_prb: Option<u8>,
    pub antenna_ports: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IqSample {
    pub i: f32,
    pub q: f32,
    pub timestamp_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdrCommand {
    pub cmd: String,
    pub params: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdrResponse {
    pub status: String,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedFrame {
    pub frame_type: FrameType,
    pub timestamp_ns: u64,
    pub earfcn: u32,
    pub pci: u16,
    pub payload: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FrameType {
    Mib,
    Sib1,
    Sib2,
    RrcConnectionRequest,
    RrcConnectionSetup,
    RrcConnectionRelease,
    AttachRequest,
    AuthenticationRequest,
    SecurityModeCommand,
    IdentityRequest,
    PagingMessage,
    MeasurementReport,
    HandoverCommand,
    PbchMib,
    Sib1Decoded,
    RachPreamble,
}

pub struct SdrBridge {
    config: SdrConfig,
    scan_results: Arc<Mutex<Vec<CellScanResult>>>,
    #[allow(dead_code)]
    decoded_frames: Arc<Mutex<Vec<DecodedFrame>>>,
    running: Arc<Mutex<bool>>,
    /// Real SoapySDR device when built with the `soapy` feature; the stub
    /// device layer (None) preserves the catalog/simulation behavior.
    #[cfg(feature = "soapy")]
    device: Option<std::sync::Arc<crate::soapy::SoapyDevice>>,
}

impl SdrBridge {
    pub fn new(config: SdrConfig) -> Self {
        Self {
            config,
            scan_results: Arc::new(Mutex::new(Vec::new())),
            decoded_frames: Arc::new(Mutex::new(Vec::new())),
            running: Arc::new(Mutex::new(false)),
            #[cfg(feature = "soapy")]
            device: None,
        }
    }

    pub fn init_device(&mut self) -> Result<()> {
        info!(
            "Initializing SDR device: type={}, freq={}MHz, sr={}Msps, gain={}dB",
            self.config.device_type,
            self.config.frequency_hz / 1_000_000,
            self.config.sample_rate_hz / 1_000_000,
            self.config.gain_db
        );

        #[cfg(feature = "soapy")]
        {
            // Real hardware path: one SoapySDR backend covers all five
            // vendor families through their driver modules.
            let device = crate::soapy::SoapyDevice::open(
                Some(self.config.device_type.as_str()),
                self.config.device_id.as_deref(),
            )
            .map_err(anyhow::Error::msg)?;
            device
                .configure(
                    crate::soapy::SOAPY_SDR_RX,
                    self.config.frequency_hz,
                    self.config.sample_rate_hz,
                    self.config.bandwidth_hz,
                    self.config.gain_db,
                )
                .map_err(anyhow::Error::msg)?;
            device
                .configure(
                    crate::soapy::SOAPY_SDR_TX,
                    self.config.frequency_hz,
                    self.config.sample_rate_hz,
                    self.config.bandwidth_hz,
                    self.config.gain_db,
                )
                .map_err(anyhow::Error::msg)?;
            info!(
                "SoapySDR device open and configured (RX+TX, CF32, {} MHz)",
                self.config.frequency_hz / 1_000_000
            );
            self.device = Some(std::sync::Arc::new(device));
            Ok(())
        }

        #[cfg(not(feature = "soapy"))]
        {
            // Stub device layer: logs the vendor FFI calls the real path
            // would make. Build with `--features soapy` for hardware.
            match self.config.device_type.as_str() {
                "hackrf" | "bladerf" | "usrp" | "rtlsdr" | "limesdr" => {
                    info!(
                        "{}: stub device layer (build with --features soapy for real hardware)",
                        self.config.device_type
                    );
                    Ok(())
                }
                other => anyhow::bail!("Unsupported SDR type: {}", other),
            }
        }
    }

    pub fn start_capture(&self, iq_pipe: Option<&PathBuf>) -> Result<()> {
        *self.running.lock().expect("lock poisoned") = true;
        info!(
            "Starting IQ capture at {}MHz",
            self.config.frequency_hz / 1_000_000
        );

        if let Some(path) = iq_pipe {
            info!("IQ data streaming to: {}", path.display());
            #[cfg(feature = "soapy")]
            if let Some(device) = self.device.as_ref() {
                // Real capture: a dedicated reader thread runs the
                // readStream loop and writes raw CF32 (interleaved
                // native-endian f32 I/Q) to the output file until stopped.
                let device = std::sync::Arc::clone(device);
                let stream = device.rx_stream().map_err(anyhow::Error::msg)?;
                let running = self.running.clone();
                let path = path.clone();
                std::thread::spawn(move || {
                    use std::io::Write;
                    let mut file = match std::fs::File::create(&path) {
                        Ok(file) => file,
                        Err(error) => {
                            error!("cannot create IQ output {}: {error}", path.display());
                            return;
                        }
                    };
                    info!(
                        "capturing CF32 IQ to {} ({} samples per read)",
                        path.display(),
                        stream.mtu()
                    );
                    let mut buffer = vec![0f32; stream.mtu() * 2];
                    while *running.lock().expect("lock poisoned") {
                        match device.read_into(&stream, &mut buffer, 1_000_000) {
                            Ok(0) => continue, // timeout, keep going
                            Ok(count) => {
                                let bytes = unsafe {
                                    std::slice::from_raw_parts(
                                        buffer.as_ptr().cast::<u8>(),
                                        count * 8,
                                    )
                                };
                                if file.write_all(bytes).is_err() {
                                    error!("IQ output write failed; stopping capture");
                                    break;
                                }
                            }
                            Err(error) => {
                                error!("readStream failed: {error}; stopping capture");
                                break;
                            }
                        }
                    }
                    info!("IQ capture thread stopped");
                });
            }
            // Without the feature (or no device): documented stub, no RF.
        }
        Ok(())
    }

    pub fn scan_cells(&self, earfcns: &[u32]) -> Result<Vec<CellScanResult>> {
        info!("Scanning {} EARFCNs for cells...", earfcns.len());
        let mut results = Vec::new();

        #[cfg(feature = "soapy")]
        let measured: Option<Vec<(u32, f32)>> = match self.device.as_ref() {
            Some(device) => {
                // Real power scan: tune to each EARFCN, receive a burst of
                // CF32 samples, measure wideband channel power. This is a
                // physical-layer survey only — LTE PSS/SSS correlation and
                // MIB/SIB decode are not implemented, so mib_decoded stays
                // false and the measured power is reported honestly.
                let stream = device.rx_stream().map_err(anyhow::Error::msg)?;
                let mut measurements = Vec::with_capacity(earfcns.len());
                const SAMPLES_PER_CHANNEL: usize = 65_536; // ~3ms at 20 Msps
                for &earfcn in earfcns {
                    let freq_hz = earfcn_to_freq(earfcn);
                    if let Err(error) = device.set_frequency(crate::soapy::SOAPY_SDR_RX, freq_hz) {
                        warn!("EARFCN {earfcn}: tune failed: {error}");
                        continue;
                    }
                    match crate::soapy::receive(device, &stream, SAMPLES_PER_CHANNEL) {
                        Ok(samples) => {
                            let power = crate::soapy::power_dbfs(&samples);
                            info!(
                                "  EARFCN {} ({} MHz): measured {:.1} dBFS",
                                earfcn,
                                freq_hz / 1_000_000,
                                power
                            );
                            measurements.push((earfcn, power));
                        }
                        Err(error) => warn!("EARFCN {earfcn}: receive failed: {error}"),
                    }
                }
                Some(measurements)
            }
            None => None,
        };

        for &earfcn in earfcns {
            #[cfg(feature = "soapy")]
            let (rsrp_dbm, mib_decoded) = match &measured {
                Some(list) => match list.iter().find(|(e, _)| *e == earfcn) {
                    Some((_, power)) => (*power, false),
                    None => (f32::NEG_INFINITY, false),
                },
                None => (-999.0, false),
            };
            #[cfg(not(feature = "soapy"))]
            let (rsrp_dbm, mib_decoded) = (-999.0, false);

            let result = CellScanResult {
                earfcn,
                pci: 0,
                rsrp_dbm,
                rsrq_db: -99.0,
                frequency_offset_hz: 0.0,
                mib_decoded,
                sib1_decoded: false,
                mcc: None,
                mnc: None,
                tac: None,
                cell_id: None,
                bandwidth_prb: None,
                antenna_ports: None,
            };
            results.push(result);
        }

        *self.scan_results.lock().unwrap() = results.clone();
        Ok(results)
    }

    pub fn inject_frame(&self, frame: &DecodedFrame) -> Result<()> {
        warn!(
            "TX inject: {:?} on EARFCN {} PCI {}",
            frame.frame_type, frame.earfcn, frame.pci
        );
        // In production: encode frame → OFDM modulate → DAC → TX
        Ok(())
    }

    pub fn get_rf_fingerprint(&self) -> Result<RfFingerprint> {
        Ok(RfFingerprint {
            frequency_offset_hz: 0.0,
            iq_imbalance_db: 0.0,
            timing_advance_us: 0.0,
            power_ramp_slope: 0.0,
            spectral_flatness: 0.0,
            phase_noise_dbc: 0.0,
        })
    }

    pub fn start_iq_capture(&self, config: IqCaptureConfig) -> Result<IqSampleStream> {
        info!(
            "Starting IQ capture: freq={}MHz, rate={}Msps, gain={}dB, bits={}",
            config.center_freq_hz / 1_000_000,
            config.sample_rate_hz / 1_000_000,
            config.gain_db,
            config.bits_per_sample,
        );

        *self.running.lock().expect("lock poisoned") = true;

        let (tx, rx) = mpsc::channel::<Vec<u8>>(config.buffer_size / 4096);

        // In production: configure SDR with IQ params → start async RX stream → push chunks to tx
        Ok(IqSampleStream {
            config,
            receiver: rx,
            _sender: tx,
            total_samples: 0,
        })
    }

    pub fn feed_iq_to_defense(&self, samples: &[u8], meta: IqSampleMeta) -> Result<()> {
        info!(
            "Feeding {} bytes IQ data to defense engine (freq={}MHz, ts={})",
            samples.len(),
            meta.center_freq_hz / 1_000_000,
            meta.timestamp_ns,
        );

        // In production: connect to defense engine TCP port and stream
        // IQ metadata header + raw samples for real-time analysis
        // Defense modules use this for:
        //   - Jamming detection (spectral anomaly in IQ domain)
        //   - RF fingerprinting (IQ imbalance, phase noise extraction)
        //   - Rogue cell identification (PSS/SSS correlation on raw IQ)
        Ok(())
    }

    pub fn stop(&self) {
        *self.running.lock().expect("lock poisoned") = false;
        info!("SDR capture stopped");
    }

    /// The open SoapySDR device (real hardware), when built with the
    /// `soapy` feature and a device is present.
    #[cfg(feature = "soapy")]
    pub fn device(&self) -> Option<&Arc<crate::soapy::SoapyDevice>> {
        self.device.as_ref()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IqCaptureConfig {
    pub center_freq_hz: u64,
    pub sample_rate_hz: u32,
    pub gain_db: u16,
    pub bits_per_sample: u8,
    pub buffer_size: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct IqSampleMeta {
    pub center_freq_hz: u64,
    pub sample_rate_hz: u32,
    pub gain_db: u16,
    pub bits_per_sample: u8,
    pub timestamp_ns: u64,
}

pub struct IqSampleStream {
    pub config: IqCaptureConfig,
    receiver: mpsc::Receiver<Vec<u8>>,
    _sender: mpsc::Sender<Vec<u8>>,
    total_samples: u64,
}

impl IqSampleStream {
    pub async fn next_chunk(&mut self) -> Option<Vec<u8>> {
        let chunk = self.receiver.recv().await?;
        let samples_in_chunk = chunk.len() as u64 / (self.config.bits_per_sample as u64 / 4);
        self.total_samples += samples_in_chunk;
        Some(chunk)
    }

    pub fn total_samples(&self) -> u64 {
        self.total_samples
    }

    pub fn meta(&self) -> IqSampleMeta {
        IqSampleMeta {
            center_freq_hz: self.config.center_freq_hz,
            sample_rate_hz: self.config.sample_rate_hz,
            gain_db: self.config.gain_db,
            bits_per_sample: self.config.bits_per_sample,
            timestamp_ns: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RfFingerprint {
    pub frequency_offset_hz: f32,
    pub iq_imbalance_db: f32,
    pub timing_advance_us: f32,
    pub power_ramp_slope: f32,
    pub spectral_flatness: f32,
    pub phase_noise_dbc: f32,
}

fn earfcn_to_freq(earfcn: u32) -> u64 {
    // Simplified LTE EARFCN to frequency mapping (Band 7 example)
    // Full table: 3GPP TS 36.101 Table 5.7.3-1
    match earfcn {
        2750..=3449 => 2_620_000_000 + (earfcn as u64 - 2750) * 100_000, // Band 7 DL
        1200..=1949 => 1_805_000_000 + (earfcn as u64 - 1200) * 100_000, // Band 3 DL
        0..=599 => 2_110_000_000 + earfcn as u64 * 100_000,              // Band 1 DL
        _ => earfcn as u64 * 100_000,                                    // Fallback
    }
}

fn lte_band_earfcns(band: &str) -> Vec<u32> {
    match band {
        "all-lte" => {
            let mut earfcns = Vec::new();
            // Band 1 (2100 MHz): EARFCN 0-599
            earfcns.extend((0..600).step_by(10));
            // Band 3 (1800 MHz): EARFCN 1200-1949
            earfcns.extend((1200..1950).step_by(10));
            // Band 7 (2600 MHz): EARFCN 2750-3449
            earfcns.extend((2750..3450).step_by(10));
            // Band 20 (800 MHz): EARFCN 6150-6449
            earfcns.extend((6150..6450).step_by(10));
            earfcns
        }
        _ => band
            .split(',')
            .filter_map(|s| s.trim().parse::<u32>().ok())
            .collect(),
    }
}

fn handle_control_client(stream: TcpStream, bridge: Arc<SdrBridge>) {
    let reader = BufReader::new(stream.try_clone().expect("clone TCP stream"));
    let mut writer = stream;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        let cmd: SdrCommand = match serde_json::from_str(&line) {
            Ok(c) => c,
            Err(e) => {
                let resp = SdrResponse {
                    status: "error".into(),
                    data: None,
                    error: Some(format!("Invalid JSON: {}", e)),
                };
                let _ = writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&resp).expect("serialize")
                );
                continue;
            }
        };

        let resp = match cmd.cmd.as_str() {
            "scan" => {
                let earfcns = cmd
                    .params
                    .get("earfcns")
                    .and_then(|v| v.as_str())
                    .unwrap_or("all-lte");
                let earfcn_list = lte_band_earfcns(earfcns);
                match bridge.scan_cells(&earfcn_list) {
                    Ok(results) => SdrResponse {
                        status: "ok".into(),
                        data: Some(serde_json::to_value(&results).expect("serialize")),
                        error: None,
                    },
                    Err(e) => SdrResponse {
                        status: "error".into(),
                        data: None,
                        error: Some(e.to_string()),
                    },
                }
            }
            "tune" => {
                let freq = cmd
                    .params
                    .get("frequency")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                info!("Tuning to {}MHz", freq / 1_000_000);
                SdrResponse {
                    status: "ok".into(),
                    data: Some(serde_json::json!({"frequency_hz": freq})),
                    error: None,
                }
            }
            "fingerprint" => match bridge.get_rf_fingerprint() {
                Ok(fp) => SdrResponse {
                    status: "ok".into(),
                    data: Some(serde_json::to_value(&fp).expect("serialize")),
                    error: None,
                },
                Err(e) => SdrResponse {
                    status: "error".into(),
                    data: None,
                    error: Some(e.to_string()),
                },
            },
            "inject" => {
                let frame_type = cmd
                    .params
                    .get("frame_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("RrcConnectionRelease");
                info!("Inject request: {}", frame_type);
                SdrResponse {
                    status: "ok".into(),
                    data: Some(serde_json::json!({"injected": frame_type})),
                    error: None,
                }
            }
            "stop" => {
                bridge.stop();
                SdrResponse {
                    status: "ok".into(),
                    data: None,
                    error: None,
                }
            }
            "status" => {
                let running = *bridge.running.lock().expect("lock poisoned");
                SdrResponse {
                    status: "ok".into(),
                    data: Some(serde_json::json!({
                        "running": running,
                        "device": bridge.config.device_type,
                        "frequency_mhz": bridge.config.frequency_hz / 1_000_000,
                        "sample_rate_msps": bridge.config.sample_rate_hz / 1_000_000,
                    })),
                    error: None,
                }
            }
            other => SdrResponse {
                status: "error".into(),
                data: None,
                error: Some(format!("Unknown command: {}", other)),
            },
        };

        let _ = writeln!(
            writer,
            "{}",
            serde_json::to_string(&resp).expect("serialize")
        );
    }
}

/// Entry point invoked by the standalone bin and the multi-call
/// `staticzero` binary's subcommand.
pub async fn run(cli: Cli) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    info!("StaticZero SDR Integration Layer");
    info!(
        "  Device: {} ({})",
        cli.sdr_type,
        cli.device_id.as_deref().unwrap_or("auto")
    );
    info!("  Frequency: {} MHz", cli.frequency / 1_000_000);
    info!("  Sample rate: {} Msps", cli.sample_rate / 1_000_000);
    info!("  Mode: {}", cli.mode);

    // Device enumeration: list attached SDRs (works with no hardware —
    // an empty list is a valid, successful result) and exit.
    if cli.mode == "list" {
        #[cfg(feature = "soapy")]
        {
            let devices = crate::soapy::enumerate().map_err(anyhow::Error::msg)?;
            println!("{}", serde_json::to_string_pretty(&devices)?);
            info!(
                "enumerated {} SoapySDR device(s) via libSoapySDR",
                devices.len()
            );
            return Ok(());
        }
        #[cfg(not(feature = "soapy"))]
        {
            anyhow::bail!(
                "--mode list requires real hardware support: rebuild with --features soapy (needs libSoapySDR)"
            );
        }
    }

    // RF TX self-test: exercises the transmission pipeline (and, when
    // STATICZERO_SDR_TX=1 with the cabled HackRF→RTL-SDR loopback connected,
    // real RF over a cable) and exits instead of serving the control API.
    if cli.mode == "selftest-tx" {
        let options = crate::rf_selftest::SelfTestOptions {
            frequency_hz: cli.frequency,
            sample_rate_hz: cli.sample_rate,
            tx_gain_db: cli.gain,
            require_hardware: std::env::var_os("STATICZERO_SDR_TX")
                .map(|v| v == "1")
                .unwrap_or(false),
            ..crate::rf_selftest::SelfTestOptions::default()
        };
        let workdir = std::env::temp_dir().join(format!("sdr-selftest-{}", std::process::id()));
        let report = crate::rf_selftest::run_selftest(&workdir, &options)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        ensure!(
            report.passed,
            "RF TX self-test failed; see the report above"
        );
        let _ = std::fs::remove_dir_all(&workdir);
        return Ok(());
    }

    let mode = match cli.mode.as_str() {
        "scan" => SdrMode::Scan,
        "capture" => SdrMode::Capture,
        "inject" => SdrMode::Inject,
        "relay" => SdrMode::Relay,
        other => anyhow::bail!("Unknown mode: {}", other),
    };

    let config = SdrConfig {
        device_type: cli.sdr_type.clone(),
        device_id: cli.device_id.clone(),
        frequency_hz: cli.frequency,
        sample_rate_hz: cli.sample_rate,
        gain_db: cli.gain,
        bandwidth_hz: cli.bandwidth,
        mode,
    };

    let mut bridge = SdrBridge::new(config);
    bridge.init_device()?;
    let bridge = Arc::new(bridge);

    if matches!(cli.mode.as_str(), "capture" | "relay") {
        let iq_output = cli.iq_output.clone();
        bridge.start_capture(iq_output.as_ref())?;
    }

    // Real transmit: stream a CF32 IQ file over the configured frequency
    // and gain. Requires the soapy feature and a TX-capable device.
    if cli.mode == "inject" {
        let path = cli
            .iq_input
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("inject mode requires --iq-input <cf32-file>"))?;
        let samples = read_cf32_file(path)?;
        info!(
            "Transmitting {} I/Q samples at {} MHz, gain {} dB",
            samples.len() / 2,
            cli.frequency / 1_000_000,
            cli.gain
        );
        #[cfg(feature = "soapy")]
        {
            let device = bridge
                .device()
                .ok_or_else(|| anyhow::anyhow!("soapy feature built but no device open"))?;
            let stream = device.tx_stream().map_err(anyhow::Error::msg)?;
            crate::soapy::transmit(device, &stream, &samples).map_err(anyhow::Error::msg)?;
            info!("Transmission complete");
        }
        #[cfg(not(feature = "soapy"))]
        {
            warn!(
                "stub device layer: {} samples not transmitted (build with --features soapy for real TX)",
                samples.len() / 2
            );
        }
    }

    if cli.mode == "scan" {
        let earfcns = lte_band_earfcns(cli.scan_bands.as_deref().unwrap_or("all-lte"));
        let results = bridge.scan_cells(&earfcns)?;
        info!(
            "Scan complete: {} channels measured, {} above the detection threshold",
            results.len(),
            results
                .iter()
                .filter(|r| r.rsrp_dbm > POWER_SCAN_THRESHOLD_DBFS)
                .count()
        );
        for r in results
            .iter()
            .filter(|r| r.rsrp_dbm > POWER_SCAN_THRESHOLD_DBFS)
        {
            info!(
                "  EARFCN={} ({} MHz) measured={:.1} dBFS",
                r.earfcn,
                earfcn_to_freq(r.earfcn) / 1_000_000,
                r.rsrp_dbm
            );
        }
    }

    // Start control API server
    let control_bridge = bridge.clone();
    let control_port = cli.control_port;
    tokio::task::spawn_blocking(move || {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", control_port))
            .expect("Failed to bind control port");
        info!("Control API listening on 127.0.0.1:{}", control_port);

        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let b = control_bridge.clone();
                    std::thread::spawn(move || handle_control_client(s, b));
                }
                Err(e) => error!("Control connection error: {}", e),
            }
        }
    });

    // Wait for shutdown
    tokio::signal::ctrl_c().await?;
    bridge.stop();
    info!("SDR bridge shutdown complete");

    Ok(())
}
