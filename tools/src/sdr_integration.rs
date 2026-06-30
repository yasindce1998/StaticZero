use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

#[derive(Debug, Parser)]
#[command(name = "sdr-bridge")]
#[command(about = "SDR Integration Layer — bridges SDR hardware to StaticZero telecom modules")]
struct Cli {
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

    /// Operating mode: scan, capture, inject, relay
    #[arg(long, default_value = "scan")]
    mode: String,

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
}

pub struct SdrBridge {
    config: SdrConfig,
    scan_results: Arc<Mutex<Vec<CellScanResult>>>,
    decoded_frames: Arc<Mutex<Vec<DecodedFrame>>>,
    running: Arc<Mutex<bool>>,
}

impl SdrBridge {
    pub fn new(config: SdrConfig) -> Self {
        Self {
            config,
            scan_results: Arc::new(Mutex::new(Vec::new())),
            decoded_frames: Arc::new(Mutex::new(Vec::new())),
            running: Arc::new(Mutex::new(false)),
        }
    }

    pub fn init_device(&self) -> Result<()> {
        info!(
            "Initializing SDR device: type={}, freq={}MHz, sr={}Msps, gain={}dB",
            self.config.device_type,
            self.config.frequency_hz / 1_000_000,
            self.config.sample_rate_hz / 1_000_000,
            self.config.gain_db
        );

        match self.config.device_type.as_str() {
            "hackrf" => self.init_hackrf(),
            "bladerf" => self.init_bladerf(),
            "usrp" => self.init_usrp(),
            "rtlsdr" => self.init_rtlsdr(),
            "limesdr" => self.init_limesdr(),
            other => anyhow::bail!("Unsupported SDR type: {}", other),
        }
    }

    fn init_hackrf(&self) -> Result<()> {
        info!("HackRF: Opening device via libhackrf");
        // hackrf_init() → hackrf_open() → hackrf_set_freq/sample_rate/lna_gain/vga_gain
        // In production: links to libhackrf.so via FFI
        Ok(())
    }

    fn init_bladerf(&self) -> Result<()> {
        info!("bladeRF: Opening device via libbladeRF");
        // bladerf_open() → bladerf_set_frequency/sample_rate/gain
        Ok(())
    }

    fn init_usrp(&self) -> Result<()> {
        info!("USRP: Opening device via UHD");
        // uhd::usrp::multi_usrp::make() → set_rx_freq/rate/gain
        Ok(())
    }

    fn init_rtlsdr(&self) -> Result<()> {
        info!("RTL-SDR: Opening device via librtlsdr");
        // rtlsdr_open() → rtlsdr_set_center_freq/sample_rate/tuner_gain
        Ok(())
    }

    fn init_limesdr(&self) -> Result<()> {
        info!("LimeSDR: Opening device via LimeSuite");
        // LMS_Open() → LMS_SetLOFrequency/SetSampleRate/SetGaindB
        Ok(())
    }

    pub fn start_capture(&self, iq_pipe: Option<&PathBuf>) -> Result<()> {
        *self.running.lock().unwrap() = true;
        info!(
            "Starting IQ capture at {}MHz",
            self.config.frequency_hz / 1_000_000
        );

        if let Some(path) = iq_pipe {
            info!("IQ data streaming to: {}", path.display());
            // In production: write IQ samples to named pipe for srsRAN/gr-lte consumption
        }
        Ok(())
    }

    pub fn scan_cells(&self, earfcns: &[u32]) -> Result<Vec<CellScanResult>> {
        info!("Scanning {} EARFCNs for cells...", earfcns.len());
        let mut results = Vec::new();

        for &earfcn in earfcns {
            let freq_hz = earfcn_to_freq(earfcn);
            info!(
                "  Scanning EARFCN {} ({}MHz)...",
                earfcn,
                freq_hz / 1_000_000
            );

            // In production: tune SDR → PSS/SSS correlation → MIB decode → SIB1 decode
            // Returns cell info if found
            let result = CellScanResult {
                earfcn,
                pci: 0,
                rsrp_dbm: -999.0,
                rsrq_db: -99.0,
                frequency_offset_hz: 0.0,
                mib_decoded: false,
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

    pub fn stop(&self) {
        *self.running.lock().unwrap() = false;
        info!("SDR capture stopped");
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
        2750..=3449 => (2620_000_000 + (earfcn as u64 - 2750) * 100_000), // Band 7 DL
        1200..=1949 => (1805_000_000 + (earfcn as u64 - 1200) * 100_000), // Band 3 DL
        0..=599 => (2110_000_000 + earfcn as u64 * 100_000),              // Band 1 DL
        _ => earfcn as u64 * 100_000,                                     // Fallback
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
    let reader = BufReader::new(stream.try_clone().unwrap());
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
                let _ = writeln!(writer, "{}", serde_json::to_string(&resp).unwrap());
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
                        data: Some(serde_json::to_value(&results).unwrap()),
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
                    data: Some(serde_json::to_value(&fp).unwrap()),
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
                let running = *bridge.running.lock().unwrap();
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

        let _ = writeln!(writer, "{}", serde_json::to_string(&resp).unwrap());
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

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

    let bridge = Arc::new(SdrBridge::new(config));
    bridge.init_device()?;

    if matches!(cli.mode.as_str(), "capture" | "relay") {
        bridge.start_capture(cli.iq_output.as_ref())?;
    }

    if cli.mode == "scan" {
        let earfcns = lte_band_earfcns(cli.scan_bands.as_deref().unwrap_or("all-lte"));
        let results = bridge.scan_cells(&earfcns)?;
        info!(
            "Scan complete: {} cells found",
            results.iter().filter(|r| r.mib_decoded).count()
        );
        for r in &results {
            if r.mib_decoded {
                info!(
                    "  EARFCN={} PCI={} RSRP={:.1}dBm MCC={} MNC={} TAC={} CID={}",
                    r.earfcn,
                    r.pci,
                    r.rsrp_dbm,
                    r.mcc.unwrap_or(0),
                    r.mnc.unwrap_or(0),
                    r.tac.unwrap_or(0),
                    r.cell_id.unwrap_or(0)
                );
            }
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
