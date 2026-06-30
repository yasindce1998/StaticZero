use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::{error, info, warn};

#[derive(Debug, Parser)]
#[command(name = "modem-firmware")]
#[command(about = "Modem Firmware Analysis — extract, patch, and analyze baseband images")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Verbose output
    #[arg(long, short, global = true)]
    verbose: bool,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Extract firmware components from a modem image
    Extract {
        /// Path to firmware image (.mbn, .elf, .bin)
        #[arg(long)]
        image: PathBuf,

        /// Output directory for extracted components
        #[arg(long, default_value = "./fw_extracted")]
        output: PathBuf,

        /// Modem chipset (qualcomm, mediatek, samsung-shannon, intel-xgold, huawei-balong)
        #[arg(long)]
        chipset: String,
    },

    /// Analyze firmware for vulnerabilities and interesting patterns
    Analyze {
        /// Path to firmware image or extracted directory
        #[arg(long)]
        target: PathBuf,

        /// Chipset type
        #[arg(long)]
        chipset: String,

        /// Output report path
        #[arg(long, default_value = "./fw_analysis.json")]
        report: PathBuf,
    },

    /// Patch firmware with custom modifications
    Patch {
        /// Path to original firmware image
        #[arg(long)]
        image: PathBuf,

        /// Patch specification file (JSON)
        #[arg(long)]
        patchfile: PathBuf,

        /// Output path for patched image
        #[arg(long)]
        output: PathBuf,
    },

    /// Diff two firmware images
    Diff {
        /// First firmware image
        #[arg(long)]
        old: PathBuf,

        /// Second firmware image
        #[arg(long)]
        new: PathBuf,

        /// Chipset type
        #[arg(long)]
        chipset: String,
    },

    /// Extract NV items (carrier config, band settings)
    NvDump {
        /// Path to NV image or EFS dump
        #[arg(long)]
        image: PathBuf,

        /// Output path
        #[arg(long, default_value = "./nv_items.json")]
        output: PathBuf,
    },

    /// Monitor modem debug interface in real-time
    Monitor {
        /// Device path (/dev/diag, /dev/ttyUSB0, etc.)
        #[arg(long, default_value = "/dev/diag")]
        device: PathBuf,

        /// Protocol (diag, at, qmi, mbim)
        #[arg(long, default_value = "diag")]
        protocol: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareImage {
    pub path: String,
    pub chipset: ChipsetType,
    pub size_bytes: u64,
    pub sections: Vec<FirmwareSection>,
    pub metadata: FirmwareMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChipsetType {
    Qualcomm,
    MediaTek,
    SamsungShannon,
    IntelXGold,
    HuaweiBalong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareSection {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub section_type: SectionType,
    pub load_address: u64,
    pub entry_point: Option<u64>,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SectionType {
    BootRom,
    Modem,
    Dsp,
    Rtos,
    L1Protocol,
    L2Protocol,
    NasStack,
    RrcStack,
    ImsStack,
    NvData,
    Certificate,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareMetadata {
    pub version: Option<String>,
    pub build_date: Option<String>,
    pub supported_bands: Vec<String>,
    pub supported_rats: Vec<String>,
    pub security_level: SecurityLevel,
    pub signed: bool,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityLevel {
    None,
    SignedOnly,
    SignedAndEncrypted,
    SecureBoot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityReport {
    pub firmware_path: String,
    pub chipset: String,
    pub findings: Vec<Finding>,
    pub attack_surfaces: Vec<AttackSurface>,
    pub protocol_handlers: Vec<ProtocolHandler>,
    pub nv_items_of_interest: Vec<NvItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: FindingCategory,
    pub title: String,
    pub description: String,
    pub offset: u64,
    pub size: u64,
    pub cve: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingCategory {
    MemoryCorruption,
    CryptoWeakness,
    AuthBypass,
    ProtocolFlaw,
    Backdoor,
    DebugInterface,
    HardcodedCredential,
    InsecureDefault,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurface {
    pub interface: String,
    pub protocol: String,
    pub description: String,
    pub reachable_from: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolHandler {
    pub protocol: String,
    pub handler_offset: u64,
    pub message_types: Vec<String>,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvItem {
    pub id: u32,
    pub name: String,
    pub value: Vec<u8>,
    pub description: String,
    pub security_relevant: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchSpec {
    pub patches: Vec<Patch>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patch {
    pub offset: u64,
    pub original: Vec<u8>,
    pub replacement: Vec<u8>,
    pub description: String,
}

struct FirmwareAnalyzer {
    chipset: ChipsetType,
}

impl FirmwareAnalyzer {
    fn new(chipset_str: &str) -> Result<Self> {
        let chipset = match chipset_str {
            "qualcomm" => ChipsetType::Qualcomm,
            "mediatek" => ChipsetType::MediaTek,
            "samsung-shannon" | "shannon" => ChipsetType::SamsungShannon,
            "intel-xgold" | "intel" => ChipsetType::IntelXGold,
            "huawei-balong" | "balong" => ChipsetType::HuaweiBalong,
            other => anyhow::bail!("Unsupported chipset: {}", other),
        };
        Ok(Self { chipset })
    }

    fn extract(&self, image_path: &PathBuf, output_dir: &PathBuf) -> Result<FirmwareImage> {
        let data = fs::read(image_path)
            .with_context(|| format!("Failed to read firmware image: {}", image_path.display()))?;

        info!("Loaded firmware: {} bytes", data.len());
        fs::create_dir_all(output_dir)?;

        let sections = match self.chipset {
            ChipsetType::Qualcomm => self.extract_qualcomm(&data, output_dir)?,
            ChipsetType::MediaTek => self.extract_mediatek(&data, output_dir)?,
            ChipsetType::SamsungShannon => self.extract_shannon(&data, output_dir)?,
            ChipsetType::IntelXGold => self.extract_xgold(&data, output_dir)?,
            ChipsetType::HuaweiBalong => self.extract_balong(&data, output_dir)?,
        };

        let metadata = self.extract_metadata(&data);

        Ok(FirmwareImage {
            path: image_path.display().to_string(),
            chipset: self.chipset.clone(),
            size_bytes: data.len() as u64,
            sections,
            metadata,
        })
    }

    fn extract_qualcomm(&self, data: &[u8], output_dir: &PathBuf) -> Result<Vec<FirmwareSection>> {
        info!("Parsing Qualcomm MBN/ELF format...");
        let mut sections = Vec::new();

        // Check for ELF header
        if data.len() >= 4 && &data[0..4] == b"\x7fELF" {
            info!("  ELF format detected (modem.mbn)");
            sections.push(self.parse_elf_sections(data, output_dir)?);
        }

        // Check for Qualcomm SBL/MBN header (0x844BDCD1 magic for signed images)
        if data.len() >= 40 {
            let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if magic == 0x844BDCD1 {
                info!("  Qualcomm signed MBN header detected");
                let code_size = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
                let sig_size = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
                info!("  Code size: {}, Signature size: {}", code_size, sig_size);

                sections.push(FirmwareSection {
                    name: "modem_code".into(),
                    offset: 40,
                    size: code_size as u64,
                    section_type: SectionType::Modem,
                    load_address: u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as u64,
                    entry_point: Some(
                        u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as u64
                    ),
                    hash: format!("{:016x}", simple_hash(&data[40..40 + code_size as usize])),
                });

                sections.push(FirmwareSection {
                    name: "signature".into(),
                    offset: 40 + code_size as u64,
                    size: sig_size as u64,
                    section_type: SectionType::Certificate,
                    load_address: 0,
                    entry_point: None,
                    hash: String::new(),
                });
            }
        }

        // Look for AMSS (Advanced Mobile Subscriber Software) markers
        if let Some(pos) = find_pattern(data, b"AMSS") {
            info!("  AMSS marker at offset 0x{:x}", pos);
        }

        // Look for Q6 DSP sections
        if let Some(pos) = find_pattern(data, b"QDSP6") {
            info!("  QDSP6 section at offset 0x{:x}", pos);
            sections.push(FirmwareSection {
                name: "dsp".into(),
                offset: pos as u64,
                size: 0, // determined by section header
                section_type: SectionType::Dsp,
                load_address: 0,
                entry_point: None,
                hash: String::new(),
            });
        }

        // Write extracted sections
        for section in &sections {
            if section.size > 0 && (section.offset + section.size) <= data.len() as u64 {
                let section_data =
                    &data[section.offset as usize..(section.offset + section.size) as usize];
                let out_path = output_dir.join(format!("{}.bin", section.name));
                fs::write(&out_path, section_data)?;
                info!("  Extracted {} -> {}", section.name, out_path.display());
            }
        }

        Ok(sections)
    }

    fn extract_mediatek(&self, data: &[u8], output_dir: &PathBuf) -> Result<Vec<FirmwareSection>> {
        info!("Parsing MediaTek format...");
        let mut sections = Vec::new();

        // MediaTek modem images use a custom header format
        // Look for "BRLYT" (BootRom Layout Table)
        if let Some(pos) = find_pattern(data, b"BRLYT") {
            info!("  BRLYT header at offset 0x{:x}", pos);
        }

        // Look for "FILE_INFO" markers
        if let Some(pos) = find_pattern(data, b"FILE_INFO") {
            info!("  FILE_INFO at offset 0x{:x}", pos);
        }

        // DSP section marker
        if let Some(pos) = find_pattern(data, b"DSP_BL") {
            info!("  DSP bootloader at offset 0x{:x}", pos);
            sections.push(FirmwareSection {
                name: "dsp_bl".into(),
                offset: pos as u64,
                size: 0,
                section_type: SectionType::Dsp,
                load_address: 0,
                entry_point: None,
                hash: String::new(),
            });
        }

        // Modem binary (MDIMG)
        if let Some(pos) = find_pattern(data, b"MDIMG") {
            info!("  Modem image at offset 0x{:x}", pos);
            sections.push(FirmwareSection {
                name: "modem".into(),
                offset: pos as u64,
                size: 0,
                section_type: SectionType::Modem,
                load_address: 0,
                entry_point: None,
                hash: String::new(),
            });
        }

        Ok(sections)
    }

    fn extract_shannon(&self, data: &[u8], output_dir: &PathBuf) -> Result<Vec<FirmwareSection>> {
        info!("Parsing Samsung Shannon format...");
        let mut sections = Vec::new();

        // Shannon modem images (CP/modem.bin in Samsung firmware)
        // Look for TOC (Table of Contents) header
        if data.len() >= 512 {
            let toc_magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if toc_magic == 0x53484E00 {
                // "SHN\0"
                info!("  Shannon TOC header detected");
                let num_entries = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                info!("  {} TOC entries", num_entries);

                for i in 0..num_entries.min(32) {
                    let entry_offset = (8 + i * 32) as usize;
                    if entry_offset + 32 > data.len() {
                        break;
                    }
                    let name_bytes = &data[entry_offset..entry_offset + 12];
                    let name = String::from_utf8_lossy(name_bytes)
                        .trim_end_matches('\0')
                        .to_string();
                    let offset = u32::from_le_bytes([
                        data[entry_offset + 12],
                        data[entry_offset + 13],
                        data[entry_offset + 14],
                        data[entry_offset + 15],
                    ]);
                    let size = u32::from_le_bytes([
                        data[entry_offset + 16],
                        data[entry_offset + 17],
                        data[entry_offset + 18],
                        data[entry_offset + 19],
                    ]);

                    info!(
                        "  Section: {} offset=0x{:x} size=0x{:x}",
                        name, offset, size
                    );
                    sections.push(FirmwareSection {
                        name,
                        offset: offset as u64,
                        size: size as u64,
                        section_type: SectionType::Modem,
                        load_address: 0,
                        entry_point: None,
                        hash: String::new(),
                    });
                }
            }
        }

        Ok(sections)
    }

    fn extract_xgold(&self, data: &[u8], output_dir: &PathBuf) -> Result<Vec<FirmwareSection>> {
        info!("Parsing Intel XGold/XMM format...");
        let sections = Vec::new();

        // Intel XMM/XGold modems use FLS (Flash Layout Structure)
        if let Some(pos) = find_pattern(data, b"FLSH") {
            info!("  FLS header at offset 0x{:x}", pos);
        }

        // PSI (Pre-Silicon Init) / EBL (Extended Boot Loader)
        if let Some(pos) = find_pattern(data, b"\x01\x01\x01\x01") {
            if pos < 256 {
                info!("  PSI section candidate at offset 0x{:x}", pos);
            }
        }

        Ok(sections)
    }

    fn extract_balong(&self, data: &[u8], output_dir: &PathBuf) -> Result<Vec<FirmwareSection>> {
        info!("Parsing Huawei Balong format...");
        let sections = Vec::new();

        // Huawei Balong modem images
        if let Some(pos) = find_pattern(data, b"BALONG") {
            info!("  Balong marker at offset 0x{:x}", pos);
        }

        // Look for VxWorks markers (Balong uses VxWorks RTOS)
        if let Some(pos) = find_pattern(data, b"VxWorks") {
            info!("  VxWorks RTOS at offset 0x{:x}", pos);
        }

        Ok(sections)
    }

    fn parse_elf_sections(&self, data: &[u8], output_dir: &PathBuf) -> Result<FirmwareSection> {
        // Minimal ELF parsing for modem images
        let entry_point = if data.len() >= 24 {
            u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as u64
        } else {
            0
        };

        Ok(FirmwareSection {
            name: "modem_elf".into(),
            offset: 0,
            size: data.len() as u64,
            section_type: SectionType::Modem,
            load_address: 0,
            entry_point: Some(entry_point),
            hash: format!("{:016x}", simple_hash(data)),
        })
    }

    fn extract_metadata(&self, data: &[u8]) -> FirmwareMetadata {
        let mut version = None;
        let mut build_date = None;

        // Search for version strings
        let version_patterns = [b"VERSION:" as &[u8], b"MPSS.", b"AMSS_", b"M_", b"CP_"];
        for pat in &version_patterns {
            if let Some(pos) = find_pattern(data, pat) {
                let end = (pos + 64).min(data.len());
                let s = String::from_utf8_lossy(&data[pos..end]);
                if let Some(line) = s.split('\0').next() {
                    version = Some(line.to_string());
                    break;
                }
            }
        }

        // Search for date strings
        let date_patterns = [b"20" as &[u8]]; // Year prefix
        for pat in &date_patterns {
            if let Some(pos) = find_pattern(data, pat) {
                let end = (pos + 20).min(data.len());
                let s = String::from_utf8_lossy(&data[pos..end]);
                if s.len() >= 10 && s.chars().take(4).all(|c| c.is_ascii_digit()) {
                    build_date = Some(s[..10].to_string());
                    break;
                }
            }
        }

        FirmwareMetadata {
            version,
            build_date,
            supported_bands: detect_bands(data),
            supported_rats: detect_rats(data),
            security_level: detect_security_level(data),
            signed: find_pattern(data, b"-----BEGIN CERTIFICATE").is_some()
                || find_pattern(data, &[0x30, 0x82]).is_some(),
            encrypted: data.iter().take(1024).filter(|&&b| b == 0x00).count() < 100,
        }
    }

    fn analyze(&self, target: &PathBuf) -> Result<VulnerabilityReport> {
        let data =
            fs::read(target).with_context(|| format!("Failed to read: {}", target.display()))?;

        info!("Analyzing {} ({} bytes)...", target.display(), data.len());

        let mut findings = Vec::new();
        let mut attack_surfaces = Vec::new();
        let mut protocol_handlers = Vec::new();

        // Check for known vulnerable patterns
        findings.extend(self.check_memory_corruption_patterns(&data));
        findings.extend(self.check_crypto_weaknesses(&data));
        findings.extend(self.check_debug_interfaces(&data));
        findings.extend(self.check_hardcoded_credentials(&data));

        // Identify attack surfaces
        attack_surfaces.extend(self.identify_attack_surfaces(&data));

        // Find protocol handler entry points
        protocol_handlers.extend(self.find_protocol_handlers(&data));

        // NV items of security interest
        let nv_items = self.find_security_nv_items(&data);

        Ok(VulnerabilityReport {
            firmware_path: target.display().to_string(),
            chipset: format!("{:?}", self.chipset),
            findings,
            attack_surfaces,
            protocol_handlers,
            nv_items_of_interest: nv_items,
        })
    }

    fn check_memory_corruption_patterns(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for strcpy/sprintf usage (common in baseband firmware)
        let dangerous_funcs = [
            (
                b"strcpy" as &[u8],
                "Use of strcpy (potential buffer overflow)",
            ),
            (
                b"sprintf",
                "Use of sprintf (potential format string/overflow)",
            ),
            (b"gets", "Use of gets (guaranteed buffer overflow)"),
            (b"strcat", "Use of strcat (potential buffer overflow)"),
        ];

        for (pattern, desc) in &dangerous_funcs {
            let count = count_pattern(data, pattern);
            if count > 0 {
                findings.push(Finding {
                    severity: Severity::Medium,
                    category: FindingCategory::MemoryCorruption,
                    title: format!(
                        "Dangerous function usage: {} ({} instances)",
                        String::from_utf8_lossy(pattern),
                        count
                    ),
                    description: desc.to_string(),
                    offset: find_pattern(data, pattern).unwrap_or(0) as u64,
                    size: pattern.len() as u64,
                    cve: None,
                });
            }
        }

        // Check for heap metadata patterns indicating no ASLR
        if let Some(pos) = find_pattern(data, &[0x00, 0x00, 0x00, 0x40]) {
            // Fixed load addresses suggest no ASLR
            if pos < 64 {
                findings.push(Finding {
                    severity: Severity::Medium,
                    category: FindingCategory::MemoryCorruption,
                    title: "Fixed load address (no ASLR)".into(),
                    description: "Firmware loaded at fixed address, no address randomization"
                        .into(),
                    offset: pos as u64,
                    size: 4,
                    cve: None,
                });
            }
        }

        findings
    }

    fn check_crypto_weaknesses(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // A5/1 stream cipher (weak GSM cipher)
        if find_pattern(data, b"A5/1").is_some() || find_pattern(data, b"GEA1").is_some() {
            findings.push(Finding {
                severity: Severity::High,
                category: FindingCategory::CryptoWeakness,
                title: "Weak cipher support: A5/1 or GEA1".into(),
                description: "Firmware supports broken GSM ciphers vulnerable to real-time decryption".into(),
                offset: find_pattern(data, b"A5/1").unwrap_or(0) as u64,
                size: 0,
                cve: None,
            });
        }

        // Check for null cipher support (A5/0, EEA0, NEA0)
        if find_pattern(data, b"A5/0").is_some() || find_pattern(data, b"EEA0").is_some() {
            findings.push(Finding {
                severity: Severity::High,
                category: FindingCategory::CryptoWeakness,
                title: "Null cipher accepted".into(),
                description: "Firmware accepts null encryption, enabling passive interception"
                    .into(),
                offset: 0,
                size: 0,
                cve: None,
            });
        }

        // Hardcoded keys/IVs (all-zero patterns in crypto context)
        let zero_key: Vec<u8> = vec![0u8; 16];
        if let Some(pos) = find_pattern(data, &zero_key) {
            findings.push(Finding {
                severity: Severity::Low,
                category: FindingCategory::CryptoWeakness,
                title: "Potential null key in crypto section".into(),
                description: "16 zero bytes found — may be null key or uninitialized buffer".into(),
                offset: pos as u64,
                size: 16,
                cve: None,
            });
        }

        findings
    }

    fn check_debug_interfaces(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let debug_markers = [
            (b"DIAG_" as &[u8], "Qualcomm DIAG interface"),
            (b"QXDM", "QXDM debug port"),
            (b"AT+SLOG", "Samsung debug AT command"),
            (b"AT+DEBUG", "Debug AT command"),
            (b"AT+FACTORYRESET", "Factory reset AT command"),
            (b"AT+UNLOCK", "Unlock AT command"),
            (b"JTAG", "JTAG debug interface reference"),
        ];

        for (pattern, desc) in &debug_markers {
            if let Some(pos) = find_pattern(data, pattern) {
                findings.push(Finding {
                    severity: Severity::Info,
                    category: FindingCategory::DebugInterface,
                    title: format!("Debug interface: {}", desc),
                    description: format!(
                        "Found marker '{}' at offset 0x{:x}",
                        String::from_utf8_lossy(pattern),
                        pos
                    ),
                    offset: pos as u64,
                    size: pattern.len() as u64,
                    cve: None,
                });
            }
        }

        findings
    }

    fn check_hardcoded_credentials(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let cred_patterns = [
            (b"password" as &[u8], "Password string reference"),
            (b"DEFAULT_PIN", "Default PIN reference"),
            (b"admin:admin", "Hardcoded admin credentials"),
            (b"root:root", "Hardcoded root credentials"),
        ];

        for (pattern, desc) in &cred_patterns {
            if let Some(pos) = find_pattern(data, pattern) {
                findings.push(Finding {
                    severity: Severity::High,
                    category: FindingCategory::HardcodedCredential,
                    title: desc.to_string(),
                    description: format!("Found at offset 0x{:x}", pos),
                    offset: pos as u64,
                    size: pattern.len() as u64,
                    cve: None,
                });
            }
        }

        findings
    }

    fn identify_attack_surfaces(&self, data: &[u8]) -> Vec<AttackSurface> {
        let mut surfaces = Vec::new();

        if find_pattern(data, b"RRC").is_some() {
            surfaces.push(AttackSurface {
                interface: "Radio (Uu)".into(),
                protocol: "RRC".into(),
                description: "Radio Resource Control — handles cell connection, measurement reports, handover".into(),
                reachable_from: vec!["Over-the-air (eNB/gNB)".into(), "Fake base station".into()],
            });
        }

        if find_pattern(data, b"NAS").is_some() || find_pattern(data, b"EMM").is_some() {
            surfaces.push(AttackSurface {
                interface: "NAS layer".into(),
                protocol: "NAS/EMM/ESM".into(),
                description:
                    "Non-Access Stratum — authentication, security mode, session management".into(),
                reachable_from: vec!["Core network (MME/AMF)".into(), "MitM relay".into()],
            });
        }

        if find_pattern(data, b"IMS").is_some() || find_pattern(data, b"SIP/2.0").is_some() {
            surfaces.push(AttackSurface {
                interface: "IMS/VoLTE".into(),
                protocol: "SIP/SDP/RTP".into(),
                description: "IP Multimedia Subsystem — voice calls, SMS over IP".into(),
                reachable_from: vec!["P-CSCF".into(), "Network proxy".into()],
            });
        }

        if find_pattern(data, b"AT+").is_some() {
            surfaces.push(AttackSurface {
                interface: "AT command".into(),
                protocol: "Hayes AT".into(),
                description: "Modem control interface via serial/USB".into(),
                reachable_from: vec![
                    "Application processor".into(),
                    "USB host".into(),
                    "Bluetooth tether".into(),
                ],
            });
        }

        surfaces
    }

    fn find_protocol_handlers(&self, data: &[u8]) -> Vec<ProtocolHandler> {
        let mut handlers = Vec::new();

        let protocol_signatures: Vec<(&[u8], &str, Vec<&str>)> = vec![
            (
                b"rrc_connection_setup",
                "RRC",
                vec!["ConnectionSetup", "ConnectionRelease", "Reconfiguration"],
            ),
            (
                b"nas_attach",
                "NAS",
                vec!["AttachRequest", "AuthRequest", "SecurityModeCmd"],
            ),
            (
                b"sip_invite",
                "SIP",
                vec!["INVITE", "REGISTER", "BYE", "OPTIONS"],
            ),
            (
                b"gtp_create_session",
                "GTP-C",
                vec!["CreateSession", "DeleteSession", "ModifyBearer"],
            ),
        ];

        for (pattern, protocol, msg_types) in &protocol_signatures {
            if let Some(pos) = find_pattern(data, pattern) {
                handlers.push(ProtocolHandler {
                    protocol: protocol.to_string(),
                    handler_offset: pos as u64,
                    message_types: msg_types.iter().map(|s| s.to_string()).collect(),
                    notes: format!("Handler reference at 0x{:x}", pos),
                });
            }
        }

        handlers
    }

    fn find_security_nv_items(&self, data: &[u8]) -> Vec<NvItem> {
        let mut items = Vec::new();

        // Well-known Qualcomm NV items of security interest
        let nv_ids: Vec<(u32, &str, &str)> = vec![
            (10, "NV_SEC_CODE_I", "Security/lock code (6 digits)"),
            (65, "NV_OTKSL_I", "One-time keypad subsidy lock"),
            (85, "NV_LOCK_CODE_I", "Phone lock code"),
            (
                453,
                "NV_BAND_PREF_I",
                "Band preference (security: can lock to weak bands)",
            ),
            (906, "NV_DS_MIP_SS_USER_PROF_I", "MIP shared secret"),
            (
                1192,
                "NV_HDRSCP_SESSION_STATUS_I",
                "HDR/EV-DO session status",
            ),
            (
                6828,
                "NV_ROAMING_LIST_683_I",
                "PRL (Preferred Roaming List)",
            ),
            (6853, "NV_WCDMA_RRC_VERSION_I", "RRC protocol version"),
        ];

        for (id, name, desc) in &nv_ids {
            items.push(NvItem {
                id: *id,
                name: name.to_string(),
                value: Vec::new(),
                description: desc.to_string(),
                security_relevant: true,
            });
        }

        items
    }

    fn apply_patch(
        &self,
        image_path: &PathBuf,
        patch_spec: &PatchSpec,
        output: &PathBuf,
    ) -> Result<()> {
        let mut data = fs::read(image_path)
            .with_context(|| format!("Failed to read: {}", image_path.display()))?;

        info!(
            "Applying {} patches to firmware...",
            patch_spec.patches.len()
        );

        for (i, patch) in patch_spec.patches.iter().enumerate() {
            let offset = patch.offset as usize;
            let end = offset + patch.original.len();

            if end > data.len() {
                warn!(
                    "Patch {} extends beyond image boundary (offset 0x{:x})",
                    i, offset
                );
                continue;
            }

            if &data[offset..end] != patch.original.as_slice() {
                warn!(
                    "Patch {} original bytes don't match at offset 0x{:x}",
                    i, offset
                );
                continue;
            }

            data[offset..offset + patch.replacement.len()].copy_from_slice(&patch.replacement);
            info!(
                "  Applied patch {}: {} at 0x{:x}",
                i, patch.description, offset
            );
        }

        fs::write(output, &data)?;
        info!("Patched firmware written to: {}", output.display());
        Ok(())
    }

    fn diff_images(&self, old_path: &PathBuf, new_path: &PathBuf) -> Result<()> {
        let old_data = fs::read(old_path)?;
        let new_data = fs::read(new_path)?;

        info!("Comparing firmware images:");
        info!("  Old: {} ({} bytes)", old_path.display(), old_data.len());
        info!("  New: {} ({} bytes)", new_path.display(), new_data.len());

        if old_data.len() != new_data.len() {
            info!(
                "  Size difference: {} bytes",
                new_data.len() as i64 - old_data.len() as i64
            );
        }

        let mut diff_regions = Vec::new();
        let mut in_diff = false;
        let mut diff_start = 0;

        let min_len = old_data.len().min(new_data.len());
        for i in 0..min_len {
            if old_data[i] != new_data[i] {
                if !in_diff {
                    diff_start = i;
                    in_diff = true;
                }
            } else if in_diff {
                diff_regions.push((diff_start, i - diff_start));
                in_diff = false;
            }
        }
        if in_diff {
            diff_regions.push((diff_start, min_len - diff_start));
        }

        info!("  {} differing regions found", diff_regions.len());
        for (offset, size) in diff_regions.iter().take(20) {
            info!(
                "    0x{:08x} - 0x{:08x} ({} bytes)",
                offset,
                offset + size,
                size
            );
        }
        if diff_regions.len() > 20 {
            info!("    ... and {} more regions", diff_regions.len() - 20);
        }

        Ok(())
    }
}

fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    data.windows(pattern.len()).position(|w| w == pattern)
}

fn count_pattern(data: &[u8], pattern: &[u8]) -> usize {
    data.windows(pattern.len())
        .filter(|w| *w == pattern)
        .count()
}

fn simple_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn detect_bands(data: &[u8]) -> Vec<String> {
    let mut bands = Vec::new();
    let band_markers = [
        (b"BAND1" as &[u8], "LTE Band 1 (2100MHz)"),
        (b"BAND3", "LTE Band 3 (1800MHz)"),
        (b"BAND7", "LTE Band 7 (2600MHz)"),
        (b"BAND20", "LTE Band 20 (800MHz)"),
        (b"BAND41", "LTE Band 41 (TDD 2500MHz)"),
        (b"n78", "NR n78 (3500MHz)"),
        (b"n77", "NR n77 (3700MHz)"),
        (b"n257", "NR n257 (mmWave 28GHz)"),
    ];

    for (pattern, name) in &band_markers {
        if find_pattern(data, pattern).is_some() {
            bands.push(name.to_string());
        }
    }
    bands
}

fn detect_rats(data: &[u8]) -> Vec<String> {
    let mut rats = Vec::new();
    if find_pattern(data, b"GSM").is_some() {
        rats.push("GSM (2G)".into());
    }
    if find_pattern(data, b"WCDMA").is_some() || find_pattern(data, b"UMTS").is_some() {
        rats.push("UMTS (3G)".into());
    }
    if find_pattern(data, b"LTE").is_some() || find_pattern(data, b"E-UTRA").is_some() {
        rats.push("LTE (4G)".into());
    }
    if find_pattern(data, b"NR").is_some() || find_pattern(data, b"5G-NR").is_some() {
        rats.push("NR (5G)".into());
    }
    rats
}

fn detect_security_level(data: &[u8]) -> SecurityLevel {
    if find_pattern(data, b"SECURE_BOOT").is_some() {
        SecurityLevel::SecureBoot
    } else if find_pattern(data, b"-----BEGIN").is_some() {
        if find_pattern(data, b"AES").is_some() || find_pattern(data, b"encrypted").is_some() {
            SecurityLevel::SignedAndEncrypted
        } else {
            SecurityLevel::SignedOnly
        }
    } else {
        SecurityLevel::None
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                if cli.verbose {
                    tracing_subscriber::EnvFilter::new("debug")
                } else {
                    tracing_subscriber::EnvFilter::new("info")
                }
            }),
        )
        .with_target(false)
        .init();

    info!("StaticZero Modem Firmware Analysis Tool");

    match cli.command {
        Commands::Extract {
            image,
            output,
            chipset,
        } => {
            let analyzer = FirmwareAnalyzer::new(&chipset)?;
            let fw = analyzer.extract(&image, &output)?;
            info!("Extraction complete: {} sections found", fw.sections.len());
            let manifest = serde_json::to_string_pretty(&fw)?;
            let manifest_path = output.join("manifest.json");
            fs::write(&manifest_path, &manifest)?;
            info!("Manifest written to: {}", manifest_path.display());
        }

        Commands::Analyze {
            target,
            chipset,
            report,
        } => {
            let analyzer = FirmwareAnalyzer::new(&chipset)?;
            let report_data = analyzer.analyze(&target)?;
            info!("Analysis complete:");
            info!("  {} findings", report_data.findings.len());
            info!("  {} attack surfaces", report_data.attack_surfaces.len());
            info!(
                "  {} protocol handlers",
                report_data.protocol_handlers.len()
            );

            let json = serde_json::to_string_pretty(&report_data)?;
            fs::write(&report, &json)?;
            info!("Report written to: {}", report.display());
        }

        Commands::Patch {
            image,
            patchfile,
            output,
        } => {
            let analyzer = FirmwareAnalyzer::new("qualcomm")?;
            let spec_data = fs::read_to_string(&patchfile)?;
            let spec: PatchSpec = serde_json::from_str(&spec_data)?;
            analyzer.apply_patch(&image, &spec, &output)?;
        }

        Commands::Diff { old, new, chipset } => {
            let analyzer = FirmwareAnalyzer::new(&chipset)?;
            analyzer.diff_images(&old, &new)?;
        }

        Commands::NvDump { image, output } => {
            info!("Extracting NV items from: {}", image.display());
            let analyzer = FirmwareAnalyzer::new("qualcomm")?;
            let items = analyzer.find_security_nv_items(&fs::read(&image)?);
            let json = serde_json::to_string_pretty(&items)?;
            fs::write(&output, &json)?;
            info!(
                "NV dump written to: {} ({} items)",
                output.display(),
                items.len()
            );
        }

        Commands::Monitor { device, protocol } => {
            info!(
                "Monitoring modem on {} (protocol: {})",
                device.display(),
                protocol
            );
            info!("Listening for DIAG/AT/QMI messages...");
            info!("(In production: opens device FD, parses protocol frames, streams to stdout)");
            // In production: open /dev/diag or serial, parse DIAG/QMI/AT frames,
            // stream decoded messages to stdout for analysis
            tokio::signal::ctrl_c().await?;
            info!("Monitor stopped");
        }
    }

    Ok(())
}
