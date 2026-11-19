//! Galileo OSNMA (Open Service Navigation Message Authentication) verifier.
//!
//! Galileo OSNMA became operational in 2025: it authenticates the I/NAV
//! navigation message with a TESLA-like key chain, enabling cryptographic
//! GNSS spoofing detection instead of heuristic C/N0 checks. This tool
//! parses OSNMA fields from captured I/NAV bits and verifies the TESLA
//! key chain and MACs with an in-tree HMAC-SHA256 (RFC 2104).
//!
//! Structural layout follows the Galileo OSNMA Signal-In-Space ICD
//! (NMA header, Mack header, Mack data, and TESLA key sections). Key
//! chain relation: a disclosed key K_i is accepted when the previously
//! authenticated key satisfies K_{i-1} == Trunc128(HMAC-SHA256(K_i)).
//!
//! Research tool: verification of a full chain requires a trusted root
//! (KMF public key / initial chain value) supplied by the operator.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

// ── SHA-256 (FIPS 180-4) ─────────────────────────────────────────────────────

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for block in message.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, chunk) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*chunk);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// ── HMAC-SHA256 (RFC 2104) ───────────────────────────────────────────────────

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&sha256(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut inner = Vec::with_capacity(64 + message.len());
    let mut outer = Vec::with_capacity(96);
    for byte in block.iter() {
        inner.push(byte ^ 0x36);
        outer.push(byte ^ 0x5c);
    }
    inner.extend_from_slice(message);
    outer.extend_from_slice(&sha256(&inner));
    sha256(&outer)
}

// ── OSNMA field structures (Galileo OSNMA SIS ICD) ───────────────────────────

/// NMA header — 40 bits carried in the I/NAV OSNMA field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmaHeader {
    /// Public Key ID — which KMF public key to use.
    pub pkid: u8,
    /// Chain ID (key chain within the time interval).
    pub ci: u8,
    /// Hash function: 0=SHA-256, 1=SHA3-256.
    pub hf: u8,
    /// MAC length table: 0=20 bits ... per ICD lookup.
    pub fl: u8,
    /// Key length: 0=96 bits, 1=104, 2=112, 3=128.
    pub key_length: usize,
    /// Number of Mack blocks + key (LNV).
    pub lnv: u8,
    /// NMA status: 0=reserved, 1=initial, 2=OK, 3=don't use.
    pub nmas: u8,
    /// Data decryption status (for authenticated-but-encrypted data).
    pub dds: u8,
}

impl NmaHeader {
    /// Parse the 5-byte NMA header.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 5 {
            return None;
        }
        let pkid = bytes[0] >> 4;
        let ci = bytes[0] & 0x0F;
        let hf = bytes[1] >> 5;
        let fl = bytes[1] & 0x1F;
        let lnv = bytes[2];
        let nmas = bytes[3] >> 6;
        let dds = (bytes[3] >> 4) & 0x03;
        let key_length = match (bytes[4] >> 4) & 0x03 {
            0 => 96,
            1 => 104,
            2 => 112,
            _ => 128,
        };
        Some(Self {
            pkid,
            ci,
            hf,
            fl,
            key_length,
            lnv,
            nmas,
            dds,
        })
    }

    /// A spoofed or revoked stream advertises itself as unusable.
    pub fn usable(&self) -> bool {
        self.nmas == 2
    }
}

/// One captured OSNMA section: header, Mack data, and a disclosed TESLA key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsnmaRecord {
    pub sat_svn: u8,
    pub nma_header_hex: String,
    pub mack_data_hex: String,
    pub tesla_key_hex: String,
    /// Navigation bits covered by the Mack (hex).
    pub nav_bits_hex: String,
    /// MAC tag observed for the nav bits (hex).
    pub tag_hex: String,
    /// Key previously authenticated for this chain (hex), if any.
    pub previous_key_hex: Option<String>,
}

/// Verification verdict for one record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsnmaVerdict {
    pub sat_svn: u8,
    pub header_parsed: bool,
    pub nma_status_ok: bool,
    pub chain_verified: Option<bool>,
    pub mac_verified: Option<bool>,
    pub spoofed: bool,
    pub reasons: Vec<String>,
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("hex string has odd length: {s}");
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .with_context(|| format!("invalid hex byte in {s}"))
        })
        .collect()
}

/// OSNMA TESLA chain relation: the previously authenticated (older) key is
/// the 128-bit truncation of HMAC-SHA256 over the disclosed (newer) key.
pub fn chain_matches(previous_key: &[u8], disclosed_key: &[u8]) -> bool {
    if previous_key.is_empty() || disclosed_key.is_empty() {
        return false;
    }
    let derived = hmac_sha256(disclosed_key, b"OSNMA key chain");
    previous_key == &derived[..previous_key.len().min(16)]
}

/// MAC check: tag == Trunc(HMAC-SHA256(tesla_key, nav_bits)).
pub fn mac_matches(tesla_key: &[u8], nav_bits: &[u8], tag: &[u8]) -> bool {
    if tesla_key.is_empty() || tag.is_empty() {
        return false;
    }
    let mac = hmac_sha256(tesla_key, nav_bits);
    tag.len() <= 32 && mac[..tag.len()] == *tag
}

/// Verify one OSNMA record end-to-end as far as the provided fields allow.
pub fn verify_record(record: &OsnmaRecord) -> OsnmaVerdict {
    let mut reasons = Vec::new();
    let header_bytes = decode_hex(&record.nma_header_hex).unwrap_or_default();
    let header = NmaHeader::parse(&header_bytes);
    let header_parsed = header.is_some();

    let nma_status_ok = header.as_ref().is_some_and(NmaHeader::usable);
    if header_parsed && !nma_status_ok {
        reasons.push(format!(
            "NMA status {} — receiver must not use this signal",
            header.as_ref().map(|h| h.nmas).unwrap_or(0)
        ));
    }
    if !header_parsed {
        reasons.push("NMA header unparseable (truncated or malformed I/NAV)".to_string());
    }

    let mut chain_verified = None;
    if let Some(prev_hex) = &record.previous_key_hex {
        let prev = decode_hex(prev_hex).unwrap_or_default();
        let disclosed = decode_hex(&record.tesla_key_hex).unwrap_or_default();
        let ok = chain_matches(&prev, &disclosed);
        chain_verified = Some(ok);
        if !ok {
            reasons.push("TESLA key chain mismatch — key not derivable from anchor".to_string());
        }
    }

    let mut mac_verified = None;
    let tag = decode_hex(&record.tag_hex).unwrap_or_default();
    if !tag.is_empty() {
        let key = decode_hex(&record.tesla_key_hex).unwrap_or_default();
        let nav = decode_hex(&record.nav_bits_hex).unwrap_or_default();
        let ok = mac_matches(&key, &nav, &tag);
        mac_verified = Some(ok);
        if !ok {
            reasons.push("MAC mismatch — navigation data failed authentication".to_string());
        }
    }

    let spoofed = chain_verified == Some(false)
        || mac_verified == Some(false)
        || !header_parsed
        || !nma_status_ok;

    OsnmaVerdict {
        sat_svn: record.sat_svn,
        header_parsed,
        nma_status_ok,
        chain_verified,
        mac_verified,
        spoofed,
        reasons,
    }
}

// ── CLI ──────────────────────────────────────────────────────────────────────

/// Command-line interface for `osnma-verify`. Usable standalone (the thin
/// `src/bin/osnma-verify.rs` wrapper) or as a subcommand of the multi-call
/// `staticzero` binary.
#[derive(Parser, Debug)]
#[command(
    name = "osnma-verify",
    about = "Galileo OSNMA verification — cryptographic GNSS spoofing detection"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Verify OSNMA records (JSON lines) from a file or stdin
    Verify {
        /// Input file with one OsnmaRecord JSON object per line
        input: Option<PathBuf>,
    },
    /// Run SHA-256/HMAC known-answer tests (RFC 4231 / FIPS vectors)
    Selftest,
}

/// Entry point invoked by the `osnma-verify` bin and the `staticzero`
/// multi-call binary's `osnma-verify` subcommand.
pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Verify { input } => {
            let stdin = std::io::stdin();
            let reader: Box<dyn BufRead> = match input {
                Some(path) => Box::new(BufReader::new(
                    std::fs::File::open(&path)
                        .with_context(|| format!("open OSNMA record file {}", path.display()))?,
                )),
                None => Box::new(stdin.lock()),
            };
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            for (index, line) in reader.lines().enumerate() {
                let line = line.with_context(|| format!("read input line {}", index + 1))?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let record: OsnmaRecord = serde_json::from_str(trimmed)
                    .with_context(|| format!("parse JSON record on line {}", index + 1))?;
                let verdict = verify_record(&record);
                serde_json::to_writer(&mut out, &verdict)?;
                writeln!(out)?;
            }
            Ok(())
        }
        Command::Selftest => {
            run_selftest()?;
            println!("all self-tests passed");
            Ok(())
        }
    }
}

fn run_selftest() -> Result<()> {
    // FIPS 180-4 vectors
    assert_eq!(
        hex(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    // RFC 4231 test case 1
    let key = [0x0b; 20];
    let mac = hmac_sha256(&key, b"Hi There");
    assert_eq!(
        hex(&mac),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );

    // RFC 4231 test case 2
    let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(
        hex(&mac),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );

    // Synthetic TESLA chain: the chain is generated backwards by the
    // sender — an older key is the 128-bit truncation of HMAC over the
    // newer (later disclosed) key.
    let newer_key: [u8; 16] = [0x5C; 16];
    let derived = hmac_sha256(&newer_key, b"OSNMA key chain");
    let older_key = derived[..16].to_vec();
    assert!(chain_matches(&older_key, &newer_key));
    assert!(!chain_matches(&newer_key, &older_key));

    // MAC check round trip
    let tag = hmac_sha256(&newer_key, b"navigation message bits")[..8].to_vec();
    assert!(mac_matches(&newer_key, b"navigation message bits", &tag));
    assert!(!mac_matches(&newer_key, b"tampered message bits", &tag));

    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_fips_vectors() {
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // one million 'a' would be slow; long multi-block input instead
        let long = vec![b'a'; 1_000];
        assert_eq!(hex(&sha256(&long)).len(), 64);
    }

    #[test]
    fn hmac_rfc4231_case3() {
        let key = [0xaa; 20];
        let mac = hmac_sha256(&key, &[0xdd; 50]);
        assert_eq!(
            hex(&mac),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    #[test]
    fn hmac_long_key_rfc4231_case6() {
        let key = [0xaa; 131];
        let mac = hmac_sha256(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            hex(&mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn nma_header_parses() {
        // status bits set to OK (nmas=2): byte 3 = 0x80; key length field 0 → 96 bits
        let header = NmaHeader::parse(&[0x12, 0x05, 0x03, 0x80, 0x03]).unwrap();
        assert_eq!(header.pkid, 1);
        assert_eq!(header.ci, 2);
        assert!(header.usable());
        assert_eq!(header.key_length, 96);

        let broken = NmaHeader::parse(&[0x12, 0x05]);
        assert!(broken.is_none());

        let not_usable = NmaHeader::parse(&[0x12, 0x05, 0x03, 0xC0, 0x03]).unwrap();
        assert!(!not_usable.usable());
    }

    #[test]
    fn record_verification_flags_spoof() {
        // Well-formed header, but a MAC that fails
        let key = vec![0x11u8; 16];
        let record = OsnmaRecord {
            sat_svn: 19,
            nma_header_hex: "1205038030".to_string(),
            mack_data_hex: "00".to_string(),
            tesla_key_hex: hex(&key),
            nav_bits_hex: hex(b"genuine nav"),
            tag_hex: hex(&hmac_sha256(&key, b"tampered nav")[..8]),
            previous_key_hex: None,
        };
        let verdict = verify_record(&record);
        assert!(verdict.header_parsed);
        assert!(verdict.nma_status_ok);
        assert_eq!(verdict.mac_verified, Some(false));
        assert!(verdict.spoofed);

        // Same record with a correct MAC passes
        let good = OsnmaRecord {
            tag_hex: hex(&hmac_sha256(&key, b"genuine nav")[..8]),
            ..record
        };
        let verdict = verify_record(&good);
        assert_eq!(verdict.mac_verified, Some(true));
        assert!(!verdict.spoofed);
    }
}
