# StaticZero

eBPF-based telecom security research framework covering 2G through 5G protocol exploitation and defense. Operates at the kernel level using Linux eBPF for real-time interception, analysis, and anomaly detection across cellular network protocols.

> **Research/educational purposes only.** Unauthorized interception of telecommunications is illegal in most jurisdictions.

## Architecture

```
staticzero/
├── common/           # Shared types, event constants, map value structs
├── offense-ebpf/     # Kernel-space telecom exploitation eBPF programs
├── offense/          # User-space loader for offense programs
├── defense-ebpf/     # Kernel-space telecom detection eBPF probes
├── defense/          # User-space detection engine + correlation library
├── tools/            # SDR bridge, modem firmware analyzer, protocol correlator
├── docs/             # Threat model, lab setup guides
└── scripts/          # Lab automation
```

## Offensive Capabilities (F89–F108)

### Core Telecom Interception (F89–F100)

| # | Feature | Hook Point | Target |
|---|---------|-----------|--------|
| 89 | AT Command Injection | kprobe: `tty_write` | 2G/3G/4G modem serial |
| 90 | Baseband Exploitation | kprobe: `usb_submit_urb` | USB bulk to baseband |
| 91 | SIM Data Extraction | kprobe: `vfs_read` | APDU filesystem |
| 92 | IMSI Interception | kprobe: `qmi_wwan_rx_fixup` | NAS Identity/Attach |
| 93 | Protocol Downgrade | TC classifier | TAU Reject (5G/4G→2G) |
| 94 | GTP Tunnel Hijacking | XDP on GTP iface | TEID manipulation |
| 95 | SS7 MAP Injection | TC (SCTP:2905) | SendRoutingInfo/UpdateLocation |
| 96 | Diameter AVP Manipulation | TC (SCTP/TCP:3868) | S6a/S6b AVPs |
| 97 | RRC Connection Redirect | kprobe: `tty_write` | RRCConnectionRelease |
| 98 | NAS Message Interception | kprobe: `qmi_wwan_rx_fixup` | Pre-encryption NAS PDUs |
| 99 | 5G SUPI De-concealment | kprobe: `ecies_decrypt` | SUCI→SUPI recovery |
| 100 | 5G N2 Interface Injection | TC (SCTP:38412) | NGAP on AMF↔gNB |

### Advanced Telecom (F101–F108)

| # | Feature | Description |
|---|---------|-------------|
| 101 | VoLTE/VoNR Interception | SIP/SDP manipulation, RTP/SRTP key extraction, ReVoLTE |
| 102 | eSIM Provisioning Attack | SM-DP+ intercept, BPP injection, EID tracking |
| 103 | Network Slicing Exploit | S-NSSAI spoofing, cross-slice injection, UPF escape |
| 104 | WiFi Calling Exploitation | ePDG MitM, IKEv2/EAP-AKA' intercept, SWu hijack |
| 105 | Lawful Intercept Abuse | ADMF provisioning, IRI/CC redirect, warrant manipulation |
| 106 | Femtocell Exploitation | HeNB IPsec extraction, local RRC MitM, CSG spoofing |
| 107 | SUPL/Location Spoofing | SUPL SET forge, ULP falsification, A-GPS injection |
| 108 | Roaming/IPX Pivoting | GRX/IPX route injection, VPLMN impersonation |

## Defensive Capabilities (Modules 16–28)

### Basic Telecom Detection (16–23)

| # | Module | Detection Method |
|---|--------|-----------------|
| 16 | Rogue Tower Detection | Unknown Cell IDs, LAC/TAC mismatches, signal anomalies |
| 17 | Downgrade Attack Detection | RAT/cipher downgrades (5G→4G→2G, EEA2→EEA0) |
| 18 | IMSI Catcher Detection | Identity Request frequency, fake paging |
| 19 | Cell Parameter Anomaly | SIB changes, band violations vs baseline |
| 20 | GTP Traffic Anomaly | TEID collisions, GTP-in-GTP tunneling |
| 21 | SS7/SIGTRAN Anomaly | Unauthorized SRI/CLR/ISD operations |
| 22 | Modem Tamper Detection | Unauthorized PID access to modem devices |
| 23 | NAS Replay/Injection | Duplicate sequences, unprotected NAS messages |

### Advanced Telecom Detection (24–28)

| # | Module | Detection Method |
|---|--------|-----------------|
| 24 | VoLTE Fraud Detection | SIP/SDP modification, SRTP key theft |
| 25 | eSIM Provisioning Monitor | Unauthorized downloads, BPP injection, EID probing |
| 26 | Slice Isolation Verification | S-NSSAI consistency, cross-slice leakage |
| 27 | Roaming Anomaly Detection | Unusual VPLMN, IPX route changes, billing anomalies |
| 28 | RF Fingerprint Analysis | Tower hardware fingerprint deviation |

## Requirements

- Linux 5.15+ (kernel with BPF CO-RE support)
- Rust nightly (aya-rs eBPF toolchain)
- clang/llvm for eBPF compilation
- Optional: SDR hardware (RTL-SDR, HackRF, USRP) for RF layer

## Lab Setup

See [docs/LAB_SETUP.md](docs/LAB_SETUP.md) for isolated test environment configuration using:
- Open5GS (5G core)
- srsRAN (gNB/UE simulation)
- Osmocom (2G/3G stack)
- UERANSIM (5G UE/gNB emulation)

## Build

```bash
# Build eBPF programs
cargo xtask build-ebpf --release

# Build user-space
cargo build --release

# Run defense engine
sudo ./target/release/staticzero-defense --all

# Run offense loader (authorized testing only)
sudo ./target/release/staticzero-offense --enable-telecom --gtp-iface gtp0
```

## License

MIT
