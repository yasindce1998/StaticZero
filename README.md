# StaticZero

[![CI](https://github.com/yasindce1998/StaticZero/actions/workflows/ci.yml/badge.svg)](https://github.com/yasindce1998/StaticZero/actions/workflows/ci.yml)
[![Release](https://github.com/yasindce1998/StaticZero/actions/workflows/release.yml/badge.svg)](https://github.com/yasindce1998/StaticZero/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/yasindce1998/StaticZero)](https://github.com/yasindce1998/StaticZero/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-nightly-orange.svg)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/eBPF-CO--RE-green.svg)](https://ebpf.io/)

eBPF-based telecom security research framework covering 2G through 5G and non-terrestrial networks (satellite, GNSS, aviation). Operates at the kernel level using Linux eBPF for real-time interception, analysis, and anomaly detection across cellular and satellite protocols.

> **Research/educational purposes only.** Unauthorized interception of telecommunications is illegal in most jurisdictions.

> **Implementation status:** The capability tables are a research catalog, not
> proof of working live interception/detection. Defense Module 22 has an
> experimental passive `openat` adapter; Modules 16–21 and 23–55 currently lack
> validated attachment adapters and are reported as unsupported by the loader.
> SDR hardware methods also include scaffolding. See
> [defense validation](docs/DEFENSE_VALIDATION.md) for limitations and smoke tests.

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

## Offensive Capabilities (F89–F172)

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

### 5G Advanced Exploitation (F109–F120)

| # | Feature | Hook Point | Target |
|---|---------|-----------|--------|
| 109 | PBCH/SIB Broadcast Spoofing | kprobe: `tty_write` | MIB/SIB injection for fake cell selection |
| 110 | RRC Measurement Manipulation | kprobe: `qmi_wwan_rx_fixup` | Tamper RSRP/RSRQ to influence handover |
| 111 | Handover Hijacking | TC (SCTP:38412/36422) | NGAP/X2AP handover command injection |
| 112 | HTTP/2 SBI Exploitation | TC (ports 7777–7780) | NF-to-NF service API manipulation |
| 113 | NRF/AUSF/UDM API Abuse | TC (port 7778) | Rogue NF registration, discovery abuse |
| 114 | OAuth2 Token Theft | kprobe: `tcp_sendmsg` | Bearer tokens between Network Functions |
| 115 | Jamming Detection Evasion | XDP on SDR iface | Anti-detection waveform patterns |
| 116 | MIMO Beamforming Fingerprint | kprobe: `qmi_wwan_rx_fixup` | CSI-RS/SSB beam pattern extraction |
| 117 | Sidelink PC5/V2X Exploit | TC (UDP:38472) | ProSe/C-V2X L2 injection and tracking |
| 118 | 5G-AKA Protocol Downgrade | kprobe: `tcp_sendmsg` | Force 5G-AKA → EAP-AKA' fallback |
| 119 | SUCI Replay Attack | kprobe: `tcp_sendmsg` | Replay SUCI for cross-session tracking |
| 120 | ARPF Key Extraction | kprobe: `tcp_sendmsg` | Probe UDM/ARPF for auth vectors/keys |

### Satellite Communications (F121–F134)

| # | Feature | Hook Point | Target |
|---|---------|-----------|--------|
| 121 | DVB-S2 Downlink Interception | kprobe: `dvb_dmx_swfilter_packets` | Broadcast TS capture, BISS key patterns |
| 122 | Transponder Hijack Injection | TC on sat-iface | Spoofed PLHeader, carrier-ID manipulation |
| 123 | NTN Timing Advance Exploitation | kprobe: `tcp_sendmsg` | NR-NTN TA pre-compensation exploit |
| 124 | NTN-5G Core Gateway Injection | TC on sat-iface | NGAP injection via NTN feeder link |
| 125 | Iridium L-Band Frame Capture | kprobe: `sdr_rx_callback` | 1616–1626.5 MHz burst decode |
| 126 | LEO Constellation Signaling Injection | TC on sat-iface | Globalstar CDMA / Thuraya GMR-1 |
| 127 | VSAT Terminal Firmware Extraction | kprobe: `usb_submit_urb` | Hughes/iDirect/Newtec ACM tables |
| 128 | SCPC Carrier Manipulation | TC on sat-iface | DVB-RCS2 return channel, MF-TDMA slot |
| 129 | Starlink Dishy Auth Probe | kprobe: `tcp_sendmsg` | gRPC session tokens, firmware channel |
| 130 | ISL Laser Link Fingerprint | XDP on sat-iface | Inter-satellite laser timing metadata |
| 131 | ADS-B/ACARS Frame Injection | TC on sat-iface | Mode-S ES (1090 MHz), VHF data link |
| 132 | COSPAS-SARSAT Beacon Spoofing | kprobe: `sdr_rx_callback` | 406 MHz PLB/ELT hex ID spoofing |
| 133 | GPS L1 C/A Code Spoofing | XDP on SDR iface | L1 1575.42 MHz PRN code replicas |
| 134 | Multi-Constellation L5/E5 Spoofing | XDP on SDR iface | GPS L5 + Galileo E5a/b + BeiDou B2a |

### TETRA/P25 Public Safety LMR (F135–F138)

| # | Feature | Hook Point | Target |
|---|---------|-----------|--------|
| 135 | TETRA Air Interface Intercept | kprobe: `sdr_rx_callback` | π/4-DQPSK bursts, TEA1 backdoor (CVE-2022-24400) |
| 136 | TETRA Encryption Downgrade | TC classifier | SYSINFO encryption indicator → SCK/DCK fallback |
| 137 | P25 Control Channel Harvest | kprobe: `sdr_rx_callback` | Phase I/II trunking, TGID/WACN/NAC mapping |
| 138 | P25 IMBE Voice Interception | XDP on SDR iface | Unencrypted IMBE voice frames |

### Bluetooth/BLE (F139–F142)

| # | Feature | Hook Point | Target |
|---|---------|-----------|--------|
| 139 | BLE GATT Enumeration | kprobe: `hci_send_frame` | Service/characteristic discovery dumps |
| 140 | BLE Pairing Downgrade | kprobe: `smp_send_cmd` | LE Secure Connections → LE Legacy |
| 141 | BlueBorne-style RCE Probe | kprobe: `l2cap_recv_frame` | Malformed L2CAP PDUs |
| 142 | BLE Advertisement Spoofing | TC classifier | iBeacon/Eddystone impersonation |

### Zigbee/Z-Wave/Thread (F143–F145)

| # | Feature | Hook Point | Target |
|---|---------|-----------|--------|
| 143 | Zigbee Network Key Sniff | kprobe: `sdr_rx_callback` | Transport key during join/ZLL touchlink |
| 144 | Z-Wave S0 Key Extraction | kprobe: `sdr_rx_callback` | Zero temporary key in S0 inclusion |
| 145 | Thread/6LoWPAN MLE Exploit | TC on WPAN iface | MLE injection, leader election manipulation |

### LoRa/LoRaWAN (F146–F148)

| # | Feature | Hook Point | Target |
|---|---------|-----------|--------|
| 146 | LoRaWAN Join Replay | kprobe: `sdr_rx_callback` | DevNonce reuse in OTAA join |
| 147 | LoRaWAN ABP Session Hijack | XDP on SDR iface | DevAddr spoof, frame counter desync |
| 148 | LoRa PHY Jamming/Capture | kprobe: `sdr_rx_callback` | CSS chirp selective jamming by SF |

### NB-IoT/LTE-M (F149–F150)

| # | Feature | Hook Point | Target |
|---|---------|-----------|--------|
| 149 | NB-IoT RRC/NAS Exploit | kprobe: `qmi_wwan_rx_fixup` | NPSS/NSSS, pre-security NAS |
| 150 | LTE-M eDRX/PSM Timing Attack | TC on modem iface | Paging occasion prediction |

### WiFi 802.11 (F151–F155)

| # | Feature | Hook Point | Target |
|---|---------|-----------|--------|
| 151 | Deauth/Disassoc Flood | TC on WLAN iface | Management frames (subtypes 10/12) |
| 152 | WPA3 Dragonblood Exploit | kprobe: `cfg80211_rx_mgmt` | SAE side-channels, group downgrade |
| 153 | Evil Twin/Karma Attack | kprobe: `cfg80211_rx_mgmt` | Probe request/response abuse |
| 154 | FT Roaming Abuse | TC on WLAN iface | 802.11r PMKR1 extraction |
| 155 | PMKID Capture | kprobe: `cfg80211_rx_mgmt` | RSN IE in EAPOL-1 |

### Remote Keyless Entry (F156–F157)

| # | Feature | Hook Point | Target |
|---|---------|-----------|--------|
| 156 | RollJam Rolling Code Attack | kprobe: `sdr_rx_callback` | OOK/FSK at 315/433 MHz |
| 157 | Relay/Amplification Attack | XDP on SDR iface | 125 kHz wake + UHF response relay |

### Drone/UAV C2 (F158–F160)

| # | Feature | Hook Point | Target |
|---|---------|-----------|--------|
| 158 | MAVLink Command Injection | TC on UAV iface | Unsigned SET_MODE/NAV_WAYPOINT commands |
| 159 | DJI OcuSync Fingerprint | kprobe: `sdr_rx_callback` | DroneID beacons, operator location |
| 160 | FPV Video Link Intercept | XDP on SDR iface | 5.8 GHz analog/digital FPV + OSD telemetry |

### POCSAG/FLEX Paging (F161–F162)

| # | Feature | Hook Point | Target |
|---|---------|-----------|--------|
| 161 | POCSAG Message Decode | kprobe: `sdr_rx_callback` | 512/1200/2400 baud FSK, RIC + messages |
| 162 | FLEX/ReFLEX Intercept | kprobe: `sdr_rx_callback` | 4-FSK 1600/3200/6400 baud |

### RDS/DAB+ Broadcast (F163–F164)

| # | Feature | Hook Point | Target |
|---|---------|-----------|--------|
| 163 | FM RDS Injection | TC on SDR iface | 57 kHz subcarrier, RadioText/TMC spoofing |
| 164 | DAB+ Ensemble Manipulation | TC on SDR iface | FIC/FIG reconfiguration |

### EAS/WEA Emergency Alert (F165–F166)

| # | Feature | Hook Point | Target |
|---|---------|-----------|--------|
| 165 | SAME/EAS Header Injection | TC on SDR iface | 1050 Hz AFSK, spoofed originator codes |
| 166 | WEA/CMAS Cell Broadcast | TC on modem iface | SIB12 Presidential-level alerts |

### O-RAN Fronthaul (F167–F170)

| # | Feature | Hook Point | Target |
|---|---------|-----------|--------|
| 167 | eCPRI IQ Sample Intercept | XDP on fronthaul iface | Unencrypted O-RU↔O-DU IQ plane |
| 168 | Fronthaul MitM Injection | TC on fronthaul iface | Beamforming weight tampering |
| 169 | O-RAN xApp Exploitation | kprobe: `tcp_sendmsg` | E2/A1 rogue xApp registration |
| 170 | CU/DU Split Exploitation | TC (SCTP:38472) | F1AP UE context theft |

### AIS Maritime (F171–F172)

| # | Feature | Hook Point | Target |
|---|---------|-----------|--------|
| 171 | AIS Position Spoofing | TC on SDR iface | 161.975/162.025 MHz GMSK, phantom vessels |
| 172 | AIS Collision Avoidance Abuse | kprobe: `sdr_rx_callback` | Ghost tracks triggering CPA/TCPA alarms |

## Defensive Capabilities (Modules 16–55)

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

### 5G Core Defense (29–32)

| # | Module | Detection Method |
|---|--------|-----------------|
| 29 | SBI Anomaly Detection | Unknown NF registration, OAuth2 reuse, abnormal API rates |
| 30 | Handover Integrity Monitoring | Handover to unregistered cells, measurement inconsistencies |
| 31 | RAN Sharing Isolation | Cross-operator resource access, PLMN boundary violations |
| 32 | Signaling Storm Detection | NAS message rate spikes, coordinated attach/paging floods |

### Satellite Defense (33–39)

| # | Module | Detection Method |
|---|--------|-----------------|
| 33 | DVB-S2/S2X Anomaly Detection | Unauthorized carrier IDs, symbol rate changes, unscheduled MODCOD transitions |
| 34 | NTN Access Anomaly Detection | Timing advance / ephemeris mismatch, NTN gateway auth failures |
| 35 | LEO Constellation Signaling Monitor | L-band burst pattern anomalies vs TDM schedule, orbital timing checks |
| 36 | VSAT/SCPC Integrity Monitor | Unauthorized firmware updates, ACM table changes, burst time plan deviations |
| 37 | Starlink Authentication Monitor | gRPC token reuse/replay, unauthorized firmware images, TLE timing mismatch |
| 38 | Aviation/Maritime Signal Integrity | ADS-B physics violations, unauthorized ACARS source IDs, false SARSAT beacons |
| 39 | GNSS Spoofing Detection | C/N0 anomalies (meaconing), cross-constellation timing divergence, code-phase jumps |

### Public Safety LMR Defense (40–41)

| # | Module | Detection Method |
|---|--------|-----------------|
| 40 | TETRA Encryption Monitor | TEA cipher downgrades, SYSINFO encryption=0, DCK fallback (TETRA:BURST CVEs) |
| 41 | P25 Control Channel Integrity | Rogue NAC, unexpected system/WACN ID changes |

### IoT Radio Defense (42–45)

| # | Module | Detection Method |
|---|--------|-----------------|
| 42 | BLE Pairing/Scanning Defense | LE Legacy downgrade, GATT enumeration floods, BlueBorne L2CAP patterns |
| 43 | Zigbee/Z-Wave Key Provisioning Monitor | Unprotected transport keys, Z-Wave S0 zero-key inclusion, ZLL touchlink |
| 44 | LoRaWAN Join Integrity | DevNonce replay, ABP frame counter reset, DevAddr collisions |
| 45 | NB-IoT/LTE-M RRC Anomaly | RRC rate spikes, NAS without security context, abnormal paging |

### WiFi Defense (46–47)

| # | Module | Detection Method |
|---|--------|-----------------|
| 46 | WiFi Deauth/Disassoc Detection | Management frame floods (>10/s per BSSID), AP impersonation |
| 47 | WPA3/FT Integrity Monitor | SAE group downgrade, anti-clogging floods, commit/confirm timing anomalies |

### RF Control Defense (48–49)

| # | Module | Detection Method |
|---|--------|-----------------|
| 48 | RKE Jamming Detection | Sustained 315/433 MHz energy with fob transmit failure (RollJam) |
| 49 | UAV C2 Integrity Monitor | Unsigned MAVLink commands, unauthorized DroneID serials, GCS mismatch |

### Broadcast/Paging Defense (50–52)

| # | Module | Detection Method |
|---|--------|-----------------|
| 50 | Pager Signal Anomaly | Unknown RICs, off-schedule bursts, baud rate changes |
| 51 | Broadcast Injection Detection | RDS PI code changes, unauthorized DAB+ FIG sources |
| 52 | Emergency Alert Spoofing Detection | Invalid SAME originator/event codes, unauthorized WEA in SIB12 |

### O-RAN Defense (53–54)

| # | Module | Detection Method |
|---|--------|-----------------|
| 53 | O-RAN Fronthaul Integrity | eCPRI sequence gaps, IQ amplitude violations, timing >±65ns (WG4) |
| 54 | O-RAN RIC Security Monitor | Rogue xApp registration, A1 policy injection, O1 window violations |

### AIS Maritime Defense (55)

| # | Module | Detection Method |
|---|--------|-----------------|
| 55 | AIS Signal Integrity | Physics violations (>50kn, impossible turn rates), position jumps, duplicate MMSI |

## Correlation Engine

Cross-layer protocol correlation detects complex attack chains that single-module detection would miss. The `TelecomCorrelationEngine` ingests alerts from all modules and identifies compound threats across seven protocol layers (Radio, NAS, Transport, Signaling, Core, SBI, Satellite).

Threat categories: IMSI Catching, MitM, Protocol Downgrade, Signaling Abuse, Toll Fraud, Location Tracking, Data Interception, Service Denial, Slice Escape, Roaming Exploit, SBI Compromise, Handover Hijack, RAN Sharing Breach, Signaling Storm, Identity Exposure, Satellite Link Hijack, GNSS Spoofing, Beacon Falsification, Terminal Compromise, WiFi Rogue AP, Fronthaul Compromise, AIS Spoofing.

Satellite-specific correlation patterns:
- DVB-S2 anomaly + VSAT integrity failure → coordinated transponder takeover
- GNSS spoofing + ADS-B injection → aviation-targeted multi-vector attack
- Starlink auth + LEO signaling anomaly → terminal impersonation chain
- NTN timing divergence + NAS replay → satellite-terrestrial positioning attack

RF protocol domain correlation patterns:
- WiFi deauth flood + WPA3/FT integrity failure → rogue AP / evil twin attack
- eCPRI fronthaul anomaly + RIC security violation → coordinated O-RAN compromise (confidence 0.93, severity 5)
- AIS physics violation + GNSS spoofing → maritime position falsification (confidence 0.94, severity 5)

## Tools

### SDR Bridge

Hardware-abstracted radio interface supporting HackRF, bladeRF, USRP, RTL-SDR, and LimeSDR. Modes: Scan, Capture, Inject, Relay. JSON control API on TCP port 9999.

### Protocol Dissectors

- **PFCP** (N4: SMF↔UPF) — Session/Association/Heartbeat parsing per 3GPP TS 29.244
- **NGAP** (N2: AMF↔gNB) — UE context, handover, PDU session, paging per TS 38.413
- **XnAP** (Xn: gNB↔gNB) — Handover preparation, SN status transfer, RAN paging per TS 38.423

## Documentation

- [docs/usecase.md](docs/usecase.md) — Use cases, how-to guides, full offense/defense reference
- [docs/TELECOM_THREAT_MODEL.md](docs/TELECOM_THREAT_MODEL.md) — Attack trees, threat actors, MITRE mapping
- [docs/LAB_SETUP.md](docs/LAB_SETUP.md) — Isolated lab environment configuration
- [docs/DEFENSE_VALIDATION.md](docs/DEFENSE_VALIDATION.md) — Runtime support, read-only preflight, passive smoke tests

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

# Inspect supported/unsupported modules without loading or attaching BPF
./target/release/staticzero-defense --doctor --all

# Run defense engine (only supported adapters attach; see validation guide)
sudo ./target/release/staticzero-defense --all

# Run offense loader (authorized testing only)
sudo ./target/release/staticzero-offense --enable-telecom --gtp-iface gtp0

# Run with satellite modules
sudo ./target/release/staticzero-defense --satellite_defense
sudo ./target/release/staticzero-offense --enable-satellite --sat-iface sat0

# Run with RF protocol domain modules (TETRA/P25, BLE, Zigbee, LoRaWAN, WiFi, RKE, UAV, paging, broadcast, O-RAN, AIS)
sudo ./target/release/staticzero-defense --rf_defense
sudo ./target/release/staticzero-offense --enable-rf --sdr-iface sdr0 --fronthaul-iface eth0
```

## License

MIT
