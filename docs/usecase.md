# StaticZero — Use Cases, How-To, and Capability Reference

## Table of Contents

- [Use Cases](#use-cases)
- [How-To Guides](#how-to-guides)
- [Offense Capabilities (F89–F172)](#offense-capabilities-f89f172)
- [Defense Capabilities (Modules 16–55)](#defense-capabilities-modules-1655)
- [Correlation Engine](#correlation-engine)
- [SDR Integration](#sdr-integration)
- [Protocol Dissectors](#protocol-dissectors)

---

## Use Cases

### 1. Telecom Security Audit

Assess the security posture of a mobile network operator's infrastructure by deploying StaticZero's defense modules against a controlled test environment.

**Actors:** Red team / pentest firm under engagement contract  
**Scenario:** Deploy defense engine with all modules (16–32) to baseline the network, then use offense features (F89–F120) to simulate real-world attacks and verify detection coverage.

**Steps:**
1. Stand up isolated lab (Open5GS + srsRAN + UERANSIM)
2. Enable defense engine with `--all` to establish baselines
3. Execute offense modules one at a time, verify alerts fire
4. Generate audit report from SQLite persistence layer + HTTP API metrics

### 2. IMSI Catcher Detection Research

Study how stingray/IMSI catcher devices operate and develop detection signatures.

**Actors:** Academic researchers, national CERTs  
**Scenario:** Use F92 (IMSI Interception) in a Faraday cage to understand identity request patterns, then validate Module 18 (IMSI Catcher Detection) catches the behavior.

### 3. 5G Core Network Function Security Testing

Evaluate the security of Service-Based Interface (SBI) communication between 5G Network Functions.

**Actors:** 5G core vendors, MNO security teams  
**Scenario:** Deploy F112 (SBI Exploitation), F113 (NRF Abuse), and F114 (OAuth2 Token Theft) against a test 5GC deployment. Validate that Module 29 (SBI Anomaly Detection) and the correlation engine's `SbiCompromise` pattern detect the intrusion chain.

### 4. Roaming Security Assessment

Test inter-operator signaling security (SS7/Diameter/GTP) at roaming boundaries.

**Actors:** IPX providers, roaming hubs, regulatory bodies  
**Scenario:** Use F95 (SS7 MAP Injection), F96 (Diameter AVP Manipulation), and F108 (Roaming/IPX Pivoting) to simulate signaling abuse. Validate with Module 21 (SS7/SIGTRAN Anomaly) and Module 27 (Roaming Anomaly Detection).

### 5. Network Slicing Isolation Verification

Confirm that network slice boundaries cannot be breached by a compromised UE or malicious NF.

**Actors:** Enterprise customers of private 5G, MNO assurance teams  
**Scenario:** F103 (Network Slicing Exploit) attempts S-NSSAI spoofing and cross-slice data injection. Module 26 (Slice Isolation Verification) and the correlation engine's `SliceEscape` pattern validate containment.

### 6. VoLTE/VoNR Fraud Detection

Detect and prevent toll fraud, caller-ID spoofing, and call interception on IMS networks.

**Actors:** MNO fraud teams, law enforcement technical units  
**Scenario:** F101 (VoLTE/VoNR Interception) replicates ReVoLTE-style attacks. Module 24 (VoLTE Fraud Detection) validates that SIP manipulation and SRTP key theft are caught.

### 7. Handover Security Testing

Verify that mobility management (handovers between cells) cannot be exploited to force UEs onto rogue cells.

**Actors:** RAN vendors, MNO RAN security teams  
**Scenario:** F110 (RRC Measurement Manipulation) and F111 (Handover Hijacking) simulate forced handovers. Module 30 (Handover Integrity Monitoring) and the `HandoverHijack` correlation pattern detect the attack chain.

### 8. RF Fingerprinting for Rogue Base Station Detection

Build a hardware fingerprint database of legitimate cell towers and detect imposters via radio characteristics.

**Actors:** National security agencies, MNO field operations  
**Scenario:** Use the SDR bridge to scan cell towers, collect RF fingerprints via `CellScanResult`, and feed them to Module 28 (RF Fingerprint Analysis) for baseline comparison.

### 9. V2X / Sidelink Security Research

Evaluate the security of ProSe (Proximity Services) and V2X communication over the PC5 interface.

**Actors:** Automotive OEMs, C-V2X standardization bodies  
**Scenario:** F117 (Sidelink PC5/V2X Exploit) injects malicious sidelink messages. Validate detection through the defense engine's alert pipeline.

### 10. Authentication Protocol Downgrade Analysis

Study whether 5G-AKA can be forced down to weaker EAP-AKA' and whether SUCI replay enables subscriber tracking.

**Actors:** Protocol researchers, 3GPP SA3 delegates  
**Scenario:** F118 (5G-AKA Downgrade) and F119 (SUCI Replay) execute the attacks. Defense Module 17 (Downgrade Detection) and the correlation engine's `IdentityExposure` pattern validate detection.

### 11. TETRA/P25 Public Safety Radio Security Audit

Evaluate security of land mobile radio (LMR) networks used by emergency services.

**Actors:** Government CERTs, public safety network operators  
**Scenario:** Deploy F135 (TETRA Air Interface Intercept) and F136 (TETRA Encryption Downgrade) to test TEA cipher implementation. Validate that Module 40 (TETRA Encryption Monitor) detects cipher downgrade attempts and Module 41 (P25 Control Channel Integrity) flags rogue control channels.

### 12. IoT Mesh Network Penetration Test

Assess wireless IoT protocol security across BLE, Zigbee, LoRa, and NB-IoT deployments.

**Actors:** Smart building security teams, industrial IoT vendors  
**Scenario:** Use F139–F142 (BLE attacks), F143–F145 (Zigbee/Z-Wave), F146–F148 (LoRa), and F149–F150 (NB-IoT) to test device provisioning and key management. Validate detection via Modules 42–45.

### 13. WiFi Infrastructure Security Assessment

Test enterprise WiFi networks for deauthentication, rogue AP, and WPA3 vulnerabilities.

**Actors:** Enterprise IT security teams, WiFi hardware vendors  
**Scenario:** Deploy F151 (Deauth Flood), F152 (WPA3 Dragonblood), and F153 (Evil Twin) against a test WLAN. Validate Modules 46 (Deauth Detection) and 47 (WPA3/FT Integrity) catch the attacks. Confirm correlation engine links deauth + WPA3 failure → rogue AP credential harvest.

### 14. O-RAN Fronthaul Security Research

Test the security of Open RAN fronthaul interfaces where IQ samples flow unencrypted between O-RU and O-DU.

**Actors:** O-RAN Alliance members, RAN vendors, MNO RAN security teams  
**Scenario:** Deploy F167 (eCPRI IQ Intercept) and F168 (Fronthaul MitM) to capture and modify IQ samples on the fronthaul Ethernet segment. Use F169 (xApp Exploitation) to test Near-RT RIC security. Validate Modules 53–54 detect anomalies.

### 15. Maritime AIS Security Testing

Evaluate vulnerability of AIS (Automatic Identification System) to position spoofing and ghost vessel injection.

**Actors:** Maritime security agencies, port authorities, coast guards  
**Scenario:** Deploy F171 (AIS Position Spoofing) and F172 (Collision Avoidance Abuse) in a controlled maritime lab. Validate Module 55 (AIS Signal Integrity) detects physics violations and duplicate MMSI. Confirm cross-correlation with GNSS spoofing detection.

### 16. Emergency Alert System Integrity Verification

Test resilience of EAS/WEA broadcast systems against spoofed alerts.

**Actors:** FEMA, national broadcasting regulators, emergency management  
**Scenario:** Use F165 (SAME/EAS Header Injection) and F166 (WEA Cell Broadcast) in an isolated environment. Validate Module 52 (Emergency Alert Spoofing Detection) identifies invalid SAME headers and unauthorized SIB12 injections.

### 17. Drone/UAV Command & Control Security

Assess vulnerability of UAV control links to command injection and fingerprinting.

**Actors:** Drone manufacturers, counter-UAS teams, aviation authorities  
**Scenario:** Deploy F158 (MAVLink Injection), F159 (DJI OcuSync Fingerprint), and F160 (FPV Intercept) to test C2 link security. Validate Module 49 (UAV C2 Integrity) detects unauthenticated commands and anomalous DroneID beacons.

### 18. Automotive Keyless Entry Security

Test vehicle remote keyless entry systems for replay and relay vulnerabilities.

**Actors:** Automotive OEMs, vehicle security researchers  
**Scenario:** Use F156 (RollJam) and F157 (Relay/Amplification) in a shielded environment. Validate Module 48 (RKE Jamming Detection) identifies sustained RF jamming coinciding with key fob failures.

---

## How-To Guides

### Building the Project

**Prerequisites:**
- Linux 5.15+ with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`)
- Rust nightly toolchain
- `bpf-linker` (install via `cargo install bpf-linker`)
- clang/llvm 14+
- `libbpf-dev` or equivalent

```bash
# Install Rust nightly and eBPF target
rustup toolchain install nightly
rustup +nightly target add bpfel-unknown-none

# Install bpf-linker
cargo install bpf-linker

# Build eBPF programs (both offense and defense)
cargo xtask build-ebpf --release

# Build all user-space binaries
cargo build --release
```

**Output binaries:**
- `target/release/staticzero-offense` — Telecom exploitation loader
- `target/release/staticzero-defense` — Detection/correlation engine

### Running the Defense Engine

```bash
# All modules enabled, JSON output for SIEM integration
sudo ./target/release/staticzero-defense \
  --bpf-path target/bpfel-unknown-none/release/staticzero-defense \
  --all \
  --json

# Only basic telecom detection (modules 16-23)
sudo ./target/release/staticzero-defense --telecom-detect

# Basic + advanced (modules 16-28)
sudo ./target/release/staticzero-defense --telecom-detect --telecom-advanced

# Full stack including 5G core defense (modules 16-32)
sudo ./target/release/staticzero-defense --telecom-detect --telecom-advanced --telecom-5g-defense

# Custom correlation window (seconds)
sudo ./target/release/staticzero-defense --all --correlation-window 120

# Skip security hardening (development only)
sudo ./target/release/staticzero-defense --all --no-harden
```

### Running the Offense Loader

```bash
# Core telecom interception (F89-F100)
sudo ./target/release/staticzero-offense \
  --enable-telecom \
  --gtp-iface gtp0

# Advanced telecom exploitation (F101-F108)
sudo ./target/release/staticzero-offense \
  --enable-telecom-advanced \
  --ims-iface ims0 \
  --wifi-iface wlan0

# 5G advanced exploitation (F109-F120)
sudo ./target/release/staticzero-offense \
  --enable-5g-advanced \
  --sbi-iface sbi0 \
  --sdr-iface sdr0

# All features simultaneously
sudo ./target/release/staticzero-offense \
  --all \
  --gtp-iface gtp0 \
  --ims-iface ims0 \
  --wifi-iface wlan0 \
  --sbi-iface sbi0 \
  --sdr-iface sdr0

# Target specific subscriber (authorized testing only)
sudo ./target/release/staticzero-offense \
  --enable-telecom \
  --target-imsi 001010123456789
```

### Running Extended RF Modules

```bash
# TETRA/P25 — Public Safety LMR (F135-F138)
sudo ./target/release/staticzero-offense \
  --enable-tetra-p25 \
  --lmr-iface sdr0

# IoT Radio — BLE/Zigbee/LoRa/NB-IoT (F139-F150)
sudo ./target/release/staticzero-offense \
  --enable-iot-radio \
  --hci-iface hci0 \
  --wpan-iface wpan0

# WiFi 802.11 (F151-F155)
sudo ./target/release/staticzero-offense \
  --enable-wifi \
  --wlan-iface wlan0

# RF Control — RKE + UAV (F156-F160)
sudo ./target/release/staticzero-offense \
  --enable-rf-control \
  --uav-iface uav0

# Broadcast/Paging — POCSAG + RDS + EAS (F161-F166)
sudo ./target/release/staticzero-offense \
  --enable-broadcast

# O-RAN Fronthaul (F167-F170)
sudo ./target/release/staticzero-offense \
  --enable-oran \
  --fronthaul-iface eth1

# AIS Maritime (F171-F172)
sudo ./target/release/staticzero-offense \
  --enable-ais

# Extended defense modules
sudo ./target/release/staticzero-defense --lmr_defense
sudo ./target/release/staticzero-defense --iot_defense
sudo ./target/release/staticzero-defense --wifi_defense
sudo ./target/release/staticzero-defense --rf_control_defense
sudo ./target/release/staticzero-defense --broadcast_defense
sudo ./target/release/staticzero-defense --oran_defense
sudo ./target/release/staticzero-defense --ais_defense
```

### Configuration File

The defense engine reads `/etc/staticzero/config.toml` (or path specified with `--config`):

```toml
[engine]
correlation_window_secs = 60
json_output = false

[persistence]
enabled = true
db_path = "/var/lib/staticzero/alerts.db"

[server]
enabled = true
listen_addr = "127.0.0.1:8080"

[thresholds]
min_confidence = 0.6
```

Hot-reload is supported — changes to the config file are picked up automatically.

### HTTP API Endpoints

When `server.enabled = true`, the defense engine exposes:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health check |
| `/metrics` | GET | Prometheus-format metrics |
| `/alerts` | GET | Recent alerts from SQLite store |
| `/threats` | GET | Correlated threat events |
| `/correlation/metrics` | GET | Correlation engine statistics |
| `/feedback` | POST | Submit operator feedback (false positive overrides) |

### SDR Hardware Setup

```bash
# Start SDR bridge with HackRF
staticzero-sdr --device hackrf --mode scan --freq-start 700e6 --freq-end 2700e6

# Control API (JSON over TCP, port 9999)
echo '{"command":"scan","params":{"band":"n78","duration_ms":5000}}' | nc localhost 9999
echo '{"command":"fingerprint","params":{"earfcn":1234}}' | nc localhost 9999
echo '{"command":"inject","params":{"freq":1842500000,"power":-30}}' | nc localhost 9999
```

Supported SDR hardware:
- **HackRF One** — TX/RX, 1 MHz – 6 GHz, 20 MHz bandwidth
- **bladeRF 2.0** — Full duplex, 47 MHz – 6 GHz, 56 MHz bandwidth
- **USRP B210** — Full duplex, 70 MHz – 6 GHz, 56 MHz bandwidth
- **RTL-SDR** — RX only, 24 – 1766 MHz, 2.4 MHz bandwidth (scanning/fingerprinting)
- **LimeSDR** — Full duplex, 100 kHz – 3.8 GHz, 61.44 MHz bandwidth

### Lab Environment Setup

See [LAB_SETUP.md](LAB_SETUP.md) for full lab configuration. Quick start:

```bash
# Docker-based 5G core (Open5GS)
docker-compose -f lab/open5gs.yml up -d

# srsRAN gNB simulator
sudo srsenb --config lab/enb.conf

# UERANSIM for 5G UE emulation
./nr-ue -c lab/ue-config.yaml

# Osmocom for 2G/3G (GSM BTS + SGSN)
docker-compose -f lab/osmocom.yml up -d
```

---

## Offense Capabilities (F89–F172)

### Core Telecom Interception (F89–F100)

#### F89: AT Command Injection
- **Hook:** kprobe on `tty_write`
- **Target:** 2G/3G/4G modem serial interface
- **Technique:** Injects Hayes AT commands into modem TTY sessions to control radio parameters, extract subscriber data, or force network reselection
- **Protocols:** AT+COPS, AT+CFUN, AT+CRSM, AT+CGDCONT

#### F90: Baseband Exploitation
- **Hook:** kprobe on `usb_submit_urb`
- **Target:** USB bulk transfers to baseband processors (Qualcomm QMI, MediaTek, Samsung Shannon)
- **Technique:** Intercepts and modifies USB URBs carrying control messages to the baseband, enabling firmware-level code execution

#### F91: SIM Data Extraction
- **Hook:** kprobe on `vfs_read`
- **Target:** SIM/USIM/ISIM filesystem via APDU
- **Technique:** Intercepts APDU reads targeting EF_IMSI, EF_Ki, EF_OPc, EF_LOCI, EF_PSLOCI for cloning or tracking

#### F92: IMSI Interception
- **Hook:** kprobe on `qmi_wwan_rx_fixup`
- **Target:** NAS Identity Response / Attach Request messages
- **Technique:** Extracts IMSI/IMEI from NAS signaling before encryption is established
- **Generations:** Works on 2G (plain), 3G/4G (during attach), 5G (if SUCI fails)

#### F93: Protocol Downgrade
- **Hook:** TC classifier
- **Target:** TAU Reject with cause code forcing RAT fallback
- **Technique:** Injects NAS messages causing UE to drop from 5G/4G to 2G where weaker ciphers (A5/1, A5/0) are used
- **Implements:** Known "downgrade to 2G" attack chains

#### F94: GTP Tunnel Hijacking
- **Hook:** XDP on GTP interface
- **Target:** GTP-U TEID values on S1-U/N3 interface
- **Technique:** Manipulates tunnel endpoint identifiers to redirect user-plane traffic, inject packets, or create parallel data taps

#### F95: SS7 MAP Injection
- **Hook:** TC classifier (SCTP port 2905)
- **Target:** MAP operations: SendRoutingInfo, UpdateLocation, ProvideSubscriberInfo
- **Technique:** Injects SS7 MAP messages to obtain subscriber location, reroute calls/SMS, or register as fake VLR/HLR
- **Protocols:** MTP3/SCCP/TCAP/MAP

#### F96: Diameter AVP Manipulation
- **Hook:** TC classifier (SCTP/TCP port 3868)
- **Target:** S6a (MME↔HSS), S6b, Cx/Dx interfaces
- **Technique:** Modifies Diameter AVPs in transit to alter subscriber profiles, authentication vectors, or session parameters

#### F97: RRC Connection Redirect
- **Hook:** kprobe on `tty_write`
- **Target:** RRCConnectionRelease with redirectedCarrierInfo
- **Technique:** Forces UE to reselect to attacker-controlled frequency/cell by injecting crafted RRC release messages

#### F98: NAS Message Interception
- **Hook:** kprobe on `qmi_wwan_rx_fixup`
- **Target:** Pre-encryption NAS PDUs (before integrity/ciphering)
- **Technique:** Captures NAS messages at the modem interface before NAS security context activation, exposing registration, authentication, and session management

#### F99: 5G SUPI De-concealment
- **Hook:** kprobe on `ecies_decrypt`
- **Target:** SUCI → SUPI recovery
- **Technique:** Intercepts ECIES Profile A/B decryption to recover permanent subscriber identity (SUPI) from concealed identifier (SUCI)
- **Requires:** Access to home network key (K) or compromise of SIDF

#### F100: 5G N2 Interface Injection
- **Hook:** TC classifier (SCTP port 38412)
- **Target:** NGAP messages between AMF and gNB
- **Technique:** Injects or modifies NGAP procedures (InitialUEMessage, HandoverRequired, PDUSessionResourceSetup) to manipulate 5G control plane

### Advanced Telecom (F101–F108)

#### F101: VoLTE/VoNR Interception
- **Hook:** kprobe on `sip_msg_send`
- **Target:** IMS SIP/SDP signaling and RTP/SRTP media streams
- **Technique:** Manipulates SIP INVITE/200OK to downgrade SRTP to RTP (ReVoLTE), extracts SRTP master keys, or forces codec changes for easier decoding
- **Protocols:** SIP, SDP, RTP, SRTP, SRTP-DTLS

#### F102: eSIM Provisioning Attack
- **Hook:** kprobe on `tty_write`
- **Target:** SM-DP+ (Subscription Manager Data Preparation) communication
- **Technique:** Intercepts BPP (Bound Profile Package) downloads, injects malicious profiles, tracks EIDs, or clones eSIM provisioning sessions

#### F103: Network Slicing Exploit
- **Hook:** TC classifier
- **Target:** S-NSSAI (Single Network Slice Selection Assistance Information)
- **Technique:** Spoofs slice identifiers to access unauthorized network slices, injects traffic cross-slice, or escapes UPF isolation boundaries

#### F104: WiFi Calling Exploitation
- **Hook:** XDP on WiFi interface
- **Target:** ePDG (Evolved Packet Data Gateway) via SWu interface
- **Technique:** MitM on IKEv2 tunnel establishment, intercepts EAP-AKA' authentication, hijacks IPsec SAs for WiFi calling sessions

#### F105: Lawful Intercept Abuse
- **Hook:** TC classifier
- **Target:** ADMF (Administration Function), IRI/CC delivery functions
- **Technique:** Provisions unauthorized intercept targets via ADMF, redirects IRI (Intercept Related Information) and CC (Content of Communication) streams

#### F106: Femtocell Exploitation
- **Hook:** kprobe on `ipsec_output`
- **Target:** HeNB (Home eNodeB) IPsec tunnels and local RRC
- **Technique:** Extracts IPsec keys from femtocell security gateway tunnel, enables local RRC MitM, spoofs CSG (Closed Subscriber Group) IDs

#### F107: SUPL/Location Spoofing
- **Hook:** TC classifier
- **Target:** SUPL SET (SUPL Enabled Terminal) communication
- **Technique:** Forges SUPL INIT messages, falsifies ULP (UserPlane Location Protocol) responses, injects false A-GPS assistance data

#### F108: Roaming/IPX Pivoting
- **Hook:** TC classifier
- **Target:** GRX/IPX interconnect routing
- **Technique:** Injects routes into GRX/IPX to reroute signaling, impersonates VPLMN nodes, exploits bilateral peering trust

### 5G Advanced Exploitation (F109–F120)

#### F109: PBCH/SIB Broadcast Spoofing
- **Hook:** kprobe on `tty_write`
- **Target:** MIB (Master Information Block) on PBCH, SIB1-SIBx
- **Technique:** Injects fake system information broadcasts to manipulate cell selection, barring, and access control parameters
- **Impact:** Forces UEs to camp on attacker cell or deny service to legitimate cells

#### F110: RRC Measurement Report Manipulation
- **Hook:** kprobe on `qmi_wwan_rx_fixup`
- **Target:** RRC MeasurementReport (UL-DCCH message type 0x08)
- **Technique:** Tampers with measurement reports (RSRP, RSRQ, PCI, EARFCN) to influence handover decisions by the network, steering UEs toward rogue cells

#### F111: Handover Hijacking
- **Hook:** TC classifier (NGAP port 38412, X2AP port 36422)
- **Target:** HandoverRequired, HandoverCommand, HandoverPreparation procedures
- **Technique:** Injects neighbor cell information into handover signaling to force UE migration to attacker-controlled cell during active sessions

#### F112: HTTP/2 SBI Exploitation
- **Hook:** TC classifier (ports 7777–7780)
- **Target:** 5G Service-Based Interface between Network Functions
- **Technique:** Intercepts and manipulates HTTP/2 frames on NF-to-NF communication, exploiting service discovery, session management, and subscription data APIs
- **Protocols:** HTTP/2, gRPC, JSON/CBOR over SBI

#### F113: NRF/AUSF/UDM API Abuse
- **Hook:** TC classifier (NRF port 7778)
- **Target:** NRF (Network Repository Function) registration/discovery
- **Technique:** Registers rogue NF instances in NRF, manipulates NF profiles to redirect service traffic, exploits discovery for unauthorized access to subscriber data

#### F114: OAuth2 Token Theft Between NFs
- **Hook:** kprobe on `tcp_sendmsg`
- **Target:** OAuth2 Bearer tokens in HTTP/2 headers between NFs
- **Technique:** Captures access tokens from NF-to-NF communication to impersonate legitimate network functions, bypass NRF authorization, access subscriber APIs without credentials

#### F115: Jamming Detection Evasion
- **Hook:** XDP on SDR interface (UDP ports 9000–9100)
- **Target:** IQ sample streams from SDR hardware
- **Technique:** Implements anti-detection waveform patterns for uplink/downlink jamming that evade spectrum monitoring systems; drops packets matching jam-detection patterns at XDP layer

#### F116: MIMO Beamforming Fingerprinting
- **Hook:** kprobe on `qmi_wwan_rx_fixup`
- **Target:** CSI-RS (Channel State Information Reference Signals), SSB beam patterns
- **Technique:** Fingerprints 5G NR cells via their unique MIMO beam patterns (beam ID, SSB index, precoding matrices, layer count) for identification without relying on broadcast parameters

#### F117: Sidelink (PC5/V2X) Exploitation
- **Hook:** TC classifier (UDP port 38472)
- **Target:** ProSe (Proximity Services) / C-V2X sidelink communication
- **Technique:** Intercepts and injects PC5 sidelink frames between vehicles/UEs, exploiting Layer-2 IDs and direct communication to spoof vehicle safety messages or track proximity

#### F118: 5G-AKA Protocol Downgrade
- **Hook:** kprobe on `tcp_sendmsg`
- **Target:** AUSF authentication procedures (NAS 5GMM type 0x56)
- **Technique:** Forces authentication downgrade from native 5G-AKA to weaker EAP-AKA', which has known vulnerabilities to MITM and doesn't bind to serving network name

#### F119: SUCI Replay Attack
- **Hook:** kprobe on `tcp_sendmsg`
- **Target:** SUCI values with ECIES protection scheme 0x01/0x02 (Profile A/B)
- **Technique:** Replays previously captured SUCI values to correlate subscriber identity across sessions without needing to decrypt the SUCI, enabling long-term tracking

#### F120: ARPF Key Extraction via UDM Probing
- **Hook:** kprobe on `tcp_sendmsg`
- **Target:** Nudm_UEAuthentication service (`/nudm-ueau/v1/`)
- **Technique:** Probes the Authentication Repository Processing Function through UDM's HTTP/2 API to extract authentication vectors, K/OPc values, or trigger key generation for targeted subscribers

### TETRA/P25 — Public Safety LMR (F135–F138)

#### F135: TETRA Air Interface Intercept
- **Hook:** kprobe on `sdr_rx_callback`
- **Target:** TETRA air interface (π/4-DQPSK modulation)
- **Technique:** Demodulates TETRA bursts, extracts color codes, MCC/MNC, and attempts TEA1/TEA2/TEA3 cipher recovery. Exploits CVE-2022-24400 (TEA1 backdoor reducing effective key to 32 bits)

#### F136: TETRA Encryption Downgrade
- **Hook:** TC classifier on SDR interface
- **Target:** TETRA SYSINFO PDU encryption indicator
- **Technique:** Injects modified SYSINFO broadcast forcing SCK→DCK key fallback or setting encryption=0, enabling cleartext interception of all traffic in the cell

#### F137: P25 Control Channel Harvest
- **Hook:** kprobe on `sdr_rx_callback`
- **Target:** P25 Phase I (FDMA) and Phase II (TDMA) control channels
- **Technique:** Decodes P25 Trunking Signaling Blocks to extract TGID (Talk Group ID), individual radio IDs, system/WACN/NAC identifiers for network mapping

#### F138: P25 IMBE Voice Interception
- **Hook:** XDP on SDR interface
- **Target:** P25 IMBE (Improved Multi-Band Excitation) voice frames
- **Technique:** Captures unencrypted P25 voice traffic, correlates with control channel metadata for attribution. Works on systems without AES-256 or DES-OFB encryption enabled

### Bluetooth/BLE (F139–F142)

#### F139: BLE GATT Enumeration
- **Hook:** kprobe on `hci_send_frame`
- **Target:** GATT (Generic Attribute Profile) service discovery
- **Technique:** Enumerates all services, characteristics, and descriptors on target BLE devices. Dumps handle-value pairs including sensitive data (health, location, authentication tokens)

#### F140: BLE Pairing Downgrade
- **Hook:** kprobe on `smp_send_cmd`
- **Target:** SMP (Security Manager Protocol) pairing negotiation
- **Technique:** Forces LE Secure Connections downgrade to LE Legacy pairing (vulnerable to passive eavesdropping). Reduces passkey entropy for brute-force attacks

#### F141: BlueBorne-style RCE Probe
- **Hook:** kprobe on `l2cap_recv_frame`
- **Target:** L2CAP (Logical Link Control and Adaptation Protocol)
- **Technique:** Sends malformed L2CAP PDUs to trigger info leaks or heap overflows in target Bluetooth stacks, enabling remote code execution without pairing

#### F142: BLE Advertisement Spoofing
- **Hook:** TC classifier on HCI interface
- **Target:** BLE advertising PDUs (ADV_IND, ADV_DIRECT_IND)
- **Technique:** Crafts spoofed BLE advertisements to impersonate legitimate beacons (iBeacon, Eddystone), enabling location spoofing and device impersonation

### Zigbee/Z-Wave/Thread (F143–F145)

#### F143: Zigbee Network Key Sniff
- **Hook:** kprobe on `sdr_rx_callback`
- **Target:** Zigbee transport key exchange during device join
- **Technique:** Captures the unencrypted network key transmitted during standard join procedures and ZLL (Zigbee Light Link) touchlink commissioning. Once captured, decrypts all network traffic

#### F144: Z-Wave S0 Key Extraction
- **Hook:** kprobe on `sdr_rx_callback`
- **Target:** Z-Wave S0 security inclusion handshake at 868/908 MHz
- **Technique:** Exploits the known-weak S0 inclusion protocol where the temporary key is all zeros (0x00...00), allowing extraction of the permanent network key

#### F145: Thread/6LoWPAN MLE Exploit
- **Hook:** TC classifier on WPAN interface
- **Target:** Thread Mesh Link Establishment (MLE) protocol
- **Technique:** Injects MLE frames to manipulate Thread network leader election, partition the mesh, or force devices onto an attacker-controlled Thread network

### LoRa/LoRaWAN (F146–F148)

#### F146: LoRaWAN Join Replay
- **Hook:** kprobe on `sdr_rx_callback`
- **Target:** LoRaWAN OTAA JoinRequest messages at 868/915 MHz
- **Technique:** Replays captured JoinRequest messages with reused DevNonces to derive session keys. Exploits implementations that don't properly track nonce reuse

#### F147: LoRaWAN ABP Session Hijack
- **Hook:** XDP on SDR interface
- **Target:** ABP (Activation By Personalization) LoRaWAN devices
- **Technique:** Spoofs the DevAddr of ABP devices (which use static keys) and desynchronizes frame counters to inject or capture data

#### F148: LoRa PHY Jamming/Capture
- **Hook:** kprobe on `sdr_rx_callback`
- **Target:** LoRa CSS (Chirp Spread Spectrum) physical layer
- **Technique:** Demodulates CSS chirps for selective frame capture at 868/915 MHz ISM bands. Can perform targeted jamming of specific spreading factors

### NB-IoT/LTE-M (F149–F150)

#### F149: NB-IoT RRC/NAS Exploit
- **Hook:** kprobe on `qmi_wwan_rx_fixup`
- **Target:** NB-IoT narrowband synchronization signals and NAS messages
- **Technique:** Decodes NPSS/NSSS for cell identification, extracts NAS messages before security context is established (during initial attach)

#### F150: LTE-M eDRX/PSM Timing Attack
- **Hook:** TC classifier on modem interface
- **Target:** eDRX (extended Discontinuous Reception) and PSM (Power Saving Mode) timing
- **Technique:** Predicts eDRX wake-up cycles and paging occasions to precisely time attacks when IoT devices are in receive mode, minimizing detection window

### WiFi 802.11 (F151–F155)

#### F151: Deauth/Disassoc Flood
- **Hook:** TC classifier on WLAN interface
- **Target:** 802.11 management frames (type 0, subtypes 10/12)
- **Technique:** Injects deauthentication and disassociation frames to disconnect clients from APs, enabling subsequent evil twin or credential capture attacks

#### F152: WPA3 Dragonblood Exploit
- **Hook:** kprobe on `cfg80211_rx_mgmt`
- **Target:** SAE (Simultaneous Authentication of Equals) handshake in WPA3
- **Technique:** Exploits timing/cache side-channels in SAE implementation (CVE-2019-9494/9495/9496/9497) or forces group downgrade to weak elliptic curves

#### F153: Evil Twin/Karma Attack
- **Hook:** kprobe on `cfg80211_rx_mgmt`
- **Target:** 802.11 probe request/response mechanism
- **Technique:** Responds to all probe requests (Karma) or impersonates specific SSIDs with stronger signal strength to attract clients to attacker AP

#### F154: FT Roaming Abuse
- **Hook:** TC classifier on WLAN interface
- **Target:** 802.11r (Fast BSS Transition) key hierarchy
- **Technique:** Extracts PMKR1 (Pairwise Master Key R1) from FT authentication frames, enables session hijacking during roaming transitions

#### F155: PMKID Capture
- **Hook:** kprobe on `cfg80211_rx_mgmt`
- **Target:** RSN (Robust Security Network) information element in EAPOL-1
- **Technique:** Extracts PMKID from the first EAPOL message without requiring a full 4-way handshake or active client, enabling offline WPA2/WPA3 dictionary attacks

### Remote Keyless Entry (F156–F157)

#### F156: RollJam Rolling Code Attack
- **Hook:** kprobe on `sdr_rx_callback`
- **Target:** OOK/FSK rolling code transmissions at 315/433 MHz
- **Technique:** Simultaneously jams and captures key fob transmissions, storing valid codes while preventing the vehicle from receiving them. Later replays captured codes for unauthorized access

#### F157: Relay/Amplification Attack
- **Hook:** XDP on SDR interface
- **Target:** Key fob proximity detection (125 kHz wake + 315/433 MHz response)
- **Technique:** Relays key fob challenge-response over IP/radio link to extend effective range from meters to kilometers, defeating proximity-based access control

### Drone/UAV C2 (F158–F160)

#### F158: MAVLink Command Injection
- **Hook:** TC classifier on UAV interface
- **Target:** MAVLink v1/v2 protocol (unauthenticated by default)
- **Technique:** Injects MAVLink commands (SET_MODE, NAV_WAYPOINT, DO_SET_HOME) into UAV telemetry link. Most consumer/prosumer drones lack MAVLink message signing

#### F159: DJI OcuSync Fingerprint
- **Hook:** kprobe on `sdr_rx_callback`
- **Target:** DJI DroneID beacon and OcuSync OFDM link at 2.4/5.8 GHz
- **Technique:** Decodes DJI DroneID beacons (mandatory in newer firmware) to extract operator location, UAV serial number, and flight telemetry

#### F160: FPV Video Link Intercept
- **Hook:** XDP on SDR interface
- **Target:** Analog (5.8 GHz FM) and digital FPV (DJI Digital, HDZero) video links
- **Technique:** Captures FPV video streams and embedded telemetry data (OSD overlay with GPS, altitude, battery), enabling passive UAV surveillance

### POCSAG/FLEX Paging (F161–F162)

#### F161: POCSAG Message Decode
- **Hook:** kprobe on `sdr_rx_callback`
- **Target:** POCSAG protocol at 512/1200/2400 baud
- **Technique:** Demodulates FSK paging signals to extract RIC (Radio Identity Code) addresses, function codes, and alphanumeric/numeric messages. Paging is broadcast unencrypted

#### F162: FLEX/ReFLEX Intercept
- **Hook:** kprobe on `sdr_rx_callback`
- **Target:** Motorola FLEX protocol (4-FSK at 1600/3200/6400 baud)
- **Technique:** Decodes FLEX paging including group addressing and high-speed data messages used by emergency services and enterprise paging

### RDS/DAB+ Broadcast (F163–F164)

#### F163: FM RDS Injection
- **Hook:** TC classifier on SDR interface
- **Target:** Radio Data System (RDS) subcarrier at 57 kHz on FM broadcast
- **Technique:** Injects spoofed RDS data including RadioText, Program Service name, and TMC (Traffic Message Channel) messages for traffic information manipulation

#### F164: DAB+ Ensemble Manipulation
- **Hook:** TC classifier on SDR interface
- **Target:** DAB+ FIC (Fast Information Channel) at 174–240 MHz
- **Technique:** Injects modified FIG (Fast Information Group) data to reconfigure service components, redirect listeners, or inject false emergency announcements

### EAS/WEA Emergency Alert (F165–F166)

#### F165: SAME/EAS Header Injection
- **Hook:** TC classifier on SDR interface
- **Target:** SAME (Specific Area Message Encoding) protocol at 1050 Hz AFSK
- **Technique:** Generates valid SAME headers with spoofed originator codes, event codes, and location codes to trigger false emergency alerts on broadcast receivers

#### F166: WEA/CMAS Cell Broadcast
- **Hook:** TC classifier on modem interface
- **Target:** SIB12 (SystemInformationBlockType12) for cell broadcast
- **Technique:** Injects CMAS (Commercial Mobile Alert System) messages via SIB12 to trigger WEA (Wireless Emergency Alert) on mobile devices, including Presidential-level alerts that cannot be disabled

### O-RAN Fronthaul (F167–F170)

#### F167: eCPRI IQ Sample Intercept
- **Hook:** XDP on fronthaul Ethernet interface
- **Target:** eCPRI (enhanced Common Public Radio Interface) user plane
- **Technique:** Captures raw IQ samples flowing between O-RU (Radio Unit) and O-DU (Distributed Unit) over Ethernet. IQ data is unencrypted per O-RAN WG4 spec, enabling reconstruction of all UE data before PDCP encryption

#### F168: Fronthaul MitM Injection
- **Hook:** TC classifier on fronthaul interface
- **Target:** eCPRI downlink/uplink IQ plane data
- **Technique:** Modifies IQ samples in transit to tamper with beamforming weights, inject false uplink data, or selectively null specific resource blocks targeting individual UEs

#### F169: O-RAN xApp Exploitation
- **Hook:** kprobe on `tcp_sendmsg`
- **Target:** Near-RT RIC (RAN Intelligent Controller) E2 interface
- **Technique:** Exploits E2 Application Protocol to register rogue xApps, inject false RAN metrics, or manipulate scheduling/admission control decisions via the A1/E2 interfaces

#### F170: CU/DU Split Exploitation
- **Hook:** TC classifier (SCTP port 38472)
- **Target:** F1AP (F1 Application Protocol) between O-CU and O-DU
- **Technique:** Manipulates F1AP procedures to steal UE context (security keys, bearer configuration), redirect data radio bearers, or inject false RRC messages via the CU-DU interface

### AIS Maritime (F171–F172)

#### F171: AIS Position Spoofing
- **Hook:** TC classifier on SDR interface
- **Target:** AIS VHF data link at 161.975 MHz (Ch. 87B) / 162.025 MHz (Ch. 88B)
- **Technique:** Transmits GMSK-modulated AIS messages with spoofed MMSI (Maritime Mobile Service Identity), false position/course/speed, creating phantom vessels or masking real vessel positions

#### F172: AIS Collision Avoidance Abuse
- **Hook:** kprobe on `sdr_rx_callback`
- **Target:** AIS Class A/B position reports and CPA/TCPA calculations
- **Technique:** Injects ghost vessel tracks calculated to trigger CPA (Closest Point of Approach) and TCPA (Time to CPA) alarms, forcing shipping lane diversions or port closures

---

## Defense Capabilities (Modules 16–55)

### Basic Telecom Detection (Modules 16–23)

#### Module 16: Rogue Tower Detection
- **Method:** Compares observed Cell IDs, LAC/TAC, PLMN against known-good baselines
- **Indicators:** Unknown cell appearing, signal strength anomalies, implausible geographic placement
- **Alert:** `ALERT_ROGUE_TOWER`

#### Module 17: Downgrade Attack Detection
- **Method:** Monitors RAT changes and cipher suite selection
- **Indicators:** 5G→4G→2G forced transitions, EEA2→EEA0 cipher drops, A5/3→A5/1→A5/0 downgrades
- **Alert:** `ALERT_DOWNGRADE`

#### Module 18: IMSI Catcher Detection
- **Method:** Tracks frequency of NAS Identity Request messages
- **Indicators:** Excessive identity queries, fake paging for non-existent subscribers, rapid TMSI reassignment
- **Alert:** `ALERT_IMSI_CATCHER`

#### Module 19: Cell Parameter Anomaly
- **Method:** Baselines SIB/MIB parameters and detects unauthorized changes
- **Indicators:** SIB modification without operator schedule, band/EARFCN violations, inconsistent cell-barring
- **Alert:** `ALERT_CELL_ANOMALY`

#### Module 20: GTP Traffic Anomaly
- **Method:** Inspects GTP-C/GTP-U for protocol violations
- **Indicators:** TEID collisions, GTP-in-GTP encapsulation, tunnel to unknown PGW/UPF, malformed IEs
- **Alert:** `ALERT_GTP_ANOMALY`

#### Module 21: SS7/SIGTRAN Anomaly
- **Method:** Monitors MAP/TCAP operations over SIGTRAN
- **Indicators:** Unauthorized SRI (SendRoutingInfo), CLR (CancelLocation), ISD (InsertSubscriberData), messages from unexpected point codes
- **Alert:** `ALERT_SS7_ANOMALY`

#### Module 22: Modem Tamper Detection
- **Method:** Monitors process access to modem device nodes (`/dev/ttyUSB*`, `/dev/cdc-wdm*`)
- **Indicators:** Unexpected PIDs accessing modem, AT commands from non-RIL processes, unauthorized QMI operations
- **Alert:** `ALERT_MODEM_TAMPER`

#### Module 23: NAS Replay/Injection Detection
- **Method:** Tracks NAS message sequence numbers and integrity verification
- **Indicators:** Duplicate NAS sequence numbers, messages without valid integrity protection, unprotected NAS PDUs after security activation
- **Alert:** `ALERT_NAS_REPLAY`

### Advanced Telecom Detection (Modules 24–28)

#### Module 24: VoLTE Fraud Detection
- **Method:** Deep inspection of SIP/SDP within IMS bearer
- **Indicators:** SDP crypto attribute removal (ReVoLTE), SRTP-to-RTP downgrade, unexpected codec negotiation, SIP header manipulation
- **Alert:** `ALERT_VOLTE_FRAUD`

#### Module 25: eSIM Provisioning Monitor
- **Method:** Monitors SM-DP+ communication and BPP handling
- **Indicators:** Unauthorized profile downloads, BPP injection from unknown SM-DP+, EID enumeration/probing
- **Alert:** `ALERT_ESIM_TAMPER`

#### Module 26: Slice Isolation Verification
- **Method:** Validates S-NSSAI consistency across protocol layers
- **Indicators:** S-NSSAI mismatch between NAS and transport, traffic on unexpected slice, UPF forwarding across slice boundaries
- **Alert:** `ALERT_SLICE_VIOLATION`

#### Module 27: Roaming Anomaly Detection
- **Method:** Monitors inter-operator signaling and roaming state transitions
- **Indicators:** Registration from unusual VPLMN, rapid PLMN changes, IPX route mutations, billing discrepancies
- **Alert:** `ALERT_ROAMING_ANOMALY`

#### Module 28: RF Fingerprint Analysis
- **Method:** Compares tower RF characteristics against hardware fingerprint database
- **Indicators:** Frequency stability deviation, phase noise profile mismatch, transmission power inconsistency, IQ constellation distortion
- **Alert:** `ALERT_RF_ANOMALY`

### 5G Core Defense (Modules 29–32)

#### Module 29: SBI Anomaly Detection
- **Method:** Monitors HTTP/2 traffic patterns between Network Functions
- **Indicators:** Unknown NF registration in NRF, unauthorized API calls, OAuth2 token reuse across NFs, abnormal request rates, path traversal in service URLs
- **Alert:** `ALERT_SBI_ANOMALY`
- **Correlation:** Feeds `SbiCompromise` pattern in correlation engine

#### Module 30: Handover Integrity Monitoring
- **Method:** Validates handover signaling against legitimate cell topology
- **Indicators:** Handover commands to unregistered cells, measurement report inconsistencies, rapid ping-pong between cells, source/target PCI mismatch
- **Alert:** `ALERT_HANDOVER_ANOMALY`
- **Correlation:** Feeds `HandoverHijack` pattern when combined with rogue cell alerts

#### Module 31: RAN Sharing Isolation
- **Method:** Monitors Multi-Operator RAN (MORAN/MOCN) sharing boundaries
- **Indicators:** Cross-operator resource access, PLMN-ID boundary violations, shared RAN configuration leaking between operators
- **Alert:** `ALERT_RAN_SHARING_LEAK`
- **Correlation:** Feeds `RanSharingBreach` pattern

#### Module 32: Signaling Storm Detection
- **Method:** Tracks signaling message rates and detects distributed storms
- **Indicators:** NAS message rate exceeding threshold, coordinated attach floods, paging storms, multi-layer signaling bursts
- **Alert:** `ALERT_SIGNALING_STORM`
- **Correlation:** Feeds `SignalingStorm` pattern when storms span multiple protocol layers

### Public Safety LMR Defense (Modules 40–41)

#### Module 40: TETRA Encryption Monitor
- **Method:** Monitors TETRA air interface for cipher suite changes and SYSINFO broadcasts
- **Indicators:** TEA cipher algorithm downgrade (TEA3→TEA1→TEA0), SYSINFO with encryption indicator set to 0, unexpected DCK (Derived Cipher Key) fallback from SCK (Static Cipher Key)
- **Alert:** `ALERT_TETRA_ENCRYPTION`
- **Context:** Detects exploitation of TETRA:BURST vulnerabilities (CVE-2022-24400 through CVE-2022-24404)

#### Module 41: P25 Control Channel Integrity
- **Method:** Baselines legitimate P25 control channel parameters and detects anomalies
- **Indicators:** Unauthorized TGID (Talk Group ID) changes, rogue control channel signals from unknown NAC (Network Access Code), unexpected system/WACN ID changes
- **Alert:** `ALERT_P25_CONTROL`

### IoT Radio Defense (Modules 42–45)

#### Module 42: BLE Pairing/Scanning Defense
- **Method:** Monitors BLE SMP exchanges and GATT access patterns
- **Indicators:** Pairing downgrade from LE Secure Connections to LE Legacy, abnormal GATT service enumeration rates (>100 handles/sec), L2CAP malformed PDU patterns matching BlueBorne signatures
- **Alert:** `ALERT_BLE_PAIRING`

#### Module 43: Zigbee/Z-Wave Key Provisioning Monitor
- **Method:** Monitors key exchange during device provisioning
- **Indicators:** Unprotected transport key visible during Zigbee standard join, Z-Wave S0 inclusion (known-zero temporary key), ZLL touchlink commissioning from unexpected source
- **Alert:** `ALERT_ZIGBEE_KEY`

#### Module 44: LoRaWAN Join Integrity
- **Method:** Tracks LoRaWAN OTAA join procedures and ABP session state
- **Indicators:** JoinRequest DevNonce reuse (replay attack), ABP frame counter reset to zero (session hijack), DevAddr collision between different devices
- **Alert:** `ALERT_LORAWAN_JOIN`

#### Module 45: NB-IoT/LTE-M RRC Anomaly
- **Method:** Monitors NB-IoT/LTE-M RRC and NAS messaging patterns
- **Indicators:** Unusual RRC connection frequency for eDRX/PSM-configured devices, NAS messages without active security context, abnormal paging patterns targeting IoT UEs
- **Alert:** `ALERT_NBIOT_RRC`

### WiFi Defense (Modules 46–47)

#### Module 46: WiFi Deauth/Disassoc Detection
- **Method:** Monitors 802.11 management frame rates and patterns
- **Indicators:** Deauth/disassoc frame floods (>10/sec per BSSID), CSA (Channel Switch Announcement) abuse, AP impersonation (same SSID, different BSSID, stronger RSSI)
- **Alert:** `ALERT_WIFI_DEAUTH`
- **Correlation:** Combined with ALERT_WPA3_INTEGRITY feeds `WifiRogueAp` pattern

#### Module 47: WPA3/FT Integrity Monitor
- **Method:** Validates SAE handshake timing and 802.11r FT key derivation
- **Indicators:** SAE anti-clogging token flooding, abnormal commit/confirm timing (side-channel indicator), FT PMKR1 derivation with unknown R0KH-ID, group downgrade attempts
- **Alert:** `ALERT_WPA3_INTEGRITY`

### RF Control Defense (Modules 48–49)

#### Module 48: RKE Jamming Detection
- **Method:** Monitors RF energy at key fob frequencies correlated with vehicle events
- **Indicators:** Sustained narrowband energy at 315/433 MHz coinciding with key fob transmission failure, jamming pattern consistent with RollJam attack (jam + capture)
- **Alert:** `ALERT_RKE_JAMMING`

#### Module 49: UAV C2 Integrity Monitor
- **Method:** Validates MAVLink/DJI command link authenticity
- **Indicators:** MAVLink commands without message signing (when signing is configured), DroneID beacons with serial numbers not in authorized fleet, command source from unexpected GCS address
- **Alert:** `ALERT_UAV_C2`

### Broadcast/Paging Defense (Modules 50–52)

#### Module 50: Pager Signal Anomaly
- **Method:** Baselines POCSAG/FLEX burst patterns and validates addressing
- **Indicators:** POCSAG bursts with unusual timing (outside scheduled windows), RIC addresses not in registered database, sudden frequency/baud rate changes
- **Alert:** `ALERT_PAGER_ANOMALY`

#### Module 51: Broadcast Injection Detection
- **Method:** Validates RDS and DAB+ FIC data integrity
- **Indicators:** RDS PI (Programme Identification) code changes without proper switchover, DAB+ FIG data modification from unauthorized source, TMC messages inconsistent with traffic authority
- **Alert:** `ALERT_BROADCAST_INJECTION`

#### Module 52: Emergency Alert Spoofing Detection
- **Method:** Validates EAS/SAME header format and WEA/CMAS origin
- **Indicators:** SAME header with invalid originator code or location code format, WEA messages in SIB12 without proper PLMN authorization chain, alert timing inconsistent with authorized originator schedule
- **Alert:** `ALERT_EAS_SPOOFING`

### O-RAN Defense (Modules 53–54)

#### Module 53: O-RAN Fronthaul Integrity
- **Method:** Monitors eCPRI frame integrity on fronthaul Ethernet segment
- **Indicators:** eCPRI sequence number gaps (dropped/injected frames), IQ sample amplitude exceeding expected range (injection), timing violations (>±65ns per O-RAN WG4 spec), unexpected PC_ID values
- **Alert:** `ALERT_ORAN_FRONTHAUL`
- **Correlation:** Combined with ALERT_ORAN_RIC feeds `FronthaulCompromise` pattern (confidence 0.93, severity 5)

#### Module 54: O-RAN RIC Security Monitor
- **Method:** Monitors E2/A1/O1 interface activity on Near-RT RIC
- **Indicators:** Unauthorized E2 subscriptions from unknown xApp IDs, rogue xApp registration attempts, A1 policy injection from unauthenticated source, O1 configuration changes outside maintenance window
- **Alert:** `ALERT_ORAN_RIC`

### AIS Maritime Defense (Module 55)

#### Module 55: AIS Signal Integrity
- **Method:** Physics-based validation of AIS position reports
- **Indicators:** Speed exceeding vessel class maximum (e.g., >50kn for cargo), turn rate exceeding physical limits (>720°/min), position jumps inconsistent with prior trajectory, duplicate MMSI from different geographic locations
- **Alert:** `ALERT_AIS_INTEGRITY`
- **Correlation:** Combined with ALERT_GNSS_SPOOFING feeds `AisSpoofing` pattern (confidence 0.94, severity 5)

---

## Correlation Engine

The `TelecomCorrelationEngine` performs cross-layer protocol correlation to identify complex attack patterns that single-layer detection would miss.

### Threat Categories

| Category | Description | Trigger Pattern |
|----------|-------------|-----------------|
| `ImsiCatching` | Active identity harvesting | Rogue tower + IMSI catcher alerts from same cell |
| `ManInTheMiddle` | Full relay/interception | Radio + NAS layer alerts in same time window |
| `ProtocolDowngrade` | Forced RAT/cipher downgrade | Downgrade + cell anomaly combination |
| `SignalingAbuse` | SS7/Diameter exploitation | SS7 + GTP anomalies from same source |
| `TollFraud` | Billing/charging abuse | VoLTE + roaming anomalies |
| `LocationTracking` | Subscriber location surveillance | IMSI correlation across multiple cells |
| `DataInterception` | User-plane traffic capture | GTP + NAS + tunnel anomalies |
| `ServiceDenial` | Targeted or broad DoS | Signaling storm + multi-layer alerts |
| `SliceEscape` | Network slice boundary breach | Radio + Core alerts with slice context |
| `RoamingExploit` | Inter-operator abuse | Roaming + VoLTE anomalies |
| `SbiCompromise` | 5G core NF exploitation | SBI + NAS layer anomalies |
| `HandoverHijack` | Forced mobility to rogue cell | Handover + rogue tower alerts |
| `RanSharingBreach` | MORAN/MOCN isolation failure | RAN sharing + slice alerts |
| `SignalingStorm` | Distributed signaling attack | Storm + multi-layer presence |
| `IdentityExposure` | SUPI/IMSI exposure in 5G | NAS + SBI identity-related anomalies |
| `TetraDowngrade` | LMR cipher weakening | TETRA encryption + P25 control anomalies |
| `BleExploit` | BLE stack exploitation | Pairing downgrade + L2CAP anomalies |
| `MeshKeyLeak` | IoT mesh key compromise | BLE pairing + Zigbee key provisioning |
| `LoraReplay` | LoRaWAN session takeover | Join replay + NB-IoT RRC anomaly |
| `WifiRogueAp` | Rogue AP credential harvest | Deauth flood + WPA3 integrity failure |
| `DeauthAttack` | WiFi denial of service | Sustained deauth + CSA abuse |
| `RkeReplay` | Vehicle keyless entry attack | RKE jamming + rolling code anomaly |
| `UavHijack` | UAV command takeover | MAVLink injection + C2 integrity failure |
| `AlertSpoofing` | Emergency alert fabrication | EAS header + broadcast injection |
| `FronthaulCompromise` | O-RAN data path attack | Fronthaul integrity + RIC compromise |
| `AisSpoofing` | Maritime AIS falsification | AIS integrity + GNSS spoofing |

### Correlation Layers

Events are classified into protocol layers for multi-dimensional correlation:

- **Radio** — RF/PHY/MAC layer (rogue towers, RF fingerprints, beamforming)
- **NAS** — Non-Access Stratum (identity, authentication, session management)
- **Transport** — GTP/PFCP user plane tunneling
- **Signaling** — SS7/Diameter/NGAP control plane
- **Core** — IMS, slice management, roaming logic
- **SBI** — 5G Service-Based Interface between NFs
- **Satellite** — DVB-S2, NTN, LEO, VSAT, Starlink, GNSS
- **LMR** — TETRA/P25 land mobile radio
- **IoT** — BLE, Zigbee, Z-Wave, Thread, LoRa, NB-IoT
- **WiFi** — 802.11 management/data frames
- **RF Control** — RKE, UAV C2, FPV links
- **Broadcast** — POCSAG/FLEX paging, RDS/DAB+, EAS/WEA
- **O-RAN** — eCPRI fronthaul, Near-RT RIC, F1AP
- **Maritime** — AIS VHF data link

### Adaptive Thresholds

The defense engine uses adaptive thresholds that adjust based on operator feedback:
- False positive reports lower the firing threshold for that category
- Confirmed threats increase sensitivity
- Time-decay ensures thresholds revert if traffic patterns change

---

## SDR Integration

The `SdrBridge` provides hardware abstraction for Software Defined Radio operations.

### Operating Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `Scan` | Wideband spectrum sweep | Cell tower discovery, spectrum occupancy |
| `Capture` | Narrowband IQ recording | Protocol decoding, signal analysis |
| `Inject` | Transmit on specified frequency | Authorized testing (broadcast spoofing, jamming research) |
| `Relay` | Receive + retransmit (relay) | MitM radio research, protocol translation |

### Cell Scan Results

Each discovered cell produces a `CellScanResult`:
- `freq_hz` — Center frequency
- `bandwidth_hz` — Channel bandwidth
- `pci` — Physical Cell Identity
- `rsrp_dbm` / `rsrq_db` — Signal quality measurements
- `cell_id` / `tac` / `plmn` — Cell identification
- `technology` — RAT (LTE/NR/GSM/UMTS)
- `mimo_layers` / `earfcn` — Physical layer parameters

### RF Fingerprinting

The SDR bridge generates hardware fingerprints based on:
- Frequency offset (oscillator drift)
- Phase noise profile
- IQ imbalance characteristics
- Power spectral density shape
- Timing advance patterns

### Control API

JSON-over-TCP on port 9999:

```json
{"command": "scan", "params": {"band": "n78", "duration_ms": 5000}}
{"command": "tune", "params": {"freq_hz": 1842500000, "bandwidth_hz": 20000000}}
{"command": "fingerprint", "params": {"earfcn": 1234}}
{"command": "inject", "params": {"freq": 1842500000, "power": -30}}
{"command": "stop", "params": {}}
{"command": "status", "params": {}}
```

### EARFCN-to-Frequency Conversion

The SDR bridge includes LTE band mapping (EARFCN → frequency in Hz) for automated scanning across:
- Band 1 (2100 MHz), Band 3 (1800 MHz), Band 7 (2600 MHz)
- Band 20 (800 MHz), Band 28 (700 MHz), Band 38 (2600 MHz TDD)
- Band 40 (2300 MHz TDD), Band 41 (2500 MHz TDD)

---

## Protocol Dissectors

The `tools` crate includes protocol dissectors for 5G control-plane analysis:

### PFCP (N4 Interface — 3GPP TS 29.244)

Parses communication between SMF and UPF:
- Session management (Establishment/Modification/Deletion)
- Association management (Setup/Update/Release)
- Heartbeat monitoring
- Information Elements: F-SEID, PDR, FAR, QER, URR

### NGAP (N2 Interface — 3GPP TS 38.413)

Parses communication between AMF and gNB:
- UE context management (Initial, Release)
- NAS transport (Uplink/Downlink)
- Handover procedures (Required, Command, Notify, Cancel)
- PDU Session management (Setup, Release, Modify)
- Paging, NG Setup, Reset

### XnAP (Xn Interface — 3GPP TS 38.423)

Parses inter-gNB communication:
- Handover preparation and cancellation
- UE context retrieval
- SN Status Transfer (PDCP SN/HFN for DRBs)
- RAN paging
- Secondary RAT data usage reporting

---

## Legal Disclaimer

StaticZero is a **security research framework** intended exclusively for:
- Authorized penetration testing under written engagement contracts
- Academic research in controlled lab environments
- National security agency use under lawful mandate
- MNO internal security teams testing their own infrastructure

**Unauthorized interception of telecommunications is a criminal offense** in virtually all jurisdictions (e.g., US Wiretap Act 18 USC 2511, EU ePrivacy Directive, UK Investigatory Powers Act). Users are solely responsible for ensuring legal authorization before any operation.

Always operate within a Faraday cage or RF-isolated environment unless explicitly authorized for live-network testing by the network operator.
