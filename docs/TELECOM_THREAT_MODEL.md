# Telecom Threat Model

Attack trees and threat analysis per cellular generation for StaticZero telecom modules.

---

## Overview

This document maps the attack surfaces, threat actors, and attack paths across cellular generations (2G–5G) that StaticZero's telecom offensive features exploit and defensive modules detect.

## Threat Actors

| Actor | Capability | Motivation | Examples |
|-------|-----------|------------|----------|
| Nation-State | Full spectrum (SS7 access, lawful intercept, zero-days) | Surveillance, espionage | IMSI catchers, LI abuse |
| Organized Crime | SS7 access (purchased/leased), SIM farms | Toll fraud, SMS intercept for banking | SIM swap, bypass 2FA |
| Corporate Espionage | Targeted implants, rogue femtocells | Trade secrets, executive tracking | Femtocell MitM, VoLTE tap |
| Researcher/Red Team | SDR hardware, protocol knowledge | Authorized security testing | All StaticZero features |
| Insider (Operator) | Core network access, configuration | Data theft, surveillance-for-hire | LI abuse, HLR manipulation |

---

## Attack Trees by Generation

### 2G (GSM/GPRS/EDGE)

```
[Intercept Voice/SMS]
├── [Passive] A5/1 cracking (Kraken rainbow tables)
│   └── Requires: RTL-SDR, ~2TB storage, GSM downlink capture
├── [Active] IMSI Catcher (fake BTS)
│   ├── Force A5/0 (null cipher) → plaintext intercept
│   ├── Force A5/1 → real-time crack
│   └── Identity Request flood → IMSI harvest
├── [SS7] SendRoutingInfo + SendIMSI
│   └── Requires: SS7 access via roaming hub or MVNO
└── [Baseband] OTA exploit via SMS/USSD
    └── Requires: Baseband zero-day (Shannon, Qualcomm)

[Location Tracking]
├── [SS7] AnyTimeInterrogation (ATI)
├── [SS7] ProvideSubscriberLocation (PSL)
├── [Active] Timing Advance measurement (IMSI catcher)
└── [Passive] Cell ID correlation (tower dumps)

[SMS Intercept]
├── [SS7] UpdateLocation → redirect SMS to attacker MSC
├── [SS7] RegisterSS → forward SMS to attacker
└── [Active] IMSI catcher relay (MitM)
```

**StaticZero Coverage:**
- Offense: F89 (AT inject), F90 (baseband exploit), F91 (SIM clone), F92 (IMSI intercept), F93 (downgrade), F95 (SS7 MAP)
- Defense: M19 (rogue tower), M20 (downgrade), M21 (IMSI catcher), M24 (SS7 anomaly)

---

### 3G (UMTS/HSPA)

```
[Break Mutual Authentication]
├── [Downgrade] Force 3G → 2G (no mutual auth)
│   ├── RRC Connection Release with redirect
│   ├── TAU Reject (cause #7)
│   └── Jammer on 3G bands + fake 2G cell
├── [MITM] Fake NodeB (before integrity protection)
│   └── Exploit: RRC messages before SMC are unprotected
└── [Core] Compromise HLR/AuC → extract Ki/OPc

[Data Interception]
├── [Downgrade] Force UEA0 (null cipher on user plane)
├── [GTP] Tunnel hijack on Gn/Gp interface
│   └── TEID prediction + GTP-C manipulation
└── [Femtocell] HeNB compromise → local MitM
    └── IPsec key extraction from femtocell hardware

[Location Tracking]
├── [SS7] Same as 2G (SS7 unchanged)
├── [Active] IMSI paging on multiple cells
└── [RRC] Measurement Report manipulation
```

**StaticZero Coverage:**
- Offense: F93 (downgrade), F94 (GTP hijack), F95 (SS7), F97 (RRC redirect), F106 (femtocell)
- Defense: M20 (downgrade), M22 (cell anomaly), M23 (GTP anomaly), M24 (SS7)

---

### 4G (LTE/LTE-A)

```
[Break Encryption]
├── [Downgrade] Force to 2G/3G (no mutual auth)
│   ├── TAU Reject (EMM cause #7)
│   ├── RRC Release with redirectedCarrierInfo
│   └── Band-selective jamming
├── [Key Recovery] Exploit AKA protocol weaknesses
│   ├── aLTEr attack (DNS redirect via malleable user plane)
│   └── ReVoLTE (VoLTE key reuse → voice decryption)
└── [Core] Diameter S6a exploitation
    └── Authentication vector theft from HSS

[VoLTE Interception] (Feature 101)
├── [SIP MitM] Rogue P-CSCF (IMS proxy)
│   ├── INVITE manipulation → call redirect
│   ├── SDP modification → media relay through attacker
│   └── RTP/SRTP key extraction from SDP
├── [ReVoLTE] Keystream reuse on radio bearer
│   └── Requires: Same cell, second call within reuse window
└── [Core] S-CSCF/I-CSCF compromise

[IMSI/Identity Attacks]
├── [Pre-auth] IMSI exposed in Attach Request (plaintext)
│   └── Passive capture with SDR on PRACH
├── [Active] Identity Request (before SMC)
│   └── Exploit: NAS messages before SecurityModeCommand are unprotected
└── [Tracking] GUTI reallocation tracking
    └── Correlate old GUTI ↔ new GUTI from same cell

[Network Slice Attacks] (5G NSA with LTE anchor)
├── [Bearer mapping] Manipulate DRB ↔ QoS mapping
└── [EPC interwork] Exploit interworking function (IWF)

[eSIM Attacks] (Feature 102)
├── [SM-DP+ MitM] Intercept profile download
├── [Profile injection] Forge BPP (Bound Profile Package)
└── [EID correlation] Track device via eSIM identifier
```

**StaticZero Coverage:**
- Offense: F92-F100, F101 (VoLTE), F102 (eSIM), F103 (slicing), F104 (VoWiFi), F105 (LI), F106 (femto)
- Defense: M19-M26, M24 (VoLTE fraud), M25 (eSIM tamper), M26 (slice violation)

---

### 5G (NR/SA)

```
[SUCI/SUPI De-concealment] (Feature 99)
├── [Crypto] Break ECIES (quantum computing future threat)
├── [Side-channel] Timing attack on SIDF
├── [Core] Compromise UDM → access de-concealment keys
└── [Correlation] Link SUCI to SUPI via traffic analysis

[Network Slicing Attacks] (Feature 103)
├── [Slice escape] Cross-slice traffic via shared UPF
│   ├── S-NSSAI spoofing in registration
│   ├── PDU session modification with wrong slice ID
│   └── Exploit shared infrastructure (same physical NF)
├── [Slice DoS] Resource exhaustion on target slice
│   ├── Mass UE registration to exhaust slice capacity
│   └── Signaling storm on NSSF
└── [Slice reconnaissance] Enumerate available slices
    └── Registration Request with various S-NSSAI values

[5G Core (SBA) Attacks]
├── [API abuse] NRF service discovery manipulation
│   └── Register rogue NF, intercept service requests
├── [SEPP bypass] Roaming security edge proxy evasion
│   └── Exploit N32-f/N32-c interface vulnerabilities
├── [Token theft] OAuth2 token from NRF
│   └── Access any 5G core NF with stolen token
└── [Service mesh] Lateral movement via HTTP/2 between NFs

[N2/NGAP Injection] (Feature 100)
├── [Handover] Force handover to rogue gNB
│   ├── Inject HandoverRequired (source to target)
│   └── Fake measurement report via manipulated UE
├── [Context] Modify UE security context
│   └── InitialContextSetupRequest with weak algorithms
└── [Paging] Paging-based location tracking
    └── 5G Paging with SystemInformationRequest correlation

[WiFi Calling / VoWiFi] (Feature 104)
├── [ePDG MitM] Rogue WiFi → intercept IKEv2
│   ├── Break EAP-AKA' (with stolen vectors)
│   └── SSL strip on initial EAP identity
├── [SWu tunnel] IPsec tunnel hijack after establishment
└── [DNS redirect] Force UE to rogue ePDG

[Lawful Intercept Abuse] (Feature 105)
├── [X1] Unauthorized target provisioning
│   └── Access ADMF → add interception target
├── [X2/X3] Intercept delivery function compromise
│   └── Redirect IRI/CC to attacker collection system
└── [Warrant manipulation] Delete/modify target records
```

**StaticZero Coverage:**
- Offense: F99-F100, F101-F108 (all advanced telecom)
- Defense: M19-M28 (all telecom detection modules)

---

### TETRA/P25 — Public Safety LMR

```
[TETRA Air Interface Attack]
├── [Passive] TEA1 cipher exploitation (CVE-2022-24400)
│   ├── 80-bit key reduced to 32-bit effective (backdoor)
│   └── Requires: SDR @ 380–400 MHz, offline brute-force
├── [Active] Encryption downgrade
│   ├── Inject SYSINFO with encryption=0
│   ├── Force SCK → DCK fallback
│   └── Force TEA3 → TEA1 (weaker algorithm)
├── [OTA Key Management] CVE-2022-24401
│   └── Key stream reuse under TETRA air interface
└── [Identity] TETRA subscriber identity tracking
    └── Monitor unencrypted SYSINFO PDUs for radio IDs

[P25 LMR Attack]
├── [Passive] Control channel harvest
│   ├── FDMA control channel decode (Phase I)
│   ├── TDMA control channel decode (Phase II)
│   └── Extract TGID, radio ID, WACN, NAC
├── [Active] IMBE voice intercept
│   └── Systems without AES-256/DES-OFB are cleartext
└── [Active] Rogue P25 repeater
    └── Higher power → force radio affiliation
```

**StaticZero Coverage:**
- Offense: F135 (TETRA intercept), F136 (encryption downgrade), F137 (P25 harvest), F138 (IMBE intercept)
- Defense: M40 (TETRA encryption monitor), M41 (P25 control integrity)

---

### IoT Radio Protocols (BLE/Zigbee/LoRa/NB-IoT)

```
[BLE/Bluetooth Attack]
├── [Passive] GATT enumeration (CVE-2020-0022)
│   └── Service discovery, handle-value dumping
├── [Active] Pairing downgrade
│   ├── Force LE Legacy from Secure Connections
│   ├── Passkey brute-force (6 digits = 1M combinations)
│   └── JustWorks exploitation (no MITM protection)
├── [Active] BlueBorne-style RCE
│   ├── L2CAP info leak (CVE-2017-1000251)
│   └── Heap overflow via malformed PDU
└── [Active] Advertisement spoofing
    └── iBeacon/Eddystone impersonation

[Zigbee/Z-Wave/Thread Attack]
├── [Passive] Zigbee key sniffing
│   ├── Transport key visible during standard join
│   ├── ZLL touchlink commissioning key exchange
│   └── Requires: Capture during provisioning window
├── [Active] Z-Wave S0 key extraction
│   ├── S0 temporary key is 0x00...00 (by design)
│   └── Network key revealed in single handshake
└── [Active] Thread MLE exploitation
    └── Leader election manipulation, mesh partitioning

[LoRaWAN Attack]
├── [Active] OTAA Join Replay
│   ├── DevNonce reuse → session key derivation
│   └── Exploits: implementations without nonce tracking
├── [Active] ABP Session Hijack
│   ├── Static keys → DevAddr spoofing
│   ├── Frame counter desync → injection
│   └── No mutual authentication in ABP mode
└── [Passive] PHY-layer capture
    └── CSS chirp demodulation at ISM bands

[NB-IoT/LTE-M Attack]
├── [Passive] Pre-auth NAS extraction
│   └── Messages before security context (same as LTE)
└── [Active] eDRX/PSM timing attack
    └── Paging occasion prediction → targeted exploitation
```

**StaticZero Coverage:**
- Offense: F139–F142 (BLE), F143–F145 (Zigbee/Z-Wave/Thread), F146–F148 (LoRa), F149–F150 (NB-IoT)
- Defense: M42 (BLE pairing), M43 (Zigbee key), M44 (LoRaWAN join), M45 (NB-IoT RRC)

---

### WiFi 802.11

```
[WiFi Denial of Service]
├── [Active] Deauth/Disassoc flood
│   ├── Targeted (specific STA MAC)
│   ├── Broadcast (entire BSS)
│   └── Pre-condition for evil twin
├── [Active] CSA (Channel Switch) abuse
│   └── Force clients to move to attacker channel
└── [Active] NAV hijacking
    └── Virtual carrier sense manipulation

[WiFi Credential Theft]
├── [Active] WPA3 Dragonblood (CVE-2019-9494/5/6/7)
│   ├── SAE timing side-channel
│   ├── SAE cache side-channel
│   └── Group downgrade to weak curve
├── [Active] Evil Twin / Karma
│   ├── SSID impersonation (stronger signal)
│   ├── Probe response to all probe requests
│   └── Captive portal credential harvest
├── [Passive] PMKID capture
│   ├── RSN IE in EAPOL message 1
│   └── No client interaction required
└── [Active] FT roaming abuse (802.11r)
    └── PMKR1 extraction during fast transition
```

**StaticZero Coverage:**
- Offense: F151 (deauth), F152 (WPA3), F153 (evil twin), F154 (FT abuse), F155 (PMKID)
- Defense: M46 (deauth detection), M47 (WPA3/FT integrity)

---

### RF Control Systems (RKE/UAV)

```
[Remote Keyless Entry Attack]
├── [Active] RollJam
│   ├── Jam 315/433 MHz + capture valid code
│   ├── Victim retries → capture second code
│   └── Replay first code → have spare stored
├── [Active] Relay/Amplification
│   ├── 125 kHz wake → relay over IP
│   ├── 315/433 MHz response → relay back
│   └── Effective range: unlimited (IP backhaul)
└── [Passive] Code analysis
    └── Fixed-code systems → simple replay

[UAV/Drone C2 Attack]
├── [Active] MAVLink injection
│   ├── No authentication in MAVLink v1
│   ├── v2 signing optional (rarely enabled)
│   └── Commands: SET_MODE, NAV_WAYPOINT, RTL
├── [Passive] DJI DroneID decode
│   ├── OFDM at 2.4/5.8 GHz
│   ├── Operator GPS, serial number, flight path
│   └── Mandatory in newer DJI firmware
└── [Passive] FPV video intercept
    └── Analog 5.8 GHz FM or digital (unencrypted)
```

**StaticZero Coverage:**
- Offense: F156 (RollJam), F157 (relay), F158 (MAVLink), F159 (DroneID), F160 (FPV)
- Defense: M48 (RKE jamming), M49 (UAV C2 integrity)

---

### Broadcast/Paging Systems

```
[Paging System Attack]
├── [Passive] POCSAG decode
│   ├── All paging is broadcast unencrypted
│   ├── 512/1200/2400 baud FSK demod
│   └── Extract: RIC address, message content
└── [Passive] FLEX/ReFLEX decode
    └── 4-FSK 1600/3200/6400 baud

[Broadcast Injection]
├── [Active] FM RDS spoofing
│   ├── RadioText/PS name injection
│   └── TMC traffic message falsification
├── [Active] DAB+ FIC manipulation
│   └── Service reconfiguration via FIG injection
├── [Active] EAS/SAME header injection
│   ├── Valid SAME format with false content
│   └── 1050 Hz AFSK header spoof
└── [Active] WEA/CMAS cell broadcast
    ├── SIB12 injection (requires rogue eNB)
    └── Presidential-level alerts cannot be disabled
```

**StaticZero Coverage:**
- Offense: F161–F162 (paging), F163–F164 (RDS/DAB+), F165–F166 (EAS/WEA)
- Defense: M50 (pager anomaly), M51 (broadcast injection), M52 (EAS spoofing)

---

### O-RAN Fronthaul

```
[O-RAN Fronthaul Attack]
├── [Passive] eCPRI IQ sample capture
│   ├── Unencrypted per O-RAN WG4 specification
│   ├── Full UE data reconstruction from IQ
│   └── Requires: Ethernet tap on fronthaul segment
├── [Active] Fronthaul MitM
│   ├── Modify DL IQ → alter what UE receives
│   ├── Modify UL IQ → alter what gNB decodes
│   ├── Tamper beamforming weights → steer nulls
│   └── Selective resource block nulling
├── [Active] RIC exploitation
│   ├── Rogue xApp registration
│   ├── E2 subscription manipulation
│   ├── A1 policy injection
│   └── O1 configuration tampering
└── [Active] F1AP exploitation
    ├── UE context theft (security keys)
    ├── DRB redirect between CU and DU
    └── RRC message injection via CU/DU split
```

**StaticZero Coverage:**
- Offense: F167 (eCPRI intercept), F168 (fronthaul MitM), F169 (xApp exploit), F170 (F1AP exploit)
- Defense: M53 (fronthaul integrity), M54 (RIC security monitor)

---

### AIS Maritime

```
[AIS Attack]
├── [Active] Position spoofing
│   ├── False MMSI + position on VHF (161.975/162.025 MHz)
│   ├── Ghost vessel creation
│   └── Real vessel position masking
├── [Active] Collision avoidance abuse
│   ├── Inject ghost tracks triggering CPA/TCPA alarms
│   ├── Force shipping lane diversions
│   └── Port closure via phantom vessel swarm
└── [Combined] AIS + GNSS spoofing
    └── Multi-vector maritime navigation attack
```

**StaticZero Coverage:**
- Offense: F171 (AIS spoofing), F172 (collision avoidance abuse)
- Defense: M55 (AIS signal integrity)

---

## Next-Generation Attack Surfaces

### Wi-Fi 6/6E/7/8 (F173–F179)

Wi-Fi 7 (802.11be) Multi-Link Operation is deployed in consumer hardware, and key-confusion attacks against the MLO key hierarchy were demonstrated in the lab in 2025 — the standard mandates that every link refuse keys belonging to another link or an older set of links, which is exactly the invariant attackers break. On 6 GHz, standard-power operation depends on Automated Frequency Coordination (AFC), so an impersonated AFC lets a rogue AP bypass power constraints that clients trust. IEEE 802.11bf WLAN Sensing (finalized 2024) turns Wi-Fi into a through-wall presence radar for passive tracking, while Wi-Fi 8 multi-AP coordination and sub-GHz HaLow (802.11ah) extend the rogue-infrastructure surface.

**StaticZero Coverage:**
- Offense: F173 (MLO link desync), F174 (MLO key separation abuse), F175 (6 GHz AFC impersonation), F176 (OFDMA RU selective jamming), F177 (802.11bf sensing privacy), F178 (HaLow), F179 (Wi-Fi 8 MAPC rogue)
- Defense: M56 (MLO integrity), M64 (Wi-Fi sensing privacy guard), M69 (MAPC/HaLow integrity)

---

### Satellite Direct-to-Cell & PNT (F180–F184)

Direct-to-Cell puts LTE eNodeBs in orbit (Starlink/T-Mobile live; AST SpaceMobile, Skylo NB-NTN), and because Android now exposes satellite network identities, a spoofed "satellite" cell is the direct-to-device successor of the IMSI catcher. LEO PNT constellations (Xona Pulsar-class) broadcast narrow-beam commercial positioning signals with no authentication — a new spoofable signal class. Galileo OSNMA has been operational since July 2025, making cryptographic spoofing detection possible for open-service users and a target for bypass probes. 3GPP Release 19 adds regenerative payloads (gNB on board) and store-and-forward NB-NTN, moving core-adjacent attack surfaces into orbit.

**StaticZero Coverage:**
- Offense: F180 (D2C spoofed satellite cell), F181 (NTN regenerative gNB injection), F182 (LEO PNT spoofing), F183 (Galileo OSNMA bypass probe), F184 (NB-NTN store-and-forward abuse)
- Defense: M61 (D2C cell verification), M62 (GNSS authentication monitor), M63 (NTN regenerative anomaly), M68 (LEO PNT authentication)

---

### UWB / Bluetooth 6.0 Secure Ranging (F185–F188)

IEEE 802.15.4z secure ranging underpins CCC Digital Key 3.0 vehicle keys and item finders, but Mix-Down distance-reduction attacks on commercial 4z chips (STS clock desync) have been demonstrated, defeating proximity-based authorization. Bluetooth 6.0 (2024) Channel Sounding combines phase-based ranging with round-trip time as a relay countermeasure, making the ranging channel itself the new target. Auracast LE Audio broadcast key handling is the mass-eavesdropping surface, with specification issues published in 2025.

**StaticZero Coverage:**
- Offense: F185 (UWB 802.15.4z ranging manipulation), F186 (UWB digital key relay), F187 (BT 6.0 channel sounding spoof), F188 (Auracast broadcast key abuse)
- Defense: M57 (secure ranging anomaly)

---

### Matter / Ambient IoT / Critical Infrastructure (F189–F194)

Matter onboarding runs SPAKE2+ over low-entropy setup passcodes with weakened PBKDF2 and static per-device salts (IACR ePrint 2025/1268), and CVE-2024-56317-class non-atomic ACL updates turn temporary privileges into persistent surveillance access. Release 19 Ambient IoT (TS 33.369, published October 2025) introduces batteryless ~1 µW devices whose security spec just landed — device cloning and backscatter identity spoofing are the obvious first attacks. DECT-2020 NR massive mesh, the FRMCS 5G-based railway signaling successor to GSM-R, and the LDACS L-band aeronautical datalink all carry safety-critical traffic while their security frameworks are still under construction.

**StaticZero Coverage:**
- Offense: F189 (Matter passcode attack), F190 (Matter ACL manipulation), F191 (Ambient IoT device cloning), F192 (DECT-2020 NR mesh injection), F193 (FRMCS railway signaling injection), F194 (LDACS aviation datalink injection)
- Defense: M58 (Matter commissioning anomaly), M59 (Ambient IoT identity anomaly), M60 (DECT-2020 mesh integrity), M65 (FRMCS/LDACS integrity)

---

### 6G Horizon (F195–F200)

3GPP Release 20 (commercialization ~2028–2030) designs an AI-native air interface, making adversarial perturbation of learned receivers and model poisoning of AI-RAN the new RAN attack surface. Reconfigurable Intelligent Surfaces make reflection control a physical-layer MitM with no standard defense yet, and THz narrow beams make codebook and beam-training exhaustion a denial vector. Downgrading quantum-safe handshakes against long-lived telecom keys is the harvest-now-decrypt-later enabler, while the network-of-networks trust fabric and ISAC cellular radar expand credential abuse and tracking surfaces.

**StaticZero Coverage:**
- Offense: F195 (AI-RAN adversarial perturbation), F196 (RIS reflection manipulation), F197 (THz beam blockage), F198 (PQC handshake downgrade), F199 (network-of-networks credential abuse), F200 (ISAC sensing abuse)
- Defense: M66 (AI-RAN model integrity), M67 (PQC downgrade detection), M70 (network-of-networks credential monitor)

---

## Cross-Generation Attack Patterns

### Protocol Downgrade Chain
```
5G SA → 5G NSA → LTE → 3G → 2G
  │         │       │     │     └── A5/0 (no cipher)
  │         │       │     └── UEA0 (no cipher)
  │         │       └── EEA0 (no cipher) + aLTEr
  │         └── Fallback to LTE (lose 5G security)
  └── Redirection attacks via N2/NGAP
```

### SS7/Diameter/HTTP2 Evolution
```
2G/3G: SS7 MAP (SendRoutingInfo, UpdateLocation, InsertSubscriberData)
4G: Diameter S6a/S6b (ULR, AIR, CLR)
5G: HTTP/2 SBA (Nudm, Nausf, Namf REST APIs)
    └── Same logical attacks, different transport
```

---

## Protocol Correlation Patterns

The correlation engine detects multi-layer attack sequences:

| Pattern | Layers | Indicators | Threat |
|---------|--------|-----------|--------|
| Downgrade+Intercept | Radio→NAS→Transport | RRC release → 2G camp → null cipher → data flow | Active MitM |
| Location Track | Signaling→Core | SRI + PSI from same OPC within 60s | SS7 tracking |
| VoLTE Tap | Application→Transport | SIP INVITE mod + RTP redirect + new media path | Call intercept |
| Slice Escape | Core→Transport | S-NSSAI mismatch + cross-UPF traffic + GTP anomaly | Isolation breach |
| Roaming Fraud | Signaling→Core | ULR from unknown VPLMN + ISD without auth | Roaming exploit |
| Femtocell MitM | Radio→NAS→Transport | CSG access + IPsec anomaly + RRC reconfiguration | Local intercept |
| TETRA+P25 Downgrade | LMR→Radio | TETRA encryption=0 + P25 rogue control in same time window | LMR surveillance |
| IoT Mesh Compromise | IoT→IoT | BLE pairing downgrade + Zigbee key sniff on same network | Smart building takeover |
| WiFi Rogue AP Chain | WiFi→WiFi | Deauth flood + evil twin + WPA3 SAE failure | Credential harvest |
| O-RAN Full MitM | O-RAN→Core | Fronthaul IQ tamper + RIC xApp compromise + F1AP exploit | Complete RAN compromise |
| Maritime Multi-Vector | Maritime→Satellite | AIS spoofing + GPS spoofing + VSAT integrity failure | Navigation attack |
| UAV Takeover Chain | RF Control | MAVLink injection + DroneID spoof + FPV intercept | Full UAV compromise |
| Emergency Alert Fabrication | Broadcast→Core | EAS header + WEA SIB12 + broadcast injection | Mass panic/disruption |
| D2C Cell Spoof | Satellite→NAS | Satellite-indicated cell with terrestrial TA/doppler + IMSI catcher correlation (M61+M18) | D2cCellSpoofing |
| LEO PNT + OSNMA Failure | Satellite | LEO PNT physics anomaly with Galileo OSNMA authentication failure (M68+M62) | GnssSpoofing |
| Smart Home Takeover | Radio | Matter commissioning abuse + Ambient IoT/DECT-2020 anomaly (M58+M59/M60) | SmartHomeCompromise |
| Wi-Fi 7 MLO Evil Twin | Radio | MLO integrity failure + WPA3 integrity failure (M56+M47) | WifiRogueAp |
| 6G Control Plane Compromise | Core→NAS | AI-RAN model tampering + PQC handshake downgrade (M66+M67) | AiRanCompromise |
| Vehicle Key Theft Chain | Radio | Secure ranging manipulation + RKE jamming (M57+M48) | SecureRangingSpoofing |
| Harvest-Now-Decrypt-Later | NAS | Repeated PQC handshake downgrades (M67) | PqcDowngrade |

---

## MITRE ATT&CK Mapping (Mobile)

| Technique ID | Name | StaticZero Features |
|-------------|------|----------------|
| T1430 | Location Tracking | F92, F95, F107, M19, M22 |
| T1617 | Cellular Interception | F89-F92, F101, M21, M24 |
| T1600.001 | Downgrade System Image | F93, M20 |
| T1587.001 | Develop Capabilities: Malware | F90 (baseband) |
| T1583.003 | Acquire Infrastructure: VPS | F95, F96 (SS7/Diameter proxy) |
| T1557 | Adversary-in-the-Middle | F94, F97, F101, F104, F106, F173, F174, F180, F185 |
| T1499 | Endpoint Denial of Service | F103 (slice DoS) |
| T1565 | Data Manipulation | F96, F100, F108 |
| T1498 | Network Denial of Service | F151, F165, F172, F176, F197, M46, M52, M55 |
| T1205 | Traffic Signaling | F156, F157, M48 |
| T1595.002 | Active Scanning: Vulnerability Scanning | F139, F143, F146, M42, M43, M44 |
| T1071.001 | Application Layer Protocol: Web | F167, F169, M53, M54 |
| T1542 | Pre-OS Boot | F140, F144, M42, M43 |
| T1040 | Network Sniffing | F135, F137, F155, F161, F177, F188, F191, M40, M41 |
| T1531 | Account Access Removal | F136, F152, M40, M47 |
| T1110.001 | Brute Force: Password Guessing | F189 (Matter passcode), M58 |
| T1562.001 | Impair Defenses | F183 (OSNMA bypass), F198 (PQC downgrade), M62, M67 |
| T1565.001 | Data Manipulation: Stored Data | F195 (AI-RAN), F196 (RIS), M66 |
| T1078 | Valid Accounts | F199 (network-of-networks credentials), M70 |

---

## Risk Matrix

| Attack | Likelihood | Impact | Detection Difficulty | StaticZero Detection |
|--------|-----------|--------|---------------------|-----------------|
| IMSI catching (2G) | High | Medium | Low | M21 (high confidence) |
| SS7 location tracking | High | High | Medium | M24 + correlation |
| Protocol downgrade | Medium | High | Medium | M20 (multi-layer) |
| VoLTE intercept | Low | Critical | High | M24 + F101 signatures |
| 5G slice escape | Low | Critical | Very High | M26 + correlation |
| GTP tunnel hijack | Medium | Critical | Medium | M23 |
| Baseband exploit | Low | Critical | Very High | M25 (modem tamper) |
| eSIM provisioning attack | Low | High | High | M25 |
| LI abuse (insider) | Low | Critical | Very High | Audit logs only |
| Roaming/IPX pivot | Medium | High | High | M27 + correlation |
| TETRA cipher downgrade | High | Critical | Medium | M40 (TEA monitoring) |
| BLE pairing exploitation | High | Medium | Low | M42 (pairing defense) |
| Zigbee key sniffing | Medium | High | Medium | M43 (key provisioning) |
| LoRaWAN session hijack | Medium | High | Medium | M44 (join integrity) |
| WiFi deauth/evil twin | High | Medium | Low | M46 + M47 (correlation) |
| WPA3 Dragonblood | Low | High | High | M47 (SAE timing) |
| RollJam vehicle attack | Medium | High | High | M48 (RF energy) |
| MAVLink UAV hijack | Medium | Critical | Medium | M49 (C2 integrity) |
| EAS/WEA alert spoofing | Low | Critical | High | M52 (header validation) |
| O-RAN fronthaul MitM | Low | Critical | Very High | M53 + M54 (correlation) |
| AIS position spoofing | Medium | High | Medium | M55 (physics validation) |
| Wi-Fi 7 MLO desync | Medium | High | Medium | M56 (MLO integrity monitor) |
| D2C satellite cell spoofing | Low | Critical | Very High | M61 + correlation engine |
| Galileo OSNMA bypass | Low | Critical | Very High | M62 (OSNMA verification) |
| Matter passcode attack | High | High | Low | M58 (commissioning anomaly) |
| PQC handshake downgrade | Medium | Critical | High | M67 (PQC downgrade detection) |
| AI-RAN model tampering | Low | Critical | Very High | M66 + correlation engine |

---

## Defensive Recommendations by Generation

### 2G (Legacy — minimize exposure)
- Disable 2G fallback where possible (Android: `*#*#4636#*#*` → LTE only)
- Monitor for forced reselection to 2G cells
- Deploy IMSI catcher detection (Module 21)

### 3G (Transitioning out)
- Enforce integrity protection (UIA ≠ 0)
- Monitor GTP-C on Gn/Gp interfaces
- Verify femtocell IPsec integrity

### 4G (Primary network)
- Enforce EEA2 (AES) minimum cipher strength
- Monitor VoLTE SIP/SDP for manipulation
- Deploy eSIM provisioning integrity checks
- Cell baseline anomaly detection (Module 22)

### 5G (Emerging)
- Enable SUCI (SUPI concealment) — prevents IMSI exposure
- Network slice isolation verification
- SEPP integrity for roaming
- SBA API authentication hardening
- RF fingerprinting for rogue gNB detection (Module 28)

### TETRA/P25 (Public Safety)
- Enforce TEA3 minimum cipher (disable TEA1 — backdoored)
- Enable end-to-end encryption for sensitive communications
- Monitor for SYSINFO encryption indicator changes (Module 40)
- Deploy P25 AES-256 encryption on all talk groups

### IoT (BLE/Zigbee/LoRa)
- Enforce LE Secure Connections (reject LE Legacy pairing)
- Use Zigbee 3.0 Install Code provisioning (never unprotected join)
- Prefer LoRaWAN OTAA over ABP; enforce DevNonce tracking
- Enable Z-Wave S2 security (retire S0 devices)

### WiFi 802.11
- Deploy WIDS (Wireless Intrusion Detection System) with deauth monitoring
- Enable WPA3 with SAE-PK (Public Key) to prevent Dragonblood
- Disable 802.11r FT in environments without legitimate roaming needs
- Monitor for BSSID impersonation (same SSID, different hardware fingerprint)

### O-RAN
- Encrypt fronthaul using MACsec (IEEE 802.1AE) where supported
- Enforce xApp authentication and authorization on Near-RT RIC
- Monitor eCPRI sequence numbers for injection/drop detection (Module 53)
- Restrict E2/A1 interfaces to authenticated sources only

### Maritime AIS
- Cross-validate AIS reports with radar/LRIT/satellite tracking
- Flag position reports violating physics constraints (Module 55)
- Implement multi-source verification for CPA/TCPA alerts
- Deploy AIS receiver authentication where mandated

### Next-Generation Wi-Fi (6/7/8)
- Monitor MLO key hierarchy consistency and per-link sequence numbers (Module 56)
- Validate AFC standard-power claims on 6 GHz; reject APs claiming power without coordination
- Disable or policy-limit 802.11bf sensing in privacy-sensitive environments
- Watch MAPC coordination set membership for rogue APs (Module 69)

### Satellite D2C & PNT
- Cross-validate satellite-indicated cells against physics: timing advance, doppler, ephemeris (Module 61, `d2c-monitor` tool)
- Enforce Galileo OSNMA verification for all positioning (Module 62, `osnma-verify` tool)
- Authenticate LEO PNT signals; flag C/N0 ceiling and doppler slope anomalies (Module 68)

### UWB / Bluetooth 6.0
- Enforce 802.15.4z STS on all ranging sessions
- Monitor ranging consistency for Mix-Down class distance-reduction attacks (Module 57)
- Prefer UWB distance bounding over BLE-only digital keys

### Smart-Home & Critical IoT
- Rate-limit Matter commissioning attempts and enforce ACL version monotonicity (Module 58)
- Monitor Ambient IoT identity and power consistency for clones (Module 59)
- Validate DECT-2020 NR mesh joins (Module 60)
- Source-validate FRMCS/LDACS signaling (Module 65)

### 6G Horizon
- Sign and verify AI-RAN models before deployment (Module 66)
- Mandate hybrid PQC with no silent downgrade to classic key exchange (Module 67)
- Bind credentials to member networks in the network-of-networks trust fabric (Module 70)
