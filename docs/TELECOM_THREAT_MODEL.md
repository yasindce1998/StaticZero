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

---

## MITRE ATT&CK Mapping (Mobile)

| Technique ID | Name | Aegis Features |
|-------------|------|----------------|
| T1430 | Location Tracking | F92, F95, F107, M19, M22 |
| T1617 | Cellular Interception | F89-F92, F101, M21, M24 |
| T1600.001 | Downgrade System Image | F93, M20 |
| T1587.001 | Develop Capabilities: Malware | F90 (baseband) |
| T1583.003 | Acquire Infrastructure: VPS | F95, F96 (SS7/Diameter proxy) |
| T1557 | Adversary-in-the-Middle | F94, F97, F101, F104, F106 |
| T1499 | Endpoint Denial of Service | F103 (slice DoS) |
| T1565 | Data Manipulation | F96, F100, F108 |

---

## Risk Matrix

| Attack | Likelihood | Impact | Detection Difficulty | Aegis Detection |
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
