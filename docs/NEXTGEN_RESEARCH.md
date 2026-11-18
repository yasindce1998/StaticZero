# Next-Generation Wireless Research Basis (F173–F200, Modules 56–70)

This document records the research and standards basis for the
next-generation capability catalog added in this repository: what is
deployed today, what is standardizing now, and what is on the 6G horizon.
Each section maps published research or an active standards work item to
the corresponding StaticZero features and defense modules.

The features themselves follow the repository's established model: they
are a **research catalog** with eBPF scaffolding that decodes
header/pattern markers on the traffic path. They are not proof of
working over-the-air attack chains; see the implementation-status note
in the README and [LAB_SMOKE_TESTS.md](LAB_SMOKE_TESTS.md) for what is
actually validated.

## Wi-Fi 6/6E/7/8 (F173–F179, Modules 56, 64, 69)

Wi-Fi 7 (802.11be) is deployed in consumer hardware with Multi-Link
Operation (MLO): a multi-link device (MLD) aggregates 2.4/5/6 GHz links,
each with its own keys. The standard mandates that every link refuse
keys belonging to another link or an older set of links.

Research basis:

- Multi-link key separation attacks — lab-confirmed key-confusion
  attacks against MLO key hierarchy (2025). Mapped to **F173/F174** and
  **Module 56**.
- MLO backoff manipulation detectable with graph neural networks
  (Peradeniya e20-4yp, 2025). Informs the Module 56 sequence/desync
  heuristics.
- 6 GHz operation mandates WPA3/PMF and disallows transition modes
  inside MLO; impersonating an AFC-approved standard-power AP bypasses
  power constraints clients trust (**F175**).
- OFDMA resource-unit granularity in HE/EHT enables per-station
  selective denial via RU puncturing (**F176**).
- IEEE 802.11bf (WLAN Sensing, finalized 2024): Wi-Fi as radar for
  presence/motion detection — a privacy attack surface for passive
  through-wall tracking, with interference injection studied as a
  countermeasure (**F177**, Module 64).
- Wi-Fi HaLow (802.11ah): sub-GHz long-range Wi-Fi for IoT (**F178**).
- Wi-Fi 8 (802.11bn "Ultra High Reliability", expected ~2028):
  multi-AP coordination (Co-BF/Co-SR/Co-TDMA) creates a rogue-AP-in-
  coordination-set attack vector (**F179**, Module 69).

## Satellite Direct-to-Cell & PNT (F180–F184, Modules 61–63, 68)

Starlink Direct-to-Cell (LTE eNodeB on satellites, live with T-Mobile),
AST SpaceMobile, and Skylo NB-NTN put base stations in orbit. First
measurement studies appeared 2025–2026:

- "Direct-to-Cell: A First Look into Starlink's Direct Satellite-to-
  Device RAN through Crowdsourced Measurements" (IEEE, 2025) —
  characterizes the deployed SCS service.
- "Direct-to-Cell Satellite Network without Satellite Navigation"
  (ACM SIGCOMM 2025) — D2C's GNSS dependency propagates navigation
  defects into billing and access.
- Android exposes satellite network identities (T-Sat/Starlink, Skylo,
  Globalstar, AST, Lynk), making a spoofed "satellite" cell the D2D
  successor of the IMSI catcher (**F180**, Module 61, `d2c-monitor`
  tool).
- 3GPP Release 19 NTN: regenerative payloads (gNB on board),
  store-and-forward operation, NB-IoT NTN in the 5G core (**F181/F184**,
  Module 63).
- Galileo OSNMA (navigation message authentication) became operational
  July 2025; Galileo SAS achieved the first civil authenticated position
  fix under spoofing conditions. Cryptographic spoofing detection is now
  possible for open-service users (**F183**, Module 62, `osnma-verify`
  tool).
- LEO PNT (Xona Pulsar-class): narrow-beam commercial positioning
  signals without authentication — a new spoofable signal class
  (**F182**, Module 68).

## UWB / Secure Ranging / Bluetooth 6.0 (F185–F188, Module 57)

- IEEE 802.15.4z added cryptography (STS) to UWB ranging, underpinning
  CCC Digital Key 3.0 car keys and item finders. "Time for Change: How
  Clocks Break UWB Secure Ranging" demonstrates Mix-Down distance-
  reduction attacks on commercial 4z chips and studies the upcoming
  802.15.4ab (**F185/F186**).
- Bluetooth 6.0 (2024) Channel Sounding combines phase-based ranging
  with round-trip time as a relay countermeasure; BT 6.1+ continue
  hardening. The ranging channel itself is the new target (**F187**).
- Auracast LE Audio broadcast: security researchers published
  specification/documentation issues in 2025; broadcast key handling is
  the mass-eavesdropping surface (**F188**).

## Matter / Ambient IoT / DECT-2020 / FRMCS / LDACS (F189–F194, Modules 58–60, 65)

- "What's the Matter? An In-Depth Security Analysis of the Matter
  Protocol" (IACR ePrint 2025/1268): low-entropy setup passcodes,
  static per-device salts, weakened PBKDF2 vs the SPAKE2+/SIGMA design
  goals (**F189**).
- CVE-2024-56317: non-atomic Matter ACL updates grant persistent
  access from temporary privileges; "From Temporary Access to
  Persistent Surveillance" (2025) chains commissioning flaws into
  surveillance (**F190**).
- 3GPP Release 19 Ambient IoT (TS 33.369, published October 2025):
  batteryless ~1 µW devices with envelope-detector receivers. Device
  cloning and backscatter identity spoofing are the obvious first
  attack surface for a technology whose security spec just landed
  (**F191**).
- DECT-2020 NR: ETSI ITU-R-recognized IMT-2020 technology (1.9 GHz
  massive mesh); ETSI is currently building its modern security
  framework — early-researcher territory (**F192**).
- FRMCS: the 5G-based GSM-R railway successor in ETSI/shift2rail
  standardization (**F193**). LDACS: the L-band digital aeronautical
  communications system planned as the VHF datalink successor (**F194**).
  Both carry safety-critical signaling (Module 65).

## 6G Horizon (F195–F200, Modules 66, 67, 70)

3GPP Release 20 (6G study ~66% complete at time of writing, 100+ use
cases in TR 22.870) with ~2028–2030 commercialization:

- AI-native air interface: adversarial ML against learned receivers,
  model poisoning of AI-RAN, and agentic-AI security surveys (IEEE
  2025) define the new RAN attack surface (**F195**, Module 66).
- Reconfigurable Intelligent Surfaces (RIS): dynamically steer
  propagation; hijacking reflection control is a physical-layer MitM
  with no standard defense yet (**F196**).
- THz communications: narrow beams make codebook/beam-training
  exhaustion a denial vector (**F197**).
- Post-quantum migration: 6G is being designed NIST-PQC-first;
  downgrading quantum-safe handshakes against long-lived telecom keys
  is the harvest-now-decrypt-later enabler (**F198**, Module 67).
- Network-of-networks: 6G integrates satellite/WLAN/private networks
  under one trust fabric — cross-network credential abuse expands the
  identity attack surface (**F199**, Module 70).
- Integrated Sensing and Communication (ISAC): the network senses its
  environment; cellular radar as a tracking side channel is a
  first-class privacy concern in TR 22.870 use cases (**F200**).

## Tools

| Tool | Purpose | Basis |
|------|---------|-------|
| `osnma-verify` | Cryptographic GNSS spoofing detection | Galileo OSNMA SIS ICD; operational since 2025; HMAC-SHA256 per RFC 2104 validated against RFC 4231 vectors |
| `d2c-monitor` | Spoofed satellite-cell detection | SIGCOMM 2025 D2C measurements; TS 38.213 timing advance limits; LEO doppler physics |
| `mlo-analyzer` | Wi-Fi 7 MLO attack detection | 802.11be key hierarchy and per-link separation requirements |
| E2AP dissector | O-RAN RIC E2 parsing | O-RAN.WG3.E2AP |
| F1AP dissector | CU/DU split parsing | 3GPP TS 38.423 |

## References

Selected sources behind this catalog:

1. 3GPP TR 22.870 — 6G use cases and service requirements (Release 20 study).
2. 3GPP TS 33.369 — Security aspects of Ambient IoT services (Rel-19, Oct 2025).
3. "Direct-to-Cell: A First Look into Starlink's Direct Satellite-to-Device Radio Access Network through Crowdsourced Measurements", IEEE (2025).
4. "Direct-to-Cell Satellite Network without Satellite Navigation", ACM SIGCOMM (2025).
5. EUSPA — "Galileo achieves first-ever civil authenticated GNSS position using Signal Authentication Service (SAS)" (2025); OSNMA operational July 2025.
6. "Time for Change: How Clocks Break UWB Secure Ranging" — attacks on IEEE 802.15.4z and 4ab secure ranging.
7. "What's the Matter? An In-Depth Security Analysis of the Matter Protocol", IACR ePrint 2025/1268.
8. CVE-2024-56317 — Matter ACL non-atomic update.
9. "An Overview on IEEE 802.11bf: WLAN Sensing" (2022) and NIST WLAN sensing publications.
10. Bluetooth SIG — Core Specification 6.0 feature overview (Channel Sounding).
11. ETSI TC DECT — DECT-2020 NR security framework work items.
12. "Securing Wi-Fi 7 Multi-Link Operation (MLO): A Distributed Ledger and Cryptographic Framework for Control Plane Integrity" (2025).
13. "A Tutorial on IEEE 802.11bn Multi-AP Coordination for Wi-Fi 8" (2025).
14. IEEE surveys on federated learning and agentic-AI security for 6G (2025–2026).
