# Telecom Lab Setup Guide

Hardware selection, procurement, and configuration guide for the StaticZero telecom testing laboratory.

---

## Overview

A complete telecom security lab requires:
1. **Software-Defined Radios** — RF capture, injection, and relay
2. **SIM Tools** — Programming, tracing, and cloning
3. **Modem Hardware** — UE emulation and baseband research
4. **Core Network** — Open-source EPC/5GC for end-to-end testing
5. **RF Isolation** — Faraday cage or attenuators to prevent interference

---

## 1. Software-Defined Radio (SDR) Hardware

### Recommended SDR Selection

| SDR | Freq Range | Bandwidth | TX | Price | Use Case |
|-----|-----------|-----------|-----|-------|----------|
| **RTL-SDR v3** | 24–1766 MHz | 2.4 MHz | No | ~$30 | Passive GSM/LTE sniffing, cell survey |
| **HackRF One** | 1–6000 MHz | 20 MHz | Yes | ~$350 | 2G/3G testing, IMSI catcher research |
| **bladeRF 2.0 micro** | 47–6000 MHz | 56 MHz | Yes | ~$500 | LTE eNB, full-duplex operation |
| **LimeSDR Mini 2.0** | 10–3500 MHz | 30.72 MHz | Yes | ~$300 | srsRAN base station, NB-IoT |
| **USRP B210** | 70–6000 MHz | 56 MHz | Yes | ~$2000 | 5G NR research, MIMO, production labs |
| **USRP X310** | DC–6000 MHz | 160 MHz | Yes | ~$8000 | Carrier-grade testing, wide-band NR |
| **Yard Stick One** | 300–928 MHz | 20 MHz | Yes | ~$120 | Sub-GHz: RKE, POCSAG, LoRa, AIS |
| **ADALM-PLUTO** | 325–3800 MHz | 20 MHz | Yes | ~$200 | IoT protocols, LoRa, AIS research |

### Minimum Viable Lab

For getting started with StaticZero telecom features:

**Budget ($400):**
- 1x RTL-SDR v3 (passive monitoring, cell survey)
- 1x HackRF One (active 2G/3G testing)
- SMA cables, antennas (700/900/1800/2100 MHz bands)

**Recommended ($1500):**
- 1x RTL-SDR v3 (monitoring)
- 1x bladeRF 2.0 micro (LTE eNB via srsRAN)
- 1x HackRF One (injection/relay)
- RF attenuators (30dB SMA inline)
- Band-specific antennas

**Full Lab ($5000+):**
- 1x USRP B210 (5G NR via srsRAN Project)
- 1x bladeRF 2.0 micro (LTE)
- 1x HackRF One (2G/3G)
- 1x RTL-SDR v3 (monitoring)
- RF shielded enclosure
- Programmable attenuators
- GPS-disciplined oscillator (GPSDO) for timing

**Extended RF Lab ($8000+):**
- Everything in Full Lab
- 1x Ubertooth One (BLE research)
- 1x Yard Stick One (sub-GHz: RKE, paging, Z-Wave)
- 1x nRF52840 Dongle (BLE/Thread/Zigbee multi-protocol)
- 1x ALFA AWUS036ACH (WiFi monitor mode + injection)
- 1x RAK2287 LoRaWAN gateway module
- 1x Network TAP for O-RAN fronthaul
- 1x dAISy HAT (AIS receive)
- Marine VHF + sub-GHz antennas
- Pixhawk 4 Mini + SiK radios (MAVLink testing)

### SDR-to-Feature Mapping

| Feature | Minimum SDR | Notes |
|---------|------------|-------|
| Cell scanning (F92) | RTL-SDR | Passive only |
| IMSI catching (F92) | HackRF | Requires TX |
| Protocol downgrade (F93) | HackRF | Fake BTS |
| LTE eNB (F97, F101) | bladeRF / LimeSDR | srsRAN compatible |
| 5G gNB (F100, F103) | USRP B210 | Wide bandwidth needed |
| RF fingerprinting (M28) | RTL-SDR | Passive, needs calibration |
| VoLTE testing (F101) | bladeRF | Full IMS stack |
| Femtocell research (F106) | Any TX-capable | Or use real femtocell hardware |
| TETRA/P25 (F135-F138) | HackRF / Yard Stick One | 380-400 MHz (TETRA), 700-900 MHz (P25) |
| BLE (F139-F142) | Ubertooth One | 2.4 GHz Bluetooth-specific |
| Zigbee (F143-F145) | HackRF / ApiMote | 2.4 GHz (802.15.4) |
| Z-Wave (F144) | Yard Stick One | 868 MHz (EU) / 908 MHz (US) |
| LoRa (F146-F148) | HackRF / ADALM-PLUTO | 868/915 MHz ISM bands |
| WiFi (F151-F155) | Any WiFi adapter + monitor mode | ALFA AWUS036ACH recommended |
| RKE (F156-F157) | Yard Stick One / HackRF | 315/433 MHz OOK/FSK |
| UAV C2 (F158-F160) | HackRF / USRP B210 | 2.4/5.8 GHz (OcuSync, WiFi) |
| POCSAG/FLEX (F161-F162) | RTL-SDR | 150-170 MHz (RX only, passive) |
| RDS/DAB+ (F163-F164) | HackRF | 87.5-108 MHz (FM), 174-240 MHz (DAB) |
| EAS (F165-F166) | HackRF | 162.4-162.55 MHz (NOAA/EAS) |
| O-RAN Fronthaul (F167-F170) | Network tap (not SDR) | Ethernet-based eCPRI |
| AIS (F171-F172) | RTL-SDR / ADALM-PLUTO | 161.975/162.025 MHz |

### Antenna Selection

| Band | Frequency | Antenna Type | Use |
|------|-----------|-------------|-----|
| GSM-900 | 880–960 MHz | Whip omnidirectional | 2G testing |
| GSM-1800/DCS | 1710–1880 MHz | PCB patch or whip | 2G/3G |
| UMTS B1 | 2110–2170 MHz | Directional panel | 3G |
| LTE B7 | 2620–2690 MHz | Wideband discone | 4G |
| LTE B3 | 1805–1880 MHz | Dual-band whip | 4G |
| NR n78 | 3300–3800 MHz | Horn or patch array | 5G sub-6 |
| NR n77 | 3300–4200 MHz | Wide-band horn | 5G sub-6 |
| TETRA | 380–400 MHz | Wideband whip | Public safety LMR |
| P25 | 700–900 MHz | Dual-band whip | P25 Phase I/II |
| LoRa/ISM | 868/915 MHz | ¼-wave ground plane | IoT testing |
| AIS VHF | 162 MHz | Marine VHF whip | AIS research |
| WiFi 2.4G | 2400–2483 MHz | Omnidirectional | BLE/Zigbee/WiFi |
| WiFi 5G | 5150–5850 MHz | Patch or panel | WiFi/UAV |
| Sub-GHz | 300–433 MHz | Telescopic whip | RKE, POCSAG |

---

## 2. SIM Tools

### SIM Programmers

| Device | Interface | Protocol | Price | Capabilities |
|--------|----------|----------|-------|-------------|
| **sysmocom SJA2** | USB | PC/SC | ~$15/card | Programmable ISIM/USIM, MILENAGE |
| **SIMtrace2** | USB | APDU trace | ~$100 | Real-time SIM ↔ modem APDU sniffing |
| **Omnikey 3121** | USB | PC/SC | ~$30 | Standard smart card reader |
| **ACR122U** | USB | NFC+contact | ~$40 | Dual-interface (NFC + contact) |
| **ReinerSCT** | USB | PC/SC | ~$50 | Extended APDU support |

### Programmable SIM Cards

| Card | Type | Algorithm | Use |
|------|------|-----------|-----|
| **sysmoISIM-SJA2** | ISIM+USIM | MILENAGE (XOR/AES) | LTE/5G lab testing |
| **sysmoUSIM-SJS1** | USIM only | MILENAGE | 3G/4G testing |
| **GreenCard** | SIM | COMP128v1/v2/v3 | 2G research |
| **Magic SIM** | Multi-profile | Configurable | Multi-IMSI testing |

### SIM Programming Workflow

```bash
# Install pySim (included in lab_setup.sh)
pip3 install pysim

# Read existing SIM
pySim-read.py -p 0

# Program test USIM for lab
pySim-prog.py -p 0 -t sysmoISIM-SJA2 \
  --mcc 001 --mnc 01 \
  --imsi 001010000000001 \
  --iccid 8901010000000000001 \
  --ki 00112233445566778899AABBCCDDEEFF \
  --opc 00000000000000000000000000000000 \
  --acc 0001

# Real-time APDU trace (SIMtrace2)
simtrace2-sniff -i 0
```

### Key SIM Parameters

| Parameter | Length | Purpose |
|-----------|--------|---------|
| IMSI | 15 digits | Subscriber identity |
| Ki | 128 bits | Authentication key (never leaves SIM) |
| OPc | 128 bits | Derived operator key (MILENAGE) |
| ICCID | 19–20 digits | Card serial number |
| ADM | 8 bytes | Administrative PIN for programming |
| ACC | 2 bytes | Access control class |

---

## 3. Modem Hardware

### Research-Grade Modems

| Modem | Chipset | Generations | Interface | Research Use |
|-------|---------|-------------|-----------|-------------|
| **Quectel RM500Q** | Qualcomm X55 | 4G/5G SA+NSA | USB 3.0 / PCIe | 5G NAS/RRC research |
| **Sierra MC7455** | Qualcomm MDM9230 | 4G Cat 6 | M.2 | LTE baseband, QMI |
| **Huawei ME909s** | Balong 711 | 4G Cat 4 | M.2/mPCIe | Firmware RE |
| **Samsung Shannon** | Exynos Modem | 4G/5G | Embedded (phone) | Baseband exploit research |
| **Qualcomm SDX55** | SDX55 | 5G | M.2 | Diag/QXDM, NV items |
| **Simcom SIM7600** | Qualcomm | 4G Cat 4 | USB/UART | AT command research, cheap |
| **u-blox SARA-R5** | Proprietary | LTE-M/NB-IoT | UART | IoT cellular testing |

### Diagnostic Interfaces

| Chipset | Diag Tool | Port | Capabilities |
|---------|----------|------|-------------|
| Qualcomm | QXDM / libqcdm | /dev/ttyUSB0 (DM) | NAS/RRC/MAC logs, NV read/write |
| MediaTek | MTK Engineering Mode | Serial | Cell info, AT extensions |
| Samsung Shannon | Samsung IPC | USB | Proprietary debug frames |
| Intel XGold | xgold-diag | USB | Baseband trace |
| Huawei Balong | Balong AT | /dev/ttyUSB2 | Extended AT+^commands |

### Qualcomm Diagnostic (DIAG/QXDM)

```bash
# Enable DIAG mode on Qualcomm modem
echo "AT$QCRMCALL=1,1" > /dev/ttyUSB2

# NV item read (requires DIAG port)
# NV 10 = preferred mode (GSM/WCDMA/LTE)
# NV 65 = RF calibration
# NV 453 = LTE band preference
# NV 6828 = 5G NR band preference

# Capture RRC/NAS with scat (open-source DIAG parser)
sudo scat -t qc -s /dev/ttyUSB0 -d -F pcap -P nr_rrc,lte_rrc,lte_nas,nr_nas
```

### USB Adapters for M.2 Modems

| Adapter | Slots | Power | Notes |
|---------|-------|-------|-------|
| M.2 to USB 3.0 enclosure | B-key | 5V/2A | Most common for lab use |
| mPCIe to USB adapter | mPCIe | 3.3V/1A | Older modems |
| M.2 to PCIe riser | M-key | PCIe power | High-speed 5G modems |

---

## 4. Core Network Software

### Open-Source Stacks (installed by lab_setup.sh)

| Component | Software | Generation | Role |
|-----------|----------|------------|------|
| 2G BTS | OsmoBTS + OsmoTRX | GSM | Base station |
| 2G/3G Core | OsmoMSC + OsmoHLR | GSM/UMTS | Core network |
| 4G eNB | srsRAN 4G (srsENB) | LTE | Base station |
| 4G EPC | Open5GS | LTE | MME/SGW/PGW/HSS |
| 5G gNB | srsRAN Project | NR SA | Base station |
| 5G Core | Open5GS | 5G SA | AMF/SMF/UPF/UDM |
| IMS | Kamailio + Asterisk | VoLTE | P-CSCF/S-CSCF |

### Network Architecture (Lab)

```
┌──────────────────────────────────────────────────────────┐
│                    Lab Host Machine                        │
├──────────────┬──────────────┬──────────────┬─────────────┤
│   Open5GS    │   srsRAN     │  Osmocom     │  Aegis      │
│   (Core)     │   (eNB/gNB)  │  (2G/3G)     │  (Monitor)  │
│              │              │              │             │
│  AMF/MME     │  ┌────────┐  │  OsmoBTS     │  sdr-bridge │
│  SMF/SGW     │  │ SDR HW │  │  OsmoTRX     │  defense    │
│  UPF/PGW     │  └────────┘  │  OsmoMSC     │  correlator │
│  UDM/HSS     │              │  OsmoHLR     │             │
└──────────────┴──────────────┴──────────────┴─────────────┘
                      │                │
                 ┌────┴────┐     ┌─────┴────┐
                 │ Test UE │     │ SIM Trace │
                 │ (Modem) │     │ (SIMtrace)│
                 └─────────┘     └──────────┘
```

### Quick Start

```bash
# Run the automated lab setup
sudo ./tools/lab_setup.sh

# Start core network
sudo systemctl start open5gs-amfd open5gs-smfd open5gs-upfd

# Start srsRAN eNB (LTE)
sudo srsenb /etc/srsran/enb.conf

# Start Aegis SDR bridge
sudo systemctl start aegis-sdr-bridge

# Start protocol correlator
./target/release/protocol-correlator --ingest-port 7892
```

---

## 4a. Extended RF Protocol Hardware

### TETRA/P25 Equipment

| Device | Type | Use Case | Price |
|--------|------|----------|-------|
| **Motorola APX** | P25 portable | Test radio for P25 Phase II | ~$500 (used) |
| **Hytera PD785** | DMR/TETRA portable | TETRA air interface testing | ~$400 |
| **osmo-tetra** | Software decoder | TETRA downlink decode | Free (OSS) |
| **OP25** | Software decoder | P25 Phase I/II decode | Free (OSS) |

### BLE/Zigbee/Thread Hardware

| Device | Protocol | Interface | Price | Use |
|--------|----------|-----------|-------|-----|
| **Ubertooth One** | BLE/Bluetooth | USB | ~$130 | BLE sniffing, injection |
| **nRF52840 Dongle** | BLE/Thread/Zigbee | USB | ~$10 | Multi-protocol sniffer |
| **CC2531 USB Dongle** | Zigbee | USB | ~$5 | Zigbee packet capture |
| **Z-Wave.Me UZB** | Z-Wave | USB | ~$30 | Z-Wave sniffing |
| **ApiMote** | 802.15.4 | USB | ~$150 | Zigbee injection |

### LoRa/LoRaWAN Hardware

| Device | Type | Interface | Price | Use |
|--------|------|-----------|-------|-----|
| **RN2483/RN2903** | LoRa modem | UART | ~$15 | LoRa endpoint emulation |
| **RAK2287** | LoRaWAN gateway | SPI/USB | ~$100 | Lab gateway for testing |
| **SX1276 breakout** | LoRa transceiver | SPI | ~$10 | Custom PHY research |

### WiFi Testing Hardware

| Device | Chipset | Monitor Mode | Injection | Use |
|--------|---------|-------------|-----------|-----|
| **ALFA AWUS036ACH** | RTL8812AU | Yes | Yes | Dual-band deauth/injection |
| **ALFA AWUS1900** | RTL8814AU | Yes | Yes | 4x4 MIMO testing |
| **Panda PAU09** | RT5572 | Yes | Yes | Budget dual-band |
| **Intel AX210** | AX210 | Yes | Limited | WPA3/WiFi 6E research |

### RKE/Sub-GHz Hardware

| Device | Freq Range | TX | Price | Use |
|--------|-----------|-----|-------|-----|
| **Yard Stick One** | 300–928 MHz | Yes | ~$120 | RKE, sub-GHz protocols |
| **Flipper Zero** | 300–928 MHz | Yes | ~$170 | Sub-GHz TX/RX, NFC, IR |
| **CC1101 module** | 315–915 MHz | Yes | ~$5 | Custom RKE research |

### UAV/Drone Testing

| Device | Type | Use | Price |
|--------|------|-----|-------|
| **Pixhawk 4 Mini** | Flight controller | MAVLink testing | ~$200 |
| **SiK Telemetry Radio** | 433/915 MHz | MAVLink radio link | ~$40/pair |
| **DJI Tello** | Consumer drone | DJI protocol research | ~$100 |

### O-RAN Fronthaul Equipment

| Device | Type | Use | Price |
|--------|------|-----|-------|
| **Network TAP (Dualcomm)** | Passive Ethernet tap | eCPRI capture | ~$100 |
| **Mellanox ConnectX-5** | 25GbE NIC | High-speed fronthaul | ~$200 |
| **DPDK + testpmd** | Software | eCPRI packet generation | Free |
| **O-RAN SC (Software Community)** | O-DU/O-CU reference | Lab RAN stack | Free (OSS) |

### AIS Maritime Hardware

| Device | Type | Freq | Price | Use |
|--------|------|------|-------|-----|
| **dAISy HAT** | AIS receiver | 162 MHz | ~$65 | Raspberry Pi AIS rx |
| **Quark-elec QK-A027** | AIS transceiver | 162 MHz | ~$200 | AIS TX testing |
| **RTL-SDR + rtl_ais** | Software receiver | 162 MHz | ~$30 | Low-cost AIS monitoring |

---

## 5. RF Isolation

### Why Isolation Matters

Transmitting on cellular frequencies without a license is illegal in most jurisdictions. Lab setups MUST be RF-isolated to prevent interference with commercial networks.

### Isolation Options

| Method | Attenuation | Cost | Suitability |
|--------|------------|------|-------------|
| **RF shielded box** | 60–80 dB | $200–500 | Single device testing |
| **Faraday cage (room)** | 80–100 dB | $5000+ | Full lab |
| **Cable + attenuators** | Configurable | $100–300 | No-antenna testing |
| **RF absorber tiles** | 20–40 dB (add-on) | $50/tile | Supplement shielding |

### Cabled RF Setup (Recommended for Lab)

```
SDR TX ──[SMA Cable]──[30dB Attenuator]──[Splitter]──[30dB Attenuator]──[SMA Cable]── Modem RX
```

Components needed:
- SMA male-male cables (various lengths)
- Fixed attenuators: 10dB, 20dB, 30dB (make sure power handling > SDR output)
- 2-way or 4-way splitter (if testing multiple UEs)
- DC block (if SDR has DC on RF port)
- Terminator (50 ohm) for unused splitter ports

### Compliance Checklist

- [ ] All RF testing conducted inside shielded enclosure OR via cabled connection
- [ ] No antennas connected during TX operation (unless inside Faraday cage)
- [ ] TX power reduced to minimum required (≤ -30 dBm radiated)
- [ ] Lab documented per local regulations (FCC Part 15 in US, ETSI in EU)
- [ ] "RF Testing in Progress" signage displayed

---

## 6. StaticZero Integration

### SDR Bridge Configuration

Create `/etc/staticzero/sdr-bridge.toml`:
```toml
[sdr]
type = "bladerf"          # hackrf, bladerf, usrp, rtlsdr, limesdr
device_id = "0"
sample_rate = 15360000    # 15.36 MHz (LTE 10 MHz BW)
gain = 40
bandwidth = 10000000

[control]
listen_addr = "127.0.0.1:7890"
defense_addr = "127.0.0.1:7891"

[scan]
bands = "3,7,20"          # LTE bands to scan
dwell_time_ms = 500       # Time per EARFCN during scan

[fingerprint]
enabled = true
samples_per_cell = 1000
reference_db = "/var/lib/staticzero/rf_baselines.json"
```

### Defense Module Configuration

Create `/etc/staticzero/telecom-defense.toml`:
```toml
[detection]
rogue_tower = true
downgrade_attack = true
imsi_catcher = true
cell_anomaly = true
gtp_anomaly = true
ss7_anomaly = true
modem_tamper = true
nas_replay = true

[advanced]
volte_fraud = true
esim_monitor = true
slice_verify = true
roaming_anomaly = true
rf_fingerprint = true

[baseline]
cell_database = "/var/lib/staticzero/cell_baselines.json"
update_interval_hours = 24
min_observations = 10

[correlation]
engine_port = 7892
window_ms = 5000
threshold = 0.7

[alerting]
syslog = true
json_output = "/var/log/staticzero/telecom-alerts.json"
severity_threshold = "medium"    # low, medium, high, critical

[lmr]
tetra_encryption = true
p25_control = true

[iot]
ble_pairing = true
zigbee_key = true
lorawan_join = true
nbiot_rrc = true

[wifi]
deauth_detect = true
wpa3_integrity = true

[rf_control]
rke_jamming = true
uav_c2 = true

[broadcast]
pager_anomaly = true
broadcast_injection = true
eas_spoofing = true

[oran]
fronthaul_integrity = true
ric_security = true

[maritime]
ais_integrity = true
```

### Feature Activation

```bash
# Offense — full telecom module
sudo staticzero-offense \
  --enable-telecom \
  --enable-telecom-advanced \
  --target-imsi "001010000000001" \
  --modem-device /dev/ttyUSB0 \
  --gtp-iface enp0s3 \
  --ims-iface ims0

# Defense — full telecom detection
sudo staticzero-defense \
  --telecom-detect \
  --telecom-advanced \
  --cell-baseline /var/lib/staticzero/cell_baselines.json \
  --modem-monitor \
  --sdr-bridge 127.0.0.1:7891

# Standalone tools
./target/release/sdr-bridge --sdr-type bladerf --mode scan --scan-bands 3,7
./target/release/modem-firmware analyze --chipset qualcomm --firmware modem.mbn
./target/release/protocol-correlator --threshold 0.8

# Extended RF domains — Offense
sudo staticzero-offense \
  --enable-tetra-p25 \
  --lmr-iface sdr0

sudo staticzero-offense \
  --enable-iot-radio \
  --hci-iface hci0 \
  --wpan-iface wpan0

sudo staticzero-offense \
  --enable-wifi \
  --wlan-iface wlan0

sudo staticzero-offense \
  --enable-oran \
  --fronthaul-iface eth1

sudo staticzero-offense \
  --enable-ais

# Extended RF domains — Defense
sudo staticzero-defense \
  --lmr_defense \
  --iot_defense \
  --wifi_defense \
  --rf_control_defense \
  --broadcast_defense \
  --oran_defense \
  --ais_defense
```

---

## 7. Test Scenarios

### Scenario 1: IMSI Catcher Detection Test

1. Start Open5GS + srsRAN (legitimate network)
2. Connect test UE to legitimate cell
3. Start second SDR as fake BTS (same PLMN, stronger signal)
4. Verify Aegis defense detects: ALERT_ROGUE_TOWER, ALERT_IMSI_CATCHER
5. Verify RF fingerprint mismatch (Module 28)

### Scenario 2: Protocol Downgrade Attack

1. Start LTE eNB with test UE attached
2. Trigger staticzero-offense with `--enable-telecom` (Feature 93)
3. Verify UE reselects to 2G cell
4. Verify defense detects: ALERT_DOWNGRADE_ATTACK
5. Check correlation engine output for multi-layer pattern

### Scenario 3: VoLTE Interception

1. Start Open5GS + IMS (Kamailio) + srsRAN
2. Register two test UEs for VoLTE
3. Initiate call between UEs
4. Activate Feature 101 (VoLTE intercept)
5. Verify SIP INVITE capture, media redirect detection
6. Verify defense Module 24 alerts on SDP manipulation

### Scenario 4: 5G Slice Isolation

1. Configure Open5GS with multiple slices (eMBB, URLLC, mMTC)
2. Attach UE to specific slice
3. Activate Feature 103 (slice escape)
4. Verify cross-slice traffic attempt
5. Verify defense Module 26 detects S-NSSAI mismatch

### Scenario 5: SS7/Diameter Signaling

1. Set up Osmocom core (OsmoSTP + OsmoMSC)
2. Configure SIGTRAN link to lab STP
3. Activate Feature 95 (SS7 MAP injection)
4. Send SendRoutingInfo from unauthorized point code
5. Verify defense Module 24 (SS7 anomaly) triggers

### Scenario 6: TETRA Encryption Downgrade Detection

1. Set up osmo-tetra decoder with HackRF on TETRA frequency (380-400 MHz)
2. Configure test TETRA base station (or use SDR-based TETRA transmitter)
3. Activate Feature F136 (TETRA Encryption Downgrade)
4. Inject SYSINFO with encryption=0
5. Verify Module 40 (TETRA Encryption Monitor) fires ALERT_TETRA_ENCRYPTION
6. Verify correlation with Module 41 if P25 rogue signals detected simultaneously

### Scenario 7: BLE Pairing Downgrade Attack

1. Set up Ubertooth One for BLE sniffing
2. Configure target BLE device (nRF52840 devkit as peripheral)
3. Activate Feature F140 (BLE Pairing Downgrade)
4. Force LE Legacy pairing negotiation
5. Verify Module 42 detects downgrade: ALERT_BLE_PAIRING
6. Attempt F141 (BlueBorne probe) and verify L2CAP anomaly detection

### Scenario 8: WiFi Evil Twin + WPA3 Chain

1. Start legitimate AP with WPA3-SAE on test SSID
2. Connect test client to legitimate AP
3. Activate Feature F151 (Deauth Flood) to disconnect client
4. Activate Feature F153 (Evil Twin) with stronger signal
5. Verify Module 46 detects deauth flood: ALERT_WIFI_DEAUTH
6. Verify Module 47 detects SAE anomaly: ALERT_WPA3_INTEGRITY
7. Confirm correlation engine produces `WifiRogueAp` compound threat

### Scenario 9: O-RAN Fronthaul Interception

1. Set up O-RAN SC reference implementation (O-DU + O-RU simulator)
2. Install passive network TAP on fronthaul Ethernet link
3. Activate Feature F167 (eCPRI IQ Sample Intercept) on TAP interface
4. Capture eCPRI frames, verify IQ sample extraction
5. Activate Feature F168 (Fronthaul MitM) to modify IQ data
6. Verify Module 53 detects sequence number gaps: ALERT_ORAN_FRONTHAUL
7. Activate Feature F169 (xApp Exploitation) against Near-RT RIC
8. Verify Module 54: ALERT_ORAN_RIC
9. Confirm correlation: `FronthaulCompromise` pattern (severity 5)

### Scenario 10: AIS Position Spoofing

1. Set up dAISy HAT or RTL-SDR with rtl_ais as AIS receiver
2. Configure AIS TX capability (QK-A027 or SDR at 162 MHz) in shielded box
3. Activate Feature F171 (AIS Position Spoofing)
4. Inject ghost vessel with false MMSI + position
5. Verify Module 55 detects physics violation: ALERT_AIS_INTEGRITY
6. Combine with Feature F133 (GPS spoofing) for multi-vector test
7. Confirm correlation: `AisSpoofing` pattern

### Scenario 11: LoRaWAN Join Replay

1. Set up RAK2287 as LoRaWAN gateway connected to ChirpStack
2. Configure test LoRa device (RN2483) for OTAA join
3. Capture JoinRequest with HackRF/SDR at 868/915 MHz
4. Activate Feature F146 (LoRaWAN Join Replay)
5. Replay JoinRequest with same DevNonce
6. Verify Module 44 detects nonce reuse: ALERT_LORAWAN_JOIN
7. Test ABP session hijack (F147) with DevAddr spoofing

---

## 8. Procurement Sources

| Category | Supplier | Notes |
|----------|---------|-------|
| SDR (HackRF, bladeRF) | Great Scott Gadgets, Nuand | Direct from manufacturer |
| SDR (USRP) | Ettus Research / NI | Academic pricing available |
| SDR (LimeSDR) | Lime Microsystems / CrowdSupply | Open hardware |
| SDR (RTL-SDR) | rtl-sdr.com / Amazon | V3 recommended |
| SIM cards | sysmocom.de | Programmable ISIM/USIM |
| SIM trace | sysmocom.de | SIMtrace2 hardware |
| Card readers | Amazon / electronics distributors | Omnikey, ACR series |
| Modems (Quectel) | Quectel direct / Mouser / DigiKey | RM500Q for 5G |
| Modems (Sierra) | Sierra Wireless / eBay | MC7455 widely available |
| RF shielding | Ramsey Electronics / Holland Shielding | Boxes and rooms |
| Attenuators / cables | Mini-Circuits / Pasternack / Amazon | SMA connectors |
| Antennas | L-com / Taoglas / Amazon | Band-specific |

---

## 9. Legal Considerations

- **Do NOT** transmit on licensed cellular frequencies outside an RF-shielded environment
- **Do NOT** target real subscribers or commercial infrastructure
- Ensure you have explicit authorization before any testing
- Use test PLMNs (MCC 001, MNC 01) as configured by lab_setup.sh
- Document all testing in a lab notebook for compliance audits
- Familiarize yourself with local regulations:
  - **US**: FCC Part 15 (unintentional radiators), Part 90/22/24 (licensed bands)
  - **EU**: ETSI EN 301 489-1, Radio Equipment Directive 2014/53/EU
  - **UK**: Wireless Telegraphy Act 2006, Ofcom guidelines

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| No cells found in scan | Wrong frequency/band | Check EARFCN mapping, verify antenna |
| SDR "device not found" | Permissions | Run `sudo` or add udev rules (lab_setup.sh does this) |
| UE won't attach to lab eNB | SIM mismatch | Verify Ki/OPc match between SIM and HSS |
| GTP tunnel not established | IP routing | Check `ip route`, verify SGW/PGW reachability |
| srsRAN "Late" warnings | CPU too slow | Increase real-time priority, use isolated cores |
| SCTP connection refused | Firewall | Allow SCTP (protocol 132) in iptables |
| Modem not entering DIAG mode | Wrong USB composition | Set AT+QCFG="usbcfg" or similar per chipset |
| RF fingerprint unstable | Temperature drift | Allow 15min warm-up, use GPSDO reference |
