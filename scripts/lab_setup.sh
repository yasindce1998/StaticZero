#!/usr/bin/env bash
# StaticZero Telecom Lab Setup Automation
# Provisions a test environment for cellular security research
# Supports: SDR setup, srsRAN, Open5GS core, SIM programming, modem configuration
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="${LAB_DIR:-/opt/aegis-lab}"
LOG_FILE="${LAB_DIR}/setup.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOG_FILE"; }
err() { echo -e "${RED}[-]${NC} $*" | tee -a "$LOG_FILE"; exit 1; }
info() { echo -e "${CYAN}[*]${NC} $*" | tee -a "$LOG_FILE"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root (required for USB/SDR permissions)"
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
    else
        err "Unsupported OS (no /etc/os-release)"
    fi
    log "Detected OS: $OS_ID $OS_VERSION"
}

# ─────────────────────────────────────────────
# Phase 1: Base Dependencies
# ─────────────────────────────────────────────
install_base_deps() {
    log "Installing base dependencies..."

    case "$OS_ID" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq \
                build-essential cmake git curl wget \
                libusb-1.0-0-dev libfftw3-dev libmbedtls-dev \
                libboost-all-dev libconfig++-dev libsctp-dev \
                libtool autoconf automake pkg-config \
                python3 python3-pip python3-numpy python3-scipy \
                libzmq3-dev libuhd-dev uhd-host \
                pcscd pcsc-tools libpcsclite-dev \
                wireshark-common tshark \
                screen tmux jq \
                linux-headers-"$(uname -r)" \
                dkms usbutils
            ;;
        fedora|rhel|centos)
            dnf install -y \
                gcc gcc-c++ cmake git curl wget \
                libusb1-devel fftw-devel mbedtls-devel \
                boost-devel libconfig-devel lksctp-tools-devel \
                libtool autoconf automake pkgconfig \
                python3 python3-pip python3-numpy python3-scipy \
                zeromq-devel uhd-devel uhd \
                pcsc-lite pcsc-tools pcsc-lite-devel \
                wireshark-cli \
                screen tmux jq \
                kernel-devel kernel-headers \
                dkms usbutils
            ;;
        arch)
            pacman -Syu --noconfirm \
                base-devel cmake git curl wget \
                libusb fftw mbedtls \
                boost libconfig lksctp-tools \
                python python-pip python-numpy python-scipy \
                zeromq libuhd \
                ccid pcsc-tools \
                wireshark-cli \
                screen tmux jq \
                linux-headers dkms usbutils
            ;;
        *)
            err "Unsupported distribution: $OS_ID"
            ;;
    esac

    log "Base dependencies installed"
}

# ─────────────────────────────────────────────
# Phase 2: SDR Drivers
# ─────────────────────────────────────────────
install_sdr_drivers() {
    log "Installing SDR drivers..."

    mkdir -p "$LAB_DIR/src"
    cd "$LAB_DIR/src"

    # HackRF
    if ! command -v hackrf_info &>/dev/null; then
        log "  Building libhackrf..."
        git clone --depth 1 https://github.com/greatscottgadgets/hackrf.git
        cd hackrf/host
        mkdir -p build && cd build
        cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
        make -j"$(nproc)"
        make install
        ldconfig
        cd "$LAB_DIR/src"
        log "  HackRF driver installed"
    else
        info "  HackRF already installed"
    fi

    # BladeRF
    if ! command -v bladeRF-cli &>/dev/null; then
        log "  Building libbladeRF..."
        git clone --depth 1 https://github.com/Nuand/bladeRF.git
        cd bladeRF/host
        mkdir -p build && cd build
        cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
        make -j"$(nproc)"
        make install
        ldconfig
        cd "$LAB_DIR/src"
        log "  bladeRF driver installed"
    else
        info "  bladeRF already installed"
    fi

    # LimeSDR (LimeSuite)
    if ! command -v LimeUtil &>/dev/null; then
        log "  Building LimeSuite..."
        git clone --depth 1 https://github.com/myriadrf/LimeSuite.git
        cd LimeSuite
        mkdir -p builddir && cd builddir
        cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
        make -j"$(nproc)"
        make install
        ldconfig
        cd "$LAB_DIR/src"
        log "  LimeSuite installed"
    else
        info "  LimeSuite already installed"
    fi

    # RTL-SDR
    if ! command -v rtl_test &>/dev/null; then
        log "  Building rtl-sdr..."
        git clone --depth 1 https://github.com/osmocom/rtl-sdr.git
        cd rtl-sdr
        mkdir -p build && cd build
        cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DDETACH_KERNEL_DRIVER=ON
        make -j"$(nproc)"
        make install
        ldconfig
        cd "$LAB_DIR/src"
        log "  RTL-SDR installed"
    else
        info "  RTL-SDR already installed"
    fi

    # UHD (for USRP — usually from package manager but can build from source)
    if ! command -v uhd_find_devices &>/dev/null; then
        log "  Building UHD from source..."
        git clone --depth 1 --branch v4.6.0.0 https://github.com/EttusResearch/uhd.git
        cd uhd/host
        mkdir -p build && cd build
        cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
        make -j"$(nproc)"
        make install
        ldconfig
        uhd_images_downloader
        cd "$LAB_DIR/src"
        log "  UHD installed"
    else
        info "  UHD already installed"
    fi

    # udev rules for SDR devices
    cat > /etc/udev/rules.d/99-sdr.rules << 'UDEV'
# HackRF
ATTR{idVendor}=="1d50", ATTR{idProduct}=="6089", MODE="0666", GROUP="plugdev"
ATTR{idVendor}=="1d50", ATTR{idProduct}=="604b", MODE="0666", GROUP="plugdev"

# bladeRF
ATTR{idVendor}=="2cf0", ATTR{idProduct}=="5246", MODE="0666", GROUP="plugdev"
ATTR{idVendor}=="2cf0", ATTR{idProduct}=="5250", MODE="0666", GROUP="plugdev"

# LimeSDR
ATTR{idVendor}=="0403", ATTR{idProduct}=="601f", MODE="0666", GROUP="plugdev"
ATTR{idVendor}=="1d50", ATTR{idProduct}=="6108", MODE="0666", GROUP="plugdev"

# RTL-SDR
ATTR{idVendor}=="0bda", ATTR{idProduct}=="2838", MODE="0666", GROUP="plugdev"
ATTR{idVendor}=="0bda", ATTR{idProduct}=="2832", MODE="0666", GROUP="plugdev"

# Osmocom SIMtrace2
ATTR{idVendor}=="1d50", ATTR{idProduct}=="60e3", MODE="0666", GROUP="plugdev"
UDEV

    udevadm control --reload-rules
    udevadm trigger
    log "SDR udev rules installed"
}

# ─────────────────────────────────────────────
# Phase 3: srsRAN (4G/5G RAN)
# ─────────────────────────────────────────────
install_srsran() {
    log "Installing srsRAN 4G + Project..."
    cd "$LAB_DIR/src"

    # srsRAN 4G (eNB/EPC for testing)
    if [[ ! -d "$LAB_DIR/srsran4g" ]]; then
        git clone --depth 1 https://github.com/srsran/srsRAN_4G.git
        cd srsRAN_4G
        mkdir -p build && cd build
        cmake .. -DCMAKE_INSTALL_PREFIX="$LAB_DIR/srsran4g"
        make -j"$(nproc)"
        make install
        cd "$LAB_DIR/src"
        log "  srsRAN 4G installed"
    else
        info "  srsRAN 4G already installed"
    fi

    # srsRAN Project (5G gNB/UE)
    if [[ ! -d "$LAB_DIR/srsran5g" ]]; then
        git clone --depth 1 https://github.com/srsran/srsRAN_Project.git
        cd srsRAN_Project
        mkdir -p build && cd build
        cmake .. -DCMAKE_INSTALL_PREFIX="$LAB_DIR/srsran5g"
        make -j"$(nproc)"
        make install
        cd "$LAB_DIR/src"
        log "  srsRAN Project (5G) installed"
    else
        info "  srsRAN Project already installed"
    fi

    # Generate default configs
    mkdir -p "$LAB_DIR/configs/srsran"
    cat > "$LAB_DIR/configs/srsran/enb.conf" << 'EOF'
[enb]
mcc = 001
mnc = 01
mme_addr = 127.0.0.2
gtp_bind_addr = 127.0.0.1
s1c_bind_addr = 127.0.0.1
n_prb = 50
tm = 1
nof_ports = 1

[rf]
dl_earfcn = 3350
tx_gain = 80
rx_gain = 40
device_name = auto
device_args = auto

[log]
all_level = info
filename = /tmp/srs_enb.log
EOF

    log "  srsRAN configs generated"
}

# ─────────────────────────────────────────────
# Phase 4: Open5GS Core Network
# ─────────────────────────────────────────────
install_open5gs() {
    log "Installing Open5GS core network..."

    case "$OS_ID" in
        ubuntu|debian)
            # Add Open5GS PPA
            add-apt-repository -y ppa:open5gs/latest 2>/dev/null || true
            apt-get update -qq
            apt-get install -y -qq open5gs
            ;;
        *)
            # Build from source
            cd "$LAB_DIR/src"
            if [[ ! -d "open5gs" ]]; then
                git clone --depth 1 https://github.com/open5gs/open5gs.git
                cd open5gs
                meson build --prefix="$LAB_DIR/open5gs"
                ninja -C build
                ninja -C build install
            fi
            ;;
    esac

    # Generate lab-specific configs
    mkdir -p "$LAB_DIR/configs/open5gs"
    cat > "$LAB_DIR/configs/open5gs/lab-subscriber.json" << 'EOF'
{
  "subscribers": [
    {
      "imsi": "001010000000001",
      "k": "465b5ce8b199b49faa5f0a2ee238a6bc",
      "opc": "e8ed289deba952e4283b54e88e6183ca",
      "apn": "internet",
      "qci": 9,
      "description": "Lab test UE 1"
    },
    {
      "imsi": "001010000000002",
      "k": "0396eb317b6d1c36f19c1c5d968ae714",
      "opc": "53b63a265e6158c76d4c2ff55e1e8e27",
      "apn": "internet",
      "qci": 9,
      "description": "Lab test UE 2"
    }
  ]
}
EOF

    log "  Open5GS installed with lab subscriber configs"
}

# ─────────────────────────────────────────────
# Phase 5: SIM Card Programming
# ─────────────────────────────────────────────
install_sim_tools() {
    log "Installing SIM card programming tools..."
    cd "$LAB_DIR/src"

    # pySim (SIM card read/write)
    if [[ ! -d "$LAB_DIR/pysim" ]]; then
        git clone --depth 1 https://github.com/osmocom/pysim.git
        cd pysim
        pip3 install -e .
        cd "$LAB_DIR/src"
        log "  pySim installed"
    else
        info "  pySim already installed"
    fi

    # SIMtrace2 (SIM card tracing)
    if [[ ! -d "$LAB_DIR/simtrace2" ]]; then
        git clone --depth 1 https://gitea.osmocom.org/sim-card/simtrace2.git
        cd simtrace2/host
        make
        make install PREFIX="$LAB_DIR/simtrace2"
        cd "$LAB_DIR/src"
        log "  SIMtrace2 installed"
    else
        info "  SIMtrace2 already installed"
    fi

    # Generate SIM programming script
    cat > "$LAB_DIR/scripts/program_sim.sh" << 'PROG'
#!/usr/bin/env bash
# Program a sysmoISIM-SJA2 card for lab use
set -euo pipefail

READER="${READER:-0}"
MCC="${MCC:-001}"
MNC="${MNC:-01}"
IMSI="${IMSI:-001010000000001}"
KI="${KI:-465b5ce8b199b49faa5f0a2ee238a6bc}"
OPC="${OPC:-e8ed289deba952e4283b54e88e6183ca}"
ADM="${ADM:-11111111}"

echo "[*] Programming SIM card..."
echo "    IMSI: $IMSI"
echo "    MCC/MNC: $MCC/$MNC"

pySim-prog -p "$READER" \
    --mcc "$MCC" --mnc "$MNC" \
    --imsi "$IMSI" \
    --ki "$KI" --opc "$OPC" \
    --acc 0001 \
    --adm "$ADM" \
    --type sysmoISIM-SJA2

echo "[+] SIM card programmed successfully"
PROG
    chmod +x "$LAB_DIR/scripts/program_sim.sh"
    log "  SIM programming scripts generated"
}

# ─────────────────────────────────────────────
# Phase 6: Osmocom Stack (2G/3G testing)
# ─────────────────────────────────────────────
install_osmocom() {
    log "Installing Osmocom stack (2G/3G)..."

    case "$OS_ID" in
        ubuntu|debian)
            # Add Osmocom repo
            wget -qO - https://downloads.osmocom.org/packages/osmocom:/latest/Debian_12/Release.key | apt-key add -
            echo "deb https://downloads.osmocom.org/packages/osmocom:/latest/Debian_12/ ./" > /etc/apt/sources.list.d/osmocom.list 2>/dev/null || true
            apt-get update -qq
            apt-get install -y -qq \
                osmo-bts osmo-bsc osmo-msc osmo-hlr \
                osmo-stp osmo-mgw osmo-sgsn osmo-ggsn \
                osmo-trx 2>/dev/null || warn "Some Osmocom packages unavailable (OK for non-Debian)"
            ;;
        *)
            warn "  Osmocom packages not available for $OS_ID — build from source if needed"
            ;;
    esac

    log "  Osmocom stack installed"
}

# ─────────────────────────────────────────────
# Phase 7: Analysis Tools
# ─────────────────────────────────────────────
install_analysis_tools() {
    log "Installing analysis tools..."

    # GNU Radio (signal processing)
    case "$OS_ID" in
        ubuntu|debian)
            apt-get install -y -qq gnuradio gr-osmosdr 2>/dev/null || warn "GNU Radio install skipped"
            ;;
        fedora|rhel|centos)
            dnf install -y gnuradio gr-osmosdr 2>/dev/null || warn "GNU Radio install skipped"
            ;;
    esac

    # gr-lte (LTE receiver blocks for GNU Radio)
    cd "$LAB_DIR/src"
    if [[ ! -d "gr-lte" ]]; then
        git clone --depth 1 https://github.com/kit-cel/gr-lte.git 2>/dev/null || true
        if [[ -d "gr-lte" ]]; then
            cd gr-lte
            mkdir -p build && cd build
            cmake ..
            make -j"$(nproc)" 2>/dev/null || warn "gr-lte build failed (optional)"
            cd "$LAB_DIR/src"
        fi
    fi

    # Kalibrate-RTL (GSM frequency calibration)
    if [[ ! -d "kalibrate-rtl" ]]; then
        git clone --depth 1 https://github.com/steve-m/kalibrate-rtl.git
        cd kalibrate-rtl
        autoreconf -i
        ./configure
        make -j"$(nproc)"
        make install
        cd "$LAB_DIR/src"
        log "  kalibrate-rtl installed"
    fi

    # grgsm (GSM decoding)
    if ! command -v grgsm_decode &>/dev/null; then
        pip3 install grgsm 2>/dev/null || warn "grgsm pip install failed (build from source if needed)"
    fi

    log "  Analysis tools installed"
}

# ─────────────────────────────────────────────
# Phase 8: StaticZero Integration
# ─────────────────────────────────────────────
setup_aegis_integration() {
    log "Configuring StaticZero integration..."

    mkdir -p "$LAB_DIR/configs/aegis"

    # SDR bridge config
    cat > "$LAB_DIR/configs/aegis/sdr-bridge.toml" << 'EOF'
[sdr]
device_type = "hackrf"
frequency_hz = 2620000000
sample_rate_hz = 20000000
gain_db = 40
bandwidth_hz = 20000000

[output]
iq_pipe = "/tmp/aegis_iq_pipe"
defense_port = 7891
control_port = 7890

[scan]
bands = ["B1", "B3", "B7", "B20", "n78"]
dwell_time_ms = 500
threshold_dbm = -120

[rf_fingerprint]
enabled = true
sample_window = 1000
variance_threshold = 0.05
EOF

    # Defense engine telecom config
    cat > "$LAB_DIR/configs/aegis/telecom-defense.toml" << 'EOF'
[telecom]
enable_advanced = true
sdr_bridge_port = 7891
correlation_window_ms = 5000

[cell_baseline]
# Known good cells (from initial survey)
# Format: cell_id, tac, earfcn, min_rsrp, max_rsrp, expected_cipher, rat
cells = []

[thresholds]
downgrade_alert_count = 2
identity_request_max_per_min = 3
cell_reselection_max_per_min = 5
signal_strength_anomaly_db = 20
EOF

    # Create named pipe for IQ data
    if [[ ! -p /tmp/aegis_iq_pipe ]]; then
        mkfifo /tmp/aegis_iq_pipe
    fi

    # systemd service for SDR bridge
    cat > /etc/systemd/system/aegis-sdr-bridge.service << EOF
[Unit]
Description=StaticZero SDR Bridge
After=network.target

[Service]
Type=simple
ExecStart=$LAB_DIR/bin/sdr-bridge --sdr-type hackrf --mode capture --control-port 7890 --defense-port 7891
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log "  Aegis integration configured"
}

# ─────────────────────────────────────────────
# Phase 9: Network Isolation (RF Shielding)
# ─────────────────────────────────────────────
setup_rf_isolation() {
    log "Configuring RF isolation parameters..."

    cat > "$LAB_DIR/configs/rf_isolation.md" << 'EOF'
# RF Isolation Requirements

## CRITICAL: Legal Compliance
Operating a cellular base station (even for testing) requires:
1. RF-shielded enclosure (Faraday cage) OR
2. Extremely low TX power (-40 dBm or below) OR
3. Licensed spectrum (test license from regulator)

## Recommended Lab Setup
- RF shielded box: Ramsey STE-2200 or similar (>80dB isolation)
- Attenuators: 30dB + 30dB on TX path
- Dummy load on SDR TX when not actively testing
- All test devices inside the shielded enclosure

## TX Power Limits for Lab Use
- srsRAN eNB tx_gain: set to minimum (≤10) initially
- HackRF max TX: limit to -30dBm with external attenuator
- Never transmit without confirmed RF isolation

## Verification
- Use spectrum analyzer to confirm no leakage outside enclosure
- Measure with RTL-SDR outside the shielded area
- Document isolation measurements before first test
EOF

    # iptables rules: isolate lab network from production
    cat > "$LAB_DIR/scripts/isolate_network.sh" << 'NET'
#!/usr/bin/env bash
# Isolate lab core network from external
set -euo pipefail

LAB_SUBNET="10.45.0.0/16"

# Prevent lab traffic from reaching internet
iptables -I FORWARD -s "$LAB_SUBNET" -o eth0 -j DROP
iptables -I FORWARD -d "$LAB_SUBNET" -i eth0 -j DROP

# Allow only lab-internal communication
iptables -A FORWARD -s "$LAB_SUBNET" -d "$LAB_SUBNET" -j ACCEPT

echo "[+] Lab network isolated (subnet: $LAB_SUBNET)"
NET
    chmod +x "$LAB_DIR/scripts/isolate_network.sh"

    log "  RF isolation docs and network isolation scripts created"
}

# ─────────────────────────────────────────────
# Phase 10: Validation
# ─────────────────────────────────────────────
validate_setup() {
    log "Validating lab setup..."

    local issues=0

    # Check SDR tools
    for tool in hackrf_info bladeRF-cli LimeUtil rtl_test uhd_find_devices; do
        if command -v "$tool" &>/dev/null; then
            info "  ✓ $tool available"
        else
            warn "  ✗ $tool not found"
            ((issues++)) || true
        fi
    done

    # Check srsRAN
    if [[ -d "$LAB_DIR/srsran4g" ]]; then
        info "  ✓ srsRAN 4G installed"
    else
        warn "  ✗ srsRAN 4G not found"
        ((issues++)) || true
    fi

    # Check Open5GS
    if command -v open5gs-mmed &>/dev/null || [[ -d "$LAB_DIR/open5gs" ]]; then
        info "  ✓ Open5GS installed"
    else
        warn "  ✗ Open5GS not found"
        ((issues++)) || true
    fi

    # Check SIM tools
    if command -v pySim-prog &>/dev/null; then
        info "  ✓ pySim installed"
    else
        warn "  ✗ pySim not found"
        ((issues++)) || true
    fi

    # Check USB devices
    info "  USB devices:"
    lsusb 2>/dev/null | grep -iE "hackrf|bladerf|lime|rtl|simtrace" | while read -r line; do
        info "    $line"
    done

    echo ""
    if [[ $issues -eq 0 ]]; then
        log "Lab setup complete — all components verified"
    else
        warn "Lab setup complete with $issues warnings (some components may need manual install)"
    fi
}

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
usage() {
    echo "Usage: $0 [OPTIONS] [PHASE...]"
    echo ""
    echo "Phases (run in order by default):"
    echo "  base        Install base system dependencies"
    echo "  sdr         Install SDR drivers (HackRF, bladeRF, LimeSDR, USRP)"
    echo "  srsran      Install srsRAN 4G/5G"
    echo "  core        Install Open5GS core network"
    echo "  sim         Install SIM card programming tools"
    echo "  osmocom     Install Osmocom 2G/3G stack"
    echo "  analysis    Install signal analysis tools"
    echo "  aegis       Configure StaticZero integration"
    echo "  isolation   Setup RF isolation and network isolation"
    echo "  validate    Validate installation"
    echo "  all         Run all phases (default)"
    echo ""
    echo "Options:"
    echo "  --lab-dir DIR    Set lab directory (default: /opt/aegis-lab)"
    echo "  --skip-sdr       Skip SDR driver compilation"
    echo "  --help           Show this help"
}

main() {
    check_root
    detect_os

    mkdir -p "$LAB_DIR"/{src,bin,configs,scripts,logs}
    touch "$LOG_FILE"

    log "════════════════════════════════════════════"
    log "  StaticZero Telecom Lab Setup"
    log "  Lab directory: $LAB_DIR"
    log "════════════════════════════════════════════"

    local phases=("$@")
    if [[ ${#phases[@]} -eq 0 ]] || [[ "${phases[0]}" == "all" ]]; then
        phases=(base sdr srsran core sim osmocom analysis aegis isolation validate)
    fi

    for phase in "${phases[@]}"; do
        case "$phase" in
            base)       install_base_deps ;;
            sdr)        install_sdr_drivers ;;
            srsran)     install_srsran ;;
            core)       install_open5gs ;;
            sim)        install_sim_tools ;;
            osmocom)    install_osmocom ;;
            analysis)   install_analysis_tools ;;
            aegis)      setup_aegis_integration ;;
            isolation)  setup_rf_isolation ;;
            validate)   validate_setup ;;
            --lab-dir)  ;; # handled by getopts
            --help)     usage; exit 0 ;;
            *)          err "Unknown phase: $phase" ;;
        esac
    done

    log ""
    log "Setup complete. Next steps:"
    log "  1. Connect SDR hardware and verify with: hackrf_info / LimeUtil --find"
    log "  2. Program test SIMs: $LAB_DIR/scripts/program_sim.sh"
    log "  3. Start core network: systemctl start open5gs-mmed open5gs-sgwud"
    log "  4. Start eNB: $LAB_DIR/srsran4g/bin/srsenb $LAB_DIR/configs/srsran/enb.conf"
    log "  5. Start Aegis SDR bridge: systemctl start aegis-sdr-bridge"
    log ""
    log "  IMPORTANT: Ensure RF isolation before transmitting!"
}

# Parse global options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --lab-dir)
            LAB_DIR="$2"
            LOG_FILE="$LAB_DIR/setup.log"
            shift 2
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            break
            ;;
    esac
done

main "$@"
