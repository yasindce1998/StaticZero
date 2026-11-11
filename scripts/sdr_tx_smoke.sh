#!/usr/bin/env bash
# RF transmission self-test runner.
#
# Offline stage (always): IQ tone generation, file round trip, and RMS
# analysis run as ordinary unit tests — no hardware, no RF.
#
# Hardware stage (opt-in): set STATICZERO_SDR_TX=1 only when a HackRF TX port
# is cabled through an attenuator into an RTL-SDR RX port inside a shielded
# enclosure. NEVER with antennas, and never outside an RF-isolated lab —
# see the compliance checklist in docs/LAB_SETUP.md. When the variable is set,
# missing tools or a failed loopback are hard failures, not skips.
set -euo pipefail

workspace="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$workspace"

echo "Running offline RF TX pipeline unit tests (no hardware)."
cargo test --locked -p staticzero-tools rf_selftest

echo "Building sdr-bridge."
cargo build --locked --release -p staticzero-tools --bin sdr-bridge

if [[ "${STATICZERO_SDR_TX:-}" == "1" ]]; then
    echo "STATICZERO_SDR_TX=1 set: running hardware TX loopback (cabled HackRF -> attenuator -> RTL-SDR only)."
    for tool in hackrf_transfer rtl_sdr; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "Required tool $tool not found in PATH." >&2
            exit 1
        fi
    done
    ./target/release/sdr-bridge --sdr-type hackrf --mode selftest-tx \
        --frequency 100000000 --sample-rate 2000000 --gain 40
else
    echo "STATICZERO_SDR_TX not set; hardware loopback stage not requested (software-only self-test below)."
    ./target/release/sdr-bridge --sdr-type hackrf --mode selftest-tx \
        --frequency 100000000 --sample-rate 2000000 --gain 40
fi
