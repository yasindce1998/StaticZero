#!/usr/bin/env bash
# Run only in a disposable Linux VM or authorized lab host. Builds as the
# caller; elevates only the narrowly filtered test executable, never Cargo or
# the compiler.
#
# Covers what the passive defense smoke tests deliberately avoid:
#   - offensive eBPF probe loading and per-CPU kprobe attachment
#   - a crafted GTP-U packet traversing a real kernel datapath (veth + XDP + TC)
#   - event delivery from the real BPF ring buffer
# No radio hardware, RF transmission, or offensive traffic leaves the host.
set -euo pipefail

workspace="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$workspace"
object="${STATICZERO_BPF_PATH:-$workspace/target/bpfel-unknown-none/release/staticzero-offense}"
if [[ ! -f "$object" ]]; then
    echo "Missing offense eBPF object: $object. Run cargo xtask build-ebpf --release first." >&2
    exit 1
fi
object="$(realpath -- "$object")"

test_binary="$(cargo test --locked -p staticzero-offense --test lab_smoke --no-run --message-format=json |
    python3 -c 'import json, sys
for line in sys.stdin:
    event = json.loads(line)
    if event.get("reason") == "compiler-artifact" and event.get("target", {}).get("name") == "lab_smoke" and event.get("executable"):
        print(event["executable"])')"
if [[ -z "$test_binary" || ! -x "$test_binary" ]]; then
    echo "Failed to locate the lab_smoke test executable." >&2
    exit 1
fi

run_test() {
    local name="$1"
    echo "Running $name against the real kernel."
    if [[ "$EUID" -eq 0 ]]; then
        env STATICZERO_BPF_PATH="$object" "$test_binary" --ignored --exact "$name" --nocapture
    else
        sudo env STATICZERO_BPF_PATH="$object" "$test_binary" --ignored --exact "$name" --nocapture
    fi
}

run_test privileged_offense_kprobe_smoke
run_test privileged_offense_xdp_tc_smoke
