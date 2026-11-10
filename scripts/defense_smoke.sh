#!/usr/bin/env bash
# Run only in a disposable Linux VM. Builds as the caller; elevates only the
# narrowly filtered test executable, never Cargo or the compiler.
set -euo pipefail

workspace="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$workspace"
object="${STATICZERO_BPF_PATH:-$workspace/target/bpfel-unknown-none/release/staticzero-defense}"
if [[ ! -f "$object" ]]; then
    echo "Missing defense eBPF object: $object. Run cargo xtask build-ebpf --release first." >&2
    exit 1
fi
object="$(realpath -- "$object")"

test_binary="$(cargo test --locked -p staticzero-defense --test modem_smoke --no-run --message-format=json |
    python3 -c 'import json, sys
for line in sys.stdin:
    event = json.loads(line)
    if event.get("reason") == "compiler-artifact" and event.get("target", {}).get("name") == "modem_smoke" and event.get("executable"):
        print(event["executable"])')"
if [[ -z "$test_binary" || ! -x "$test_binary" ]]; then
    echo "Failed to locate the modem_smoke test executable." >&2
    exit 1
fi
echo "Running passive openat smoke test; no radio hardware, transmissions, or real modem access."
if [[ "$EUID" -eq 0 ]]; then
    exec env STATICZERO_BPF_PATH="$object" "$test_binary" --ignored --exact privileged_modem_openat_smoke --nocapture
else
    exec sudo env STATICZERO_BPF_PATH="$object" "$test_binary" --ignored --exact privileged_modem_openat_smoke --nocapture
fi
