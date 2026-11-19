#!/usr/bin/env bash
# Real-environment smoke test for the userspace tool adapters
# (Modules 56/61/62/66/67/70) and the next-generation offense programs.
#
# Runs the actual defense daemon — real eBPF object load, real tracefs
# layout resolution, real tool-input verdict files — and asserts that
# alerts and correlated compound threats surface in the JSON output.
# Then runs the offense loader and asserts the next-generation kprobes
# attach to a real kernel symbol (tcp_sendmsg) and the new XDP programs
# load on a real interface.
#
# Run only in a disposable Linux VM or container (root or sudo). No radio
# hardware and no transmissions are involved.
set -euo pipefail

workspace="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$workspace"

defense_bin="target/release/staticzero-defense"
offense_bin="target/release/staticzero-offense"
for bin in "$defense_bin" "$offense_bin"; do
    if [[ ! -x "$bin" ]]; then
        echo "Missing $bin. Build with: cargo xtask build-ebpf --release && cargo build --release -p staticzero-defense -p staticzero-offense --features ebpf-bin" >&2
        exit 1
    fi
done

run_as_root() {
    if [[ "$EUID" -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

# The defense engine resolves the openat tracepoint layout at startup even
# when only userspace modules are selected; tracefs must be visible. The
# existence check runs as root because tracefs directories are often
# root-only, and the mount is idempotent (a mounted tracefs is fine).
if ! run_as_root test -d /sys/kernel/tracing/events/syscalls && \
   ! run_as_root test -d /sys/kernel/debug/tracing/events/syscalls; then
    run_as_root mkdir -p /sys/kernel/tracing
    run_as_root mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
fi

# The offense loader logs via RUST_LOG; enable info so attach results are
# visible and assertable.
export RUST_LOG=info

# A dedicated dummy interface for the XDP programs — isolated from any real
# networking, like the veth pair the offense lab smoke tests use. Falls back
# to the first real interface if dummies cannot be created.
iface="sz-smoke0"
cleanup_iface() {
    if [[ "$iface" == "sz-smoke0" ]] && ip link show "$iface" >/dev/null 2>&1; then
        run_as_root ip link del "$iface" 2>/dev/null || true
    fi
}
if ! ip link show "$iface" >/dev/null 2>&1; then
    if run_as_root ip link add name "$iface" type dummy 2>/dev/null; then
        run_as_root ip link set "$iface" up
    else
        iface="${STATICZERO_SMOKE_IFACE:-eth0}"
        if ! ip link show "$iface" >/dev/null 2>&1; then
            iface="$(ip -o link show | awk -F': ' 'NR==1 {print $2}')"
        fi
    fi
fi
echo "Using interface: $iface"

tmpdir="$(mktemp -d)"
cleanup() {
    rm -rf "$tmpdir"
    cleanup_iface
}
trap cleanup EXIT

# ── Part 1: defense engine with real tool-input verdict streams ──────────────

# One Wi-Fi 7 MLO finding (Module 56).
cat > "$tmpdir/mlo.jsonl" <<'EOF'
{"mld_addr":"aa:bb:cc:dd:ee:ff","link_id":1,"kind":"key_separation_abuse","severity":"critical","detail":"link 1 accepts key generation 2 while MLD is at 5","timestamp_ns":1}
EOF

# 6G verdicts (Modules 66/67) that must correlate into AiRanCompromise.
cat > "$tmpdir/sixg.jsonl" <<'EOF'
{"kind":"ai_ran","domain":"core-1","model_id":"airan-phy-01","tampered":true,"version":4,"reason":"integrity hash changed without version advance"}
{"kind":"pqc","domain":"core-1","peer":"amf-1","downgraded":true,"suite":"rsa-2048"}
EOF

echo "Running defense engine (real eBPF load + tool adapters, 12s window)."
run_as_root timeout --signal=INT 12s "$defense_bin" \
    --modules 56,66,67 \
    --tool-input "mlo=$tmpdir/mlo.jsonl" \
    --tool-input "airan=$tmpdir/sixg.jsonl" \
    --tool-input "pqc=$tmpdir/sixg.jsonl" \
    --json --no-harden \
    > "$tmpdir/engine.jsonl" 2> "$tmpdir/engine.log" || true

echo "── defense engine log (adapter lines) ──"
grep -E "tool adapter|userspace adapter" "$tmpdir/engine.log" || true

fail() {
    echo "SMOKE FAIL: $1" >&2
    echo "── engine stdout ──" >&2
    cat "$tmpdir/engine.jsonl" >&2 || true
    echo "── engine stderr (tail) ──" >&2
    tail -40 "$tmpdir/engine.log" >&2 || true
    exit 1
}

grep -q "tool adapter mlo: following" "$tmpdir/engine.log" \
    || fail "mlo tool adapter did not start"
grep -q "tool adapter airan: following" "$tmpdir/engine.log" \
    || fail "airan tool adapter did not start"
grep -q "tool adapter pqc: following" "$tmpdir/engine.log" \
    || fail "pqc tool adapter did not start"

# Module 56 alert (ALERT_MLO_INTEGRITY = 59)
grep -q '"alert_type":59' "$tmpdir/engine.jsonl" \
    || fail "Module 56 alert (ALERT_MLO_INTEGRITY) did not surface"
# Module 66 alert (ALERT_AI_RAN_INTEGRITY = 69)
grep -q '"alert_type":69' "$tmpdir/engine.jsonl" \
    || fail "Module 66 alert (ALERT_AI_RAN_INTEGRITY) did not surface"
# Module 67 alert (ALERT_PQC_DOWNGRADE = 70)
grep -q '"alert_type":70' "$tmpdir/engine.jsonl" \
    || fail "Module 67 alert (ALERT_PQC_DOWNGRADE) did not surface"
# Correlated compound threat from tool verdicts alone
grep -q 'AiRanCompromise' "$tmpdir/engine.jsonl" \
    || fail "AiRanCompromise compound threat did not surface"

echo "PASS: defense tool adapters — 3 modules, 3 alerts, 1 compound threat."

# ── Part 2: offense loader with next-generation programs ─────────────────────

echo "Running offense loader (next-gen kprobes + XDP on $iface, 8s window)."
# Note: the offense loader logs to stdout (tracing default); the defense
# engine logs to stderr. Combine both streams for assertions.
run_as_root timeout --signal=INT 8s "$offense_bin" \
    --enable-nextgen-iot \
    --enable-6g \
    --enable-secure-ranging \
    --wpan-iface "$iface" \
    --sdr-iface "$iface" \
    > "$tmpdir/offense.log" 2>&1 || true

fail_offense() {
    echo "SMOKE FAIL: $1" >&2
    echo "── offense stderr (tail) ──" >&2
    tail -40 "$tmpdir/offense.log" >&2 || true
    exit 1
}

# kprobes on tcp_sendmsg — a symbol present in every mainline kernel —
# must attach for real.
grep -q "F189: Matter Onboarding Passcode Attack enabled via tcp_sendmsg" "$tmpdir/offense.log" \
    || fail_offense "F189 kprobe did not attach to tcp_sendmsg"
grep -q "F196: RIS Reflection Manipulation enabled via tcp_sendmsg" "$tmpdir/offense.log" \
    || fail_offense "F196 kprobe did not attach to tcp_sendmsg"
grep -q "F198: PQC Handshake Downgrade enabled via tcp_sendmsg" "$tmpdir/offense.log" \
    || fail_offense "F198 kprobe did not attach to tcp_sendmsg"

# TC classifiers from the next-gen groups must load (they are attached to
# interfaces manually by the operator).
grep -q "F191: Ambient IoT Device Cloning loaded" "$tmpdir/offense.log" \
    || fail_offense "F191 TC classifier did not load"

# The kernel allows only one XDP program per interface: the first next-gen
# XDP attach must succeed for real, and later ones on the same interface
# must be skipped gracefully instead of crashing the loader.
grep -q "F186: UWB Digital Key Relay enabled on $iface" "$tmpdir/offense.log" \
    || fail_offense "first XDP program (F186) did not attach to $iface"
grep -q "F195: AI-Native Air Interface Adversarial Perturbation not attached, skipping" "$tmpdir/offense.log" \
    || fail_offense "second XDP program on $iface was not skipped gracefully"

# Programs whose hook points are not mainline kernel symbols must be
# skipped gracefully, never crash the loader.
grep -q "not attached, skipping" "$tmpdir/offense.log" \
    || fail_offense "missing-symbol features were not skipped gracefully"
grep -q "StaticZero Offense Engine running" "$tmpdir/offense.log" \
    || fail_offense "offense engine did not reach its running state"

echo "PASS: offense next-gen programs — 3 real kprobes, 1 real XDP attachment with graceful one-per-interface skips."

echo "All tool-adapter and next-generation smoke tests passed."
