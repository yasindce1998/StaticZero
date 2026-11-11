# Lab smoke tests

Real-kernel and real-hardware validation tiers for StaticZero. Every test in
this guide runs the same code paths as production: the real eBPF objects, the
real loaders, real kernel hooks, and the real ring buffers. Failures are
failures — nothing here silently skips except explicitly hardware-gated
stages, which are opt-in by environment variable.

The passive defense smoke test (temp-file `openat` only) remains the baseline;
see [DEFENSE_VALIDATION.md](DEFENSE_VALIDATION.md). This guide covers the
tiers that go further: offensive probes, crafted traffic through the kernel
networking datapath, real modem device nodes, and RF transmission.

## Prerequisites

- Linux 5.15+ on x86_64 or aarch64, kernel with `CONFIG_KPROBE_EVENTS`,
  tracefs available (`/sys/kernel/tracing`).
- Root or `CAP_BPF` + `CAP_PERFMON` (+ `CAP_NET_ADMIN` for the traffic test).
- Built eBPF objects: `cargo xtask build-ebpf --release`.
- `ip` from iproute2 and `sysctl` for the traffic-path test.
- Run everything in a disposable VM or an authorized lab host.

## 1. Offensive kprobe smoke test

```bash
cargo xtask build-ebpf --release
bash scripts/offense_smoke.sh        # runs both offense tests
```

What `privileged_offense_kprobe_smoke` proves, on the real kernel:

- The offense eBPF object loads and the verifier accepts `shadow_rrc_redirect`.
- The probe attaches to `fd_install` (a real mainline symbol whose first
  argument is the file descriptor). One perf event per probe is the canonical
  model: the program is pinned into the tracepoint's shared program array and
  runs on every CPU where the kprobe fires — the kernel rejects pinning the
  same program into additional per-CPU events with EEXIST.
- A negative control attaches to `sdr_rx_callback`, a documented hook point
  that is *not* a mainline kernel symbol; the attach must fail rather than
  silently succeed.
- Opening a file with a predicted, map-programmed fd number produces exactly
  one `EVENT_RRC_REDIRECT` in the real BPF ring buffer, decoded with the same
  `EventHeader` ABI as the daemon.

## 2. Traffic-path (XDP + TC) smoke test

`privileged_offense_xdp_tc_smoke` (same script) creates a veth pair, attaches
`shadow_gtp_hijack` (XDP ingress) and `shadow_protocol_downgrade` (TC clsact
ingress) to the receiving end, and pushes a crafted GTP-U packet (UDP/2152,
known TEID, RFC 5737 TEST-NET addresses) through the real kernel datapath via
an `AF_PACKET` socket. It proves:

- Both programs pass the verifier (`shadow_gtp_hijack` was rewritten with
  explicit per-field `data_end` checks — the original unchecked dereferences
  would have been rejected at load).
- The XDP probe parses the live packet and emits `EVENT_GTP_TUNNEL_HIJACK`
  with the exact TEID programmed into the `GTP_TUNNEL_STATE` map.
- The TC classifier fires on the same packet.
- The XDP verdict was `XDP_PASS`: a second `AF_PACKET` socket on the peer
  still observes the full frame, byte for byte.

No packet leaves the host; the veth pair is destroyed on test teardown.

## 3. Real modem access smoke test (defense)

```bash
# PTY-backed synthetic modem device (real /dev/pts char node, no hardware):
bash scripts/defense_smoke.sh

# Real lab modem hardware (opt-in, read-only open, O_NONBLOCK):
sudo STATICZERO_MODEM_DEVICE=/dev/ttyUSB0 bash scripts/defense_smoke.sh
# or: sudo STATICZERO_MODEM_DEVICE=/dev/cdc-wdm0 bash scripts/defense_smoke.sh
```

`privileged_modem_pty_smoke` watches a real character device node created via
`posix_openpt` instead of a plain temp file, so the monitored path is an
actual devtmpfs device. `privileged_real_modem_smoke` points Module 22 at a
real modem node: the test opens the device read-only and non-blocking and
requires exactly one `ALERT_MODEM_TAMPER` from the kernel. If the variable is
set but the device is missing, the test fails. Notes:

- Opening a modem port may have side effects on some hardware (port resets,
  exclusive opens by ModemManager). Stop ModemManager or pick an unused port.
- `/dev/cdc-wdm0` opens are non-destructive control-channel opens.

## 4. RF transmission smoke test (sdr-bridge)

```bash
# Offline stage only (IQ generation, file round trip, RMS analysis):
bash scripts/sdr_tx_smoke.sh

# Hardware loopback — see the safety requirements first:
STATICZERO_SDR_TX=1 bash scripts/sdr_tx_smoke.sh
```

The offline stage runs as ordinary unit tests plus `sdr-bridge --mode
selftest-tx`, which generates a signed 8-bit I/Q CW tone (the
`hackrf_transfer` format), verifies the write/read round trip, and checks the
signal level (≈ −5.1 dBFS).

The hardware stage is opt-in and requires **two cabled devices**: HackRF TX
port → attenuator → RTL-SDR RX port. One HackRF cannot loop back to itself;
it cannot TX and RX simultaneously. Compliance requirements from
[LAB_SETUP.md](LAB_SETUP.md) apply in full:

- Cabled or inside a shielded enclosure — never antennas.
- TX power reduced to minimum required.
- 100 MHz test frequency (adjust with `--frequency` if your lab policy
  differs).

The stage transmits the tone with `hackrf_transfer`, captures with `rtl_sdr`,
and requires the peak per-window RMS of the capture to exceed −25 dBFS. With
the variable unset the tool reports the hardware stage as skipped with the
reason; with it set, any failure (missing tool, failed capture, insufficient
energy) is a hard failure.

## What is still not covered

- Real SDR transmission through the `sdr-bridge` control API (the JSON `inject`
  command still targets the stub device layer; only the self-test TX path is
  real).
- TC/XDP probes other than the two exercised above; most offensive features
  remain research scaffolding with documented-but-unvalidated hook points.
- Offense eBPF programs other than `shadow_rrc_redirect`,
  `shadow_gtp_hijack`, and `shadow_protocol_downgrade` have no
  verifier-acceptance evidence.
