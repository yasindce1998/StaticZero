# Defense preflight and passive validation

## Current runtime support

The protocol catalog is **not a list of validated live detectors**. The explicit
registry in `defense/src/probes.rs` is the source of truth for attachment support:

| Modules | Runtime status |
| --- | --- |
| 22 | Experimental passive adapter for `syscalls/sys_enter_openat` |
| 16–21, 23–55 | Unsupported for live attachment: expect decoded protocol values, with no validated kernel/userspace adapter yet |

Unsupported probe logic remains in the eBPF object for research, and userspace
correlation rules remain testable. The loader never guesses a kernel symbol by
stripping `detect_` from a program name. `--all` reports unsupported modules and
attaches only supported modules. Selecting only unsupported modules fails.

Module 22 reports **attempts** to open one exact, configured absolute pathname
by processes not in the PID allowlist. The event does not prove that an open
succeeded, that the caller is malicious, or that a compound telecom attack
occurred. The adapter does not inspect file contents, modify traffic, or block
access.

Limitations:

- Native 64-bit Linux x86_64/aarch64 `openat` only; no `open`, `openat2`, `ioctl`,
  compat syscalls, inherited descriptors, or descriptor passing coverage.
- Literal pathname matching, not resolved inode identity: relative paths,
  symlinks, alternate mount paths, and equivalent spellings are not covered.
- One UTF-8 pathname, at most 126 bytes; no wildcard or prefix matching.
- Up to 32 allowed nonzero process IDs (TGIDs), not thread IDs. PID reuse and
  allowlist maintenance are operator responsibilities.
- Tracepoint entry reads a user pointer. Another thread could change the string;
  this is telemetry, not an enforcement boundary.

## Per-CPU attachment

Tracepoint and kprobe programs are attached with a single perf event per
probe, which is the canonical model used by aya and libbpf: the program is
pinned into the tracepoint's *shared* program array (`tp_event->prog_array`)
and executes on every CPU where the tracepoint or kprobe fires, regardless of
which CPU the perf event was opened on. Pinning the same program into
additional per-CPU perf events is rejected by the kernel with `EEXIST`
(`bpf_prog_array_copy` refuses duplicate programs), so per-CPU attachment of
a single program is impossible by design and unnecessary.

The zero-alert CI flake that prompted this investigation (run 42878645556:
identical tree and kernel, one runner passed, one delivered no alerts) is
**not explained by CPU scoping** on the affected 7.0 kernel — v7.0 runs the
BPF program array before the per-CPU perf event list check in
`perf_syscall_enter`. Its root cause remains unidentified; it has not
reproduced since. If it recurs, capture the full step log before re-running.

## Read-only preflight

```bash
cargo xtask build-ebpf --release
cargo build --release -p staticzero-defense

# Can run unprivileged; privilege/tracefs failures are expected in that case.
./target/release/staticzero-defense --doctor --all
./target/release/staticzero-defense --doctor --modules 22 --json

# Check the environment under the privileges used for the real deployment.
sudo ./target/release/staticzero-defense --doctor --modules 22
```

`--doctor` does not load BPF, create maps, attach probes, open a database, start
the HTTP server, read the daemon configuration, or alter capabilities. It checks:

- Linux architecture and kernel release (5.15+).
- Effective `CAP_BPF` + `CAP_PERFMON`, or `CAP_SYS_ADMIN` (UID 0 alone is not proof).
- eBPF ELF parsing, the supported program's type, and required map names.
- Tracepoint availability and the running kernel's `filename` field layout.
- Informational BTF, unprivileged-BPF, and perf policy settings.

Exit status is zero only when checks pass and at least one selected module is
available, with no selected supported module failing its checks. Unsupported
modules are reported separately. A passing preflight is **not** proof of kernel
verifier acceptance or attachment: security modules, lockdown, resource limits,
or container policy can still deny loading. `available` means preflight passed;
`active` is reported only after successful program loading and attachment.
No detector active means startup fails. Rebuild old eBPF objects: Module 22 is
now a tracepoint program, not the previous decoded-argument kprobe.

If tracefs is not mounted, an administrator can mount it inside the disposable
VM (`sudo mount -t tracefs tracefs /sys/kernel/tracing`). Neither doctor nor the
smoke test changes mounts or sysctls automatically.

For real, authorized modem telemetry, configure your own device path and PIDs:

```bash
sudo env RUST_LOG=info ./target/release/staticzero-defense \
  --modules 22 --modem-path /dev/cdc-wdm0 --allow-modem-pid 1234,5678 \
  --config config.example.toml --json
```

Logs go to stderr; `--json` alert records go to stdout. The existing daemon API
defaults to `0.0.0.0:9100` without authentication: bind it to loopback or disable
it in configuration for isolated testing. This milestone does not complete API
authentication, adaptive feedback wiring, or configuration hot-reload.

## Tests

### No privileges or hardware required

```bash
cargo test --locked
cargo test --locked -p staticzero-defense --test modem_smoke offline_modem_policy_pipeline_smoke
```

The offline smoke test executes the **same policy function** as the eBPF
adapter and the **same alert-processing pipeline** as the daemon. It checks a
benign path, a prefix collision, a disabled policy, and an allowlisted PID, then
decodes a native ABI alert, ingests it into correlation, persists it to a fresh
SQLite file, and verifies API responses and Prometheus metrics. Reopening the
database proves the record survives closing it. A single access alert must not
produce a compound threat. It does **not** validate syscall observation,
kernel verifier acceptance, or actual ring-buffer delivery.

### Real-kernel smoke test — disposable Linux VM only

```bash
cargo xtask build-ebpf --release
bash scripts/defense_smoke.sh
```

The script compiles the test as the invoking user and elevates only its test
executable. It runs the otherwise-ignored `privileged_modem_openat_smoke` test;
missing privileges, unavailable tracepoints, verifier rejection, or missing
events are failures, not skips. Set `STATICZERO_BPF_PATH` to test another object.

The test attaches only Module 22, opens an ordinary temporary file using the
native `openat` syscall, and verifies exactly one alert from the real BPF ring
buffer. Separate benign-path and PID-allowlist controls must emit no alerts.
It then runs that kernel alert through correlation, SQLite, API, and metrics
checks. It detaches before removing its own files. No SDR, modem device,
network traffic generation, RF transmission, or offensive probe is used.

CI runs the offline tests in the normal test job and the privileged test in
the disposable Ubuntu VM used by the eBPF build job. Local offline success
alone must never be described as live detector validation.

## Lab-tier validation

[LAB_SMOKE_TESTS.md](LAB_SMOKE_TESTS.md) extends validation beyond the passive
tier: real modem device nodes (PTY and opt-in hardware via
`STATICZERO_MODEM_DEVICE`), offensive probe attachment, and crafted GTP
traffic through the kernel datapath. Those tests run through
`scripts/defense_smoke.sh` and `scripts/offense_smoke.sh` in the same
disposable-VM, elevate-only-the-test-binary model.
