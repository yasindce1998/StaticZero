// These tests invoke the compiled staticzero-defense binary, which requires
// the ebpf-bin feature (and the eBPF objects built by cargo xtask). CI runs
// them in the eBPF job: cargo test --release --features ebpf-bin --test doctor_cli
#![cfg(feature = "ebpf-bin")]

use std::process::Command;

#[test]
fn doctor_reports_failures_as_json_without_starting_the_daemon() {
    let output = Command::new(env!("CARGO_BIN_EXE_staticzero-defense"))
        .args([
            "--doctor",
            "--json",
            "--modules",
            "46",
            "--bpf-path",
            "/nonexistent/staticzero-defense",
            "--config",
            "/nonexistent/staticzero-config.toml",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["modules"][0]["module"], 46);
    assert_eq!(report["modules"][0]["status"], "unsupported");
    assert!(report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| check["name"] == "ebpf_object" && check["status"] == "fail"));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("HTTP server"));
    assert!(!stderr.contains("config TOML"));
}

#[test]
fn unknown_module_is_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_staticzero-defense"))
        .args(["--doctor", "--modules", "99"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("unknown defense module 99"));
}

#[test]
fn malformed_object_is_rejected_without_loading_bpf() {
    let output = Command::new(env!("CARGO_BIN_EXE_staticzero-defense"))
        .args(["--doctor", "--json", "--modules", "22", "--bpf-path"])
        .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| check["name"] == "ebpf_object"
            && check["status"] == "fail"
            && check["detail"].as_str().unwrap().contains("parse eBPF ELF")));
    assert_eq!(report["modules"][0]["status"], "failed");
}
