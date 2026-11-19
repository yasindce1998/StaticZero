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

#[test]
fn tool_input_makes_userspace_module_available_in_doctor() {
    // The overall preflight may still fail on environment checks (e.g.
    // privileges on an unprivileged runner), so the assertion is on the
    // module status in the JSON report, matching the other doctor tests.
    let verdicts = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_staticzero-defense"))
        .args(["--doctor", "--json", "--modules", "56", "--tool-input"])
        .arg(format!("mlo={}", verdicts.display()))
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("doctor prints its JSON report even when the preflight fails");
    assert_eq!(report["modules"][0]["module"], 56);
    assert_eq!(report["modules"][0]["status"], "available");
    assert!(report["modules"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("mlo-analyzer"));
    // No module-level failure is allowed.
    assert!(report["modules"]
        .as_array()
        .unwrap()
        .iter()
        .all(|module| module["status"] != "failed"));
}

#[test]
fn userspace_module_without_tool_input_is_unsupported() {
    let output = Command::new(env!("CARGO_BIN_EXE_staticzero-defense"))
        .args(["--doctor", "--json", "--modules", "61"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["modules"][0]["module"], 61);
    assert_eq!(report["modules"][0]["status"], "unsupported");
    assert!(report["modules"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("--tool-input d2c="));
}

#[test]
fn unreadable_tool_input_fails_the_preflight() {
    let output = Command::new(env!("CARGO_BIN_EXE_staticzero-defense"))
        .args(["--doctor", "--json", "--modules", "62", "--tool-input"])
        .arg("osnma=/nonexistent/verdicts.jsonl")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["modules"][0]["module"], 62);
    assert_eq!(report["modules"][0]["status"], "failed");
}

#[test]
fn invalid_tool_input_kind_is_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_staticzero-defense"))
        .args(["--doctor", "--tool-input"])
        .arg("bogus=/tmp/x")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("unknown tool kind"));
}

#[test]
fn sixg_tool_inputs_activate_their_modules() {
    let verdicts = std::env::temp_dir().join("staticzero-sixg-doctor-test.jsonl");
    std::fs::write(&verdicts, "\n").expect("write temp verdict file");
    let output = Command::new(env!("CARGO_BIN_EXE_staticzero-defense"))
        .args(["--doctor", "--json", "--modules", "66,67,70"])
        .args([
            "--tool-input",
            &format!("airan={}", verdicts.display()),
            "--tool-input",
            &format!("pqc={}", verdicts.display()),
            "--tool-input",
            &format!("noncred={}", verdicts.display()),
        ])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&verdicts);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("doctor prints its JSON report even when the preflight fails");
    let modules = report["modules"].as_array().unwrap();
    assert_eq!(modules.len(), 3);
    for module in modules {
        assert_eq!(module["status"], "available", "module {module:?}");
        assert!(module["detail"]
            .as_str()
            .unwrap()
            .contains("6g-sim verdicts"));
    }
}
