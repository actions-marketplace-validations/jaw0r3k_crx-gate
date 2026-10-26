use std::process::Command;

fn get_bin_path() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove test exe name
    path.pop(); // Remove deps
    path.push("crx-gate.exe");
    if !path.exists() {
        path.set_extension("");
    }
    path
}

#[test]
fn test_cli_audit_clean_extension() {
    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args(&["audit", "tests/fixtures/clean_mv3", "--benchmark"])
        .output()
        .expect("Failed to execute crx-gate binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        panic!("Clean audit failed:\nSTDOUT:\n{}\nSTDERR:\n{}", stdout, stderr);
    }
    assert!(stdout.contains("Blast Radius Grade: A"));
    assert!(stdout.contains("Score: 10 /100"));
    assert!(stdout.contains("AUTOMATED PASS LIKELY"));
}

#[test]
fn test_cli_audit_json_format() {
    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args(&["audit", "tests/fixtures/clean_mv3", "--format", "json"])
        .output()
        .expect("Failed to execute crx-gate binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("Stdout must be valid JSON");
    assert_eq!(parsed["extension_name"], "Clean Focus Timer");
    assert_eq!(parsed["manifest_version"], 3);
    assert_eq!(parsed["score"]["total_score"], 10);
}

#[test]
fn test_cli_audit_sarif_format() {
    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args(&["audit", "tests/fixtures/cws_rejection", "--format", "sarif", "--fail-on", "none", "--max-score", "100"])
        .output()
        .expect("Failed to execute crx-gate binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("Stdout must be valid SARIF JSON");
    assert_eq!(parsed["version"], "2.1.0");
    assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "crx-gate");
}

#[test]
fn test_cli_audit_failure_thresholds() {
    let bin = get_bin_path();

    // 1. Fails when fail_on is high and critical/high issues are found
    let output_fail = Command::new(&bin)
        .args(&["audit", "tests/fixtures/exfiltrator_leak", "--fail-on", "high"])
        .output()
        .unwrap();
    assert!(!output_fail.status.success(), "Exfiltrator leak must fail with exit code 1");

    // 2. Passes when fail_on is none and max-score is 100
    let output_pass = Command::new(&bin)
        .args(&["audit", "tests/fixtures/exfiltrator_leak", "--fail-on", "none", "--max-score", "100"])
        .output()
        .unwrap();
    assert!(output_pass.status.success(), "Should pass when thresholds are set to ignore");
}

#[test]
fn test_cli_diff_degradation_failure() {
    let bin = get_bin_path();

    // Degradation from clean to exfiltrator should fail with --fail-on-degradation
    let output_fail = Command::new(&bin)
        .args(&["diff", "tests/fixtures/clean_mv3", "tests/fixtures/exfiltrator_leak", "--fail-on-degradation"])
        .output()
        .unwrap();
    assert!(!output_fail.status.success(), "Degradation diff must exit with 1");

    // Identical diff should pass
    let output_pass = Command::new(&bin)
        .args(&["diff", "tests/fixtures/clean_mv3", "tests/fixtures/clean_mv3", "--fail-on-degradation"])
        .output()
        .unwrap();
    assert!(output_pass.status.success(), "Zero-delta diff must exit with 0");
}

#[test]
fn test_cli_rules_listing() {
    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args(&["rules", "--category", "CWS"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        panic!("Rules command failed:\nSTDOUT:\n{}\nSTDERR:\n{}", stdout, stderr);
    }

    assert!(stdout.contains("CRX-GATE — Curated Threat Intel"));
    assert!(stdout.contains("CWS-001"));
    assert!(stdout.contains("CWS-002"));
}
