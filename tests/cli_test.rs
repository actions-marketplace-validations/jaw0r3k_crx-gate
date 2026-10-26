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

#[test]
fn test_cli_audit_html_format() {
    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args(&["audit", "tests/fixtures/clean_mv3", "--format", "html"])
        .output()
        .expect("Failed to execute crx-gate binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("<!DOCTYPE html>"));
    assert!(stdout.contains("Clean Focus Timer"));
    assert!(stdout.contains("crx-gate Security Audit"));
}

#[test]
fn test_cli_audit_markdown_format() {
    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args(&["audit", "tests/fixtures/clean_mv3", "--format", "markdown"])
        .output()
        .expect("Failed to execute crx-gate binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("# 🛡️ crx-gate Security & Blast-Radius Audit"));
    assert!(stdout.contains("Clean Focus Timer"));
    assert!(stdout.contains("Blast-Radius Grade"));
}

#[test]
fn test_cli_init_and_hook_install() {
    let bin = get_bin_path();
    let temp_dir = std::env::temp_dir().join(format!("crx_gate_cli_test_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    // 1. Run init
    let init_output = Command::new(&bin)
        .args(&["init"])
        .current_dir(&temp_dir)
        .output()
        .expect("Failed to execute init");
    let stdout = String::from_utf8_lossy(&init_output.stdout);
    let stderr = String::from_utf8_lossy(&init_output.stderr);
    assert!(init_output.status.success(), "Init failed!\nSTDOUT: {}\nSTDERR: {}", stdout, stderr);
    let config_path = temp_dir.join("crx-gate.toml");
    assert!(config_path.exists(), "crx-gate.toml must be created");

    // 2. Prepare mock .git/hooks directory and test hook install
    let hooks_dir = temp_dir.join(".git").join("hooks");
    std::fs::create_dir_all(&hooks_dir).unwrap();

    let hook_output = Command::new(&bin)
        .args(&["hook", "install"])
        .current_dir(&temp_dir)
        .output()
        .expect("Failed to execute hook install");
    assert!(hook_output.status.success());
    let hook_file = hooks_dir.join("pre-commit");
    assert!(hook_file.exists(), ".git/hooks/pre-commit must be created");

    let hook_content = std::fs::read_to_string(&hook_file).unwrap();
    assert!(hook_content.contains("crx-gate audit"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_completions_generation() {
    let bin = get_bin_path();
    for shell in &["bash", "zsh", "fish", "powershell"] {
        let output = Command::new(&bin)
            .args(&["completions", shell])
            .output()
            .expect("Failed to execute completions command");

        assert!(output.status.success(), "Completions for {} failed", shell);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(!stdout.is_empty());
        assert!(stdout.contains("crx-gate") || stdout.contains("crx__gate"));
    }
}

#[test]
fn test_cli_audit_nonexistent_path_fails() {
    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args(&["audit", "this/path/does/not/exist_12345"])
        .output()
        .expect("Failed to execute audit");

    assert!(!output.status.success(), "Non-existent path audit must fail with non-zero exit code");
}
