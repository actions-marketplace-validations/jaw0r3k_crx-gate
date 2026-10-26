use crx_gate::archive::crx::compute_extension_id;
use crx_gate::archive::ExtensionPackage;
use crx_gate::config::Config;
use crx_gate::Scanner;
use std::fs::File;
use std::io::Write;

#[test]
fn test_clean_mv3_audit() {
    let config = Config::default();
    let scanner = Scanner::new(config);
    let result = scanner
        .scan("tests/fixtures/clean_mv3")
        .expect("Scan should succeed");

    assert!(result.score.total_score <= 15, "Clean extension should have low score");
    assert!(result.score.grade == "A+" || result.score.grade == "A");
    assert_eq!(result.score.predicted_cws_verdict, "AUTOMATED_PASS_LIKELY");
    assert_eq!(result.taint_paths.len(), 0, "No taint leaks in clean extension");
    assert_eq!(result.score.critical_count, 0, "Zero critical findings");
    assert!(
        result.execution_duration_ms < 200,
        "Execution should complete in under 200ms (took {}ms)",
        result.execution_duration_ms
    );
}

#[test]
fn test_exfiltrator_leak_detection() {
    let config = Config::default();
    let scanner = Scanner::new(config);
    let result = scanner
        .scan("tests/fixtures/exfiltrator_leak")
        .expect("Scan should succeed");

    // Blast radius should be critical
    assert!(result.score.total_score >= 70, "Exfiltrator extension must have high blast radius");
    assert_eq!(result.score.grade, "F");

    // Check confirmed taint leak path
    assert!(
        !result.taint_paths.is_empty(),
        "Must detect cookie to fetch taint leak path"
    );
    let has_cookie_leak = result.taint_paths.iter().any(|leak| leak.source_api.contains("cookies"));
    assert!(has_cookie_leak, "Must detect cookie to fetch taint leak path");

    // Check findings for C2 endpoint and wildcard hosts
    let has_c2 = result.findings.iter().any(|f| f.rule_id == "SEC-C2-ENDPOINT");
    assert!(has_c2, "Must detect Discord webhook C2 endpoint");

    let has_wildcard = result.findings.iter().any(|f| f.rule_id == "CWS-004");
    assert!(has_wildcard, "Must detect <all_urls> wildcard host permission");
}

#[test]
fn test_overprivileged_and_dead_permissions() {
    let config = Config::default();
    let scanner = Scanner::new(config);
    let result = scanner
        .scan("tests/fixtures/overprivileged")
        .expect("Scan should succeed");

    // Check dead permissions (bookmarks and history declared but never called)
    let dead_perms: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "PERM-DEAD")
        .collect();
    assert!(
        dead_perms.len() >= 2,
        "Expected at least 2 dead permissions (bookmarks, history), found: {}",
        dead_perms.len()
    );

    // Check overprivileged tabs (tab.id accessed, but not sensitive tab.url/title)
    let has_overprivileged_tabs = result
        .findings
        .iter()
        .any(|f| f.rule_id == "PERM-OVERPRIVILEGED");
    assert!(
        has_overprivileged_tabs,
        "Expected PERM-OVERPRIVILEGED for tabs when only tab.id is used"
    );

    // Check missing action declaration
    let has_missing_action = result.findings.iter().any(|f| f.rule_id == "CWS-009");
    assert!(
        has_missing_action,
        "Expected CWS-009 when chrome.action is invoked without 'action' in manifest"
    );
}

#[test]
fn test_dnr_tampering_rulesets() {
    let config = Config::default();
    let scanner = Scanner::new(config);
    let result = scanner
        .scan("tests/fixtures/dnr_tampering")
        .expect("Scan should succeed");

    let has_csp_tamper = result.findings.iter().any(|f| f.rule_id == "DNR-TAMPER-CSP");
    assert!(
        has_csp_tamper,
        "Must flag declarativeNetRequest rule stripping CSP / XFO"
    );

    let has_auth_tamper = result.findings.iter().any(|f| f.rule_id == "DNR-AUTH-THEFT");
    assert!(
        has_auth_tamper,
        "Must flag declarativeNetRequest rule mutating request Cookie header"
    );
}

#[test]
fn test_cws_rejection_triggers() {
    let config = Config::default();
    let scanner = Scanner::new(config);
    let result = scanner
        .scan("tests/fixtures/cws_rejection")
        .expect("Scan should succeed");

    assert_eq!(result.score.predicted_cws_verdict, "REJECTION_LIKELY");

    // Check missing icon file trigger
    let has_missing_icon = result.findings.iter().any(|f| f.rule_id == "CWS-MISSING-ICON-FILE");
    assert!(has_missing_icon, "Must detect missing icon files in manifest");

    // Check eval / Function CSP trigger
    let has_eval = result.findings.iter().any(|f| f.rule_id == "CWS-002");
    assert!(has_eval, "Must detect eval() and new Function() calls");

    // Check inline script in HTML trigger
    let has_inline_html = result.findings.iter().any(|f| f.rule_id == "CWS-006");
    assert!(has_inline_html, "Must detect inline script and onclick handler in popup.html");
}

#[test]
fn test_diff_engine() {
    let config = Config::default();
    let scanner = Scanner::new(config);

    let diff = scanner
        .diff("tests/fixtures/clean_mv3", "tests/fixtures/exfiltrator_leak")
        .expect("Diff should succeed");

    assert!(diff.score_delta > 0, "Score delta must reflect degradation");
    assert!(diff.added_permissions.contains(&"cookies".to_string()));
    assert!(diff.added_hosts.contains(&"<all_urls>".to_string()));
    assert!(!diff.new_taint_paths.is_empty(), "Must report new taint paths in diff");
    assert!(!diff.new_findings.is_empty(), "Must report new findings in diff");
}

#[test]
fn test_crx_packaging_and_id_computation() {
    // Test 32-character extension ID generation from public key bytes
    let dummy_pubkey = b"dummy_rsa_public_key_bytes_for_testing_1234567890";
    let ext_id = compute_extension_id(dummy_pubkey);
    assert_eq!(ext_id.len(), 32);
    assert!(ext_id.chars().all(|c| c >= 'a' && c <= 'p'));

    // Create a temporary zip package and verify loading
    let temp_zip_path = "tests/fixtures/test_package.zip";
    {
        let file = File::create(temp_zip_path).unwrap();
        let mut zip_writer = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        zip_writer.start_file("manifest.json", options).unwrap();
        zip_writer.write_all(b"{\"manifest_version\": 3, \"name\": \"Zip Ext\", \"version\": \"1.0.0\"}").unwrap();
        zip_writer.finish().unwrap();
    }

    let pkg = ExtensionPackage::load(temp_zip_path).expect("Should load zip package");
    assert_eq!(pkg.has_file("manifest.json"), true);

    // Clean up temporary file
    let _ = std::fs::remove_file(temp_zip_path);
}
