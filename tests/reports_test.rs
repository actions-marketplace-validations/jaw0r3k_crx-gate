use crx_gate::report::sarif::generate_sarif_report;
use crx_gate::report::table::ScanFinding;
use crx_gate::report::{render_json_report, render_markdown_report, JsonReport};
use crx_gate::scorer::{BlastRadiusScore, RiskLevel, ScoreBreakdown};
use crx_gate::taint::{NetworkSinkKind, SensitiveSourceKind, TaintLeakPath};

#[test]
fn test_sarif_report_generation() {
    let findings = vec![
        ScanFinding {
            rule_id: "CWS-002".into(),
            title: "Dynamic Code Execution".into(),
            severity: "critical".into(),
            category: "CWS Policy".into(),
            file_path: Some("background.js".into()),
            line: Some(42),
            col: Some(10),
            snippet: Some("eval(code)".into()),
            description: "eval() is prohibited by MV3 CSP".into(),
            remediation: "Refactor to static functions".into(),
            cws_policy_ref: Some("MV3 CSP Reference".into()),
        },
        ScanFinding {
            rule_id: "PERM-DEAD".into(),
            title: "Dead Declared Permission".into(),
            severity: "low".into(),
            category: "Least Privilege".into(),
            file_path: Some("manifest.json".into()),
            line: None,
            col: None,
            snippet: None,
            description: "Permission 'bookmarks' unused".into(),
            remediation: "Remove from manifest.json".into(),
            cws_policy_ref: None,
        },
    ];

    let sarif = generate_sarif_report(&findings);
    assert_eq!(sarif.version, "2.1.0");
    assert_eq!(sarif.runs.len(), 1);

    let run = &sarif.runs[0];
    assert_eq!(run.tool.driver.name, "crx-gate");
    assert_eq!(run.tool.driver.rules.len(), 2);
    assert_eq!(run.results.len(), 2);

    // Critical mapped to error, low mapped to note
    assert_eq!(run.results[0].level, "error");
    assert_eq!(run.results[1].level, "note");

    let loc0 = &run.results[0].locations[0];
    assert_eq!(loc0.physical_location.artifact_location.uri, "background.js");
    let region = loc0.physical_location.region.as_ref().unwrap();
    assert_eq!(region.start_line, 42);
    assert_eq!(region.start_column, Some(10));
}

#[test]
fn test_json_report_serialization_roundtrip() {
    let score = BlastRadiusScore {
        total_score: 45,
        grade: "C".into(),
        risk_level: RiskLevel::Medium,
        breakdown: ScoreBreakdown {
            permissions_score: 15,
            host_scope_score: 20,
            taint_exfiltration_score: 0,
            vulnerability_score: 10,
        },
        predicted_cws_verdict: "MANUAL_REVIEW_LIKELY".into(),
        critical_count: 0,
        high_count: 1,
        medium_count: 2,
        low_count: 0,
    };

    let findings = vec![ScanFinding {
        rule_id: "CWS-004".into(),
        title: "Broad Host".into(),
        severity: "high".into(),
        category: "Host".into(),
        file_path: Some("manifest.json".into()),
        line: None,
        col: None,
        snippet: None,
        description: "Wildcard host".into(),
        remediation: "Scope it".into(),
        cws_policy_ref: None,
    }];

    let json_str = render_json_report(
        "./test-ext",
        "Directory",
        Some("abcdefghijklmnopabcdefghijklmnop"),
        "Test Extension",
        "1.2.3",
        3,
        &score,
        &findings,
        &[],
        15,
    );

    let parsed: JsonReport = serde_json::from_str(&json_str).expect("JSON must parse into JsonReport");
    assert_eq!(parsed.extension_name, "Test Extension");
    assert_eq!(parsed.score.total_score, 45);
    assert_eq!(parsed.score.grade, "C");
    assert_eq!(parsed.findings.len(), 1);
    assert_eq!(parsed.findings[0].rule_id, "CWS-004");
}

#[test]
fn test_html_report_generation() {
    let score = BlastRadiusScore {
        total_score: 85,
        grade: "F".into(),
        risk_level: RiskLevel::Critical,
        breakdown: ScoreBreakdown {
            permissions_score: 25,
            host_scope_score: 25,
            taint_exfiltration_score: 25,
            vulnerability_score: 10,
        },
        predicted_cws_verdict: "REJECTION_LIKELY".into(),
        critical_count: 2,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
    };

    let findings = vec![ScanFinding {
        rule_id: "SEC-C2-ENDPOINT".into(),
        title: "C2 Webhook Detected".into(),
        severity: "critical".into(),
        category: "Threat Intel".into(),
        file_path: Some("background.js".into()),
        line: Some(15),
        col: Some(4),
        snippet: Some("fetch('https://discord.com/api/webhooks/...')".into()),
        description: "Hardcoded Discord webhook".into(),
        remediation: "Remove webhook".into(),
        cws_policy_ref: None,
    }];

    let html = crx_gate::report::render_html_report(
        "./test-ext",
        "Directory",
        Some("dummy_ext_id"),
        "HTML Test Ext",
        "2.0.0",
        3,
        &score,
        &findings,
        &[],
        2,
    );

    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("HTML Test Ext"));
    assert!(html.contains("SEC-C2-ENDPOINT"));
    assert!(html.contains("85/100"));
    assert!(html.contains("CRITICAL RISK"));
    assert!(html.contains("dummy_ext_id"));
}

#[test]
fn test_markdown_report_formatting() {
    let score = BlastRadiusScore {
        total_score: 95,
        grade: "F".into(),
        risk_level: RiskLevel::Critical,
        breakdown: ScoreBreakdown {
            permissions_score: 25,
            host_scope_score: 25,
            taint_exfiltration_score: 25,
            vulnerability_score: 20,
        },
        predicted_cws_verdict: "REJECTION_LIKELY".into(),
        critical_count: 2,
        high_count: 1,
        medium_count: 0,
        low_count: 0,
    };

    let taint = vec![TaintLeakPath {
        source_kind: SensitiveSourceKind::Cookies,
        source_api: "chrome.cookies.getAll".into(),
        source_location: "background.js:10".into(),
        sink_kind: NetworkSinkKind::Fetch,
        sink_api: "fetch".into(),
        sink_location: "background.js:25".into(),
        sink_target_url: Some("https://evil.com/exfil".into()),
        flow_trace: vec!["Source: chrome.cookies.getAll".into(), "Sink: fetch".into()],
        severity: "critical".into(),
        title: "Confirmed Exfiltration".into(),
        description: "Cookies leaked".into(),
        remediation: "Stop leaking".into(),
    }];

    let md = render_markdown_report(
        "./dist",
        "CRX v3",
        Some("test_id"),
        "Sample Malware Ext",
        "0.0.1",
        3,
        &score,
        &[],
        &taint,
        4,
    );

    assert!(md.contains("# 🛡️ crx-gate Security & Blast-Radius Audit"));
    assert!(md.contains("Blast-Radius Grade"));
    assert!(md.contains("**F**"));
    assert!(md.contains("95/100"));
    assert!(md.contains("CONFIRMED LEAK"));
    assert!(md.contains("https://evil.com/exfil"));
}
