use crx_gate::manifest::hosts::{calculate_host_blast_radius, HostAnalysis, HostScope};
use crx_gate::manifest::permissions::{api_to_permission, PermissionSeverity, KNOWN_PERMISSIONS};
use crx_gate::manifest::validation::{validate_manifest, ManifestData};
use crx_gate::archive::ExtensionPackage;
use std::collections::HashMap;

#[test]
fn test_known_permissions_severity() {
    let debugger = KNOWN_PERMISSIONS.get("debugger").unwrap();
    assert_eq!(debugger.severity, PermissionSeverity::Critical);
    assert_eq!(debugger.severity.score_weight(), 25);

    let cookies = KNOWN_PERMISSIONS.get("cookies").unwrap();
    assert_eq!(cookies.severity, PermissionSeverity::High);
    assert_eq!(cookies.severity.score_weight(), 12);

    let storage = KNOWN_PERMISSIONS.get("storage").unwrap();
    assert_eq!(storage.severity, PermissionSeverity::Medium);
    assert_eq!(storage.severity.score_weight(), 5);

    let tts = KNOWN_PERMISSIONS.get("tts").unwrap();
    assert_eq!(tts.severity, PermissionSeverity::Low);
    assert_eq!(tts.severity.score_weight(), 2);
}

#[test]
fn test_api_to_permission_mapping() {
    assert_eq!(api_to_permission("chrome.cookies.get"), Some("cookies"));
    assert_eq!(api_to_permission("chrome.cookies.getAll"), Some("cookies"));
    assert_eq!(api_to_permission("chrome.tabs.query"), Some("tabs"));
    assert_eq!(api_to_permission("chrome.storage.local.get"), Some("storage"));
    assert_eq!(api_to_permission("chrome.scripting.executeScript"), Some("scripting"));
    assert_eq!(api_to_permission("chrome.history.search"), Some("history"));
    assert_eq!(api_to_permission("chrome.unknownApi.method"), None);
}

#[test]
fn test_host_scope_classification() {
    let all_urls = HostAnalysis::parse("<all_urls>");
    assert_eq!(all_urls.scope, HostScope::AllUrls);
    assert_eq!(all_urls.is_broad, true);
    assert_eq!(all_urls.risk_weight, 25);

    let wildcard_scheme = HostAnalysis::parse("*://*/*");
    assert_eq!(wildcard_scheme.scope, HostScope::AllUrls);
    assert_eq!(wildcard_scheme.is_broad, true);

    let wildcard_tld = HostAnalysis::parse("https://*.com/*");
    assert_eq!(wildcard_tld.scope, HostScope::WildcardTld);
    assert_eq!(wildcard_tld.is_broad, true);
    assert_eq!(wildcard_tld.risk_weight, 15);

    let subdomain = HostAnalysis::parse("https://*.github.com/*");
    assert_eq!(subdomain.scope, HostScope::WildcardSubdomain);
    assert_eq!(subdomain.is_broad, false);
    assert_eq!(subdomain.risk_weight, 6);

    let specific = HostAnalysis::parse("https://api.github.com/v3");
    assert_eq!(specific.scope, HostScope::SpecificDomain);
    assert_eq!(specific.is_broad, false);
    assert_eq!(specific.risk_weight, 3);

    let local = HostAnalysis::parse("http://localhost:3000/*");
    assert_eq!(local.scope, HostScope::Localhost);
    assert_eq!(local.risk_weight, 1);
}

#[test]
fn test_calculate_host_blast_radius_capping() {
    let hosts = vec![
        "<all_urls>".to_string(),
        "https://*.com/*".to_string(),
        "https://api.github.com/*".to_string(),
    ];
    let (score, analyses) = calculate_host_blast_radius(&hosts);
    assert_eq!(analyses.len(), 3);
    assert_eq!(score, 30, "Host blast radius contribution should be capped at 30");
}

#[test]
fn test_manifest_validation_catches_missing_fields_and_files() {
    let manifest = ManifestData {
        manifest_version: Some(3),
        name: Some("".into()), // empty name!
        version: None,         // missing version!
        icons: Some({
            let mut m = HashMap::new();
            m.insert("48".into(), "icons/non_existent_48.png".into());
            m
        }),
        ..Default::default()
    };

    let empty_pkg = ExtensionPackage {
        root_path: std::path::PathBuf::from("dummy"),
        package_type: crx_gate::archive::PackageType::Directory,
        extension_id: None,
        files: HashMap::new(),
        total_size: 0,
    };

    let issues = validate_manifest(&manifest, &empty_pkg);
    assert!(issues.iter().any(|i| i.code == "CWS-MISSING-NAME"));
    assert!(issues.iter().any(|i| i.code == "CWS-MISSING-VERSION"));
    assert!(issues.iter().any(|i| i.code == "CWS-MISSING-ICON-FILE"));
}

#[test]
fn test_manifest_validation_catches_mv2_deprecation() {
    let manifest = ManifestData {
        manifest_version: Some(2),
        name: Some("Legacy Extension".into()),
        version: Some("1.0.0".into()),
        ..Default::default()
    };

    let empty_pkg = ExtensionPackage {
        root_path: std::path::PathBuf::from("dummy"),
        package_type: crx_gate::archive::PackageType::Directory,
        extension_id: None,
        files: HashMap::new(),
        total_size: 0,
    };

    let issues = validate_manifest(&manifest, &empty_pkg);
    assert!(issues.iter().any(|i| i.code == "CWS-MV2-DEPRECATED"));
}

#[test]
fn test_manifest_validation_catches_unsafe_csp() {
    let manifest = ManifestData {
        manifest_version: Some(3),
        name: Some("Unsafe CSP Extension".into()),
        version: Some("1.0.0".into()),
        content_security_policy: Some(serde_json::json!({
            "extension_pages": "script-src 'self' 'unsafe-eval' https://cdn.external.com; object-src 'self'"
        })),
        ..Default::default()
    };

    let empty_pkg = ExtensionPackage {
        root_path: std::path::PathBuf::from("dummy"),
        package_type: crx_gate::archive::PackageType::Directory,
        extension_id: None,
        files: HashMap::new(),
        total_size: 0,
    };

    let issues = validate_manifest(&manifest, &empty_pkg);
    assert!(issues.iter().any(|i| i.code == "CWS-CSP-UNSAFE-EVAL"));
    assert!(issues.iter().any(|i| i.code == "CWS-CSP-REMOTE-SOURCES"));
}
