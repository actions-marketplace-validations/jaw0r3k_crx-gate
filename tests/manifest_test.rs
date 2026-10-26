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

#[test]
fn test_manifest_validation_catches_externally_connectable_wildcards() {
    let manifest_wildcard = ManifestData {
        manifest_version: Some(3),
        name: Some("Wildcard Connectable".into()),
        version: Some("1.0.0".into()),
        externally_connectable: Some(crx_gate::manifest::validation::ExternallyConnectableEntry {
            matches: vec!["*://*/*".into()],
            ..Default::default()
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

    let issues = validate_manifest(&manifest_wildcard, &empty_pkg);
    assert!(issues.iter().any(|i| i.code == "SEC-EXT-CONNECTABLE"));

    // Verify safe explicit matches do NOT trigger it
    let manifest_safe = ManifestData {
        manifest_version: Some(3),
        name: Some("Safe Connectable".into()),
        version: Some("1.0.0".into()),
        externally_connectable: Some(crx_gate::manifest::validation::ExternallyConnectableEntry {
            matches: vec!["https://auth.internal-corp.com/*".into()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let issues_safe = validate_manifest(&manifest_safe, &empty_pkg);
    assert!(!issues_safe.iter().any(|i| i.code == "SEC-EXT-CONNECTABLE"));
}

#[test]
fn test_manifest_validation_catches_web_accessible_resources_wildcard() {
    let manifest_wildcard = ManifestData {
        manifest_version: Some(3),
        name: Some("Wildcard WAR".into()),
        version: Some("1.0.0".into()),
        web_accessible_resources: vec![serde_json::json!({
            "resources": ["assets/logo.png"],
            "matches": ["*://*/*"]
        })],
        ..Default::default()
    };

    let empty_pkg = ExtensionPackage {
        root_path: std::path::PathBuf::from("dummy"),
        package_type: crx_gate::archive::PackageType::Directory,
        extension_id: None,
        files: HashMap::new(),
        total_size: 0,
    };

    let issues = validate_manifest(&manifest_wildcard, &empty_pkg);
    assert!(issues.iter().any(|i| i.code == "SEC-WAR-WILDCARD"));

    // Verify safe scoped matches do NOT trigger it
    let manifest_safe = ManifestData {
        manifest_version: Some(3),
        name: Some("Safe WAR".into()),
        version: Some("1.0.0".into()),
        web_accessible_resources: vec![serde_json::json!({
            "resources": ["assets/logo.png"],
            "matches": ["https://partner.com/*"]
        })],
        ..Default::default()
    };
    let issues_safe = validate_manifest(&manifest_safe, &empty_pkg);
    assert!(!issues_safe.iter().any(|i| i.code == "SEC-WAR-WILDCARD"));
}

#[test]
fn test_manifest_metadata_quality_check() {
    let empty_pkg = ExtensionPackage {
        root_path: std::path::PathBuf::from("dummy"),
        package_type: crx_gate::archive::PackageType::Directory,
        extension_id: None,
        files: HashMap::new(),
        total_size: 0,
    };

    // 1. Missing description
    let manifest_missing = ManifestData {
        manifest_version: Some(3),
        name: Some("Valid Name".into()),
        version: Some("1.0.0".into()),
        description: None,
        ..Default::default()
    };
    let issues1 = validate_manifest(&manifest_missing, &empty_pkg);
    assert!(issues1.iter().any(|i| i.code == "CWS-011"));

    // 2. Short placeholder description (< 25 chars)
    let manifest_short = ManifestData {
        manifest_version: Some(3),
        name: Some("Valid Name".into()),
        version: Some("1.0.0".into()),
        description: Some("My tool".into()),
        ..Default::default()
    };
    let issues2 = validate_manifest(&manifest_short, &empty_pkg);
    assert!(issues2.iter().any(|i| i.code == "CWS-011"));

    // 3. Adequate description (>= 25 chars)
    let manifest_good = ManifestData {
        manifest_version: Some(3),
        name: Some("Valid Name".into()),
        version: Some("1.0.0".into()),
        description: Some("A productivity timer that blocks distractions and tracks study hours.".into()),
        ..Default::default()
    };
    let issues3 = validate_manifest(&manifest_good, &empty_pkg);
    assert!(!issues3.iter().any(|i| i.code == "CWS-011"));
}

#[test]
fn test_nuclear_debugger_permission_check() {
    let empty_pkg = ExtensionPackage {
        root_path: std::path::PathBuf::from("dummy"),
        package_type: crx_gate::archive::PackageType::Directory,
        extension_id: None,
        files: HashMap::new(),
        total_size: 0,
    };

    let manifest_debugger = ManifestData {
        manifest_version: Some(3),
        name: Some("Dev Extension".into()),
        version: Some("1.0.0".into()),
        description: Some("Extensive developer profiling extension with detailed logs.".into()),
        permissions: vec!["debugger".into(), "storage".into()],
        ..Default::default()
    };
    let issues = validate_manifest(&manifest_debugger, &empty_pkg);
    assert!(issues.iter().any(|i| i.code == "CWS-013"));
}

#[test]
fn test_content_script_all_frames_wildcard_check() {
    let empty_pkg = ExtensionPackage {
        root_path: std::path::PathBuf::from("dummy"),
        package_type: crx_gate::archive::PackageType::Directory,
        extension_id: None,
        files: HashMap::new(),
        total_size: 0,
    };

    let manifest_all_frames = ManifestData {
        manifest_version: Some(3),
        name: Some("Frame Injector".into()),
        version: Some("1.0.0".into()),
        description: Some("Injects tracking and styling helper scripts into all frames across the web.".into()),
        content_scripts: vec![crx_gate::manifest::validation::ContentScriptEntry {
            matches: vec!["<all_urls>".into()],
            all_frames: Some(true),
            ..Default::default()
        }],
        ..Default::default()
    };
    let issues = validate_manifest(&manifest_all_frames, &empty_pkg);
    assert!(issues.iter().any(|i| i.code == "CWS-014"));
}

#[test]
fn test_warn_mv3_browser_action_migration() {
    let empty_pkg = ExtensionPackage {
        root_path: std::path::PathBuf::from("dummy"),
        package_type: crx_gate::archive::PackageType::Directory,
        extension_id: None,
        files: HashMap::new(),
        total_size: 0,
    };

    let manifest = ManifestData {
        manifest_version: Some(3),
        name: Some("MV3 with MV2 popup".into()),
        version: Some("1.0.0".into()),
        description: Some("Extension testing deprecated browser_action key in manifest v3.".into()),
        browser_action: Some(serde_json::json!({ "default_popup": "popup.html" })),
        ..Default::default()
    };
    let issues = validate_manifest(&manifest, &empty_pkg);
    assert!(issues.iter().any(|i| i.code == "WARN-MV3-BROWSER-ACTION"));
}

#[test]
fn test_warn_mv3_background_scripts_migration() {
    let empty_pkg = ExtensionPackage {
        root_path: std::path::PathBuf::from("dummy"),
        package_type: crx_gate::archive::PackageType::Directory,
        extension_id: None,
        files: HashMap::new(),
        total_size: 0,
    };

    let manifest = ManifestData {
        manifest_version: Some(3),
        name: Some("MV3 with MV2 bg".into()),
        version: Some("1.0.0".into()),
        description: Some("Extension testing background.scripts instead of service worker.".into()),
        background: Some(crx_gate::manifest::validation::BackgroundEntry {
            service_worker: None,
            scripts: vec!["background.js".into()],
            r#type: None,
        }),
        ..Default::default()
    };
    let issues = validate_manifest(&manifest, &empty_pkg);
    assert!(issues.iter().any(|i| i.code == "WARN-MV3-BACKGROUND-SCRIPTS"));
}

#[test]
fn test_warn_mv3_csp_string_migration() {
    let empty_pkg = ExtensionPackage {
        root_path: std::path::PathBuf::from("dummy"),
        package_type: crx_gate::archive::PackageType::Directory,
        extension_id: None,
        files: HashMap::new(),
        total_size: 0,
    };

    let manifest = ManifestData {
        manifest_version: Some(3),
        name: Some("MV3 with String CSP".into()),
        version: Some("1.0.0".into()),
        description: Some("Extension testing legacy string content security policy format.".into()),
        content_security_policy: Some(serde_json::json!("script-src 'self' 'unsafe-eval'")),
        ..Default::default()
    };
    let issues = validate_manifest(&manifest, &empty_pkg);
    assert!(issues.iter().any(|i| i.code == "WARN-MV3-CSP-STRING"));
}

#[test]
fn test_warn_mv3_webrequest_blocking_migration() {
    let empty_pkg = ExtensionPackage {
        root_path: std::path::PathBuf::from("dummy"),
        package_type: crx_gate::archive::PackageType::Directory,
        extension_id: None,
        files: HashMap::new(),
        total_size: 0,
    };

    let manifest = ManifestData {
        manifest_version: Some(3),
        name: Some("MV3 Blocking".into()),
        version: Some("1.0.0".into()),
        description: Some("Extension testing deprecated webRequestBlocking permission in MV3.".into()),
        permissions: vec!["webRequestBlocking".into(), "storage".into()],
        ..Default::default()
    };
    let issues = validate_manifest(&manifest, &empty_pkg);
    assert!(issues.iter().any(|i| i.code == "WARN-MV3-WEBREQUEST-BLOCKING"));
}
