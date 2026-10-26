use crx_gate::config::{Config, Waiver};

#[test]
fn test_default_config_values() {
    let cfg = Config::default();
    assert_eq!(cfg.audit.fail_on, "high");
    assert_eq!(cfg.audit.max_score, 70);
    assert_eq!(cfg.audit.ignore_dead_permissions, false);
    assert!(cfg.waivers.is_empty());
}

#[test]
fn test_waiver_path_matching() {
    let mut cfg = Config::default();
    cfg.waivers.push(Waiver {
        rule_id: "CWS-004".into(),
        path: Some("manifest.json".into()),
        reason: "Enterprise requirement".into(),
        expires: Some("2027-01-01".into()),
    });

    assert_eq!(cfg.is_waived("CWS-004", Some("manifest.json")), true);
    assert_eq!(cfg.is_waived("CWS-004", Some("path/to/manifest.json")), true);
    assert_eq!(cfg.is_waived("CWS-004", Some("background.js")), false);
    assert_eq!(cfg.is_waived("CWS-002", Some("manifest.json")), false);
}

#[test]
fn test_global_waiver_matching() {
    let mut cfg = Config::default();
    cfg.waivers.push(Waiver {
        rule_id: "PERM-DEAD".into(),
        path: None, // applies globally across all files
        reason: "Dynamic library loading".into(),
        expires: None,
    });

    assert_eq!(cfg.is_waived("PERM-DEAD", Some("manifest.json")), true);
    assert_eq!(cfg.is_waived("PERM-DEAD", Some("any_file.js")), true);
    assert_eq!(cfg.is_waived("PERM-DEAD", None), true);
    assert_eq!(cfg.is_waived("CWS-002", None), false);
}

#[test]
fn test_toml_deserialization() {
    let toml_str = r#"
        [audit]
        fail_on = "critical"
        max_score = 45
        ignore_dead_permissions = true

        [rules]
        disabled_rules = ["PERM-DEAD"]
        custom_exfiltration_endpoints = ["https://custom.exfil.org"]

        [[waivers]]
        rule_id = "CWS-002"
        path = "vendor/eval.js"
        reason = "Legacy bundled math engine"
    "#;

    let cfg: Config = toml::from_str(toml_str).expect("TOML should deserialize cleanly");
    assert_eq!(cfg.audit.fail_on, "critical");
    assert_eq!(cfg.audit.max_score, 45);
    assert_eq!(cfg.audit.ignore_dead_permissions, true);
    assert_eq!(cfg.rules.disabled_rules, vec!["PERM-DEAD"]);
    assert_eq!(cfg.rules.custom_exfiltration_endpoints, vec!["https://custom.exfil.org"]);
    assert_eq!(cfg.waivers.len(), 1);
    assert!(cfg.is_waived("CWS-002", Some("vendor/eval.js")));
}
