use crate::archive::ExtensionPackage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManifestData {
    pub manifest_version: Option<u32>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub optional_permissions: Vec<String>,
    #[serde(default)]
    pub host_permissions: Vec<String>,
    #[serde(default)]
    pub content_scripts: Vec<ContentScriptEntry>,
    pub background: Option<BackgroundEntry>,
    pub action: Option<serde_json::Value>,
    pub browser_action: Option<serde_json::Value>,
    pub page_action: Option<serde_json::Value>,
    pub icons: Option<HashMap<String, String>>,
    pub side_panel: Option<serde_json::Value>,
    pub options_page: Option<String>,
    pub options_ui: Option<OptionsUiEntry>,
    pub devtools_page: Option<String>,
    pub declarative_net_request: Option<DnrRuleResourcesEntry>,
    pub content_security_policy: Option<serde_json::Value>,
    pub sandbox: Option<SandboxEntry>,
    pub externally_connectable: Option<ExternallyConnectableEntry>,
    #[serde(default)]
    pub web_accessible_resources: Vec<serde_json::Value>,
    pub key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExternallyConnectableEntry {
    #[serde(default)]
    pub matches: Vec<String>,
    #[serde(default)]
    pub ids: Vec<String>,
    pub accept_tls_channel_id: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContentScriptEntry {
    #[serde(default)]
    pub matches: Vec<String>,
    #[serde(default)]
    pub js: Vec<String>,
    #[serde(default)]
    pub css: Vec<String>,
    pub run_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BackgroundEntry {
    pub service_worker: Option<String>,
    #[serde(default)]
    pub scripts: Vec<String>,
    pub r#type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OptionsUiEntry {
    pub page: Option<String>,
    pub open_in_tab: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnrRuleResourcesEntry {
    #[serde(default)]
    pub rule_resources: Vec<DnrResourcePath>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnrResourcePath {
    pub id: String,
    pub enabled: bool,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SandboxEntry {
    #[serde(default)]
    pub pages: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub code: String,
    pub severity: String,
    pub message: String,
    pub file_reference: Option<String>,
    pub remediation: String,
}

pub fn validate_manifest(manifest: &ManifestData, package: &ExtensionPackage) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    // 1. Manifest version check
    match manifest.manifest_version {
        Some(3) => {}
        Some(2) => {
            issues.push(ValidationIssue {
                code: "CWS-MV2-DEPRECATED".into(),
                severity: "critical".into(),
                message: "Extension uses deprecated Manifest V2. Chrome Web Store rejects new V2 submissions and Chrome is disabling existing V2 extensions.".into(),
                file_reference: Some("manifest.json".into()),
                remediation: "Upgrade manifest to Manifest V3: set 'manifest_version': 3 and replace background scripts with service_worker.".into(),
            });
        }
        Some(v) => {
            issues.push(ValidationIssue {
                code: "CWS-INVALID-MV".into(),
                severity: "critical".into(),
                message: format!("Unsupported manifest_version: {}. Manifest V3 is required.", v),
                file_reference: Some("manifest.json".into()),
                remediation: "Set 'manifest_version': 3.".into(),
            });
        }
        None => {
            issues.push(ValidationIssue {
                code: "CWS-MISSING-MV".into(),
                severity: "critical".into(),
                message: "Missing 'manifest_version' field in manifest.json.".into(),
                file_reference: Some("manifest.json".into()),
                remediation: "Add '\"manifest_version\": 3' to manifest.json.".into(),
            });
        }
    }

    // 2. Name & Version
    if manifest.name.as_deref().unwrap_or("").trim().is_empty() {
        issues.push(ValidationIssue {
            code: "CWS-MISSING-NAME".into(),
            severity: "critical".into(),
            message: "Missing or empty extension 'name' in manifest.json.".into(),
            file_reference: Some("manifest.json".into()),
            remediation: "Provide a descriptive 'name' for the extension.".into(),
        });
    }

    if manifest.version.as_deref().unwrap_or("").trim().is_empty() {
        issues.push(ValidationIssue {
            code: "CWS-MISSING-VERSION".into(),
            severity: "critical".into(),
            message: "Missing or empty 'version' in manifest.json.".into(),
            file_reference: Some("manifest.json".into()),
            remediation: "Add a valid semver version string (e.g. '1.0.0').".into(),
        });
    }

    // 3. Icons verification
    if let Some(icons) = &manifest.icons {
        for (size, path) in icons {
            if !package.has_file(path) {
                issues.push(ValidationIssue {
                    code: "CWS-MISSING-ICON-FILE".into(),
                    severity: "critical".into(),
                    message: format!("Manifest references non-existent icon file for size {}: '{}'. This triggers instant Chrome Web Store rejection.", size, path),
                    file_reference: Some(path.clone()),
                    remediation: format!("Create the icon file at '{}' with exact {}x{}px dimensions or omit this icon size.", path, size, size),
                });
            }
        }
    }

    // 4. Background service worker verification
    if let Some(bg) = &manifest.background {
        if let Some(sw) = &bg.service_worker {
            if !package.has_file(sw) {
                issues.push(ValidationIssue {
                    code: "CWS-MISSING-SERVICE-WORKER".into(),
                    severity: "critical".into(),
                    message: format!("Declared service worker file does not exist: '{}'.", sw),
                    file_reference: Some(sw.clone()),
                    remediation: format!("Create background script at '{}'.", sw),
                });
            }
        } else if !bg.scripts.is_empty() && manifest.manifest_version == Some(3) {
            issues.push(ValidationIssue {
                code: "CWS-MV3-BACKGROUND-SCRIPTS".into(),
                severity: "critical".into(),
                message: "'background.scripts' is illegal in Manifest V3. Use 'background.service_worker' instead.".into(),
                file_reference: Some("manifest.json".into()),
                remediation: "Replace 'background.scripts' array with '\"background\": { \"service_worker\": \"background.js\" }'.".into(),
            });
        }
    }

    // 5. Action default popup and icon verification
    if let Some(action) = &manifest.action {
        if let Some(popup) = action.get("default_popup").and_then(|v| v.as_str()) {
            if !package.has_file(popup) {
                issues.push(ValidationIssue {
                    code: "CWS-MISSING-POPUP-FILE".into(),
                    severity: "critical".into(),
                    message: format!("Action default_popup references missing file: '{}'.", popup),
                    file_reference: Some(popup.to_string()),
                    remediation: format!("Create popup HTML at '{}' or remove default_popup property.", popup),
                });
            }
        }
    }

    // 6. Content scripts file existence
    for cs in &manifest.content_scripts {
        for js_file in &cs.js {
            if !package.has_file(js_file) {
                issues.push(ValidationIssue {
                    code: "CWS-MISSING-CONTENT-SCRIPT".into(),
                    severity: "critical".into(),
                    message: format!("Content script references non-existent JS file: '{}'.", js_file),
                    file_reference: Some(js_file.clone()),
                    remediation: format!("Ensure '{}' is bundled and exists in package root.", js_file),
                });
            }
        }
        for css_file in &cs.css {
            if !package.has_file(css_file) {
                issues.push(ValidationIssue {
                    code: "CWS-MISSING-CONTENT-STYLE".into(),
                    severity: "high".into(),
                    message: format!("Content script references non-existent CSS file: '{}'.", css_file),
                    file_reference: Some(css_file.clone()),
                    remediation: format!("Ensure '{}' exists in package root.", css_file),
                });
            }
        }
    }

    // 7. Options page
    if let Some(opt) = &manifest.options_page {
        if !package.has_file(opt) {
            issues.push(ValidationIssue {
                code: "CWS-MISSING-OPTIONS-PAGE".into(),
                severity: "high".into(),
                message: format!("options_page references missing file: '{}'.", opt),
                file_reference: Some(opt.clone()),
                remediation: format!("Create '{}' or remove options_page field.", opt),
            });
        }
    }
    if let Some(opt_ui) = &manifest.options_ui {
        if let Some(page) = &opt_ui.page {
            if !package.has_file(page) {
                issues.push(ValidationIssue {
                    code: "CWS-MISSING-OPTIONS-UI".into(),
                    severity: "high".into(),
                    message: format!("options_ui.page references missing file: '{}'.", page),
                    file_reference: Some(page.clone()),
                    remediation: format!("Create '{}'.", page),
                });
            }
        }
    }

    // 8. Devtools page
    if let Some(dt) = &manifest.devtools_page {
        if !package.has_file(dt) {
            issues.push(ValidationIssue {
                code: "CWS-MISSING-DEVTOOLS-PAGE".into(),
                severity: "high".into(),
                message: format!("devtools_page references missing file: '{}'.", dt),
                file_reference: Some(dt.clone()),
                remediation: format!("Create devtools entry file at '{}'.", dt),
            });
        }
    }

    // 9. Declarative Net Request ruleset existence
    if let Some(dnr) = &manifest.declarative_net_request {
        for res in &dnr.rule_resources {
            if !package.has_file(&res.path) {
                issues.push(ValidationIssue {
                    code: "CWS-MISSING-DNR-RULESET".into(),
                    severity: "critical".into(),
                    message: format!("DeclarativeNetRequest ruleset file '{}' declared in manifest does not exist.", res.path),
                    file_reference: Some(res.path.clone()),
                    remediation: format!("Create declarative ruleset JSON at '{}'.", res.path),
                });
            }
        }
    }

    // 10. Content Security Policy checks
    if let Some(csp_val) = &manifest.content_security_policy {
        let csp_str = csp_val.to_string();
        if csp_str.contains("'unsafe-eval'") {
            issues.push(ValidationIssue {
                code: "CWS-CSP-UNSAFE-EVAL".into(),
                severity: "critical".into(),
                message: "Content Security Policy contains 'unsafe-eval'. Manifest V3 strictly prohibits eval execution in extension pages and service workers.".into(),
                file_reference: Some("manifest.json".into()),
                remediation: "Remove 'unsafe-eval' from CSP and refactor dynamic code generation into sandboxed iframes or static modules.".into(),
            });
        }
        if csp_str.contains("http://") || csp_str.contains("https://") {
            issues.push(ValidationIssue {
                code: "CWS-CSP-REMOTE-SOURCES".into(),
                severity: "critical".into(),
                message: "Content Security Policy allows remote script sources. Manifest V3 forbids loading remote code (Google Developer Program Policy Single Purpose & Executable Code rule).".into(),
                file_reference: Some("manifest.json".into()),
                remediation: "Bundle all third-party libraries locally within the extension directory.".into(),
            });
        }
    }

    // 11. Externally Connectable Wildcard Check
    if let Some(ext_conn) = &manifest.externally_connectable {
        for pattern in &ext_conn.matches {
            if pattern == "<all_urls>" || pattern == "*://*/*" || pattern == "https://*/*" {
                issues.push(ValidationIssue {
                    code: "SEC-EXT-CONNECTABLE".into(),
                    severity: "critical".into(),
                    message: format!("'externally_connectable.matches' declares wildcard pattern '{}'. Any arbitrary webpage on the web can invoke extension service worker message listeners.", pattern),
                    file_reference: Some("manifest.json".into()),
                    remediation: "Restrict externally_connectable.matches to explicit verified domains belonging to your organization.".into(),
                });
            }
        }
    }

    // 12. Web Accessible Resources Wildcard Check
    for war in &manifest.web_accessible_resources {
        if let Some(matches) = war.get("matches").and_then(|m| m.as_array()) {
            for match_pat in matches {
                if let Some(pat_str) = match_pat.as_str() {
                    if pat_str == "<all_urls>" || pat_str == "*://*/*" {
                        issues.push(ValidationIssue {
                            code: "SEC-WAR-WILDCARD".into(),
                            severity: "high".into(),
                            message: "web_accessible_resources declares wildcard match pattern (*://*/*). Exposing resources universally enables fingerprinting of installed extensions by malicious websites.".into(),
                            file_reference: Some("manifest.json".into()),
                            remediation: "Scope web_accessible_resources matches to specific required domains or dynamic resource keys.".into(),
                        });
                        break;
                    }
                }
            }
        }
    }

    issues
}
