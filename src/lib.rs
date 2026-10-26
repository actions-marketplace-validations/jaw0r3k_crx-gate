pub mod archive;
pub mod ast;
pub mod config;
pub mod diff;
pub mod dnr;
pub mod manifest;
pub mod report;
pub mod scorer;
pub mod signatures;
pub mod taint;

use anyhow::Result;
use archive::{ExtensionPackage, PackageType};
use ast::{analyze_package_scripts, check_html_csp_violations};
use config::Config;
pub use diff::DiffReport;
use dnr::analyze_dnr_rulesets;
use manifest::{api_to_permission, ManifestReport, KNOWN_PERMISSIONS};
pub use report::table::ScanFinding;
pub use report::{render_html_report, render_json_report, render_markdown_report, render_terminal_report, generate_sarif_report, JsonReport, SarifReport};
pub use scorer::{compute_blast_radius, BlastRadiusScore, RiskLevel};
use serde::{Deserialize, Serialize};
use signatures::rules::get_rule;
use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;
pub use taint::{TaintGraphEngine, TaintLeakPath};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target_path: String,
    pub package_type: String,
    pub extension_id: Option<String>,
    pub extension_name: String,
    pub extension_version: String,
    pub manifest_version: u32,
    pub score: BlastRadiusScore,
    pub findings: Vec<ScanFinding>,
    pub taint_paths: Vec<TaintLeakPath>,
    pub execution_duration_ms: u128,
}

pub struct Scanner {
    pub config: Config,
}

impl Scanner {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn scan<P: AsRef<Path>>(&self, path: P) -> Result<ScanResult> {
        let start_time = Instant::now();
        let target_str = path.as_ref().to_string_lossy().to_string();

        // 1. Load extension package (dir, crx, or zip)
        let package = ExtensionPackage::load(path.as_ref())?;
        let package_type_str = match package.package_type {
            PackageType::Directory => "Unpacked Directory".to_string(),
            PackageType::Crx { version } => format!("CRX v{}", version),
            PackageType::Zip => "ZIP Archive".to_string(),
        };

        // 2. Analyze manifest
        let manifest_report = ManifestReport::analyze(&package)?;
        let manifest_version = manifest_report.manifest.manifest_version.unwrap_or(3);
        let ext_name = manifest_report.manifest.name.clone().unwrap_or_else(|| "Unknown Extension".into());
        let ext_version = manifest_report.manifest.version.clone().unwrap_or_else(|| "0.0.0".into());

        let mut findings = Vec::new();

        // Convert manifest validation issues into ScanFindings
        for issue in &manifest_report.validation_issues {
            if self.config.is_waived(&issue.code, issue.file_reference.as_deref()) {
                continue;
            }
            let rule = get_rule(&issue.code);
            findings.push(ScanFinding {
                rule_id: issue.code.to_string(),
                title: rule.map(|r| r.title.to_string()).unwrap_or_else(|| issue.code.to_string()),
                severity: issue.severity.to_string(),
                category: rule.map(|r| r.category.to_string()).unwrap_or_else(|| "Manifest Validation".into()),
                file_path: issue.file_reference.clone(),
                line: None,
                col: None,
                snippet: None,
                description: issue.message.clone(),
                remediation: issue.remediation.clone(),
                cws_policy_ref: rule.and_then(|r| r.cws_policy_reference.map(|s| s.to_string())),
            });
        }

        // Host blast radius findings
        for host in &manifest_report.host_analyses {
            if host.is_broad {
                if !self.config.is_waived("CWS-004", Some("manifest.json")) {
                    findings.push(ScanFinding {
                        rule_id: "CWS-004".into(),
                        title: "Excessive Wildcard Host Permissions".into(),
                        severity: "high".into(),
                        category: "Permission Blast Radius".into(),
                        file_path: Some("manifest.json".into()),
                        line: None,
                        col: None,
                        snippet: Some(format!("\"host_permissions\": [ \"{}\" ]", host.pattern)),
                        description: format!("Host pattern '{}' grants broad script injection across arbitrary web origins. {}", host.pattern, host.explanation),
                        remediation: "Scope host_permissions to specific required domains or replace with activeTab.".into(),
                        cws_policy_ref: Some("Single Purpose Policy & Permissions Minimization".into()),
                    });
                }
            }
        }

        // 3. AST Script Analysis (Rayon parallelized)
        let ast_reports = analyze_package_scripts(&package);

        let mut all_api_calls = Vec::new();
        let mut all_side_panel_triggers = Vec::new();
        let mut tab_url_or_title_accessed = false;
        let mut has_eval_or_remote = false;
        let mut has_c2_endpoints = false;

        for report in &ast_reports {
            for call in &report.api_calls {
                all_api_calls.push(call.api_path.clone());
            }
            for trg in &report.side_panel_triggers {
                all_side_panel_triggers.push(trg.clone());
            }
            if report.tab_url_or_title_accessed {
                tab_url_or_title_accessed = true;
            }

            // Dynamic code
            for dyn_code in &report.dynamic_code {
                has_eval_or_remote = true;
                if !self.config.is_waived("CWS-002", Some(&report.file_path)) {
                    findings.push(ScanFinding {
                        rule_id: "CWS-002".into(),
                        title: "Dynamic Code Execution (CSP Violation)".into(),
                        severity: "critical".into(),
                        category: "CWS Policy Violation".into(),
                        file_path: Some(report.file_path.clone()),
                        line: Some(dyn_code.line),
                        col: Some(dyn_code.col),
                        snippet: Some(dyn_code.snippet.clone()),
                        description: format!("Dynamic string execution ({}) violates Manifest V3 extension CSP.", dyn_code.kind),
                        remediation: "Refactor dynamic evaluation to static functions or isolate in a sandboxed iframe.".into(),
                        cws_policy_ref: Some("MV3 CSP: Extension Pages & Service Workers".into()),
                    });
                }
            }

            // Suspicious endpoints
            for endpoint in &report.suspicious_endpoints {
                has_c2_endpoints = true;
                if !self.config.is_waived("SEC-C2-ENDPOINT", Some(&report.file_path)) {
                    findings.push(ScanFinding {
                        rule_id: "SEC-C2-ENDPOINT".into(),
                        title: "Known Exfiltration / C2 Webhook Detected".into(),
                        severity: endpoint.endpoint.severity.to_string(),
                        category: "Malware & Threat Intel".into(),
                        file_path: Some(report.file_path.clone()),
                        line: Some(endpoint.line),
                        col: Some(endpoint.col),
                        snippet: Some(endpoint.endpoint.url.clone()),
                        description: format!("Hardcoded {} endpoint detected in source code.", endpoint.endpoint.category),
                        remediation: "Remove unauthorized third-party exfiltration webhooks immediately.".into(),
                        cws_policy_ref: Some("Malicious Software & Data Theft Policy".into()),
                    });
                }
            }

            // Obfuscated high entropy strings
            for entropy in &report.entropy_findings {
                if !self.config.is_waived("SEC-OBFUSCATION", Some(&report.file_path)) {
                    findings.push(ScanFinding {
                        rule_id: "SEC-OBFUSCATION".into(),
                        title: "Obfuscated / Packed Payload Detected".into(),
                        severity: "critical".into(),
                        category: "Malware & Obfuscation".into(),
                        file_path: Some(report.file_path.clone()),
                        line: Some(entropy.line),
                        col: None,
                        snippet: Some(format!("Literal with Shannon entropy {:.2} bits/char: '{}...'", entropy.entropy, entropy.snippet_preview)),
                        description: "High Shannon entropy string detected, strongly indicating packed or encrypted payload to evade static review.".into(),
                        remediation: "Remove obfuscated code; Chrome Web Store strictly bans obfuscation.".into(),
                        cws_policy_ref: Some("Chrome Web Store Code Quality & Transparency".into()),
                    });
                }
            }

            // DOM XSS: innerHTML, outerHTML, document.write
            for xss in &report.dom_xss_findings {
                if !self.config.is_waived("SEC-DOM-XSS", Some(&report.file_path)) {
                    findings.push(ScanFinding {
                        rule_id: "SEC-DOM-XSS".into(),
                        title: "DOM-Based XSS Vulnerability (innerHTML / document.write)".into(),
                        severity: "critical".into(),
                        category: "Injection & DOM Security".into(),
                        file_path: Some(report.file_path.clone()),
                        line: Some(xss.line),
                        col: Some(xss.col),
                        snippet: Some(xss.snippet.clone()),
                        description: format!("Dangerous {} detected. Assigning unsanitized input to innerHTML/document.write enables attacker code execution inside extension contexts.", xss.kind),
                        remediation: "Use textContent, safe DOM APIs (createElement), or sanitize input with DOMPurify.".into(),
                        cws_policy_ref: Some("CWS Content Security Policy & Safe DOM Manipulation".into()),
                    });
                }
            }

            // Insecure external messaging
            for msg in &report.insecure_external_msg_findings {
                if !self.config.is_waived("SEC-EXTERNAL-MSG-INSECURE", Some(&report.file_path)) {
                    findings.push(ScanFinding {
                        rule_id: "SEC-EXTERNAL-MSG-INSECURE".into(),
                        title: "Unvalidated External Message Handler".into(),
                        severity: "critical".into(),
                        category: "Access Control & Messaging".into(),
                        file_path: Some(report.file_path.clone()),
                        line: Some(msg.line),
                        col: Some(msg.col),
                        snippet: Some(msg.snippet.clone()),
                        description: "chrome.runtime.onMessageExternal listener does not check sender.origin, sender.url, or sender.id. Any website can trigger privileged background routines.".into(),
                        remediation: "Validate sender.origin against a strict whitelist of trusted domains before processing external requests.".into(),
                        cws_policy_ref: Some("Cross-Extension & External Messaging Security".into()),
                    });
                }
            }

            // Keylogger & password field snooping
            for kl in &report.keylogger_findings {
                if !self.config.is_waived("SEC-KEYLOGGER-INPUT", Some(&report.file_path)) {
                    findings.push(ScanFinding {
                        rule_id: "SEC-KEYLOGGER-INPUT".into(),
                        title: "Global Keystroke / Password Input Snooping".into(),
                        severity: "critical".into(),
                        category: "Malware & Credential Harvesting".into(),
                        file_path: Some(report.file_path.clone()),
                        line: Some(kl.line),
                        col: Some(kl.col),
                        snippet: Some(kl.snippet.clone()),
                        description: format!("Detected {}. Monitoring keystrokes or querying password fields across visited web pages resembles spyware/keylogger behavior.", kl.trigger),
                        remediation: "Remove global key event listeners and password input selectors from content scripts.".into(),
                        cws_policy_ref: Some("Chrome Web Store User Data Privacy & Malicious Software Policy".into()),
                    });
                }
            }

            // Plaintext credentials in chrome.storage.sync
            for cred in &report.storage_sync_findings {
                if !self.config.is_waived("SEC-STORAGE-SYNC-CREDENTIALS", Some(&report.file_path)) {
                    findings.push(ScanFinding {
                        rule_id: "SEC-STORAGE-SYNC-CREDENTIALS".into(),
                        title: "Plaintext Credentials in chrome.storage.sync".into(),
                        severity: "high".into(),
                        category: "Data Loss Prevention & Privacy".into(),
                        file_path: Some(report.file_path.clone()),
                        line: Some(cred.line),
                        col: Some(cred.col),
                        snippet: Some(cred.snippet.clone()),
                        description: format!("Storing sensitive credential '{}' in chrome.storage.sync. Google syncs this storage unencrypted across all user browser instances.", cred.key_name),
                        remediation: "Store sensitive tokens in chrome.storage.session or encrypt data before saving.".into(),
                        cws_policy_ref: Some("Chrome Storage API Best Practices".into()),
                    });
                }
            }

            // Remote WebAssembly compilation
            for wasm in &report.remote_wasm_findings {
                if !self.config.is_waived("CWS-012", Some(&report.file_path)) {
                    findings.push(ScanFinding {
                        rule_id: "CWS-012".into(),
                        title: "Remote WebAssembly Compilation".into(),
                        severity: "critical".into(),
                        category: "CWS Policy Violation".into(),
                        file_path: Some(report.file_path.clone()),
                        line: Some(wasm.line),
                        col: Some(wasm.col),
                        snippet: Some(wasm.snippet.clone()),
                        description: format!("Dynamic compilation of remote WebAssembly via {} violates Manifest V3 executable code policy.", wasm.api_name),
                        remediation: "Bundle all WebAssembly (.wasm) modules locally inside the extension package.".into(),
                        cws_policy_ref: Some("Chrome Web Store Executable Code Policy".into()),
                    });
                }
            }
        }

        // 4. HTML CSP violations
        let mut has_html_csp_violations = false;
        for (html_path, html_content) in package.html_files() {
            let html_violations = check_html_csp_violations(html_path, html_content);
            for v in html_violations {
                has_html_csp_violations = true;
                if !self.config.is_waived("CWS-006", Some(html_path)) {
                    findings.push(ScanFinding {
                        rule_id: "CWS-006".into(),
                        title: "Inline Script or Event Handler in HTML".into(),
                        severity: "high".into(),
                        category: "CWS Policy Violation".into(),
                        file_path: Some(v.file_path.clone()),
                        line: Some(v.line),
                        col: None,
                        snippet: Some(v.snippet),
                        description: format!("Found {} inside extension HTML page. MV3 CSP strictly blocks inline scripts and DOM event handlers.", v.kind),
                        remediation: "Move code to an external .js file and bind events via addEventListener().".into(),
                        cws_policy_ref: Some("MV3 Content Security Policy".into()),
                    });
                }
            }
        }

        // 5. DNR Ruleset Tampering
        let dnr_findings = analyze_dnr_rulesets(&package);
        for dnr in &dnr_findings {
            let rule_id = if dnr.title.contains("Content-Security-Policy") {
                "DNR-TAMPER-CSP"
            } else if dnr.title.contains("Authentication") {
                "DNR-AUTH-THEFT"
            } else {
                "DNR-TAMPER-CSP"
            };

            if !self.config.is_waived(rule_id, Some(&dnr.file_path)) {
                findings.push(ScanFinding {
                    rule_id: rule_id.into(),
                    title: dnr.title.to_string(),
                    severity: dnr.severity.to_string(),
                    category: "Security Tampering".into(),
                    file_path: Some(dnr.file_path.clone()),
                    line: None,
                    col: None,
                    snippet: Some(format!("Rule ID: {}", dnr.rule_id)),
                    description: dnr.description.clone(),
                    remediation: dnr.remediation.clone(),
                    cws_policy_ref: Some("Declarative Net Request Security Policy".into()),
                });
            }
        }

        // 6. Dead & Overprivileged Permissions
        let mut dead_permissions_count = 0;
        let mut undeclared_permissions_count = 0;

        for perm in &manifest_report.declared_permissions {
            if let Some(info) = KNOWN_PERMISSIONS.get(perm.as_str()) {
                let is_used = all_api_calls.iter().any(|api| api.starts_with(info.api_prefix));
                if !is_used && !self.config.audit.ignore_dead_permissions {
                    dead_permissions_count += 1;
                    if !self.config.is_waived("PERM-DEAD", Some("manifest.json")) {
                        findings.push(ScanFinding {
                            rule_id: "PERM-DEAD".into(),
                            title: format!("Dead Declared Permission: '{}'", perm),
                            severity: "low".into(),
                            category: "Least Privilege Violation".into(),
                            file_path: Some("manifest.json".into()),
                            line: None,
                            col: None,
                            snippet: Some(format!("\"permissions\": [ \"{}\" ]", perm)),
                            description: format!("Permission '{}' is requested in manifest.json but never referenced in any script across the extension.", perm),
                            remediation: format!("Remove '{}' from permissions to minimize blast radius and avoid unnecessary user warnings.", perm),
                            cws_policy_ref: Some("Single Purpose & Permissions Minimization".into()),
                        });
                    }
                }

                // Check overprivileged tabs
                if perm == "tabs" && is_used && !tab_url_or_title_accessed {
                    if !self.config.is_waived("PERM-OVERPRIVILEGED", Some("manifest.json")) {
                        findings.push(ScanFinding {
                            rule_id: "PERM-OVERPRIVILEGED".into(),
                            title: "Overprivileged Permission: 'tabs'".into(),
                            severity: "medium".into(),
                            category: "Least Privilege Violation".into(),
                            file_path: Some("manifest.json".into()),
                            line: None,
                            col: None,
                            snippet: Some("\"permissions\": [ \"tabs\" ]".into()),
                            description: "The 'tabs' permission is declared, but the extension only accesses non-sensitive tab attributes (like tab.id). Non-sensitive attributes do not require the 'tabs' permission.".into(),
                            remediation: "Remove 'tabs' from manifest.json or replace with 'activeTab' if tab access is only needed on user gesture.".into(),
                            cws_policy_ref: Some("Chrome Extensions Permissions Minimization".into()),
                        });
                    }
                }
            }
        }

        // Undeclared permissions check
        let mut flagged_undeclared = HashSet::new();
        for api in &all_api_calls {
            if let Some(required_perm) = api_to_permission(api) {
                if !manifest_report.declared_permissions.contains(required_perm)
                    && !manifest_report.manifest.optional_permissions.iter().any(|p| p == required_perm)
                {
                    if flagged_undeclared.insert(required_perm) {
                        undeclared_permissions_count += 1;
                        if !self.config.is_waived("PERM-UNDECLARED", None) {
                            findings.push(ScanFinding {
                                rule_id: "PERM-UNDECLARED".into(),
                                title: format!("Undeclared Permission Required: '{}'", required_perm),
                                severity: "high".into(),
                                category: "Runtime Failure".into(),
                                file_path: None,
                                line: None,
                                col: None,
                                snippet: Some(format!("Calls '{}'", api)),
                                description: format!("API '{}' is called in extension code, but '{}' is missing from manifest permissions. This causes immediate runtime breakage.", api, required_perm),
                                remediation: format!("Add '\"{}\"' to 'permissions' in manifest.json.", required_perm),
                                cws_policy_ref: Some("Chrome Extensions Manifest Permissions".into()),
                            });
                        }
                    }
                }
            }
        }

        // Action API without manifest action
        let calls_action = all_api_calls.iter().any(|a| a.starts_with("chrome.action"));
        if calls_action && manifest_report.manifest.action.is_none() {
            if !self.config.is_waived("CWS-009", Some("manifest.json")) {
                findings.push(ScanFinding {
                    rule_id: "CWS-009".into(),
                    title: "chrome.action API Used Without Manifest Declaration".into(),
                    severity: "high".into(),
                    category: "Runtime Failure".into(),
                    file_path: Some("manifest.json".into()),
                    line: None,
                    col: None,
                    snippet: None,
                    description: "chrome.action.* is invoked in scripts, but 'action' is missing from manifest.json. In MV3, chrome.action is undefined without an action declaration.".into(),
                    remediation: "Add '\"action\": {}' to manifest.json.".into(),
                    cws_policy_ref: Some("Chrome Action API Reference".into()),
                });
            }
        }

        // Side panel without trigger
        if manifest_report.manifest.side_panel.is_some() && all_side_panel_triggers.is_empty() {
            if !self.config.is_waived("CWS-008", Some("manifest.json")) {
                findings.push(ScanFinding {
                    rule_id: "CWS-008".into(),
                    title: "Unopenable Side Panel Declaration".into(),
                    severity: "medium".into(),
                    category: "MV3 Architecture Bug".into(),
                    file_path: Some("manifest.json".into()),
                    line: None,
                    col: None,
                    snippet: None,
                    description: "Manifest declares 'side_panel', but no trigger (chrome.sidePanel.open or setPanelBehavior({ openPanelOnActionClick: true })) was found in service worker.".into(),
                    remediation: "Add an explicit open trigger inside chrome.action.onClicked or call setPanelBehavior.".into(),
                    cws_policy_ref: Some("Chrome Extensions Side Panel API".into()),
                });
            }
        }

        // 7. Static Taint Analysis Engine
        let mut taint_engine = TaintGraphEngine::new();
        taint_engine.populate_from_reports(&ast_reports);
        let taint_paths = taint_engine.find_leak_paths();

        for leak in &taint_paths {
            if !self.config.is_waived("SEC-TAINT-LEAK", Some(&leak.source_location)) {
                findings.push(ScanFinding {
                    rule_id: "SEC-TAINT-LEAK".into(),
                    title: leak.title.to_string(),
                    severity: leak.severity.to_string(),
                    category: "Data Loss Prevention".into(),
                    file_path: Some(leak.source_location.clone()),
                    line: None,
                    col: None,
                    snippet: Some(format!("Flow: {} ➔ {}", leak.source_api, leak.sink_api)),
                    description: leak.description.clone(),
                    remediation: leak.remediation.clone(),
                    cws_policy_ref: Some("User Data Privacy & Exfiltration Policy".into()),
                });
            }
        }

        // 8. Deterministic Blast Radius Scoring
        let has_missing_files = manifest_report.validation_issues.iter().any(|i| i.code.contains("MISSING"));
        let score = compute_blast_radius(
            &manifest_report,
            &taint_paths,
            &dnr_findings,
            has_eval_or_remote,
            has_c2_endpoints,
            has_missing_files,
            has_html_csp_violations,
            dead_permissions_count,
            undeclared_permissions_count,
        );

        let duration_ms = start_time.elapsed().as_millis();

        Ok(ScanResult {
            target_path: target_str,
            package_type: package_type_str,
            extension_id: package.extension_id,
            extension_name: ext_name,
            extension_version: ext_version,
            manifest_version,
            score,
            findings,
            taint_paths,
            execution_duration_ms: duration_ms,
        })
    }

    pub fn diff<P1: AsRef<Path>, P2: AsRef<Path>>(&self, base_path: P1, target_path: P2) -> Result<DiffReport> {
        let base_result = self.scan(base_path.as_ref())?;
        let target_result = self.scan(target_path.as_ref())?;

        let base_pkg = ExtensionPackage::load(base_path.as_ref())?;
        let target_pkg = ExtensionPackage::load(target_path.as_ref())?;

        let base_m = ManifestReport::analyze(&base_pkg)?;
        let target_m = ManifestReport::analyze(&target_pkg)?;

        let mut added_permissions = Vec::new();
        let mut removed_permissions = Vec::new();

        for p in &target_m.declared_permissions {
            if !base_m.declared_permissions.contains(p) {
                added_permissions.push(p.clone());
            }
        }
        for p in &base_m.declared_permissions {
            if !target_m.declared_permissions.contains(p) {
                removed_permissions.push(p.clone());
            }
        }

        let mut added_hosts = Vec::new();
        let mut removed_hosts = Vec::new();

        for h in &target_m.declared_hosts {
            if !base_m.declared_hosts.contains(h) {
                added_hosts.push(h.clone());
            }
        }
        for h in &base_m.declared_hosts {
            if !target_m.declared_hosts.contains(h) {
                removed_hosts.push(h.clone());
            }
        }

        let mut new_findings = Vec::new();
        let mut resolved_findings = Vec::new();

        for tf in &target_result.findings {
            if !base_result.findings.iter().any(|bf| bf.rule_id == tf.rule_id && bf.file_path == tf.file_path) {
                new_findings.push(tf.clone());
            }
        }
        for bf in &base_result.findings {
            if !target_result.findings.iter().any(|tf| tf.rule_id == bf.rule_id && tf.file_path == bf.file_path) {
                resolved_findings.push(bf.clone());
            }
        }

        let mut new_taint_paths = Vec::new();
        for tp in &target_result.taint_paths {
            if !base_result.taint_paths.iter().any(|bp| bp.source_api == tp.source_api && bp.sink_api == tp.sink_api) {
                new_taint_paths.push(tp.clone());
            }
        }

        let score_delta = target_result.score.total_score as i32 - base_result.score.total_score as i32;

        Ok(DiffReport {
            base_path: base_path.as_ref().to_string_lossy().to_string(),
            target_path: target_path.as_ref().to_string_lossy().to_string(),
            base_score: base_result.score,
            target_score: target_result.score,
            score_delta,
            added_permissions,
            removed_permissions,
            added_hosts,
            removed_hosts,
            new_findings,
            resolved_findings,
            new_taint_paths,
        })
    }
}
