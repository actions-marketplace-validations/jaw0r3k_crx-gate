use crate::archive::ExtensionPackage;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnrRule {
    pub id: Option<serde_json::Value>,
    pub priority: Option<i64>,
    pub action: Option<DnrAction>,
    pub condition: Option<DnrCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnrAction {
    pub r#type: Option<String>,
    pub redirect: Option<DnrRedirect>,
    #[serde(default)]
    pub response_headers: Vec<DnrHeaderModification>,
    #[serde(default)]
    pub request_headers: Vec<DnrHeaderModification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnrRedirect {
    pub url: Option<String>,
    pub regex_substitution: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnrHeaderModification {
    pub header: String,
    pub operation: String, // "remove", "set", "append"
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DnrCondition {
    pub url_filter: Option<String>,
    pub regex_filter: Option<String>,
    #[serde(default)]
    pub initiator_domains: Vec<String>,
    #[serde(default)]
    pub excluded_initiator_domains: Vec<String>,
    #[serde(default)]
    pub request_domains: Vec<String>,
    #[serde(default)]
    pub resource_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnrFinding {
    pub rule_id: String,
    pub file_path: String,
    pub severity: &'static str,
    pub title: &'static str,
    pub description: String,
    pub remediation: String,
}

pub fn analyze_dnr_rulesets(package: &ExtensionPackage) -> Vec<DnrFinding> {
    let mut findings = Vec::new();

    for (path, content) in package.json_files() {
        if path == "manifest.json" {
            continue;
        }

        if let Ok(rules) = serde_json::from_str::<Vec<DnrRule>>(content) {
            for (idx, rule) in rules.iter().enumerate() {
                let rule_id = rule
                    .id
                    .as_ref()
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| format!("#{}", idx + 1));

                if let Some(action) = &rule.action {
                    // Check 1: Stripping Security Headers
                    for header_mod in &action.response_headers {
                        let h_lower = header_mod.header.to_lowercase();
                        let op_lower = header_mod.operation.to_lowercase();

                        if op_lower == "remove" {
                            if h_lower == "content-security-policy"
                                || h_lower == "content-security-policy-report-only"
                            {
                                findings.push(DnrFinding {
                                    rule_id: rule_id.clone(),
                                    file_path: path.to_string(),
                                    severity: "critical",
                                    title: "DNR Stripping Content-Security-Policy",
                                    description: format!(
                                        "Rule {} removes the 'Content-Security-Policy' response header, disabling browser XSS and script execution defenses.",
                                        rule_id
                                    ),
                                    remediation: "Remove rule or restrict header modification to strictly needed domain without disabling security policies.".into(),
                                });
                            } else if h_lower == "x-frame-options" {
                                findings.push(DnrFinding {
                                    rule_id: rule_id.clone(),
                                    file_path: path.to_string(),
                                    severity: "high",
                                    title: "DNR Stripping X-Frame-Options",
                                    description: format!(
                                        "Rule {} strips 'X-Frame-Options', enabling clickjacking and iframe embedding of protected web applications.",
                                        rule_id
                                    ),
                                    remediation: "Do not remove framing protection headers.".into(),
                                });
                            } else if h_lower == "strict-transport-security" {
                                findings.push(DnrFinding {
                                    rule_id: rule_id.clone(),
                                    file_path: path.to_string(),
                                    severity: "high",
                                    title: "DNR Stripping Strict-Transport-Security (HSTS)",
                                    description: format!(
                                        "Rule {} strips HSTS header, exposing traffic to SSL-stripping man-in-the-middle attacks.",
                                        rule_id
                                    ),
                                    remediation: "Do not tamper with transport security headers.".into(),
                                });
                            }
                        }

                        if (op_lower == "set" || op_lower == "append")
                            && h_lower == "access-control-allow-origin"
                        {
                            if let Some(val) = &header_mod.value {
                                if val == "*" {
                                    findings.push(DnrFinding {
                                        rule_id: rule_id.clone(),
                                        file_path: path.to_string(),
                                        severity: "high",
                                        title: "DNR Overriding CORS to Wildcard (*)",
                                        description: format!(
                                            "Rule {} forces 'Access-Control-Allow-Origin: *', allowing unauthorized origins to read sensitive cross-origin data.",
                                            rule_id
                                        ),
                                        remediation: "Specify explicit origins instead of wildcard '*' in CORS headers.".into(),
                                    });
                                }
                            }
                        }
                    }

                    // Check 2: Traffic Redirection
                    if action.r#type.as_deref() == Some("redirect") {
                        if let Some(redirect) = &action.redirect {
                            if let Some(target_url) = &redirect.url {
                                if target_url.starts_with("http://")
                                    || target_url.starts_with("https://")
                                {
                                    findings.push(DnrFinding {
                                        rule_id: rule_id.clone(),
                                        file_path: path.to_string(),
                                        severity: "medium",
                                        title: "DNR External Traffic Redirection",
                                        description: format!(
                                            "Rule {} redirects matched network requests to external endpoint: '{}'.",
                                            rule_id, target_url
                                        ),
                                        remediation: "Ensure the redirect destination is authorized and necessary.".into(),
                                    });
                                }
                            }
                        }
                    }

                    // Check 3: Modifying sensitive request headers (Cookie / Auth)
                    for req_header in &action.request_headers {
                        let h_lower = req_header.header.to_lowercase();
                        if h_lower == "cookie" || h_lower == "authorization" {
                            findings.push(DnrFinding {
                                rule_id: rule_id.clone(),
                                file_path: path.to_string(),
                                severity: "critical",
                                title: "DNR Modifying Authentication/Cookie Headers",
                                description: format!(
                                    "Rule {} modifies sensitive request header '{}', which can lead to session hijacking or credential forgery.",
                                    rule_id, req_header.header
                                ),
                                remediation: "Do not programmatically mutate session or authentication headers via DNR rules.".into(),
                            });
                        }
                    }
                }
            }
        }
    }

    findings
}
