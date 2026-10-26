use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostScope {
    SpecificDomain,
    WildcardSubdomain,
    WildcardTld,
    AllUrls,
    Localhost,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostAnalysis {
    pub pattern: String,
    pub scope: HostScope,
    pub risk_weight: u32,
    pub is_broad: bool,
    pub explanation: String,
}

impl HostAnalysis {
    pub fn parse(pattern: &str) -> Self {
        let pattern_trimmed = pattern.trim();

        if pattern_trimmed == "<all_urls>"
            || pattern_trimmed == "*://*/*"
            || pattern_trimmed == "https://*/*"
            || pattern_trimmed == "http://*/*"
            || pattern_trimmed == "*://*/"
            || pattern_trimmed == "*://*"
        {
            return HostAnalysis {
                pattern: pattern_trimmed.to_string(),
                scope: HostScope::AllUrls,
                risk_weight: 25,
                is_broad: true,
                explanation: "Omnipresent scope: grants script injection and data interception on every visited web page. Direct trigger for Chrome Web Store manual review and Single Purpose scrutiny.".into(),
            };
        }

        if pattern_trimmed.contains("localhost") || pattern_trimmed.contains("127.0.0.1") {
            return HostAnalysis {
                pattern: pattern_trimmed.to_string(),
                scope: HostScope::Localhost,
                risk_weight: 1,
                is_broad: false,
                explanation: "Local development scope.".into(),
            };
        }

        if pattern_trimmed.contains("*.") {
            // Check if it's wildcard TLD e.g. *.com/* or subdomain *.example.com/*
            if let Some(host_part) = extract_host(pattern_trimmed) {
                let parts: Vec<&str> = host_part.split('.').collect();
                if parts.len() <= 2 {
                    // e.g. *.com or *.io
                    return HostAnalysis {
                        pattern: pattern_trimmed.to_string(),
                        scope: HostScope::WildcardTld,
                        risk_weight: 15,
                        is_broad: true,
                        explanation: "Wildcard top-level domain scope: encompasses millions of arbitrary domains.".into(),
                    };
                } else {
                    return HostAnalysis {
                        pattern: pattern_trimmed.to_string(),
                        scope: HostScope::WildcardSubdomain,
                        risk_weight: 6,
                        is_broad: false,
                        explanation: "Scoped across all subdomains of a specific organization or service.".into(),
                    };
                }
            }
        }

        HostAnalysis {
            pattern: pattern_trimmed.to_string(),
            scope: HostScope::SpecificDomain,
            risk_weight: 3,
            is_broad: false,
            explanation: "Targeted to specific origin or endpoint.".into(),
        }
    }
}

fn extract_host(pattern: &str) -> Option<&str> {
    let without_scheme = if let Some(pos) = pattern.find("://") {
        &pattern[pos + 3..]
    } else {
        pattern
    };

    let host = without_scheme.split('/').next()?.split(':').next()?;
    Some(host)
}

pub fn calculate_host_blast_radius(patterns: &[String]) -> (u32, Vec<HostAnalysis>) {
    let mut total_score = 0;
    let mut analyses = Vec::new();

    let mut has_all_urls = false;
    for pat in patterns {
        let analysis = HostAnalysis::parse(pat);
        if analysis.scope == HostScope::AllUrls {
            has_all_urls = true;
        }
        total_score += analysis.risk_weight;
        analyses.push(analysis);
    }

    if has_all_urls {
        total_score = total_score.max(25);
    }

    // Host blast radius contribution capped at 30 points
    (total_score.min(30), analyses)
}
