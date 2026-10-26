use crate::dnr::DnrFinding;
use crate::manifest::ManifestReport;
use crate::taint::TaintLeakPath;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Minimal,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub permissions_score: u32,       // max 30
    pub host_scope_score: u32,        // max 25
    pub taint_exfiltration_score: u32, // max 25
    pub vulnerability_score: u32,     // max 20
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusScore {
    pub total_score: u32,
    pub grade: String,
    pub risk_level: RiskLevel,
    pub breakdown: ScoreBreakdown,
    pub predicted_cws_verdict: String,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

pub fn compute_blast_radius(
    manifest_report: &ManifestReport,
    taint_paths: &[TaintLeakPath],
    dnr_findings: &[DnrFinding],
    has_eval_or_remote: bool,
    has_c2_endpoints: bool,
    has_missing_files: bool,
    has_html_csp_violations: bool,
    dead_permissions_count: usize,
    undeclared_permissions_count: usize,
) -> BlastRadiusScore {
    // 1. Permissions score (from manifest)
    let perm_contrib = manifest_report.permissions_score.min(30);

    // 2. Host score
    let host_contrib = manifest_report.host_blast_radius.min(25);

    // 3. Taint / exfiltration score
    let taint_contrib = if !taint_paths.is_empty() {
        25
    } else {
        0
    };

    // 4. Vulnerabilities & Tampering score
    let mut vuln_contrib = 0;
    if has_eval_or_remote {
        vuln_contrib += 15;
    }
    if has_c2_endpoints {
        vuln_contrib += 20;
    }
    if has_missing_files {
        vuln_contrib += 10;
    }
    if has_html_csp_violations {
        vuln_contrib += 5;
    }
    if !dnr_findings.is_empty() {
        vuln_contrib += 15;
    }
    if undeclared_permissions_count > 0 {
        vuln_contrib += 5;
    }
    if dead_permissions_count > 0 {
        vuln_contrib += 2;
    }
    let vuln_contrib = vuln_contrib.min(20);

    let raw_total = perm_contrib + host_contrib + taint_contrib + vuln_contrib;
    let total_score = raw_total.min(100);

    let (grade, risk_level) = match total_score {
        0..=5 => ("A+".to_string(), RiskLevel::Minimal),
        6..=15 => ("A".to_string(), RiskLevel::Low),
        16..=35 => ("B".to_string(), RiskLevel::Medium),
        36..=60 => ("C".to_string(), RiskLevel::Medium),
        61..=80 => ("D".to_string(), RiskLevel::High),
        _ => ("F".to_string(), RiskLevel::Critical),
    };

    let has_sensitive_permission = manifest_report.declared_permissions.iter().any(|p| {
        if let Some(info) = crate::manifest::KNOWN_PERMISSIONS.get(p.as_str()) {
            info.severity >= crate::manifest::PermissionSeverity::High
        } else {
            false
        }
    });

    let predicted_cws_verdict = if has_missing_files
        || has_eval_or_remote
        || !taint_paths.is_empty()
        || manifest_report.manifest.manifest_version == Some(2)
    {
        "REJECTION_LIKELY"
    } else if host_contrib >= 20 || has_sensitive_permission {
        "MANUAL_REVIEW_LIKELY"
    } else {
        "AUTOMATED_PASS_LIKELY"
    }
    .to_string();

    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;

    // Count findings
    if taint_contrib > 0 {
        critical_count += taint_paths.len();
    }
    if has_eval_or_remote {
        critical_count += 1;
    }
    if has_c2_endpoints {
        critical_count += 1;
    }
    if has_missing_files {
        critical_count += 1;
    }
    for issue in &manifest_report.validation_issues {
        match issue.severity.as_str() {
            "critical" => critical_count += 1,
            "high" => high_count += 1,
            "medium" => medium_count += 1,
            _ => low_count += 1,
        }
    }
    for dnr in dnr_findings {
        match dnr.severity {
            "critical" => critical_count += 1,
            "high" => high_count += 1,
            _ => medium_count += 1,
        }
    }
    if has_html_csp_violations {
        high_count += 1;
    }
    if host_contrib >= 25 {
        high_count += 1;
    }
    if undeclared_permissions_count > 0 {
        high_count += undeclared_permissions_count;
    }
    if dead_permissions_count > 0 {
        low_count += dead_permissions_count;
    }

    BlastRadiusScore {
        total_score,
        grade,
        risk_level,
        breakdown: ScoreBreakdown {
            permissions_score: perm_contrib,
            host_scope_score: host_contrib,
            taint_exfiltration_score: taint_contrib,
            vulnerability_score: vuln_contrib,
        },
        predicted_cws_verdict,
        critical_count,
        high_count,
        medium_count,
        low_count,
    }
}
