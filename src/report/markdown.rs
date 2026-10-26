use crate::report::table::ScanFinding;
use crate::scorer::BlastRadiusScore;
use crate::taint::TaintLeakPath;

pub fn render_markdown_report(
    target_path: &str,
    package_type: &str,
    extension_id: Option<&str>,
    extension_name: &str,
    extension_version: &str,
    manifest_version: u32,
    score: &BlastRadiusScore,
    findings: &[ScanFinding],
    taint_paths: &[TaintLeakPath],
    duration_ms: u128,
) -> String {
    let mut md = String::new();

    md.push_str("# 🛡️ crx-gate Security & Blast-Radius Audit\n\n");

    md.push_str(&format!(
        "Audited extension **{}** (v{}) inside `{}` in **{}ms**.\n\n",
        extension_name, extension_version, target_path, duration_ms
    ));

    // Summary Card
    let grade_emoji = match score.grade.as_str() {
        "A+" | "A" => "🟢",
        "B" => "🟡",
        "C" => "🟠",
        _ => "🔴",
    };

    md.push_str("### 📊 Blast-Radius Scorecard\n\n");
    md.push_str("| Metric | Value |\n");
    md.push_str("| :--- | :--- |\n");
    md.push_str(&format!("| **Blast-Radius Grade** | {} **{}** |\n", grade_emoji, score.grade));
    md.push_str(&format!("| **Risk Score** | **{}/100** ({}) |\n", score.total_score, score.risk_level.as_str().to_uppercase()));
    md.push_str(&format!("| **Chrome Web Store Verdict** | `{}` |\n", score.predicted_cws_verdict));
    md.push_str(&format!("| **Manifest Version** | MV{} |\n", manifest_version));
    if let Some(id) = extension_id {
        md.push_str(&format!("| **Extension ID** | `{}` |\n", id));
    }
    md.push_str(&format!("| **Package Format** | {} |\n\n", package_type));

    // Breakdown
    md.push_str("### 🔍 Risk Breakdown\n\n");
    md.push_str("| Audit Vector | Score | Max | Assessment |\n");
    md.push_str("| :--- | :--- | :--- | :--- |\n");
    md.push_str(&format!(
        "| Manifest Permissions | {} | 30 | {} |\n",
        score.breakdown.permissions_score,
        if score.breakdown.permissions_score <= 10 { "Low Risk" } else { "High Risk" }
    ));
    md.push_str(&format!(
        "| Host Permissions Scope | {} | 25 | {} |\n",
        score.breakdown.host_scope_score,
        if score.breakdown.host_scope_score == 0 { "Zero Hosts" } else if score.breakdown.host_scope_score < 20 { "Scoped" } else { "Wildcard <all_urls>" }
    ));
    md.push_str(&format!(
        "| Static Taint Exfiltration | {} | 25 | {} |\n",
        score.breakdown.taint_exfiltration_score,
        if score.breakdown.taint_exfiltration_score == 0 { "No Leaks" } else { "🚨 CONFIRMED LEAK" }
    ));
    md.push_str(&format!(
        "| Policy & Vulnerabilities | {} | 20 | {} |\n\n",
        score.breakdown.vulnerability_score,
        if score.breakdown.vulnerability_score == 0 { "Compliant" } else { "Policy Violations" }
    ));

    // Taint Leaks
    if !taint_paths.is_empty() {
        md.push_str("### 🚨 Confirmed Data Exfiltration Paths (Static Taint Engine)\n\n");
        for (i, leak) in taint_paths.iter().enumerate() {
            md.push_str(&format!("#### Path #{}: `{}` ➔ `{}`\n\n", i + 1, leak.source_api, leak.sink_api));
            md.push_str(&format!("- **Source:** `{}` ({})\n", leak.source_api, leak.source_location));
            md.push_str(&format!("- **Sink:** `{}` ({})\n", leak.sink_api, leak.sink_location));
            if let Some(url) = &leak.sink_target_url {
                md.push_str(&format!("- **Target URL:** `{}`\n", url));
            }
            md.push_str("\n**Taint Propagation Flow:**\n```\n");
            for step in &leak.flow_trace {
                md.push_str(&format!("  └── {}\n", step));
            }
            md.push_str("```\n\n");
        }
    }

    // Findings
    if !findings.is_empty() {
        md.push_str(&format!("### ⚠️ Detailed Findings ({} items)\n\n", findings.len()));
        md.push_str("| Severity | Rule | Location | Description & Remediation |\n");
        md.push_str("| :--- | :--- | :--- | :--- |\n");

        for f in findings {
            let sev_icon = match f.severity.as_str() {
                "critical" => "🔴 CRITICAL",
                "high" => "🟠 HIGH",
                "medium" => "🟡 MEDIUM",
                "low" => "🔵 LOW",
                _ => "⚪ INFO",
            };
            let loc = match (&f.file_path, f.line) {
                (Some(p), Some(l)) => format!("{}:{}", p, l),
                (Some(p), None) => p.clone(),
                _ => "manifest.json".into(),
            };
            md.push_str(&format!(
                "| {} | `{}` | `{}` | **{}**<br/>{}<br/>💡 *Fix:* {} |\n",
                sev_icon, f.rule_id, loc, f.title, f.description, f.remediation
            ));
        }
        md.push_str("\n");
    } else {
        md.push_str("### ✅ Clean Build\n\nNo permission over-privileges, dead permissions, or security violations detected!\n\n");
    }

    md
}
