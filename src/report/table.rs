use crate::scorer::BlastRadiusScore;
use crate::taint::TaintLeakPath;
use colored::*;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub category: String,
    pub file_path: Option<String>,
    pub line: Option<usize>,
    pub col: Option<usize>,
    pub snippet: Option<String>,
    pub description: String,
    pub remediation: String,
    pub cws_policy_ref: Option<String>,
}

pub fn render_terminal_report(
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
    let mut out = String::new();

    // Clean modern CLI header
    out.push_str("\n");
    out.push_str(&format!(
        "{} {}\n",
        "crx-gate".bright_cyan().bold(),
        format!("v{} — extension security & blast-radius audit", env!("CARGO_PKG_VERSION")).dimmed()
    ));
    out.push_str(&format!("{}\n", "─".repeat(78).dimmed()));

    // Meta box
    out.push_str(&format!(
        "  Target:       {}\n",
        target_path.bright_white()
    ));
    out.push_str(&format!(
        "  Extension:    {} (v{}) [Manifest V{}]\n",
        extension_name.bold(),
        extension_version,
        manifest_version
    ));
    if let Some(id) = extension_id {
        out.push_str(&format!(
            "  Computed ID:  {}\n",
            id.bright_yellow()
        ));
    }
    out.push_str(&format!(
        "  Package Type: {} | Scanned in: {} ms\n\n",
        package_type,
        duration_ms
    ));

    // Grade Banner
    let grade_colored = match score.grade.as_str() {
        "A+" | "A" => score.grade.bright_green().bold(),
        "B" => score.grade.green().bold(),
        "C" => score.grade.yellow().bold(),
        "D" => score.grade.bright_red().bold(),
        _ => score.grade.on_red().bright_white().bold(),
    };

    let risk_colored = match score.risk_level.as_str() {
        "minimal" => "MINIMAL RISK".bright_green().bold(),
        "low" => "LOW RISK".green().bold(),
        "medium" => "MODERATE RISK".yellow().bold(),
        "high" => "HIGH BLAST RADIUS".bright_red().bold(),
        _ => "CRITICAL BLAST RADIUS".on_red().bright_white().bold(),
    };

    let cws_verdict_colored = match score.predicted_cws_verdict.as_str() {
        "AUTOMATED_PASS_LIKELY" => "AUTOMATED PASS LIKELY".bright_green().bold(),
        "MANUAL_REVIEW_LIKELY" => "MANUAL REVIEW LIKELY".yellow().bold(),
        _ => "REJECTION LIKELY (POLICY VIOLATION)".bright_red().bold(),
    };

    out.push_str(&format!(
        "  ┌──────────────────────────────┬──────────────────────────────┬──────────────────────────────┐\n"
    ));
    out.push_str(&format!(
        "  │  Blast Radius Grade: {:<6}  │  Score: {:<3}/100             │  Risk: {:<19} │\n",
        grade_colored, score.total_score, risk_colored
    ));
    out.push_str(&format!(
        "  ├──────────────────────────────┴──────────────────────────────┴──────────────────────────────┤\n"
    ));
    out.push_str(&format!(
        "  │  CWS Submission Prediction: {:<61} │\n",
        cws_verdict_colored
    ));
    out.push_str(&format!(
        "  └────────────────────────────────────────────────────────────────────────────────────────────┘\n\n"
    ));

    // Score Breakdown Table
    let mut score_table = Table::new();
    score_table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Audit Vector").add_attribute(Attribute::Bold),
            Cell::new("Score").add_attribute(Attribute::Bold),
            Cell::new("Cap").add_attribute(Attribute::Bold),
            Cell::new("Status").add_attribute(Attribute::Bold),
        ]);

    score_table.add_row(vec![
        Cell::new("Manifest Permissions Blast"),
        Cell::new(score.breakdown.permissions_score.to_string()),
        Cell::new("/ 30"),
        if score.breakdown.permissions_score <= 5 {
            Cell::new("Clean / Minimal").fg(Color::Green)
        } else if score.breakdown.permissions_score <= 15 {
            Cell::new("Moderate").fg(Color::Yellow)
        } else {
            Cell::new("Over-privileged").fg(Color::Red)
        },
    ]);

    score_table.add_row(vec![
        Cell::new("Host Permissions Scope"),
        Cell::new(score.breakdown.host_scope_score.to_string()),
        Cell::new("/ 25"),
        if score.breakdown.host_scope_score == 0 {
            Cell::new("No host access").fg(Color::Green)
        } else if score.breakdown.host_scope_score < 20 {
            Cell::new("Scoped domains").fg(Color::Yellow)
        } else {
            Cell::new("Wildcard <all_urls>").fg(Color::Red)
        },
    ]);

    score_table.add_row(vec![
        Cell::new("Static Taint Exfiltration"),
        Cell::new(score.breakdown.taint_exfiltration_score.to_string()),
        Cell::new("/ 25"),
        if score.breakdown.taint_exfiltration_score == 0 {
            Cell::new("Zero leak paths").fg(Color::Green)
        } else {
            Cell::new("CONFIRMED LEAK").fg(Color::Red).add_attribute(Attribute::Bold)
        },
    ]);

    score_table.add_row(vec![
        Cell::new("Policy & Vulnerabilities"),
        Cell::new(score.breakdown.vulnerability_score.to_string()),
        Cell::new("/ 20"),
        if score.breakdown.vulnerability_score == 0 {
            Cell::new("Compliant").fg(Color::Green)
        } else if score.breakdown.vulnerability_score <= 10 {
            Cell::new("Warning").fg(Color::Yellow)
        } else {
            Cell::new("Policy Rejection").fg(Color::Red)
        },
    ]);

    out.push_str("  [ Blast-Radius Risk Breakdown ]\n");
    out.push_str(&format!("{}\n\n", score_table));

    // Confirmed Taint Leak Paths
    if !taint_paths.is_empty() {
        out.push_str(&format!(
            "  {}\n",
            "🚨 CRITICAL: Confirmed Data Exfiltration Paths (Static Taint Engine)"
                .bright_red()
                .bold()
        ));
        for (idx, leak) in taint_paths.iter().enumerate() {
            out.push_str(&format!(
                "  Path #{}: {} ➔ {}\n",
                idx + 1,
                leak.source_api.bright_red().bold(),
                leak.sink_api.bright_red().bold()
            ));
            for step in &leak.flow_trace {
                out.push_str(&format!("    └── {}\n", step.bright_yellow()));
            }
            if let Some(target) = &leak.sink_target_url {
                out.push_str(&format!("    └── Exfiltration Target: {}\n", target.bright_red().underline()));
            }
            out.push_str("\n");
        }
    }

    // Findings Table
    if !findings.is_empty() {
        out.push_str(&format!(
            "  [ Detailed Findings ({} issue{}) ]\n",
            findings.len(),
            if findings.len() == 1 { "" } else { "s" }
        ));

        let mut findings_table = Table::new();
        findings_table
            .load_preset(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                Cell::new("Severity").add_attribute(Attribute::Bold),
                Cell::new("Rule ID").add_attribute(Attribute::Bold),
                Cell::new("Location").add_attribute(Attribute::Bold),
                Cell::new("Finding & Remediation").add_attribute(Attribute::Bold),
            ]);

        for f in findings {
            let sev_cell = match f.severity.as_str() {
                "critical" => Cell::new("CRITICAL").fg(Color::Red).add_attribute(Attribute::Bold),
                "high" => Cell::new("HIGH").fg(Color::DarkRed),
                "medium" => Cell::new("MEDIUM").fg(Color::Yellow),
                "low" => Cell::new("LOW").fg(Color::Blue),
                _ => Cell::new("INFO").fg(Color::Grey),
            };

            let loc = match (&f.file_path, f.line) {
                (Some(path), Some(line)) => format!("{}:{}", path, line),
                (Some(path), None) => path.clone(),
                _ => "manifest.json".into(),
            };

            let mut details = format!("{}\n{}", f.title.bold(), f.description);
            if let Some(snip) = &f.snippet {
                details.push_str(&format!("\n> Code: {}", snip.dimmed()));
            }
            details.push_str(&format!("\nFix: {}", f.remediation.green()));

            findings_table.add_row(vec![
                sev_cell,
                Cell::new(&f.rule_id).fg(Color::Cyan),
                Cell::new(loc),
                Cell::new(details),
            ]);
        }

        out.push_str(&format!("{}\n\n", findings_table));
    } else {
        out.push_str(&format!(
            "  {}\n\n",
            "✨ Zero security vulnerabilities or dead permissions detected!".bright_green().bold()
        ));
    }

    out
}
