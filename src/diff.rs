use crate::report::table::ScanFinding;
use crate::scorer::BlastRadiusScore;
use crate::taint::TaintLeakPath;
use colored::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub base_path: String,
    pub target_path: String,
    pub base_score: BlastRadiusScore,
    pub target_score: BlastRadiusScore,
    pub score_delta: i32,
    pub added_permissions: Vec<String>,
    pub removed_permissions: Vec<String>,
    pub added_hosts: Vec<String>,
    pub removed_hosts: Vec<String>,
    pub new_findings: Vec<ScanFinding>,
    pub resolved_findings: Vec<ScanFinding>,
    pub new_taint_paths: Vec<TaintLeakPath>,
}

impl DiffReport {
    pub fn render_terminal(&self) -> String {
        let mut out = String::new();
        out.push_str("\n");
        out.push_str(&format!(
            "{}\n",
            "╔══════════════════════════════════════════════════════════════════════════════╗".bright_cyan()
        ));
        out.push_str(&format!(
            "║ {:<76} ║\n",
            "  CRX-GATE — Extension Security & Blast-Radius Diff Audit"
                .bright_white()
                .bold()
        ));
        out.push_str(&format!(
            "{}\n\n",
            "╚══════════════════════════════════════════════════════════════════════════════╝".bright_cyan()
        ));

        out.push_str(&format!("  Base:   {}\n", self.base_path.dimmed()));
        out.push_str(&format!("  Target: {}\n\n", self.target_path.bright_white().bold()));

        let delta_str = if self.score_delta > 0 {
            format!("+{} (DEGRADATION / INCREASED RISK)", self.score_delta).bright_red().bold()
        } else if self.score_delta < 0 {
            format!("{} (IMPROVED SECURITY POSTURE)", self.score_delta).bright_green().bold()
        } else {
            "0 (NO BLAST RADIUS CHANGE)".bright_blue()
        };

        out.push_str(&format!(
            "  Score: {} (Grade: {}) ➔ {} (Grade: {}) | Delta: {}\n\n",
            self.base_score.total_score,
            self.base_score.grade,
            self.target_score.total_score,
            self.target_score.grade,
            delta_str
        ));

        if !self.added_permissions.is_empty() {
            out.push_str(&format!("  {} Added Permissions:\n", "➕".green()));
            for p in &self.added_permissions {
                out.push_str(&format!("    • {}\n", p.bright_red().bold()));
            }
            out.push_str("\n");
        }

        if !self.removed_permissions.is_empty() {
            out.push_str(&format!("  {} Removed Permissions:\n", "➖".red()));
            for p in &self.removed_permissions {
                out.push_str(&format!("    • {}\n", p.bright_green()));
            }
            out.push_str("\n");
        }

        if !self.added_hosts.is_empty() {
            out.push_str(&format!("  {} Expanded Host Scopes:\n", "🌐".yellow()));
            for h in &self.added_hosts {
                out.push_str(&format!("    • {}\n", h.bright_yellow().bold()));
            }
            out.push_str("\n");
        }

        if !self.new_taint_paths.is_empty() {
            out.push_str(&format!(
                "  🚨 {} New Data Exfiltration Paths Introduced in this PR/Commit!\n",
                self.new_taint_paths.len()
            ));
            for leak in &self.new_taint_paths {
                out.push_str(&format!(
                    "    • {} ➔ {}\n",
                    leak.source_api.bright_red(),
                    leak.sink_api.bright_red()
                ));
            }
            out.push_str("\n");
        }

        if !self.new_findings.is_empty() {
            out.push_str(&format!(
                "  ⚠️  {} New Security Findings Introduced:\n",
                self.new_findings.len()
            ));
            for f in &self.new_findings {
                let loc = f.file_path.as_deref().unwrap_or("manifest.json");
                out.push_str(&format!(
                    "    • [{}] {} at {} ({})\n",
                    f.severity.to_uppercase().bright_red(),
                    f.rule_id.cyan(),
                    loc,
                    f.title
                ));
            }
            out.push_str("\n");
        }

        out
    }
}
