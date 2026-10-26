use crate::report::table::ScanFinding;
use crate::scorer::BlastRadiusScore;
use crate::taint::TaintLeakPath;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonReport {
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

pub fn render_json_report(
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
    let report = JsonReport {
        target_path: target_path.to_string(),
        package_type: package_type.to_string(),
        extension_id: extension_id.map(|s| s.to_string()),
        extension_name: extension_name.to_string(),
        extension_version: extension_version.to_string(),
        manifest_version,
        score: score.clone(),
        findings: findings.to_vec(),
        taint_paths: taint_paths.to_vec(),
        execution_duration_ms: duration_ms,
    };

    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}
