use crate::report::table::ScanFinding;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRuleDef>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRuleDef {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    pub full_description: SarifMessage,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String, // "error", "warning", "note"
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: Option<SarifRegion>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: usize,
    #[serde(rename = "startColumn")]
    pub start_column: Option<usize>,
}

pub fn generate_sarif_report(findings: &[ScanFinding]) -> SarifReport {
    let mut rules = Vec::new();
    let mut results = Vec::new();

    for finding in findings {
        if !rules.iter().any(|r: &SarifRuleDef| r.id == finding.rule_id) {
            rules.push(SarifRuleDef {
                id: finding.rule_id.clone(),
                name: finding.title.replace(' ', ""),
                short_description: SarifMessage {
                    text: finding.title.clone(),
                },
                full_description: SarifMessage {
                    text: format!("{}. Remediation: {}", finding.description, finding.remediation),
                },
            });
        }

        let level = match finding.severity.as_str() {
            "critical" | "high" => "error",
            "medium" => "warning",
            _ => "note",
        }
        .to_string();

        let file_uri = finding
            .file_path
            .clone()
            .unwrap_or_else(|| "manifest.json".into());

        let region = finding.line.map(|l| SarifRegion {
            start_line: l,
            start_column: finding.col,
        });

        results.push(SarifResult {
            rule_id: finding.rule_id.clone(),
            level,
            message: SarifMessage {
                text: format!("{}: {}", finding.title, finding.description),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation { uri: file_uri },
                    region,
                },
            }],
        });
    }

    SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".into(),
        version: "2.1.0".into(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "crx-gate".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    information_uri: "https://github.com/crx-gate/crx-gate".into(),
                    rules,
                },
            },
            results,
        }],
    }
}
