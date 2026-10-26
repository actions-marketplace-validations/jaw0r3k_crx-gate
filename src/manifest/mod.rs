pub mod hosts;
pub mod permissions;
pub mod validation;

use crate::archive::ExtensionPackage;
use anyhow::{Context, Result};
pub use hosts::{calculate_host_blast_radius, HostAnalysis, HostScope};
pub use permissions::{api_to_permission, PermissionInfo, PermissionSeverity, KNOWN_PERMISSIONS};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
pub use validation::{validate_manifest, ManifestData, ValidationIssue};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestReport {
    pub manifest: ManifestData,
    pub validation_issues: Vec<ValidationIssue>,
    pub host_blast_radius: u32,
    pub host_analyses: Vec<HostAnalysis>,
    pub permissions_score: u32,
    pub declared_permissions: HashSet<String>,
    pub declared_hosts: Vec<String>,
}

impl ManifestReport {
    pub fn analyze(package: &ExtensionPackage) -> Result<Self> {
        let manifest_bytes = package
            .read_file("manifest.json")
            .context("Could not find manifest.json in package")?;

        let manifest: ManifestData = serde_json::from_slice(manifest_bytes)
            .context("Failed to parse manifest.json into ManifestData")?;

        let validation_issues = validate_manifest(&manifest, package);

        // Gather host permissions (from host_permissions and content_scripts matches)
        let mut all_hosts = manifest.host_permissions.clone();
        for cs in &manifest.content_scripts {
            for m in &cs.matches {
                if !all_hosts.contains(m) {
                    all_hosts.push(m.clone());
                }
            }
        }

        let (host_blast_radius, host_analyses) = calculate_host_blast_radius(&all_hosts);

        // Calculate permissions score
        let mut permissions_score = 0;
        let mut declared_permissions = HashSet::new();

        for p in &manifest.permissions {
            declared_permissions.insert(p.clone());
            if let Some(info) = KNOWN_PERMISSIONS.get(p.as_str()) {
                permissions_score += info.severity.score_weight();
            } else {
                // Unknown permission, treat as low-medium
                permissions_score += 3;
            }
        }

        // Cap permission score contribution at 35 points
        let permissions_score = permissions_score.min(35);

        Ok(ManifestReport {
            manifest,
            validation_issues,
            host_blast_radius,
            host_analyses,
            permissions_score,
            declared_permissions,
            declared_hosts: all_hosts,
        })
    }
}
