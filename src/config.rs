use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub waivers: Vec<Waiver>,
    #[serde(default)]
    pub rules: RuleConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_fail_on")]
    pub fail_on: String, // "none", "low", "medium", "high", "critical"
    #[serde(default = "default_max_score")]
    pub max_score: u32,  // 0 - 100
    #[serde(default)]
    pub ignore_dead_permissions: bool,
    #[serde(default)]
    pub ignore_paths: Vec<String>,
}

fn default_fail_on() -> String {
    "high".to_string()
}

fn default_max_score() -> u32 {
    70
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            fail_on: default_fail_on(),
            max_score: default_max_score(),
            ignore_dead_permissions: false,
            ignore_paths: vec![
                "**/*.min.js.map".into(),
                "**/node_modules/**".into(),
                "**/.git/**".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Waiver {
    pub rule_id: String,
    pub path: Option<String>,
    pub reason: String,
    pub expires: Option<String>, // "YYYY-MM-DD"
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleConfig {
    #[serde(default)]
    pub disabled_rules: Vec<String>,
    #[serde(default)]
    pub custom_exfiltration_endpoints: Vec<String>,
}

impl Config {
    pub fn load_or_default(path: Option<&Path>) -> Self {
        if let Some(p) = path {
            if p.exists() {
                if let Ok(content) = std::fs::read_to_string(p) {
                    if let Ok(cfg) = toml::from_str::<Config>(&content) {
                        return cfg;
                    }
                }
            }
        } else {
            // Check current directory for crx-gate.toml or .crxgaterc.json
            if Path::new("crx-gate.toml").exists() {
                if let Ok(content) = std::fs::read_to_string("crx-gate.toml") {
                    if let Ok(cfg) = toml::from_str::<Config>(&content) {
                        return cfg;
                    }
                }
            }
        }
        Config::default()
    }

    pub fn is_waived(&self, rule_id: &str, file_path: Option<&str>) -> bool {
        for waiver in &self.waivers {
            if waiver.rule_id == rule_id || waiver.rule_id == "*" {
                if let Some(target_path) = &waiver.path {
                    if let Some(current_path) = file_path {
                        if current_path.contains(target_path) {
                            return true;
                        }
                    }
                } else {
                    return true;
                }
            }
        }
        false
    }
}
