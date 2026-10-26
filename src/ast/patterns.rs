use lazy_static::lazy_static;
use regex::Regex;

/// Calculates Shannon entropy of a string (in bits per character)
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

lazy_static! {
    static ref DISCORD_WEBHOOK: Regex = Regex::new(r"(?i)https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+").unwrap();
    static ref TELEGRAM_BOT: Regex = Regex::new(r"(?i)https?://api\.telegram\.org/bot[0-9]+:[a-zA-Z0-9_-]+").unwrap();
    static ref NGROK_URL: Regex = Regex::new(r"(?i)https?://[a-z0-9-]+\.(?:ngrok-free\.app|ngrok\.io|ngrok\.app)").unwrap();
    static ref WEBHOOK_SITE: Regex = Regex::new(r"(?i)https?://(?:webhook\.site|beeceptor\.com|pipedream\.net|requestbin\.net|requestcatcher\.com)/").unwrap();
    static ref RAW_IP_URL: Regex = Regex::new(r"https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?(?:/|\b)").unwrap();
    static ref PASTE_SERVICE: Regex = Regex::new(r"(?i)https?://(?:pastebin\.com|hastebin\.com|rentry\.co|ghostbin\.com)/raw/").unwrap();
}

#[derive(Debug, Clone)]
pub struct SuspiciousEndpoint {
    pub category: &'static str,
    pub url: String,
    pub severity: &'static str,
}

pub fn check_suspicious_endpoint(literal: &str) -> Option<SuspiciousEndpoint> {
    if let Some(m) = DISCORD_WEBHOOK.find(literal) {
        return Some(SuspiciousEndpoint {
            category: "Discord Webhook Exfiltration",
            url: m.as_str().to_string(),
            severity: "critical",
        });
    }
    if let Some(m) = TELEGRAM_BOT.find(literal) {
        return Some(SuspiciousEndpoint {
            category: "Telegram Bot C2 API",
            url: m.as_str().to_string(),
            severity: "critical",
        });
    }
    if let Some(m) = NGROK_URL.find(literal) {
        return Some(SuspiciousEndpoint {
            category: "Ngrok Tunneling / Ephemeral C2",
            url: m.as_str().to_string(),
            severity: "critical",
        });
    }
    if let Some(m) = WEBHOOK_SITE.find(literal) {
        return Some(SuspiciousEndpoint {
            category: "RequestBin / Webhook.site Data Collector",
            url: m.as_str().to_string(),
            severity: "high",
        });
    }
    if let Some(m) = PASTE_SERVICE.find(literal) {
        return Some(SuspiciousEndpoint {
            category: "Pastebin Raw Payload Loader",
            url: m.as_str().to_string(),
            severity: "high",
        });
    }
    if let Some(m) = RAW_IP_URL.find(literal) {
        let matched = m.as_str();
        if !matched.contains("127.0.0.1") {
            return Some(SuspiciousEndpoint {
                category: "Raw Public IP Network Sink",
                url: matched.to_string(),
                severity: "high",
            });
        }
    }
    None
}

/// Checks HTML files for inline scripts and event handlers (prohibited by MV3 CSP)
pub fn check_html_csp_violations(path: &str, content: &str) -> Vec<HtmlViolation> {
    let mut violations = Vec::new();

    let script_regex = Regex::new(r"(?is)<script([^>]*)>(.*?)</script>").unwrap();
    for cap in script_regex.captures_iter(content) {
        let attrs = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let code = cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
        if !attrs.to_lowercase().contains("src=") && !code.is_empty() {
            violations.push(HtmlViolation {
                file_path: path.to_string(),
                kind: "Inline <script>",
                snippet: code.chars().take(80).collect(),
                line: 1,
            });
        }
    }

    let handler_regex = Regex::new(r#"(?i)\s+(on[a-z]{3,12})\s*=\s*["'][^"']+["']"#).unwrap();
    for cap in handler_regex.captures_iter(content) {
        if let Some(m) = cap.get(0) {
            violations.push(HtmlViolation {
                file_path: path.to_string(),
                kind: "Inline Event Handler",
                snippet: m.as_str().trim().to_string(),
                line: 1,
            });
        }
    }

    violations
}

#[derive(Debug, Clone)]
pub struct HtmlViolation {
    pub file_path: String,
    pub kind: &'static str,
    pub snippet: String,
    pub line: usize,
}
