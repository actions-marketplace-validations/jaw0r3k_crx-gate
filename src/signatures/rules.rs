use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSeverity {
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl RuleSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDefinition {
    pub id: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub default_severity: RuleSeverity,
    pub description: &'static str,
    pub cws_policy_reference: Option<&'static str>,
    pub remediation: &'static str,
}

pub static BUILTIN_RULES: &[RuleDefinition] = &[
    RuleDefinition {
        id: "CWS-001",
        title: "Remote Hosted Code Execution",
        category: "CWS Policy Violation",
        default_severity: RuleSeverity::Critical,
        description: "Manifest V3 strictly prohibits loading executable JavaScript from remote external URLs or CDNs.",
        cws_policy_reference: Some("Chrome Web Store Developer Program Policy: Single Purpose & Executable Code"),
        remediation: "Bundle all JavaScript dependencies locally within the extension package archive.",
    },
    RuleDefinition {
        id: "CWS-002",
        title: "Dynamic String Code Execution (eval / Function)",
        category: "CWS Policy Violation",
        default_severity: RuleSeverity::Critical,
        description: "Use of eval(), Function(), or string-based setTimeout/setInterval is prohibited by the default Manifest V3 Content Security Policy.",
        cws_policy_reference: Some("MV3 CSP: Extension Pages & Service Workers"),
        remediation: "Refactor dynamic code execution into static functions or run user-provided scripts inside a sandboxed iframe using window.postMessage.",
    },
    RuleDefinition {
        id: "CWS-003",
        title: "Missing Manifest File Reference",
        category: "CWS Store Rejection",
        default_severity: RuleSeverity::Critical,
        description: "Manifest references a file (e.g. icon, background service worker, popup HTML, content script) that does not exist in the package archive.",
        cws_policy_reference: Some("Chrome Web Store Packaging & Automated Review"),
        remediation: "Ensure all referenced files exist in the extension bundle with exact casing and dimensions, or remove their declaration from manifest.json.",
    },
    RuleDefinition {
        id: "CWS-004",
        title: "Excessive Wildcard Host Permissions (<all_urls>)",
        category: "Permission Blast Radius",
        default_severity: RuleSeverity::High,
        description: "Requesting broad wildcard access (*://*/* or <all_urls>) triggers manual CWS review, Single Purpose policy scrutiny, and significant blast radius.",
        cws_policy_reference: Some("Single Purpose Policy & Permissions Minimization"),
        remediation: "Scope host_permissions to specific domains needed for extension functionality or use 'activeTab' for on-demand user-driven access.",
    },
    RuleDefinition {
        id: "CWS-005",
        title: "Deprecated Manifest V2",
        category: "CWS Deprecation",
        default_severity: RuleSeverity::Critical,
        description: "Chrome Web Store has phased out Manifest V2. All submissions must use Manifest V3.",
        cws_policy_reference: Some("Manifest V2 Support Timeline"),
        remediation: "Set '\"manifest_version\": 3' and migrate background scripts to service workers and webRequest to declarativeNetRequest.",
    },
    RuleDefinition {
        id: "CWS-006",
        title: "Inline Script or Event Handler in HTML",
        category: "CWS Policy Violation",
        default_severity: RuleSeverity::High,
        description: "Inline scripts (<script>...</script>) or inline DOM event handlers (onclick, onload) violate MV3 extension CSP.",
        cws_policy_reference: Some("MV3 Content Security Policy"),
        remediation: "Move inline JavaScript into dedicated .js files and attach listeners using element.addEventListener().",
    },
    RuleDefinition {
        id: "CWS-007",
        title: "Service Worker In-Memory State Vulnerability",
        category: "MV3 Architecture Bug",
        default_severity: RuleSeverity::Medium,
        description: "Extension service workers terminate after ~30 seconds of inactivity. In-memory global variables will be discarded.",
        cws_policy_reference: Some("Service Worker Lifecycle Best Practices"),
        remediation: "Persist state in chrome.storage.local or chrome.storage.session.",
    },
    RuleDefinition {
        id: "CWS-008",
        title: "Unopenable Side Panel Declaration",
        category: "MV3 Architecture Bug",
        default_severity: RuleSeverity::Medium,
        description: "Manifest declares 'side_panel' but no trigger (chrome.sidePanel.open or setPanelBehavior) is registered in the service worker.",
        cws_policy_reference: Some("Chrome Extensions Side Panel API"),
        remediation: "Call chrome.sidePanel.open() inside chrome.action.onClicked or call chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).",
    },
    RuleDefinition {
        id: "CWS-009",
        title: "chrome.action API Used Without Manifest Declaration",
        category: "Runtime Failure",
        default_severity: RuleSeverity::High,
        description: "Calling chrome.action.* without an 'action' key in manifest.json throws an immediate runtime TypeError.",
        cws_policy_reference: Some("Chrome Action API Reference"),
        remediation: "Add '\"action\": {}' to manifest.json.",
    },
    RuleDefinition {
        id: "CWS-010",
        title: "Privileged Tab Property Access Without 'tabs' Permission",
        category: "Runtime Failure",
        default_severity: RuleSeverity::High,
        description: "Accessing tab.url or tab.title requires the 'tabs' permission in manifest.json. Without it, tab.url returns undefined silently.",
        cws_policy_reference: Some("Chrome Tabs API & Tab Objects"),
        remediation: "Declare 'tabs' in permissions if tab.url or tab.title is required, or query only tab.id.",
    },
    RuleDefinition {
        id: "PERM-DEAD",
        title: "Dead Declared Permission",
        category: "Least Privilege Violation",
        default_severity: RuleSeverity::Low,
        description: "Permission is requested in manifest.json but never referenced in any JavaScript or HTML file across the codebase.",
        cws_policy_reference: Some("Single Purpose & Permissions Minimization"),
        remediation: "Remove unused permission from manifest.json to reduce blast radius and avoid unnecessary user warnings.",
    },
    RuleDefinition {
        id: "PERM-UNDECLARED",
        title: "Undeclared Chrome API Permission",
        category: "Runtime Failure",
        default_severity: RuleSeverity::High,
        description: "Chrome API is invoked in extension code but its corresponding permission is missing from manifest.json.",
        cws_policy_reference: Some("Chrome Extensions Manifest Permissions"),
        remediation: "Add the missing permission to manifest.json or remove the API call.",
    },
    RuleDefinition {
        id: "PERM-OVERPRIVILEGED",
        title: "Overprivileged Permission Usage",
        category: "Least Privilege Violation",
        default_severity: RuleSeverity::Medium,
        description: "High-risk permission requested when a lower-privileged alternative is sufficient (e.g. 'tabs' declared when only tab.id is used).",
        cws_policy_reference: Some("Permissions Minimization"),
        remediation: "Switch to 'activeTab' or omit the permission if only non-privileged properties (tab.id, tab.index) are needed.",
    },
    RuleDefinition {
        id: "SEC-OBFUSCATION",
        title: "Obfuscated / Packed Payload Detected",
        category: "Malware & Security",
        default_severity: RuleSeverity::Critical,
        description: "High Shannon entropy string literals or packed decode chains (eval(atob(...))) detected. CWS bans obfuscation to evade security reviews.",
        cws_policy_reference: Some("Chrome Web Store Code Quality & Transparency"),
        remediation: "Remove obfuscators, packers, and encoded payloads. Ship human-readable or standard source-mapped minified code.",
    },
    RuleDefinition {
        id: "SEC-C2-ENDPOINT",
        title: "Known Exfiltration / C2 Webhook Detected",
        category: "Malware & Threat Intel",
        default_severity: RuleSeverity::Critical,
        description: "Hardcoded Discord webhook, Telegram bot token, Ngrok tunnel, or anonymous collector endpoint detected in code.",
        cws_policy_reference: Some("Malicious Software & Data Theft Policy"),
        remediation: "Remove unauthorized third-party exfiltration webhooks immediately.",
    },
    RuleDefinition {
        id: "SEC-TAINT-LEAK",
        title: "Sensitive Data Exfiltration Path",
        category: "Data Loss Prevention",
        default_severity: RuleSeverity::Critical,
        description: "Static taint analysis traced unverified data flow from a sensitive source (cookies, tabs, passwords, identity) into an outbound network sink.",
        cws_policy_reference: Some("User Data Privacy & Exfiltration"),
        remediation: "Ensure credentials and private browsing data are not leaked to external servers.",
    },
    RuleDefinition {
        id: "SEC-EXT-CONNECTABLE",
        title: "Permissive Externally Connectable Wildcard",
        category: "Attack Surface & Exposure",
        default_severity: RuleSeverity::Critical,
        description: "Manifest externally_connectable.matches contains broad wildcards (*://*/* or <all_urls>). Any arbitrary website can exchange messages with extension service workers.",
        cws_policy_reference: Some("Cross-Extension & External Messaging Security"),
        remediation: "Restrict externally_connectable.matches to explicit verified domains belonging to your organization.",
    },
    RuleDefinition {
        id: "SEC-WAR-WILDCARD",
        title: "Overly Permissive Web Accessible Resources",
        category: "Extension Fingerprinting & Leak",
        default_severity: RuleSeverity::High,
        description: "web_accessible_resources declares broad wildcard matches (*://*/*). Exposing resources allows websites to fingerprint installed extensions or bypass origin isolation.",
        cws_policy_reference: Some("Manifest V3 Web Accessible Resources"),
        remediation: "Scope web_accessible_resources matches to specific origins or use dynamic resources.",
    },
    RuleDefinition {
        id: "DNR-TAMPER-CSP",
        title: "DNR Rule Stripping Security Headers",
        category: "Security Tampering",
        default_severity: RuleSeverity::Critical,
        description: "Declarative Net Request rule strips Content-Security-Policy or X-Frame-Options from server responses.",
        cws_policy_reference: Some("Declarative Net Request Security Policy"),
        remediation: "Do not remove browser security headers in declarativeNetRequest rulesets.",
    },
    RuleDefinition {
        id: "DNR-AUTH-THEFT",
        title: "DNR Modifying Session / Auth Headers",
        category: "Security Tampering",
        default_severity: RuleSeverity::Critical,
        description: "Declarative Net Request rule mutates Cookie or Authorization request headers.",
        cws_policy_reference: Some("Declarative Net Request Security Policy"),
        remediation: "Do not tamper with session authentication headers via DNR.",
    },
];

pub fn get_rule(id: &str) -> Option<&'static RuleDefinition> {
    BUILTIN_RULES.iter().find(|r| r.id == id)
}
