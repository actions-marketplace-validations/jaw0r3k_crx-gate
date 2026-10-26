use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionSeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl PermissionSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn score_weight(&self) -> u32 {
        match self {
            Self::Low => 2,
            Self::Medium => 5,
            Self::High => 12,
            Self::Critical => 25,
        }
    }
}

pub struct PermissionInfo {
    pub severity: PermissionSeverity,
    pub description: &'static str,
    pub api_prefix: &'static str,
}

lazy_static! {
    pub static ref KNOWN_PERMISSIONS: HashMap<&'static str, PermissionInfo> = {
        let mut m = HashMap::new();
        // Critical
        m.insert("debugger", PermissionInfo {
            severity: PermissionSeverity::Critical,
            description: "Attach debugger to any tab; full control over network, DOM, JS execution",
            api_prefix: "chrome.debugger",
        });
        m.insert("webRequest", PermissionInfo {
            severity: PermissionSeverity::Critical,
            description: "Intercept, inspect, and log all network traffic and headers",
            api_prefix: "chrome.webRequest",
        });
        m.insert("webRequestBlocking", PermissionInfo {
            severity: PermissionSeverity::Critical,
            description: "Synchronously modify, redirect, or block network requests and credentials",
            api_prefix: "chrome.webRequest",
        });
        m.insert("declarativeNetRequestFeedback", PermissionInfo {
            severity: PermissionSeverity::Critical,
            description: "Read detailed diagnostic logs of modified and blocked network traffic",
            api_prefix: "chrome.declarativeNetRequest",
        });
        m.insert("nativeMessaging", PermissionInfo {
            severity: PermissionSeverity::Critical,
            description: "Communicate with unconfined native applications installed on the host OS",
            api_prefix: "chrome.runtime.sendNativeMessage",
        });
        m.insert("proxy", PermissionInfo {
            severity: PermissionSeverity::Critical,
            description: "Control browser proxy configuration to route all network traffic",
            api_prefix: "chrome.proxy",
        });

        // High
        m.insert("cookies", PermissionInfo {
            severity: PermissionSeverity::High,
            description: "Read, write, and monitor HTTP cookies across origins",
            api_prefix: "chrome.cookies",
        });
        m.insert("scripting", PermissionInfo {
            severity: PermissionSeverity::High,
            description: "Execute arbitrary JavaScript and CSS in active browser tabs",
            api_prefix: "chrome.scripting",
        });
        m.insert("tabs", PermissionInfo {
            severity: PermissionSeverity::High,
            description: "Access privileged tab properties (sensitive URLs, tab titles, favicons)",
            api_prefix: "chrome.tabs",
        });
        m.insert("activeTab", PermissionInfo {
            severity: PermissionSeverity::High,
            description: "Temporary full access to active tab upon user gesture",
            api_prefix: "chrome.tabs",
        });
        m.insert("history", PermissionInfo {
            severity: PermissionSeverity::High,
            description: "Read and manipulate the user's complete browsing history",
            api_prefix: "chrome.history",
        });
        m.insert("bookmarks", PermissionInfo {
            severity: PermissionSeverity::High,
            description: "Read and manipulate user bookmarks and bookmarks folder tree",
            api_prefix: "chrome.bookmarks",
        });
        m.insert("browsingData", PermissionInfo {
            severity: PermissionSeverity::High,
            description: "Clear browser cache, cookies, history, and stored data",
            api_prefix: "chrome.browsingData",
        });
        m.insert("management", PermissionInfo {
            severity: PermissionSeverity::High,
            description: "Manage installed extensions and apps (install, uninstall, disable)",
            api_prefix: "chrome.management",
        });
        m.insert("privacy", PermissionInfo {
            severity: PermissionSeverity::High,
            description: "Control browser privacy settings (WebRTC IP leaks, third-party cookies)",
            api_prefix: "chrome.privacy",
        });
        m.insert("tabCapture", PermissionInfo {
            severity: PermissionSeverity::High,
            description: "Capture video and audio stream of active browser tabs",
            api_prefix: "chrome.tabCapture",
        });
        m.insert("desktopCapture", PermissionInfo {
            severity: PermissionSeverity::High,
            description: "Capture video and audio stream of the entire desktop or application windows",
            api_prefix: "chrome.desktopCapture",
        });
        m.insert("pageCapture", PermissionInfo {
            severity: PermissionSeverity::High,
            description: "Save entire tab content as an MHTML archive",
            api_prefix: "chrome.pageCapture",
        });
        m.insert("webNavigation", PermissionInfo {
            severity: PermissionSeverity::High,
            description: "Observe web navigation status in real-time across all frames",
            api_prefix: "chrome.webNavigation",
        });
        m.insert("userScripts", PermissionInfo {
            severity: PermissionSeverity::High,
            description: "Register and execute dynamic user-provided scripts in isolated/user worlds",
            api_prefix: "chrome.userScripts",
        });
        m.insert("identity", PermissionInfo {
            severity: PermissionSeverity::High,
            description: "Access OAuth2 tokens and Google user account profile information",
            api_prefix: "chrome.identity",
        });

        // Medium
        m.insert("storage", PermissionInfo {
            severity: PermissionSeverity::Medium,
            description: "Store extension settings and data locally or synced across devices",
            api_prefix: "chrome.storage",
        });
        m.insert("unlimitedStorage", PermissionInfo {
            severity: PermissionSeverity::Medium,
            description: "Bypass quota restrictions for client-side storage",
            api_prefix: "chrome.storage",
        });
        m.insert("declarativeNetRequest", PermissionInfo {
            severity: PermissionSeverity::Medium,
            description: "Block or modify network requests declaratively based on static rules",
            api_prefix: "chrome.declarativeNetRequest",
        });
        m.insert("declarativeNetRequestWithHostAccess", PermissionInfo {
            severity: PermissionSeverity::Medium,
            description: "Declarative net request with host access matching",
            api_prefix: "chrome.declarativeNetRequest",
        });
        m.insert("alarms", PermissionInfo {
            severity: PermissionSeverity::Medium,
            description: "Schedule code to run periodically or at a specified time in the future",
            api_prefix: "chrome.alarms",
        });
        m.insert("contextMenus", PermissionInfo {
            severity: PermissionSeverity::Medium,
            description: "Add custom context menu items to Google Chrome's right-click menu",
            api_prefix: "chrome.contextMenus",
        });
        m.insert("notifications", PermissionInfo {
            severity: PermissionSeverity::Medium,
            description: "Create rich desktop notifications using templates",
            api_prefix: "chrome.notifications",
        });
        m.insert("offscreen", PermissionInfo {
            severity: PermissionSeverity::Medium,
            description: "Create hidden DOM-enabled offscreen documents for audio/DOM tasks",
            api_prefix: "chrome.offscreen",
        });
        m.insert("idle", PermissionInfo {
            severity: PermissionSeverity::Medium,
            description: "Detect when the machine's idle state changes (locked, active, idle)",
            api_prefix: "chrome.idle",
        });
        m.insert("sidePanel", PermissionInfo {
            severity: PermissionSeverity::Medium,
            description: "Display custom content in Chrome's side panel UI",
            api_prefix: "chrome.sidePanel",
        });

        // Low
        m.insert("power", PermissionInfo {
            severity: PermissionSeverity::Low,
            description: "Override system power management features to keep screen awake",
            api_prefix: "chrome.power",
        });
        m.insert("tts", PermissionInfo {
            severity: PermissionSeverity::Low,
            description: "Play synthesized text-to-speech (TTS)",
            api_prefix: "chrome.tts",
        });
        m.insert("printerProvider", PermissionInfo {
            severity: PermissionSeverity::Low,
            description: "Support print jobs from Chrome print manager",
            api_prefix: "chrome.printerProvider",
        });

        m
    };
}

/// Deterministically maps a chrome.* API call to its required manifest permission
pub fn api_to_permission(api_call: &str) -> Option<&'static str> {
    if api_call.starts_with("chrome.cookies") {
        Some("cookies")
    } else if api_call.starts_with("chrome.tabs") {
        Some("tabs")
    } else if api_call.starts_with("chrome.scripting") {
        Some("scripting")
    } else if api_call.starts_with("chrome.storage") {
        Some("storage")
    } else if api_call.starts_with("chrome.alarms") {
        Some("alarms")
    } else if api_call.starts_with("chrome.history") {
        Some("history")
    } else if api_call.starts_with("chrome.bookmarks") {
        Some("bookmarks")
    } else if api_call.starts_with("chrome.contextMenus") {
        Some("contextMenus")
    } else if api_call.starts_with("chrome.notifications") {
        Some("notifications")
    } else if api_call.starts_with("chrome.identity") {
        Some("identity")
    } else if api_call.starts_with("chrome.management") {
        Some("management")
    } else if api_call.starts_with("chrome.offscreen") {
        Some("offscreen")
    } else if api_call.starts_with("chrome.sidePanel") {
        Some("sidePanel")
    } else if api_call.starts_with("chrome.userScripts") {
        Some("userScripts")
    } else if api_call.starts_with("chrome.debugger") {
        Some("debugger")
    } else if api_call.starts_with("chrome.declarativeNetRequest") {
        Some("declarativeNetRequest")
    } else if api_call.starts_with("chrome.webRequest") {
        Some("webRequest")
    } else if api_call.starts_with("chrome.webNavigation") {
        Some("webNavigation")
    } else if api_call.starts_with("chrome.idle") {
        Some("idle")
    } else if api_call.starts_with("chrome.power") {
        Some("power")
    } else if api_call.starts_with("chrome.tts") {
        Some("tts")
    } else {
        None
    }
}
