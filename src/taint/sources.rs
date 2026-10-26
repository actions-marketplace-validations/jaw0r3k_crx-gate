use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SensitiveSourceKind {
    Cookies,
    PasswordInputs,
    TabBrowsingHistory,
    AuthIdentityTokens,
    StorageSecrets,
    ClipboardData,
    Geolocation,
}

impl SensitiveSourceKind {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Cookies => "Cookies & Session Identifiers",
            Self::PasswordInputs => "Password Input Fields",
            Self::TabBrowsingHistory => "Active Tab URLs & History",
            Self::AuthIdentityTokens => "OAuth Identity Tokens",
            Self::StorageSecrets => "Extension Local Storage",
            Self::ClipboardData => "Clipboard Contents",
            Self::Geolocation => "Geolocation Coordinates",
        }
    }

    pub fn severity(&self) -> &'static str {
        match self {
            Self::Cookies | Self::PasswordInputs | Self::AuthIdentityTokens => "critical",
            Self::TabBrowsingHistory | Self::ClipboardData => "high",
            Self::StorageSecrets | Self::Geolocation => "medium",
        }
    }
}
