use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkSinkKind {
    Fetch,
    SendBeacon,
    XmlHttpRequest,
    WebSocket,
    EventSource,
    DynamicScriptBeacon,
    CrossWorldPostMessage,
}

impl NetworkSinkKind {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Fetch => "fetch() API",
            Self::SendBeacon => "navigator.sendBeacon()",
            Self::XmlHttpRequest => "XMLHttpRequest.send()",
            Self::WebSocket => "WebSocket Connection",
            Self::EventSource => "EventSource Stream",
            Self::DynamicScriptBeacon => "Dynamic Script / Image Ping",
            Self::CrossWorldPostMessage => "window.postMessage(..., '*')",
        }
    }
}
