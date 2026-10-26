# crx-gate

Static security analyzer and permission linter for Chrome extensions. Statically inspects unpacked extension directories, `.zip` bundles, or `.crx` binaries in under 3ms.

[![CI](https://github.com/jaw0r3k/crx-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/jaw0r3k/crx-gate/actions)
[![Crates.io](https://img.shields.io/crates/v/crx-gate.svg)](https://crates.io/crates/crx-gate)
[![npm](https://img.shields.io/npm/v/crx-gate.svg)](https://www.npmjs.com/package/crx-gate)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

---

## Why crx-gate?

Browser extensions hold privileged access to user session cookies, DOM state, browsing history, and network requests. Standard web SAST tools (like ESLint or Semgrep) inspect generic JavaScript syntax, but are blind to Chrome extension attack vectors:

- **Dead permissions**: APIs declared in `manifest.json` but never invoked anywhere in code.
- **Overprivileged permissions**: Requesting `tabs` when only non-sensitive properties (like `tab.id`) are accessed.
- **Data exfiltration taint paths**: Tracing data flow from sensitive sources (`chrome.cookies`, `chrome.tabs`, `document.cookie`) to outbound network sinks (`fetch`, `sendBeacon`, `WebSocket`).
- **DeclarativeNetRequest tampering**: Rulesets that strip `Content-Security-Policy` or mutate `Cookie`/`Authorization` headers.
- **Chrome Web Store rejection triggers**: Inline scripts in HTML, missing asset files, banned `eval()`, or unescaped `.innerHTML` assignments.

`crx-gate` runs locally before code review or commits land, producing a deterministic blast-radius score (0–100) and catching submission blockers before human review.

---

## Installation

### Via `npx` (No installation needed)

```bash
# Audit an extension directory
npx crx-gate audit ./dist

# Compare blast-radius between releases
npx crx-gate diff ./v1.0.0 ./v1.1.0
```

### Via Cargo

```bash
cargo install crx-gate
```

### Pre-commit hook

Add `crx-gate` to your repository's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/jaw0r3k/crx-gate
    rev: v0.1.0
    hooks:
      - id: crx-gate
```

Or install directly into `.git/hooks/pre-commit`:

```bash
crx-gate hook install --ext-dir ./src
```

---

## Usage

```text
crx-gate [OPTIONS] [PATH] [COMMAND]

Commands:
  audit        Audit an extension directory, .zip, or .crx archive
  diff         Compare blast-radius and security posture between two extension versions
  rules        List all built-in security rules and Chrome Web Store rejection heuristics
  init         Initialize crx-gate configuration in the current repository
  hook         Install git pre-commit hook
  completions  Generate shell auto-completion scripts (bash, zsh, fish, powershell)
```

### Audit an extension

```bash
# Terminal table output
crx-gate audit ./my-extension

# Standalone interactive HTML report
crx-gate audit ./my-extension --format html --output report.html

# SARIF report for GitHub Code Scanning
crx-gate audit ./my-extension --format sarif --output crx-gate.sarif

# Machine-readable JSON output
crx-gate audit ./my-extension --format json

# Fail build if high or critical issues are found, or score exceeds 60
crx-gate audit ./my-extension --fail-on high --max-score 60
```

### Diff two versions

Catch permission creeps, new taint flows, or risk degradation in pull requests:

```bash
crx-gate diff ./v1.0.0 ./v1.1.0 --fail-on-degradation
```

```text
Base:   v1.0.0
Target: v1.1.0

Score: 10 (Grade: A) -> 94 (Grade: F) | Delta: +84 (DEGRADATION / INCREASED RISK)

Added Permissions:
  + tabs
  + cookies

Expanded Host Scopes:
  + <all_urls>

1 New Data Exfiltration Path Introduced:
  * chrome.cookies.getAll -> fetch
```

### Shell auto-completions

Generate completion scripts for your shell:

```bash
# Bash
crx-gate completions bash > ~/.local/share/bash-completion/completions/crx-gate

# Zsh
crx-gate completions zsh > ~/.zfunc/_crx-gate

# Fish
crx-gate completions fish > ~/.config/fish/completions/crx-gate.fish
```

---

## Configuration (`crx-gate.toml`)

Initialize a configuration file with `crx-gate init`:

```toml
[audit]
# Exit with code 1 if findings reach this severity: none, low, medium, high, critical
fail_on = "high"

# Maximum permissible blast-radius score (0 - 100)
max_score = 60

# Ignore dead permissions for frameworks with dynamic runtime bindings
ignore_dead_permissions = false

ignore_paths = [
  "**/*.min.js.map",
  "**/node_modules/**"
]

[rules]
disabled_rules = []
custom_exfiltration_endpoints = []

# Documented exceptions with reason and expiration
[[waivers]]
rule_id = "CWS-004"
path = "manifest.json"
reason = "Enterprise proxy enforcement extension requires <all_urls>"
expires = "2027-01-01"
```

---

## GitHub Actions

Run `crx-gate` in your CI workflow and upload findings directly to the **GitHub Security -> Code Scanning** tab:

```yaml
name: Extension Security Audit

on:
  pull_request:
    branches: [ "main" ]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run crx-gate
        uses: jaw0r3k/crx-gate@v1
        with:
          path: './dist'
          fail-on: 'high'
          max-score: '60'
          sarif: 'crx-gate.sarif'

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'crx-gate.sarif'
```

---

## Built-in Rules

| Rule ID | Severity | Category | Description |
| :--- | :--- | :--- | :--- |
| `CWS-001` | Critical | CWS Policy | Remote hosted code execution (`<script src="https://...">`) |
| `CWS-002` | Critical | CWS Policy | Dynamic code execution (`eval()`, `Function()`, string `setTimeout`) |
| `CWS-003` | Critical | Packaging | Manifest references non-existent files (icons, popups, scripts) |
| `CWS-004` | High | Host Scope | Excessive wildcard host permissions (`<all_urls>`, `*://*/*`) |
| `CWS-005` | Critical | Deprecation | Use of deprecated Manifest V2 |
| `CWS-006` | High | CSP Violation | Inline scripts or inline event handlers (`onclick`) in HTML |
| `CWS-007` | Medium | MV3 Lifetime | In-memory global state in ephemeral service workers |
| `CWS-008` | Medium | Architecture | Side panel declared without opening trigger |
| `CWS-009` | High | Runtime Bug | `chrome.action.*` invoked without `"action"` key in manifest |
| `CWS-010` | High | Runtime Bug | Accessing `tab.url`/`tab.title` without declaring `"tabs"` permission |
| `CWS-011` | Medium | CWS Quality | Manifest description missing, < 25 chars, or keyword stuffing |
| `CWS-012` | Critical | CWS Policy | Compiling or streaming remote WebAssembly bytecode |
| `CWS-013` | High | CWS Scrutiny | Declaring privileged `debugger` permission (Tier-3 manual review) |
| `CWS-014` | Medium | Frame Isolation | `all_frames: true` on wildcard `<all_urls>` injecting into third-party ad iframes |
| `PERM-DEAD` | Low | Least Privilege | Declared permission is never invoked in any extension code |
| `PERM-UNDECLARED` | High | Runtime Bug | Chrome API invoked in code without manifest permission |
| `PERM-OVERPRIVILEGED` | Medium | Least Privilege | Declaring `tabs` when only non-sensitive `tab.id` is read |
| `SEC-TAINT-LEAK` | Critical | DLP / Security | Confirmed data flow from sensitive source to network sink |
| `SEC-DOM-XSS` | Critical | DOM Security | Assignments to `.innerHTML` / `.outerHTML` or `document.write` |
| `SEC-EXTERNAL-MSG-INSECURE` | Critical | Access Control | `onMessageExternal` listener missing `sender.origin` validation |
| `SEC-KEYLOGGER-INPUT` | Critical | Malware / Spyware | Global keydown listeners or password input field snooping |
| `SEC-STORAGE-SYNC-CREDENTIALS` | High | Privacy & DLP | Plaintext credentials/tokens stored in unencrypted `chrome.storage.sync` |
| `SEC-C2-ENDPOINT` | Critical | Threat Intel | Hardcoded Discord webhook, Telegram bot, or Ngrok tunnel |
| `SEC-OBFUSCATION` | Critical | Malware | High Shannon entropy packed strings or obfuscation chains |
| `SEC-EXT-CONNECTABLE` | Critical | Security Hole | Wildcard `externally_connectable` matches exposing listeners to any website |
| `SEC-WAR-WILDCARD` | High | Fingerprinting | Wildcard `web_accessible_resources` enabling cross-site tracking |
| `DNR-TAMPER-CSP` | Critical | Tampering | Declarative Net Request rule stripping CSP or X-Frame-Options |
| `DNR-AUTH-THEFT` | Critical | Tampering | Declarative Net Request rule mutating `Cookie` or `Authorization` headers |
| `WARN-MV3-BROWSER-ACTION` | High | Compatibility | Deprecated `browser_action`/`page_action` used in MV3 (popup will fail) |
| `WARN-MV3-BACKGROUND-SCRIPTS` | Critical | Compatibility | Deprecated `background.scripts` declared in MV3 without service worker |
| `WARN-MV3-CSP-STRING` | Critical | Compatibility | Legacy string CSP used in MV3 instead of dictionary object |
| `WARN-MV3-WEBREQUEST-BLOCKING` | High | Compatibility | Deprecated `webRequestBlocking` permission declared in MV3 |

---

## Benchmarks

Benchmarked on an Apple M-series / AMD Ryzen machine scanning extension bundles:

| Extension Size | Files Analyzed | AST Traversal & Taint Analysis | Resident Memory |
| :--- | :--- | :--- | :--- |
| **Small MV3 Extension** | 5 files | **1.8 ms** | < 12 MB |
| **Medium Extension (Bundled)** | 28 files | **3.4 ms** | < 18 MB |
| **Large Suite (50+ MB bundle)** | 120 files | **42.1 ms** | < 45 MB |

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
