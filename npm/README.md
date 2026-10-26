# crx-gate

> **Zero-Dependency CLI for Pre-Commit Extension Security, Permission Blast-Radius Auditing, and Chrome Web Store Rejection Prediction.**

[![GitHub](https://img.shields.io/badge/GitHub-crx--gate%2Fcrx--gate-blue?logo=github)](https://github.com/crx-gate/crx-gate)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/crx-gate/crx-gate/blob/master/LICENSE)

Statically analyzes unpacked extension directories, `.zip` archives, and `.crx` binaries in under **3ms**. Outputs deterministic blast-radius risk scores, detects hidden data-exfiltration sinks via static taint analysis, and flags Chrome Web Store rejection triggers before submission.

---

## 🚀 Instant Usage via `npx`

No installation required:

```bash
# Audit an unpacked extension directory
npx crx-gate audit ./dist

# Generate standalone interactive HTML report
npx crx-gate audit ./dist --format html --output report.html

# Audit a packed .crx binary archive
npx crx-gate audit ./extension.crx

# Diff two extension versions to block risk regressions
npx crx-gate diff ./v1.0.0 ./v1.1.0 --fail-on-degradation

# Export SARIF for GitHub Code Scanning
npx crx-gate audit ./dist --format sarif --output crx-gate.sarif

# List all built-in rules and CWS heuristics
npx crx-gate rules
```

---

## 📖 Full Documentation

Visit the official repository for full documentation, GitHub Actions setup, and pre-commit hook integrations:
👉 **[https://github.com/crx-gate/crx-gate](https://github.com/crx-gate/crx-gate)**
