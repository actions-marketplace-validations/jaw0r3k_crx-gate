# crx-gate

Static security analyzer and permission linter for Chrome extensions. Statically inspects unpacked extension directories, `.zip` bundles, or `.crx` binaries in under 3ms.

[![GitHub](https://img.shields.io/badge/GitHub-jaw0r3k%2Fcrx--gate-blue?logo=github)](https://github.com/jaw0r3k/crx-gate)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/jaw0r3k/crx-gate/blob/master/LICENSE)

---

## Instant usage via `npx`

No installation required:

```bash
# Audit an extension directory
npx crx-gate audit ./dist

# Generate standalone interactive HTML report
npx crx-gate audit ./dist --format html --output report.html

# Audit a packed .crx binary archive
npx crx-gate audit ./extension.crx

# Diff two versions to prevent permission creep
npx crx-gate diff ./v1.0.0 ./v1.1.0 --fail-on-degradation

# Export SARIF for GitHub Code Scanning
npx crx-gate audit ./dist --format sarif --output crx-gate.sarif

# List all built-in rules
npx crx-gate rules
```

---

## Documentation

Full documentation, GitHub Actions setup, and pre-commit hook integrations:
[https://github.com/jaw0r3k/crx-gate](https://github.com/jaw0r3k/crx-gate)
