# crx-gate

Zero-Dependency CLI for Pre-Commit Extension Security, Permission Blast-Radius Auditing, and CWS Rejection Prediction.

## Usage with NPX

Run without installing:

```bash
npx crx-gate audit ./path-to-extension
```

Diff two extension builds:

```bash
npx crx-gate diff ./v1.0.0 ./v1.1.0
```

Export SARIF report for GitHub Code Scanning:

```bash
npx crx-gate audit ./dist --format sarif --output crx-gate.sarif
```
