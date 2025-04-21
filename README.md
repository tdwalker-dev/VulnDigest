# VulnDigest - DAST JSON to Markdown Report Generator

**VulnDigest** is a fast, cross-platform CLI tool that converts Dynamic Application Security Testing (DAST) JSON reports into clean, readable Markdown summaries grouped by severity.

---

## Features

- Converts DAST JSON reports into structured Markdown
- Summary-only mode for fast triage
- Works with ZAP, Burp, and other compatible scanners
- Available via pip or git clone

---

## Installation Options

### Option 1: Install via pip (Python 3.8+)
```bash
pip install vulndigest
```

### Option 2: Clone and run from source
```bash
git clone https://github.com/yourname/vulndigest.git
cd vulndigest
pip install -r requirements.txt
python vulndigest_cli.py -i example_dast.json -o report.md
```

---

## Usage

### Generate Markdown Report
```bash
vulndigest -i report.json -o output.md
```

### Print Summary Only
```bash
vulndigest -i report.json --summary
```

---

## File Structure
```

vulndigest/
├── vulndigest/                # Python package
│   ├── __init__.py
│   ├── __main__.py            # Entry point
│   └── vulndigest_cli.py      # Core CLI logic
├── example_dast.json          # Sample input report
├── LICENSE                    # MIT license
├── README.md                  # You're reading it
├── requirements.txt           # Python dependencies
└── pyproject.toml             # Packaging metadata

```

---

## Example Output
```
## High Findings (1)

### VULN-001
- Severity: High
- Description: SQL Injection in login form.
- Location: /login
- Identifiers:
| Name | Value |
|------|-------|
| CWE  | 89    |
```

---

## Roadmap Ideas
- [ ] Merge multiple JSON reports
- [ ] PDF export

---

Copyright (c) 2025 Tyler Walker
