# AntiHack Platform

AI-powered penetration testing platform with 13 specialized security agents and a browser-based dashboard.

## Features

- **13 AI Agents** — DNS recon, WHOIS, port scan, SQL injection, XSS, CSRF, SSRF, auth bypass, API discovery, directory traversal, secrets detection, SSL/TLS, tech fingerprint
- **Web Dashboard** — browser UI for launching scans, viewing live output, and reviewing findings
- **Built-in Code Editor** — VS Code-style Monaco editor to modify any agent directly from the browser
- **3 Report Formats** — Markdown, JSON, and dark-theme HTML with severity charts
- **Risk Scoring** — 0–100 risk score (Critical×10 + High×5 + Medium×2 + Low×1)

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Set your Anthropic API key

```bash
cp .env.example .env
# Edit .env and add your key
export ANTHROPIC_API_KEY=sk-ant-your-key-here
```

### 3. Launch the web dashboard

```bash
python webapp.py
# Open http://127.0.0.1:7070 in your browser
```

### 4. Or run from the CLI

```bash
python main.py https://yourtarget.com
```

## Authorization Gate

**Every scan requires you to type `I CONFIRM`** before it runs. This confirms you own the target or have written authorization. Unauthorized testing is illegal.

## Agent Architecture

| Agent | Phase | Tests |
|---|---|---|
| DNS Recon | Recon | A/MX/NS/TXT records, zone transfer, subdomain brute-force |
| WHOIS | Recon | Domain expiry, registrar info |
| Port Scanner | Recon | Top 1000 ports, service banners |
| SSL/TLS Inspector | Web | Cert expiry, weak protocols, HSTS |
| Tech Fingerprint | Web | Framework detection, version disclosure, security headers |
| SQL Injection | Web | 8 payloads across forms and URL params |
| XSS | Web | 7 payloads, reflection detection |
| CSRF | Web | Missing token checks on POST forms |
| SSRF | Web | URL param detection, open redirect |
| Auth | Web | Exposed admin pages, insecure cookies, default creds |
| API Discovery | Web | 19 common API paths, rate-limit headers |
| Directory Traversal | Web | Path traversal, sensitive file exposure |
| Secrets Detection | Web | AWS keys, GitHub tokens, private keys, JWTs in source |

## Built-in Code Editor

Navigate to the **Code Editor** tab in the dashboard. Select any agent `.py` file from the left panel, edit it in the Monaco editor (full syntax highlighting, autocomplete), and click **Save**. Changes take effect on the next scan.

## Output

Reports are saved in `./reports/` with a timestamp:

- `report_YYYYMMDD_HHMMSS.md` — Markdown
- `report_YYYYMMDD_HHMMSS.json` — Machine-readable JSON
- `report_YYYYMMDD_HHMMSS.html` — Styled HTML with charts

## Security Notice

This tool is for **authorized security testing only**. Only test targets you own or have explicit written permission to test. Misuse is illegal.

## License

MIT
