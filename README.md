# 🛡️ Attack Surface Scanner

[![Version](https://img.shields.io/badge/version-0.21.0-blue)](#)
[![License](https://img.shields.io/badge/license-GPL--3.0-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-yellow)](#)
[![Tests](https://img.shields.io/badge/tests-340%20passing-brightgreen)](#)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED)](#)

A **modular, production-grade attack-surface reconnaissance and blue-team monitoring toolkit** for Kali Linux, Termux, and any modern Linux box.

It maps the *external* attack surface of a domain — from subdomains and origin servers to exposed admin panels, half-installed CMS instances, cloud assets, APIs, and misconfigurations — and turns every finding into a dashboard-ready SOC artifact.  
All checks are **read-only and operator-gated**: no brute force, no exploitation, no payload execution.

---

## ✨ Highlights

- **One-command full scan** with checkpoint/resume and polite token-bucket rate limiting
- **Discover**: crt.sh + wordlists, MX/historical DNS, CDN-aware origin IP correlation, CDN (Cloudflare/Arvan) detection
- **Probe**: batched `nmap -sV`, security-header grading, tech/CMS/framework fingerprinting
- **Critical findings**: exposed CMS setup/install pages, database ports on the Internet, admin-panel discovery + vendor scoring, subdomain takeover fingerprints (18 services)
- **CVE deep scan**: exact CPE matching against NVD, CVSS-sorted
- **Blue-team**: baseline & diff, kill-chain synthesis, MITRE ATT&CK mapping, attack-path inference
- **Red-team assist**: rule-based attack advisor, per-finding “Run / Terminal-in-Kali” workflow (audit-logged, 10-min cap)
- **New intel modules**: cloud asset discovery (AWS/Azure/GCP), API/OpenAPI/GraphQL discovery, IP-allowlist bypass detection, email-spoofing checks, SQLi surface probing, WordPress deep recon
- **Reporting**: XSS-safe HTML (exec/technical/compliance), CSV, Markdown, JSON, graph data (170 nodes/186 edges in a typical run)
- **Live dashboard** on `127.0.0.1:8443` with an Ops Console, Action Center, and web terminal
- **OpenCode skill** included (`skills/attack-surface/SKILL.md`) so the agent is auto-instructed to use it

---

## 🧱 Architecture

```
attack_surface.py            # CLI entry point
core/                        # Runner, context, rate limiter, scope, checkpoint, stream
modules/                     # 100+ focused scanners (subdomains, ports, CMS, CVE, …)
  ├── dashboard.py          # Web Operations Console (port 8443)
  ├── redteam/              # Attack advisor, terminal, action center
  ├── cloud/, api/          # Cloud asset + API security discovery
  ├── asm/                  # Continuous ASM + delta scanning
  └── reporting/            # HTML/CSV/MD/PDF exports
tests/                       # 340 unit tests
skills/attack-surface/       # OpenCode skill (SKILL.md)
```

---

## 🚀 Quick Start

### From source (any Linux)
```bash
git clone https://github.com/khalighmahdi/attack-surface.git
cd attack-surface
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python attack_surface.py --help
```

### Full scan (safe mode)
```bash
python attack_surface.py -d example.com --rate 5 \
  --cves-deep --poc --mitre --redteam
```

### Open the dashboard
```bash
python attack_surface.py serve --port 8443 --host 127.0.0.1
# → http://127.0.0.1:8443
```

### Docker team stack
```bash
docker compose up -d kali dashboard          # UI on http://127.0.0.1:8443
docker compose --profile services up -d      # + msfrpcd (SSL) / sliver
docker compose --profile watch up -d watch   # scheduled diff-scan + TG alerts
```

---

## 🔌 MCP server (Model Context Protocol)

The app can run as a **stdio MCP server**, so any MCP-capable agent (OpenCode,
Claude Desktop, Cursor, ...) can start scans, poll status, list results, and open
the dashboard as tools — not just as a CLI.

```bash
python attack_surface.py mcp
```

### Register it in OpenCode (`~/.config/opencode/opencode.json`)
```json
{
  "mcp": {
    "attack-surface": {
      "type": "local",
      "command": ["python3", "/path/to/attack-surface/attack_surface.py", "mcp"],
      "enabled": true
    }
  }
}
```

Exposed tools:
- `project_info` — path/version
- `run_scan` — start a read-only scan (returns a job id)
- `scan_status` — poll a job and get tail output
- `list_scans` — list stored scans with risk scores
- `start_dashboard` — launch the web Ops Console and get its URL

Scans run asynchronously; `run_scan` returns immediately so agents don't block on
multi-minute nmap work.

## 📋 CLI examples

```bash
# Deep CVE matching + safe active checks
python attack_surface.py -d example.com --no-ports --cves-deep --poc

# Continuous monitoring w/ Telegram on-call
python attack_surface.py -d example.com --no-ports \
  --tg-token "$BOT_TOKEN" --tg-chat "$CHAT_ID"

# Stream CEF events to your SIEM
python attack_surface.py -d example.com --syslog siem.internal:514

# Generate all report formats (exec/technical/compliance)
python attack_surface.py -d example.com --report all --pdf --mitre

# Resume an interrupted scan
python attack_surface.py -d example.com --resume reports/checkpoint.json
```

Full option reference: `man attack-surface` (or `-h`).

---

## 📊 Reports & artifacts

| Path | Content |
|------|---------|
| `reports/html/` | Human-readable HTML report |
| `reports/output.json` | Machine-readable full results |
| `reports/output.csv` / `.md` | Flat exports |
| `reports/baselines/` | Blue-team snapshots (auto diffed each run) |
| `reports/cve_deep_cache.json` | NVD cache (polite API usage) |
| `reports/graph_data.json` | Attack-graph data (nodes/edges) |

---

## 🤖 OpenCode skill

A ready-to-use skill ships at `skills/attack-surface/SKILL.md`.  
Install/copy it into your skill discovery directory (e.g. `~/.config/opencode/skills/attack-surface/SKILL.md`) and OpenCode will auto-invoke it for domain-scan requests. See `skill` loading in your client of choice.

---

## ⚖️ Ethics & Legal

> **Only scan systems you own or have explicit written permission to test.**
> The scope module (`--scope targets.txt`) technically enforces your authorization list.  
> Active checks are strictly non-destructive: no brute force, no exploitation, no payload execution.

---

## 🧪 Development

```bash
# Run all 340 tests
ATTACK_SURFACE_LLM_API_KEY=dummy \
  python -m unittest discover -s tests

# CLI smoke
python attack_surface.py --help > /dev/null

# Build the .deb
python build_deb.py
```

GitHub Actions CI runs tests + `.deb` + Docker build on every push to `main`.

---

## Author
**Mahdi Khaligh** — [@khalighmahdi](https://github.com/khalighmahdi)

## License
GPL-3.0 — see [LICENSE](LICENSE)
