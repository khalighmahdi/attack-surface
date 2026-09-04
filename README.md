# Attack Surface Scanner

![Version](https://img.shields.io/badge/version-0.10.0-blue) ![License](https://img.shields.io/badge/license-GPL--3.0-green) ![Python](https://img.shields.io/badge/python-3.8%2B-yellow)

A **modular attack-surface reconnaissance and blue-team monitoring toolkit** for Kali Linux, Termux and any Linux box.

It discovers and grades the *external* attack surface of a domain — from subdomains and origin servers to exposed admin panels and half-installed CMS instances — and turns every finding into SOC-ready telemetry.

> **Kali category:** 01 — Information Gathering / 03 — Web Analysis

---

## Features

### Discovery
- Subdomain enumeration (crt.sh + prefix wordlists) with **scope enforcement**
- Historical DNS + MX discovery (dnspython)
- CDN detection (Cloudflare/Arvan/...) — avoids scanning edge nodes
- **Origin IP correlation** behind CDNs
- Host liveness probing (HTTP/HTTPS)

### Probing
- **Batched nmap** (`-iL` one-invocation) with **`-sV` service+version banners** — e.g. `Pure-FTPd`, `MariaDB 10.3.23`
- Security-header auditing (HSTS, CSP, X-Frame-Options, ...)
- Technology fingerprinting (web server, CMS, framework)

### Critical findings
- **Exposed CMS setup pages** (`wp-admin/setup-config.php` & friends) — *site-takeover class*
- **Database ports exposed to the internet** (MySQL/MariaDB/PostgreSQL/Redis/Mongo)
- Admin-panel discovery with vendor fingerprinting & primary-panel scoring
- **Subdomain takeover** fingerprints (18 services: GitHub Pages, S3, Azure, Heroku, ...)

### Blue-team (v0.9+)
- **Baseline & diff** — continuous monitoring: new/gone hosts, opened/closed ports, new panels, risk deltas
- **CVE deep scan** — exact **CPE matching** against NVD, version-aware, CVSS-sorted
- Safe **active PoC**: TLS audit & grading, login liveness (one attempt, no brute force), DNS AXFR + DNSSEC
- **SOC telemetry**: CEF over syslog, Slack webhooks, Telegram on-call alerts, NDJSON stream

### Reporting
- XSS-safe HTML report, CSV, Markdown, full JSON, graph data
- Attack-path inference, **MITRE ATT&CK** mapping, kill-chain stages
- Checkpoint/resume for long scans; polite token-bucket rate limiting

---

## Installation

### From .deb (Kali/Debian/Parrot)
```bash
git clone https://github.com/khalighmahdi/attack-surface.git
cd attack-surface && ./build-deb.sh
sudo dpkg -i attack-surface_*_all.deb
# now available as:
attack-surface --help
man attack-surface
```

### Kali / Debian (manual)
```bash
sudo apt install -y python3 python3-pip python3-dnspython nmap
git clone https://github.com/khalighmahdi/attack-surface.git
cd attack-surface
pip3 install -r requirements.txt
python3 attack_surface.py --help
```

### Termux (Android)
```bash
pkg update -y && pkg install -y python git nmap
git clone https://github.com/khalighmahdi/attack-surface.git
cd attack-surface && pip install -r requirements.txt
```

---

## Usage

```bash
# Full scan with versioned service banners
attack-surface -d example.com --rate 5

# Deep CVE matching + safe active checks
attack-surface -d example.com --no-ports --cves-deep --poc

# Continuous monitoring w/ Telegram on-call (cron-friendly)
attack-surface -d example.com --no-ports \
    --tg-token "$BOT_TOKEN" --tg-chat "$CHAT_ID"

# Stream CEF events to your SIEM
attack-surface -d example.com --syslog siem.internal:514
```

Full option reference: `man attack-surface`

### Reports & artifacts
| Path | Content |
|------|---------|
| `reports/html/` | Human-readable HTML report |
| `reports/output.json` | Machine-readable full results |
| `reports/output.csv` / `.md` | Flat exports |
| `reports/baselines/` | Blue-team snapshots (auto diffed each run) |
| `reports/cve_deep_cache.json` | NVD cache (polite API usage) |

---

## Ethics & Legal

> **Only scan systems you own or have explicit written permission to test.**
> The scope module (`--scope targets.txt`) technically enforces your authorization list.
> Active checks are strictly non-destructive: no brute force, no exploitation, no payload execution.

## Author

**Mahdi Khaligh** — [khalighmahdi](https://github.com/khalighmahdi)

## License

GPL-3.0 — see [LICENSE](LICENSE)
