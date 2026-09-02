# Attack Surface Scanner v0.8

A modular attack surface reconnaissance and analysis tool.
Designed for Kali Linux **and Termux (Android)**.

## Features

- Subdomain discovery (crt.sh + common prefixes)
- Host availability detection (HTTP / HTTPS)
- **Batch port scanning via Nmap** (all hosts in one invocation)
- HTTP header collection + security header auditing
- Technology fingerprinting
- **CDN detection (skips scanning Cloudflare/Arvan edges)**
- **Admin panel discovery with vendor fingerprinting + primary-panel scoring**
- **Exposed CMS setup-page detection (WordPress setup-config.php etc.) — CRITICAL**
- Origin IP correlation
- Risk scoring engine (weighted, per-host)
- Attack path inference, MITRE ATT&CK mapping, Kill Chain
- **HTML report (XSS-safe), CSV, Markdown, JSON export**
- NDJSON streaming events (pipe into other tools)
- Rate limiting (token bucket), scope enforcement, checkpoint/resume
- Auto-update mechanism (Git-based)

## Installation

### Kali Linux
```bash
git clone https://github.com/khalighmahdi/attack-surface.git
cd attack-surface
sudo apt install -y python3 python3-pip nmap
pip3 install -r requirements.txt
```

### Termux (Android)
```bash
pkg update -y && pkg install -y python git nmap
git clone https://github.com/khalighmahdi/attack-surface.git
cd attack-surface
pip install -r requirements.txt
```

## Usage

```bash
# full scan (needs nmap + root for SYN; here TCP-connect is used)
python3 attack_surface.py -d example.com

# fast scan without nmap
python3 attack_surface.py -d example.com --no-ports

# polite scan (2 req/s)
python3 attack_surface.py -d example.com --rate 2

# scope-restricted scan
python3 attack_surface.py -d example.com --scope scope.txt

# resume after interruption
python3 attack_surface.py -d example.com --resume reports/checkpoint.json
```

## Outputs

| File | What |
|------|------|
| `reports/html/report_*.html` | Human-readable report |
| `reports/output.json` | Full machine-readable results |
| `reports/output.csv` | Flat table |
| `reports/output.md` | Markdown summary |
| `reports/graph_data.json` | Attack-surface graph |
| scan.ndjson (stream) | Live events |

## Legal

Only scan systems you own or have written permission to test.
The scope module enforces your target list — use it.

## Changelog

- **v0.8.0**: setup-page detection (critical), batch nmap, JSON export,
  XSS-safe HTML report, scope enforcement wired into discovery,
  fixed rate-limiter/origin/resume bugs, dnspython dependency.
- v0.7.0: unified CLI, rate limiting, scope, checkpointing, CDN awareness.


## Blue-Team Mode (v0.9)

Built for defenders — continuous attack-surface monitoring:

| Feature | What it does |
|---------|--------------|
| **Baseline & Diff** | Auto-saves a snapshot; every next scan reports NEW/GONE hosts, opened/closed ports, new admin panels, new setup pages, risk deltas |
| **Subdomain takeover check** | Flags dangling CNAME fingerprints (GitHub Pages, S3, Azure, Heroku, Shopify, Fastly, Zendesk...) |
| **CVE watchlist** | Maps fingerprinted tech versions to known CVEs via NVD (`--cves`) |
| **SOC telemetry** | Stream findings as **CEF syslog** to your SIEM, or push alerts to **Slack webhook** / **Telegram** |

```bash
# daily cron with Telegram on-call alerts + SIEM stream
python3 attack_surface.py -d example.com \
    --tg-token <BOT_TOKEN> --tg-chat <CHAT_ID> \
    --syslog siem.internal:514

# CVE watchlist too
python3 attack_surface.py -d example.com --cves

# disable baseline
python3 attack_surface.py -d example.com --no-baseline
```

Change categories reported by the baseline diff:
`NEW_HOSTS`, `GONE_HOSTS`, `NEW_OPEN_PORTS`, `CLOSED_PORTS`,
`NEW_ADMIN_PANELS`, `NEW_SETUP_PAGES`, `RISK_DELTA`.
