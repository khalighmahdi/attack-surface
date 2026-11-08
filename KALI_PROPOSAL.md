# Attack Surface Scanner — Kali Linux Integration Proposal

## Summary

**Attack Surface Scanner** is a comprehensive, modular attack-surface reconnaissance and red-team toolkit designed for Kali Linux. It discovers, analyzes, and maps the external attack surface of any domain, then provides actionable red-team paths with operator-in-the-loop automation.

**Kali Category:** 01 — Information Gathering / 03 — Web Analysis / 14 — Password Attacks

---

## What It Does

### Phase 1: Discovery
- Subdomain enumeration (crt.sh + wordlists, 185+ prefixes)
- Historical DNS + MX record discovery
- CDN detection (Cloudflare, Arvan, etc.)
- Origin IP correlation behind CDNs
- Live host probing with WAF-aware evasion

### Phase 2: Analysis
- Port scanning with service/version detection (nmap)
- Security header auditing (HSTS, CSP, X-Frame-Options)
- Technology fingerprinting (web server, CMS, framework)
- CVE matching against NVD (CPE-based, version-aware)
- WordPress/Drupal/Joomla deep analysis

### Phase 3: Red Team
- **Attack Advisor** — rule-based expert system that recommends optimal attack paths (12 techniques, zero API cost)
- **Kill Chain Engine** — weaponization, payload generation, session interception
- **Lateral Movement Engine** — 7 techniques with MITRE ATT&CK mapping
- **Autonomous Agent** — self-directed hacking agent that takes the helm after target selection
- **WAF Evasion Engine** — detects and bypasses BitNinja, Cloudflare, Sucuri, Imperva, ModSecurity
- **Phishing-as-a-Service** — mirror page generator, campaign manager, credential harvester
- **OSINT People Intel** — username pivoting, email harvesting, risk assessment
- **Breach Intelligence** — offline breach database lookup, hash cracking, credential exposure analysis

### Phase 4: Reporting
- XSS-safe HTML report (Nessus-grade)
- CSV, Markdown, full JSON export
- MITRE ATT&CK mapping with heatmaps
- Attack graph visualization (SVG)
- Risk trend analysis across scans

---

## Architecture

```
attack_surface.py          # CLI entry point
core/                      # Runner, context, rate limiter, checkpoint
modules/                   # 128 Python modules (all self-contained)
  ├── alive.py             # WAF-aware host probing
  ├── subdomains.py        # Subdomain enumeration
  ├── ports.py             # nmap integration
  ├── cve_mapper.py        # CVE matching
  ├── waf_evasion.py       # WAF detection & bypass
  ├── breach_intel.py      # Breach intelligence engine
  ├── autonomous_agent.py  # Self-directed hacking agent
  ├── attack_advisor.py    # Rule-based attack advisor
  ├── phishing_engine.py   # Phishing-as-a-Service
  ├── osint_people.py      # OSINT people intelligence
  ├── dashboard.py         # Web operations console (port 8443)
  └── redteam/             # Red team modules
tests/                     # 85 unit tests
```

---

## Key Differentiators

1. **WAF-Aware**: Built-in evasion for BitNinja, Cloudflare, Sucuri, Imperva, and 10+ other WAF/anti-bot solutions. Realistic browser headers, TLS fingerprint evasion, adaptive rate limiting.

2. **Rule-Based AI**: Attack Advisor uses expert-system rules (not LLM APIs) to recommend optimal attack paths — zero cost, zero network dependency.

3. **Autonomous Agent**: Self-directed hacking agent that autonomously decides, executes, and adapts attack strategies — like having a senior pentester on your team.

4. **Full Kill Chain**: From initial access through lateral movement to data collection — all MITRE ATT&CK mapped.

5. **Operator-in-the-Loop**: Every action is pre-filled for terminal review — nothing auto-executes without explicit operator consent.

6. **Offline-Capable**: Breach intelligence, hash cracking, and attack advisory work entirely offline — no API keys or internet required.

---

## Installation (Kali)

```bash
git clone https://github.com/khalighmahdi/attack-surface.git
cd attack-surface
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python attack_surface.py --help
```

### Docker (Recommended)
```bash
docker-compose up -d
# Dashboard: http://127.0.0.1:8443
```

---

## Usage Examples

```bash
# Basic scan
python attack_surface.py -d example.com

# Full scan with red team + httpx + nuclei
python attack_surface.py -d example.com --httpx --nuclei --redteam --cves

# Dashboard mode
python attack_surface.py serve

# Autonomous agent
python attack_surface.py -d example.com --auto-hunt
```

---

## Testing

```bash
# Run all 85 tests
python -m unittest discover -s tests

# Specific test module
python -m unittest tests.test_cool_features
```

---

## Dependencies

- Python 3.8+
- nmap
- httpx, nuclei (in Kali container)
- Metasploit Framework
- Sliver C2
- Docker (for team stack)

---

## License

GPL-3.0

---

## Contact

- Repository: https://github.com/khalighmahdi/attack-surface
- Author: khalighmahdi

---

## Screenshots

### Dashboard — Operations Console
![Dashboard](reports/dashboard_screenshot.png)

### Attack Advisor
![Advisor](reports/advisor_screenshot.png)

### Autonomous Agent
![Agent](reports/agent_screenshot.png)
