# Attack Surface Scanner

A modular attack surface reconnaissance and analysis tool designed for Kali Linux.  
This project helps security researchers and penetration testers quickly identify exposed services, misconfigurations, and potential attack paths.

---

## Features

- Subdomain discovery (basic enumeration)
- Host availability detection (HTTP / HTTPS)
- Port scanning via Nmap (SYN scan)
- HTTP header collection and analysis
- Security header auditing
- Technology fingerprinting
- Risk scoring engine
- Finding correlation & attack path inference
- MITRE ATT&CK technique mapping
- Cyber Kill Chain classification
- HTML report generation
- CSV / Markdown export support
- Auto-update mechanism (Git-based)

---

## Supported Platform

✅ **Kali Linux (Officially Supported)**  
⚠️ Other distributions are not officially supported.

Root access is required for SYN port scanning.

---

## Installation (Kali Linux)
```bash
git clone https://github.com/mahdikh007/attack-surface.git
cd attack-surface
sudo ./setup.sh

