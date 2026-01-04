# modules/correlation_engine.py
import logging

logger = logging.getLogger("AttackSurface")

def generate_findings(
    host: str,
    risk: dict,
    tech: list,
    ports: list,
    misconf: dict
) -> list:
    """
    Generates actionable findings and recommendations based on all collected data.
    """
    findings = []

    # 1. High Risk Finding based on score
    if risk.get("level") in ["high", "critical"]:
        findings.append(
            f"The host presents a **{risk['level'].upper()}** risk score ({risk['score']}). "
            "Immediate review of the exposed services and configuration is recommended."
        )
    
    # 2. Port Findings
    critical_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP"}
    for p in ports:
        if p["port"] in critical_ports:
            findings.append(
                f"**Public Exposure**: {critical_ports[p['port']]} ({p['service']}) is open on port {p['port']} "
                f"and should be restricted to internal networks or secured with a VPN."
            )
    
    # 3. Misconfiguration Findings
    if misconf.get("missing"):
        findings.append(
            f"**Missing Security Headers**: Critical security headers are missing: {', '.join(misconf['missing'])}. "
            "This exposes users to clickjacking, XSS, and content sniffing vulnerabilities."
        )
        
    if misconf.get("info_leaks"):
        findings.append(
            f"**Server Information Leak**: The server reveals sensitive version information ({len(misconf['info_leaks'])} items). "
            "These headers should be removed or obfuscated."
        )
        
    # 4. Technology Findings (Optional)
    if "WordPress CMS" in tech:
        findings.append(
            "**Known Technology**: WordPress CMS detected. Ensure all themes, plugins, and core files are up-to-date to prevent exploitation."
        )

    logger.debug(f"Findings generated for {host}: {len(findings)} items")
    return findings

