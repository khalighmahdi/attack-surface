# modules/risk_scoring.py
import logging

logger = logging.getLogger("AttackSurface")

# Risk Weights
RISK_WEIGHTS = {
    "open_port_base": 0.5,       # Base score per open port
    "misconfig_major": 3,        # Score for missing critical security headers (e.g., CSP)
    "misconfig_minor": 1.5,      # Score for other misconfigurations or info leaks
    "critical_port": 5,          # Score boost for critical ports (21, 22, 23, 3389)
}

def calculate_risk(host: str, ports: list, misconf: dict) -> dict:
    """
    Calculates a qualitative risk score (0-10) for a host based on findings.
    """
    score = 0
    level = "low"
    
    # 1. Port Scoring
    critical_ports = [21, 22, 23, 3389]
    score += len(ports) * RISK_WEIGHTS["open_port_base"]
    
    for p in ports:
        if p["port"] in critical_ports and p["state"] == "open":
            # If a critical service is exposed
            score += RISK_WEIGHTS["critical_port"]
            logger.debug(f"Critical port {p['port']} open on {host}")

    # 2. Misconfiguration Scoring
    if misconf:
        # Penalize for missing headers
        score += len(misconf.get("missing", [])) * RISK_WEIGHTS["misconfig_major"]
        # Penalize for information leaks
        score += len(misconf.get("info_leaks", [])) * RISK_WEIGHTS["misconfig_minor"]
        
    # 3. Normalization and Level Assignment (Max 10 for simplicity)
    score = round(min(score, 10.0), 1)

    if score >= 8.0:
        level = "critical"
    elif score >= 5.0:
        level = "high"
    elif score >= 2.0:
        level = "medium"
    
    result = {"score": score, "level": level}
    logger.info(f"Risk calculated for {host}: {level} ({score})")
    return result

