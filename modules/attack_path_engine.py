# modules/attack_path_engine.py
import logging
from typing import List, Dict

logger = logging.getLogger("AttackSurface")

def build_attack_paths(data: Dict) -> List[Dict]:
    """
    Analyzes the collected data (ports, misconfigs, technologies) 
    to infer potential attack paths an adversary might take.
    """
    attack_paths = []
    
    alive_hosts = data.get("alive_hosts", [])
    
    for host in alive_hosts:
        ports = data.get("ports", {}).get(host, [])
        misconfigs = data.get("misconfigurations", {}).get(host, {})
        risk = data.get("risk_scores", {}).get(host, {})

        if risk.get("score", 0) >= 5.0:
            attack_paths.append({
                "source_host": host,
                "risk_score": risk["score"],
                "path_type": "High Risk Exposure",
                "description": f"The host is highly exposed due to multiple factors (Score: {risk['score']}).",
                "steps": ["Target Identification", "Initial Access via Exposed Services or Misconfiguration"]
            })

        # Path 1: Initial Access via Exposed RDP/SSH
        for p in ports:
            if p["port"] == 3389 and p["state"] == "open":
                attack_paths.append({
                    "source_host": host,
                    "target_service": "RDP",
                    "path_type": "Initial Access",
                    "description": "RDP is exposed externally. This is a common path for brute-force attacks or credential stuffing.",
                    "steps": ["RDP Port Scan", "Brute-force/Credential Access", "Internal Lateral Movement"]
                })
        
        # Path 2: Initial Access via Web Application Vulnerabilities (inferred from technology/misconfig)
        if misconfigs.get("missing"):
            attack_paths.append({
                "source_host": host,
                "target_service": "Web Server",
                "path_type": "Exploit Web App",
                "description": "Lack of security headers (e.g., CSP, X-Frame-Options) indicates potential attack surface for XSS/Clickjacking, leading to Session Hijacking.",
                "steps": ["Exploit Missing Header", "Session Hijacking", "Privilege Escalation"]
            })

    logger.info(f"Identified {len(attack_paths)} potential attack paths.")
    return attack_paths

