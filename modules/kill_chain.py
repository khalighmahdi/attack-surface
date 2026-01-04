# modules/kill_chain.py
import logging

logger = logging.getLogger("AttackSurface")

# Simplified mapping of findings keywords to Kill Chain stages
KILL_CHAIN_MAPPING = {
    "RDP is exposed": "Delivery",
    "Public Exposure": "Delivery",
    "Missing Security Header": "Exploitation",
    "Information Leak": "Reconnaissance",
    "Server Information Leak": "Reconnaissance",
    "WordPress CMS detected": "Weaponization",
}

def map_finding_to_kill_chain(finding: str) -> str:
    """Helper function to map a single finding to a Kill Chain stage."""
    for keyword, stage in KILL_CHAIN_MAPPING.items():
        if keyword in finding:
            return stage
    return "N/A"

def build_kill_chain(data: dict) -> dict:
    """
    Categorizes all findings in the data dictionary into Cyber Kill Chain stages.
    """
    kill_chain_summary = {
        "Reconnaissance": 0,
        "Weaponization": 0,
        "Delivery": 0,
        "Exploitation": 0,
        "Installation": 0,
        "Command and Control": 0,
        "Actions on Objectives": 0,
    }
    
    findings_data = data.get("findings", {})
    
    for host, findings in findings_data.items():
        for finding in findings:
            stage = map_finding_to_kill_chain(finding)
            if stage in kill_chain_summary:
                kill_chain_summary[stage] += 1
                
    logger.info("Kill Chain summary built.")
    return kill_chain_summary

