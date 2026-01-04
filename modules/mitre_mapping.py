# modules/mitre_mapping.py
import logging

logger = logging.getLogger("AttackSurface")

# Simplified Mapping for demonstration purposes
MITRE_ATTACK_MAPPING = {
    "Missing Security Header": "T1190 - Exploit Public-Facing Application",
    "Information Leak": "T1592 - Gather Victim Host Information",
    "Open SSH": "T1078.004 - Valid Accounts: SSH",
    "Open RDP": "T1021.001 - Remote Services: RDP",
}

def map_attack_paths_to_mitre(attack_paths: list) -> list:
    """
    Maps elements of the attack paths (or findings) to relevant MITRE ATT&CK techniques.
    """
    mitre_entries = []
    
    for path in attack_paths:
        host = path.get("source_host") 
        techniques = set()
        
        # Check findings (path["steps"] would contain detailed findings)
        if "Missing Security Header" in path.get("description", ""):
            techniques.add(MITRE_ATTACK_MAPPING["Missing Security Header"])
            
        if "Server Information" in path.get("description", ""):
            techniques.add(MITRE_ATTACK_MAPPING["Information Leak"])

        if path.get("target_service") == "SSH":
            techniques.add(MITRE_ATTACK_MAPPING["Open SSH"])
        
        if path.get("target_service") == "RDP":
            techniques.add(MITRE_ATTACK_MAPPING["Open RDP"])

        if techniques:
            mitre_entries.append({
                "host": host,
                "techniques": list(techniques)
            })

    logger.info(f"Mapped {len(mitre_entries)} hosts to MITRE techniques.")
    return mitre_entries

