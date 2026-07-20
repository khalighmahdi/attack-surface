"""
modules/mitre_mapping.py
=========================
Maps attack paths to MITRE ATT&CK techniques.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("AttackSurface")

MITRE_ATTACK_MAPPING = {
    "Missing Security Header": "T1190 - Exploit Public-Facing Application",
    "Information Leak": "T1592 - Gather Victim Host Information",
    "Open SSH": "T1078.004 - Valid Accounts: SSH",
    "Open RDP": "T1021.001 - Remote Services: RDP",
    "High Risk Exposure": "T1190 - Exploit Public-Facing Application",
    "Initial Access": "T1133 - External Remote Services",
    "Critical Initial Access": "T1078 - Valid Accounts",
    "Authenticated Attack Surface": "T1078 - Valid Accounts",
    "Admin Panel": "T1078 - Valid Accounts",
    "RDP": "T1021.001 - Remote Services: RDP",
}


def map_attack_paths_to_mitre(attack_paths):
    """
    Map each attack path to one or more MITRE techniques.

    Returns a list of {"host": str, "techniques": [str, ...]}.
    """
    if not isinstance(attack_paths, list):
        logger.warning("map_attack_paths_to_mitre: expected list, got %s",
                       type(attack_paths).__name__)
        return []

    mitre_entries = []

    for path in attack_paths:
        if not isinstance(path, dict):
            continue

        host = path.get("source_host") or path.get("host")
        techniques = set()
        description = path.get("description", "") or ""

        # Map by path_type and target_service
        path_type = path.get("path_type", "")
        target_service = path.get("target_service", "")

        for keyword, technique in MITRE_ATTACK_MAPPING.items():
            haystack = " ".join([path_type, target_service, description])
            if keyword.lower() in haystack.lower():
                techniques.add(technique)

        if techniques:
            mitre_entries.append({
                "host": host,
                "techniques": sorted(techniques),
            })

    logger.info("Mapped %d hosts to MITRE techniques", len(mitre_entries))
    return mitre_entries
