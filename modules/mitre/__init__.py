"""MITRE ATT&CK Mapping — CVE/Finding to ATT&CK technique mapping.

Maps findings, CVEs, and technologies to MITRE ATT&CK techniques via:
- CAPEC to ATT&CK mapping (via NVD)
- Direct technique mapping for common vulnerability classes
- Kill chain phase assignment
- Tactic coverage analysis
"""
from __future__ import annotations

import json
import logging
import os
import requests
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("AttackSurface.MITRE")


# Core ATT&CK tactic order
TACTICS = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact"
]

# Common vulnerability class -> ATT&CK technique mappings
VULN_TO_TECHNIQUE = {
    "sql injection": ["T1190", "T1505.003"],
    "xss": ["T1059.007", "T1189"],
    "rce": ["T1190", "T1059", "T1505.003"],
    "ssrf": ["T1190", "T1590.005"],
    "idor": ["T1046", "T1580"],
    "auth bypass": ["T1078", "T1556"],
    "privilege escalation": ["T1068", "T1548"],
    "path traversal": ["T1005", "T1083"],
    "file upload": ["T1190", "T1505.003"],
    "xxe": ["T1190", "T1059"],
    "deserialization": ["T1190", "T1059"],
    "command injection": ["T1059", "T1190"],
    "ldap injection": ["T1190", "T1558"],
    "xpath injection": ["T1190"],
    "ssti": ["T1059.007", "T1190"],
    "open redirect": ["T1189"],
    "csrf": ["T1189"],
    "clickjacking": ["T1189"],
    "information disclosure": ["T1590", "T1083"],
    "weak crypto": ["T1573.002"],
    "missing auth": ["T1078", "T1190"],
    "default credentials": ["T1078", "T1556"],
    "exposed service": ["T1190", "T1590"],
    "subdomain takeover": ["T1190", "T1583.001"],
    "dangling dns": ["T1583.001"],
    "certificate issue": ["T1573.002"],
    "email spoofing": ["T1566", "T1598"],
    "dmarc missing": ["T1566"],
    "spf missing": ["T1566"],
    "dkim missing": ["T1566"],
}


class MITREMapper:
    """Map findings and CVEs to MITRE ATT&CK techniques."""

    def __init__(self):
        self.cache_dir = Path(os.path.expanduser("~/.cache/attack-surface/mitre"))
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.techniques_cache: Dict[str, Dict] = {}
        self._load_enterprise_attack()

    def _load_enterprise_attack(self):
        """Load MITRE ATT&CK Enterprise matrix from cache or GitHub."""
        cache_file = self.cache_dir / "enterprise_attack.json"
        if cache_file.exists():
            try:
                self.techniques_cache = json.loads(cache_file.read_text())
                logger.info("Loaded %d ATT&CK techniques from cache", len(self.techniques_cache))
                return
            except Exception:
                pass

        # Fetch from MITRE CTI repo
        try:
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                techniques = {}
                for obj in data.get("objects", []):
                    if obj.get("type") == "attack-pattern":
                        ext_refs = obj.get("external_references", [])
                        for ref in ext_refs:
                            if ref.get("source_name") == "mitre-attack":
                                tech_id = ref.get("external_id")
                                if tech_id and tech_id.startswith("T"):
                                    techniques[tech_id] = {
                                        "id": tech_id,
                                        "name": obj.get("name"),
                                        "description": obj.get("description", ""),
                                        "tactics": obj.get("kill_chain_phases", []),
                                        "platforms": obj.get("x_mitre_platforms", []),
                                        "detection": obj.get("x_mitre_detection", ""),
                                        "mitigations": [r.get("description", "") for r in obj.get("x_mitre_mitigations", [])]
                                    }
                self.techniques_cache = techniques
                cache_file.write_text(json.dumps(techniques))
                logger.info("Fetched and cached %d ATT&CK techniques", len(techniques))
        except Exception as e:
            logger.warning("Failed to load MITRE ATT&CK: %s", e)

    def get_technique(self, technique_id: str) -> Optional[Dict]:
        """Get technique details by ID (e.g., T1190)."""
        return self.techniques_cache.get(technique_id.upper())

    def get_techniques_for_vuln(self, vuln_type: str) -> List[Dict]:
        """Get ATT&CK techniques for a vulnerability type."""
        tech_ids = VULN_TO_TECHNIQUE.get(vuln_type.lower(), [])
        return [self.get_technique(tid) for tid in tech_ids if self.get_technique(tid)]

    def get_techniques_for_cve(self, cve_id: str) -> List[Dict]:
        """Get ATT&CK techniques for a CVE (via NVD CAPEC mapping)."""
        # This would need NVD CAPEC references -> CAPEC to ATT&CK mapping
        # For now, return empty - requires NVD API with CAPEC data
        return []

    def get_techniques_for_finding(self, finding: Dict) -> List[Dict]:
        """Map a finding to ATT&CK techniques based on title/category."""
        title = finding.get("title", "").lower()
        category = finding.get("category", "").lower()
        techniques = []

        # Check title/category against known mappings
        for vuln_class, tech_ids in VULN_TO_TECHNIQUE.items():
            if vuln_class in title or vuln_class in category:
                for tid in tech_ids:
                    tech = self.get_technique(tid)
                    if tech:
                        techniques.append(tech)

        return techniques

    def analyze_coverage(self, findings: List[Dict]) -> Dict[str, Any]:
        """Analyze ATT&CK tactic coverage for a set of findings."""
        covered_tactics: Set[str] = set()
        technique_counts: Dict[str, int] = {}

        for finding in findings:
            techs = self.get_techniques_for_finding(finding)
            for tech in techs:
                tech_id = tech.get("id")
                if tech_id:
                    technique_counts[tech_id] = technique_counts.get(tech_id, 0) + 1
                for phase in tech.get("tactics", []):
                    tactic = phase.get("phase_name", "").replace("-", " ")
                    covered_tactics.add(tactic)

        # Tactic coverage
        all_tactics = set(TACTICS)
        coverage = {
            "covered_tactics": list(covered_tactics),
            "missing_tactics": list(all_tactics - covered_tactics),
            "coverage_percent": round(len(covered_tactics) / len(all_tactics) * 100, 1),
            "top_techniques": sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        }
        return coverage

    def generate_attack_navigator_layer(self, findings: List[Dict], name: str = "Attack Surface") -> Dict:
        """Generate MITRE ATT&CK Navigator layer JSON for visualization."""
        technique_scores = {}
        for finding in findings:
            techs = self.get_techniques_for_finding(finding)
            for tech in techs:
                tid = tech.get("id")
                if tid:
                    severity = finding.get("severity", "info")
                    score = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}.get(severity, 10)
                    technique_scores[tid] = max(technique_scores.get(tid, 0), score)

        techniques = []
        for tid, score in technique_scores.items():
            tech = self.get_technique(tid)
            if tech:
                techniques.append({
                    "techniqueID": tid,
                    "score": score,
                    "comment": f"{tech['name']} - mapped from findings",
                    "enabled": True,
                    "metadata": [
                        {"name": "tactics", "value": ", ".join(p.get("phase_name", "") for p in tech.get("tactics", []))},
                        {"name": "platforms", "value": ", ".join(tech.get("platforms", []))}
                    ]
                })

        layer = {
            "version": "4.2",
            "name": name,
            "description": f"ATT&CK coverage for {len(findings)} findings",
            "domain": "enterprise-attack",
            "techniques": techniques,
            "gradient": {
                "colors": ["#ffffff", "#ff6b6b"],
                "minValue": 0,
                "maxValue": 100
            },
            "legendItems": [
                {"label": "Critical (100)", "color": "#ff6b6b"},
                {"label": "High (75)", "color": "#ffa500"},
                {"label": "Medium (50)", "color": "#ffd93d"},
                {"label": "Low (25)", "color": "#6bcb77"},
                {"label": "Info (10)", "color": "#4d96ff"}
            ]
        }
        return layer