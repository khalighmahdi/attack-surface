"""IOC Manager Module — Indicators of Compromise management, STIX/TAXII."""

from __future__ import annotations
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


@dataclass
class IOC:
    """Indicators of Compromise."""
    id: str
    type: str  # ip, domain, url, hash_md5, hash_sha1, hash_sha256, email, file_name, mutex, registry
    value: str
    severity: str  # low, medium, high, critical
    confidence: int  # 0-100
    source: str
    tags: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    description: str = ""
    expired: bool = False


class IOCManager:
    """IOC management with STIX/TAXII export."""

    def __init__(self, storage_path: str = "~/.attack_surface/iocs.json"):
        self.storage_path = Path(storage_path).expanduser()
        self._iocs: list[IOC] = []
        self._load()

    def _load(self):
        """Load IOCs from file."""
        if self.storage_path.exists():
            try:
                with open(self.storage_path) as f:
                    data = json.load(f)
                self._iocs = [IOC(**ioc) for ioc in data]
            except Exception:
                self._iocs = []

    def _save(self):
        """Save IOCs to file."""
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.storage_path, "w") as f:
            json.dump([vars(ioc) for ioc in self._iocs], f, indent=2)

    def add_ioc(
        self,
        ioc_type: str,
        value: str,
        severity: str = "medium",
        confidence: int = 50,
        source: str = "scanner",
        tags: Optional[list[str]] = None,
        description: str = "",
        mitre_techniques: Optional[list[str]] = None,
    ) -> IOC:
        """Add a new IOC."""
        ioc_id = hashlib.sha256(f"{ioc_type}:{value}".encode()).hexdigest()[:16]
        now = datetime.now().isoformat()

        ioc = IOC(
            id=ioc_id,
            type=ioc_type,
            value=value,
            severity=severity,
            confidence=confidence,
            source=source,
            tags=tags or [],
            first_seen=now,
            last_seen=now,
            description=description,
            mitre_techniques=mitre_techniques or [],
        )

        existing = next((i for i in self._iocs if i.type == ioc_type and i.value == value), None)
        if existing:
            existing.last_seen = now
            existing.confidence = max(existing.confidence, confidence)
            if severity in ("high", "critical"):
                existing.severity = severity
            return existing

        self._iocs.append(ioc)
        self._save()
        return ioc

    def add_scan_findings(self, findings: list[dict], scan_id: int = 0) -> list[IOC]:
        """Extract IOCs from scan findings."""
        iocs = []
        for finding in findings:
            title = finding.get("title", "")
            severity = finding.get("severity", "info")

            if any(x in title.lower() for x in ["ip", "host", "server"]):
                import re
                ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", title)
                for ip in ips:
                    iocs.append(self.add_ioc("ip", ip, severity, 60, f"scan_{scan_id}", ["scan_result"]))

            if any(x in title.lower() for x in ["domain", "subdomain"]):
                import re
                domains = re.findall(r"\b[\w.-]+\.(com|net|org|ir|co)\b", title)
                for d in domains:
                    iocs.append(self.add_ioc("domain", d, severity, 60, f"scan_{scan_id}", ["scan_result"]))

            if any(x in title.lower() for x in ["hash", "sha256", "md5"]):
                import re
                hashes = re.findall(r"\b[a-fA-F0-9]{32,64}\b", title)
                for h in hashes:
                    htype = "hash_sha256" if len(h) == 64 else "hash_md5"
                    iocs.append(self.add_ioc(htype, h, severity, 70, f"scan_{scan_id}", ["scan_result"]))

        self._save()
        return iocs

    def get_iocs(self, ioc_type: Optional[str] = None, severity: Optional[str] = None) -> list[IOC]:
        """Get IOCs with optional filtering."""
        result = self._iocs
        if ioc_type:
            result = [i for i in result if i.type == ioc_type]
        if severity:
            result = [i for i in result if i.severity == severity]
        return result

    def remove_ioc(self, ioc_id: str) -> bool:
        """Remove an IOC by ID."""
        before = len(self._iocs)
        self._iocs = [i for i in self._iocs if i.id != ioc_id]
        if len(self._iocs) < before:
            self._save()
            return True
        return False

    def get_statistics(self) -> dict[str, Any]:
        """Get IOC statistics."""
        stats = {
            "total": len(self._iocs),
            "by_type": {},
            "by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "by_source": {},
        }
        for ioc in self._iocs:
            stats["by_type"][ioc.type] = stats["by_type"].get(ioc.type, 0) + 1
            stats["by_severity"][ioc.severity] = stats["by_severity"].get(ioc.severity, 0) + 1
            stats["by_source"][ioc.source] = stats["by_source"].get(ioc.source, 0) + 1
        return stats

    # ==================== STIX/TAXII EXPORT ====================

    def export_stix(self) -> dict[str, Any]:
        """Export IOCs as STIX 2.1 bundle."""
        stix_objects = []
        for ioc in self._iocs:
            stix_type_map = {
                "ip": ("ipv4-addr", "value"),
                "domain": ("domain-name", "value"),
                "url": ("url", "value"),
                "hash_md5": ("file", "hashes.MD5"),
                "hash_sha1": ("file", "hashes.SHA-1"),
                "hash_sha256": ("file", "hashes.SHA-256"),
                "email": ("email-addr", "value"),
            }
            stix_type, stix_prop = stix_type_map.get(ioc.type, ("artifact", "payload_bin"))

            stix_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{ioc.id}",
                "created": ioc.first_seen,
                "modified": ioc.last_seen,
                "name": f"{ioc.type}: {ioc.value}",
                "description": ioc.description,
                "pattern": f"[{stix_type}:{stix_prop} = '{ioc.value}']",
                "pattern_type": "stix",
                "valid_from": ioc.first_seen,
                "confidence": ioc.confidence,
                "labels": ioc.tags,
                "object_marking_refs": ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"],
            }
            stix_objects.append(stix_obj)

        return {
            "type": "bundle",
            "id": f"bundle--{hashlib.md5(str(time.time()).encode()).hexdigest()[:16]}",
            "objects": stix_objects,
        }

    def export_csv(self) -> str:
        """Export IOCs as CSV."""
        lines = ["type,value,severity,confidence,source,first_seen,last_seen,tags"]
        for ioc in self._iocs:
            lines.append(
                f"{ioc.type},{ioc.value},{ioc.severity},{ioc.confidence},"
                f"{ioc.source},{ioc.first_seen},{ioc.last_seen},{';'.join(ioc.tags)}"
            )
        return "\n".join(lines)

    def export_misp(self) -> dict[str, Any]:
        """Export IOCs as MISP event format."""
        attributes = []
        misp_type_map = {
            "ip": "ip-dst",
            "domain": "domain",
            "url": "url",
            "hash_md5": "md5",
            "hash_sha1": "sha1",
            "hash_sha256": "sha256",
            "email": "email-dst",
        }
        for ioc in self._iocs:
            misp_type = misp_type_map.get(ioc.type, "text")
            attributes.append({
                "type": misp_type,
                "value": ioc.value,
                "category": "Payload delivery",
                "comment": ioc.description,
                "to_ids": True,
            })

        return {
            "Event": {
                "info": f"Attack Surface IOCs - {datetime.now().strftime('%Y-%m-%d')}",
                "date": datetime.now().strftime("%Y-%m-%d"),
                "distribution": "0",
                "attribute_count": len(attributes),
                "attributes": attributes,
            }
        }

    def export_all_formats(self) -> dict[str, Any]:
        """Export IOCs in all available formats."""
        return {
            "stix": self.export_stix(),
            "csv": self.export_csv(),
            "misp": self.export_misp(),
            "json": [vars(ioc) for ioc in self._iocs],
        }
