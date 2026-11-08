"""Network Scanning Module — masscan, zmap, advanced port scanning."""

from __future__ import annotations
import subprocess
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ScanResult:
    """Port scan result for a host."""
    ip: str
    port: int
    protocol: str
    state: str
    service: str
    version: str
    banner: str
    timestamp: str


class NetworkScanner:
    """
    Advanced network scanner using masscan, zmap, and nmap.

    Supports:
    - masscan: ultra-fast port scanning (10M+ pps)
    - zmap: internet-wide single-port scanning
    - nmap: detailed service enumeration
    """

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}

    def masscan_scan(
        self,
        target: str,
        ports: str = "1-65535",
        rate: int = 1000,
        interface: str = "eth0",
    ) -> dict[str, Any]:
        """Ultra-fast port scan with masscan."""
        cmd = (
            f"masscan {target} -p {ports} "
            f"--rate={rate} "
            f"--interface {interface} "
            f"--open "
            f"--output-format json "
            f"--output-filename /tmp/masscan_results.json "
            f"--banners"
        )
        return {
            "command": cmd,
            "description": f"Masscan {target} ports {ports} at {rate} pps",
            "risk_level": "active",
            "docker_required": True,
            "estimated_time": f"{(65535 / rate):.0f} seconds",
        }

    def masscan_scan_common(self, target: str, rate: int = 1000) -> dict[str, Any]:
        """Scan common ports with masscan."""
        common_ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1723,3306,3389,5900,8080,8443"
        cmd = (
            f"masscan {target} -p {common_ports} "
            f"--rate={rate} "
            f"--open "
            f"--output-format json "
            f"--output-filename /tmp/masscan_common.json "
            f"--banners"
        )
        return {
            "command": cmd,
            "description": f"Masscan common ports on {target}",
            "risk_level": "safe",
            "docker_required": True,
        }

    def zmap_scan(
        self,
        target: str,
        port: int = 80,
        bandwidth: str = "10M",
    ) -> dict[str, Any]:
        """Internet-wide scan with zmap (single port)."""
        cmd = (
            f"zmap -p {port} "
            f"--bandwidth={bandwidth} "
            f"--target-port={port} "
            f"--output-file=/tmp/zmap_results.csv "
            f"--output-fields=saddr,daddr,sport,dport,repeat,confidence "
            f"{target}"
        )
        return {
            "command": cmd,
            "description": f"ZMap scan port {port} on {target} at {bandwidth}",
            "risk_level": "dangerous",
            "docker_required": True,
            "estimated_time": "~5 minutes for /8 network",
        }

    def zmap_top_ports(self, target: str, count: int = 100) -> dict[str, Any]:
        """Scan top N ports with zmap."""
        cmd = (
            f"for port in 80 443 22 21 25 53 110 143 3306 3389 8080 8443; do "
            f"zmap -p ${{port}} --target-port=${{port}} "
            f"--output-file=/tmp/zmap_${{port}}.csv "
            f"{target} 2>/dev/null; "
            f"done"
        )
        return {
            "command": cmd,
            "description": f"ZMap scan top ports on {target}",
            "risk_level": "active",
            "docker_required": True,
        }

    def nmap_aggressive(self, target: str, ports: str = "") -> dict[str, Any]:
        """Detailed nmap scan with version detection and scripts."""
        port_flag = f"-p {ports}" if ports else "-p-"
        cmd = (
            f"nmap -sV -sC -O -A {port_flag} "
            f"--script=default,vuln "
            f"--version-intensity 5 "
            f"-oN /tmp/nmap_agg.txt "
            f"-oX /tmp/nmap_agg.xml "
            f"{target}"
        )
        return {
            "command": cmd,
            "description": f"Nmap aggressive scan on {target}",
            "risk_level": "active",
            "docker_required": True,
        }

    def nmap_vuln_scan(self, target: str) -> dict[str, Any]:
        """Nmap vulnerability scan."""
        cmd = (
            f"nmap -sV --script vuln "
            f"-oN /tmp/nmap_vuln.txt "
            f"-oX /tmp/nmap_vuln.xml "
            f"{target}"
        )
        return {
            "command": cmd,
            "description": f"Nmap vulnerability scan on {target}",
            "risk_level": "active",
            "docker_required": True,
        }

    def nmap_udp_scan(self, target: str, ports: str = "53,67,68,69,123,135,137,138,161,162,445,500,514,520,631,1434,1900,4500,49152") -> dict[str, Any]:
        """UDP port scan."""
        cmd = (
            f"nmap -sU -sV --version-intensity 0 "
            f"-p {ports} "
            f"-oN /tmp/nmap_udp.txt "
            f"{target}"
        )
        return {
            "command": cmd,
            "description": f"Nmap UDP scan on {target}",
            "risk_level": "active",
            "docker_required": True,
        }

    def nmap_os_detection(self, target: str) -> dict[str, Any]:
        """OS detection scan."""
        cmd = (
            f"nmap -O --osscan-guess "
            f"-oN /tmp/nmap_os.txt "
            f"{target}"
        )
        return {
            "command": cmd,
            "description": f"Nmap OS detection on {target}",
            "risk_level": "safe",
            "docker_required": True,
        }

    def nmap_discovery(self, target: str) -> dict[str, Any]:
        """Host discovery scan (ping sweep)."""
        cmd = (
            f"nmap -sn -PE -PP -PS80,443,22 -PA80,443,22 "
            f"-oN /tmp/nmap_discovery.txt "
            f"{target}"
        )
        return {
            "command": cmd,
            "description": f"Nmap host discovery on {target}",
            "risk_level": "safe",
            "docker_required": True,
        }

    def nmap_script_scan(self, target: str, script_category: str = "default") -> dict[str, Any]:
        """Nmap script scan by category."""
        valid_categories = [
            "default", "discovery", "safe", "vuln", "exploit", "auth",
            "broadcast", "brute", "dos", "external", "fuzzer", "intrusive",
        ]
        if script_category not in valid_categories:
            script_category = "default"
        cmd = (
            f"nmap --script={script_category} "
            f"-sV "
            f"-oN /tmp/nmap_script_{script_category}.txt "
            f"{target}"
        )
        return {
            "command": cmd,
            "description": f"Nmap {script_category} script scan on {target}",
            "risk_level": "active" if script_category in ("exploit", "brute", "intrusive", "dos") else "safe",
            "docker_required": True,
        }

    # ==================== COMBINED SCANS ====================

    def full_scan_pipeline(self, target: str) -> dict[str, Any]:
        """Full scanning pipeline: discovery -> masscan -> nmap."""
        return {
            "steps": [
                {
                    "step": 1,
                    "name": "Host Discovery",
                    **self.nmap_discovery(target),
                },
                {
                    "step": 2,
                    "name": "Fast Port Scan",
                    **self.masscan_scan_common(target),
                },
                {
                    "step": 3,
                    "name": "Service Enumeration",
                    **self.nmap_aggressive(target),
                },
                {
                    "step": 4,
                    "name": "Vulnerability Scan",
                    **self.nmap_vuln_scan(target),
                },
            ],
            "description": f"Full scan pipeline for {target}",
            "estimated_time": "15-30 minutes",
        }

    # ==================== PARSING ====================

    def parse_masscan_json(self, json_path: str) -> list[ScanResult]:
        """Parse masscan JSON output."""
        import json
        results = []
        try:
            with open(json_path) as f:
                data = json.load(f)
            for item in data:
                for port_info in item.get("ports", []):
                    results.append(ScanResult(
                        ip=item.get("ip", ""),
                        port=port_info.get("port", 0),
                        protocol=port_info.get("proto", "tcp"),
                        state="open" if port_info.get("status") == "open" else "closed",
                        service=port_info.get("service", {}).get("name", ""),
                        version=port_info.get("service", {}).get("version", ""),
                        banner=port_info.get("service", {}).get("banner", ""),
                        timestamp=item.get("timestamp", ""),
                    ))
        except Exception:
            pass
        return results
