"""Red Team Configuration — portable, user-customizable."""

from __future__ import annotations
import os
import shutil
from dataclasses import dataclass, field, is_dataclass, asdict
from pathlib import Path
from typing import Any, Optional
import yaml


@dataclass
class ToolConfig:
    """External tool configuration with auto-detection."""
    binary: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    timeout: int = 300
    enabled: bool = True

    @classmethod
    def auto(cls, name: str, default_args: list[str] = None) -> "ToolConfig":
        """Auto-detect binary in PATH or common locations."""
        binary = ""
        search_paths = [
            shutil.which(name),
            f"/usr/local/bin/{name}",
            f"/opt/{name}/{name}",
            f"{Path.home()}/.local/bin/{name}",
            f"{Path.home()}/go/bin/{name}",
        ]
        for p in search_paths:
            if p and Path(p).exists():
                binary = p
                break
        return cls(binary=binary, args=default_args or [], enabled=bool(binary))


@dataclass
class MetasploitConfig:
    host: str = "127.0.0.1"
    port: int = 55553
    user: str = "msf"
    password: str = ""
    ssl: bool = True
    workspace: str = "default"
    auto_start_rpcd: bool = False  # if true, tries `msfrpcd -P <pass> -S`


@dataclass
class SliverConfig:
    """Sliver C2 gRPC client config."""
    server: str = "127.0.0.1"
    port: int = 50051
    mtls: bool = True
    ca_cert: str = ""
    client_cert: str = ""
    client_key: str = ""
    operator: str = "attack-surface"
    profile: str = "http"  # implant profile: http, https, dns, mtls
    lhost: str = ""  # auto-detect if empty
    lport: int = 0  # auto-assign if 0
    timeout: int = 30


@dataclass
class BloodHoundConfig:
    uri: str = "bolt://127.0.0.1:7687"
    user: str = "neo4j"
    password: str = ""
    database: str = "neo4j"
    collection_methods: list[str] = field(default_factory=lambda: ["Default", "LocalAdmin", "GPOLocalGroup", "PSRemote", "Session", "Trusts"])


@dataclass
class C2Config:
    """Generic C2 framework config."""
    framework: str = "sliver"  # sliver, mythic, havoc, cobaltstrike
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class RedTeamConfig:
    """Master Red Team configuration."""
    # Tool configs
    hydra: ToolConfig = field(default_factory=lambda: ToolConfig.auto("hydra"))
    nmap: ToolConfig = field(default_factory=lambda: ToolConfig.auto("nmap"))
    crackmapexec: ToolConfig = field(default_factory=lambda: ToolConfig.auto("crackmapexec"))
    impacket_getuserspns: ToolConfig = field(default_factory=lambda: ToolConfig.auto("GetUserSPNs.py", ["-request"]))
    impacket_getnpusers: ToolConfig = field(default_factory=lambda: ToolConfig.auto("GetNPUsers.py", ["-no-pass", "-dc-ip", "TARGET_IP"]))
    impacket_ntlmrelayx: ToolConfig = field(default_factory=lambda: ToolConfig.auto("ntlmrelayx.py", ["-tf", "targets.txt"]))
    wpscan: ToolConfig = field(default_factory=lambda: ToolConfig.auto("wpscan"))
    nuclei: ToolConfig = field(default_factory=lambda: ToolConfig.auto("nuclei"))
    sqlmap: ToolConfig = field(default_factory=lambda: ToolConfig.auto("sqlmap"))
    bloodhound: BloodHoundConfig = field(default_factory=BloodHoundConfig)
    metasploit: MetasploitConfig = field(default_factory=MetasploitConfig)
    sliver: SliverConfig = field(default_factory=SliverConfig)
    c2: C2Config = field(default_factory=C2Config)

    # Operational
    scope_filter: list[str] = field(default_factory=list)  # CIDR/hosts allowed
    require_operator_approval: bool = True
    audit_log: str = str(Path.home() / ".attack_surface" / "redteam_audit.log")
    default_timeout: int = 600
    max_concurrent_jobs: int = 3

    # Output
    output_dir: str = str(Path.home() / ".attack_surface" / "redteam_results")
    save_raw_output: bool = True
    generate_reports: bool = True

    @classmethod
    def load(cls, path: str | None = None) -> "RedTeamConfig":
        """Load from YAML file, env vars, then defaults."""
        cfg = cls()
        # 1. YAML file
        if path and Path(path).exists():
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            cfg = cls._from_dict(data)
        # 2. Environment overrides
        cfg = cls._from_env(cfg)
        # 2b. Credentials written by the container entrypoint
        #     (~/.attack_surface/msfrpcd.env): MSF_USER/MSF_RPC_PASS/...)
        envf = Path.home() / ".attack_surface" / "msfrpcd.env"
        if envf.is_file():
            data: dict = {}
            for line in envf.read_text().splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    k, _, v = line.partition("=")
                    data[k.strip()] = v.strip()
            if data.get("MSF_HOST"):
                cfg.metasploit.host = data["MSF_HOST"]
            if data.get("MSF_PORT"):
                try:
                    cfg.metasploit.port = int(data["MSF_PORT"])
                except ValueError:
                    pass
            if data.get("MSF_USER"):
                cfg.metasploit.user = data["MSF_USER"]
            if data.get("MSF_RPC_PASS"):
                cfg.metasploit.password = data["MSF_RPC_PASS"]
            if data.get("SLIVER_HOST"):
                cfg.sliver.server = data["SLIVER_HOST"]
            if data.get("SLIVER_PORT"):
                try:
                    cfg.sliver.port = int(data["SLIVER_PORT"])
                except ValueError:
                    pass
        # 3. Auto-detect tools
        cfg._auto_detect_tools()
        return cfg

    @classmethod
    def _from_dict(cls, data: dict) -> "RedTeamConfig":
        """Recursive dataclass population."""
        import dataclasses
        cfg = cls()
        for key, value in data.items():
            if hasattr(cfg, key):
                existing = getattr(cfg, key)
                if dataclasses.is_dataclass(existing) and isinstance(value, dict):
                    # Update nested dataclass fields
                    for nk, nv in value.items():
                        if hasattr(existing, nk):
                            setattr(existing, nk, nv)
                else:
                    setattr(cfg, key, value)
        return cfg

    @classmethod
    def _from_env(cls, cfg: "RedTeamConfig") -> "RedTeamConfig":
        """Override from environment variables: RT_<SECTION>_<KEY>"""
        prefix = "RT_"
        for key, value in os.environ.items():
            if key.startswith(prefix):
                parts = key[len(prefix):].lower().split("_", 1)
                if len(parts) == 2:
                    section, field_name = parts
                    section_obj = getattr(cfg, section, None)
                    if section_obj and hasattr(section_obj, field_name):
                        # Type coercion
                        field_type = type(getattr(section_obj, field_name))
                        if field_type == bool:
                            value = value.lower() in ("1", "true", "yes", "on")
                        elif field_type == int:
                            value = int(value)
                        elif field_type == list:
                            value = value.split(",")
                        setattr(section_obj, field_name, value)
        return cfg

    def _auto_detect_tools(self):
        """Re-run auto-detection for all tools."""
        for field_name in ["hydra", "nmap", "crackmapexec", "impacket_getuserspns",
                           "impacket_getnpusers", "impacket_ntlmrelayx", "wpscan", "nuclei", "sqlmap"]:
            tool = getattr(self, field_name)
            if isinstance(tool, ToolConfig) and not tool.binary:
                detected = ToolConfig.auto(field_name.replace("impacket_", "").replace("_", "-"))
                if detected.binary:
                    tool.binary = detected.binary
                    tool.enabled = True

    def save(self, path: str):
        """Save current config to YAML."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            yaml.safe_dump(self._to_dict(), f, default_flow_style=False, sort_keys=False)

    def _to_dict(self) -> dict:
        """Convert to dict for YAML serialization."""
        import dataclasses
        def convert(obj):
            if dataclasses.is_dataclass(obj):
                return {k: convert(v) for k, v in dataclasses.asdict(obj).items() if not k.startswith("_")}
            elif isinstance(obj, (list, tuple)):
                return [convert(v) for v in obj]
            elif isinstance(obj, dict):
                return {k: convert(v) for k, v in obj.items()}
            else:
                return obj
        return convert(self)

    def validate(self) -> list[str]:
        """Return list of warnings/errors."""
        issues = []
        if not any([self.hydra.enabled, self.crackmapexec.enabled, self.impacket_getuserspns.enabled]):
            issues.append("No credential attack tools available (hydra/crackmapexec/impacket)")
        if not self.metasploit.password:
            issues.append("Metasploit RPC password not set (env: RT_METASPLOIT_PASSWORD)")
        if not self.sliver.ca_cert:
            issues.append("Sliver mTLS certs not configured (env: RT_SLIVER_CA_CERT, etc.)")
        return issues


# Global instance (lazy-loaded)
_CONFIG: RedTeamConfig | None = None


def get_config(path: str | None = None, reload: bool = False) -> RedTeamConfig:
    global _CONFIG
    if _CONFIG is None or reload:
        _CONFIG = RedTeamConfig.load(path)
    return _CONFIG


def set_config(cfg: RedTeamConfig):
    global _CONFIG
    _CONFIG = cfg