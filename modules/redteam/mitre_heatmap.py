"""MITRE ATT&CK Heatmap — Maps scanner findings to ATT&CK Enterprise matrix.

Provides technique/tactic coverage analysis, kill-chain mapping,
D3.js-compatible matrix data generation, and prioritised recommendations
for hardening based on observed attack surface findings.

All 14 ATT&CK tactics, 100+ techniques with real IDs.
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("AttackSurface.MitreHeatmap")

# ============================================================================
# ATT&CK Constants — 14 Tactics (Enterprise)
# ============================================================================

TACTICS: Dict[str, Dict[str, str]] = {
    "TA0043": {"id": "TA0043", "name": "Reconnaissance",    "short": "recon",    "phase": "pre"},
    "TA0042": {"id": "TA0042", "name": "Resource Development", "short": "resource", "phase": "pre"},
    "TA0001": {"id": "TA0001", "name": "Initial Access",    "short": "initial",  "phase": "action"},
    "TA0002": {"id": "TA0002", "name": "Execution",         "short": "execute",  "phase": "action"},
    "TA0003": {"id": "TA0003", "name": "Persistence",       "short": "persist",  "phase": "action"},
    "TA0004": {"id": "TA0004", "name": "Privilege Escalation", "short": "privesc", "phase": "action"},
    "TA0005": {"id": "TA0005", "name": "Defense Evasion",   "short": "evasion",  "phase": "action"},
    "TA0006": {"id": "TA0006", "name": "Credential Access", "short": "cred",     "phase": "action"},
    "TA0007": {"id": "TA0007", "name": "Discovery",         "short": "discover", "phase": "action"},
    "TA0008": {"id": "TA0008", "name": "Lateral Movement",  "short": "lateral",  "phase": "action"},
    "TA0009": {"id": "TA0009", "name": "Collection",        "short": "collect",  "phase": "action"},
    "TA0011": {"id": "TA0011", "name": "Command and Control", "short": "c2",     "phase": "post"},
    "TA0010": {"id": "TA0010", "name": "Exfiltration",      "short": "exfil",    "phase": "post"},
    "TA0040": {"id": "TA0040", "name": "Impact",            "short": "impact",   "phase": "post"},
}

# Kill-chain phase ordering (defence depth perspective)
KILL_CHAIN_ORDER: List[str] = [
    "TA0043", "TA0042", "TA0001", "TA0002", "TA0003",
    "TA0004", "TA0005", "TA0006", "TA0007", "TA0008",
    "TA0009", "TA0011", "TA0010", "TA0040",
]

# ============================================================================
# Techniques — 100+ real IDs mapped to tactics
# ============================================================================

TECHNIQUES: Dict[str, Dict[str, Any]] = {
    # --- Reconnaissance (TA0043) ---
    "T1592": {"id": "T1592", "name": "Gather Victim Host Information", "tactic": "TA0043"},
    "T1589": {"id": "T1589", "name": "Gather Victim Identity Information", "tactic": "TA0043"},
    "T1590": {"id": "T1590", "name": "Gather Victim Network Information", "tactic": "TA0043"},
    "T1591": {"id": "T1591", "name": "Gather Victim Org Information", "tactic": "TA0043"},
    "T1598": {"id": "T1598", "name": "Phishing for Information", "tactic": "TA0043"},
    "T1597": {"id": "T1597", "name": "Search Closed Sources", "tactic": "TA0043"},
    "T1596": {"id": "T1596", "name": "Search Open Technical Databases", "tactic": "TA0043"},
    "T1593": {"id": "T1593", "name": "Search Open Websites/Domains", "tactic": "TA0043"},
    "T1594": {"id": "T1594", "name": "Search Victim-Owned Websites", "tactic": "TA0043"},

    # --- Resource Development (TA0042) ---
    "T1583": {"id": "T1583", "name": "Acquire Infrastructure", "tactic": "TA0042"},
    "T1586": {"id": "T1586", "name": "Compromise Accounts", "tactic": "TA0042"},
    "T1584": {"id": "T1584", "name": "Compromise Infrastructure", "tactic": "TA0042"},
    "T1587": {"id": "T1587", "name": "Develop Capabilities", "tactic": "TA0042"},
    "T1585": {"id": "T1585", "name": "Establish Accounts", "tactic": "TA0042"},
    "T1588": {"id": "T1588", "name": "Obtain Capabilities", "tactic": "TA0042"},
    "T1608": {"id": "T1608", "name": "Stage Capabilities", "tactic": "TA0042"},

    # --- Initial Access (TA0001) ---
    "T1189": {"id": "T1189", "name": "Drive-by Compromise", "tactic": "TA0001"},
    "T1190": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001"},
    "T1133": {"id": "T1133", "name": "External Remote Services", "tactic": "TA0001"},
    "T1200": {"id": "T1200", "name": "Hardware Additions", "tactic": "TA0001"},
    "T1566": {"id": "T1566", "name": "Phishing", "tactic": "TA0001"},
    "T1091": {"id": "T1091", "name": "Replication Through Removable Media", "tactic": "TA0001"},
    "T1195": {"id": "T1195", "name": "Supply Chain Compromise", "tactic": "TA0001"},
    "T1199": {"id": "T1199", "name": "Trusted Relationship", "tactic": "TA0001"},
    "T1078": {"id": "T1078", "name": "Valid Accounts", "tactic": "TA0001"},

    # --- Execution (TA0002) ---
    "T1059": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "TA0002"},
    "T1203": {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "TA0002"},
    "T1559": {"id": "T1559", "name": "Inter-Process Communication", "tactic": "TA0002"},
    "T1106": {"id": "T1106", "name": "Native API", "tactic": "TA0002"},
    "T1053": {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "TA0002"},
    "T1072": {"id": "T1072", "name": "Software Deployment Tools", "tactic": "TA0002"},
    "T1569": {"id": "T1569", "name": "System Services", "tactic": "TA0002"},
    "T1204": {"id": "T1204", "name": "User Execution", "tactic": "TA0002"},
    "T1047": {"id": "T1047", "name": "Windows Management Instrumentation", "tactic": "TA0002"},

    # --- Persistence (TA0003) ---
    "T1098": {"id": "T1098", "name": "Account Manipulation", "tactic": "TA0003"},
    "T1197": {"id": "T1197", "name": "BITS Jobs", "tactic": "TA0003"},
    "T1547": {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "TA0003"},
    "T1037": {"id": "T1037", "name": "Boot or Logon Initialization Scripts", "tactic": "TA0003"},
    "T1176": {"id": "T1176", "name": "Browser Extensions", "tactic": "TA0003"},
    "T1554": {"id": "T1554", "name": "Compromise Client Software Binary", "tactic": "TA0003"},
    "T1136": {"id": "T1136", "name": "Create Account", "tactic": "TA0003"},
    "T1543": {"id": "T1543", "name": "Create or Modify System Process", "tactic": "TA0003"},
    "T1546": {"id": "T1546", "name": "Event Triggered Execution", "tactic": "TA0003"},
    "T1574": {"id": "T1574", "name": "Hijack Execution Flow", "tactic": "TA0003"},
    "T1525": {"id": "T1525", "name": "Implant Internal Image", "tactic": "TA0003"},
    "T1556": {"id": "T1556", "name": "Modify Authentication Process", "tactic": "TA0003"},
    "T1137": {"id": "T1137", "name": "Office Application Startup", "tactic": "TA0003"},
    "T1542": {"id": "T1542", "name": "Pre-OS Boot", "tactic": "TA0003"},
    "T1505": {"id": "T1505", "name": "Server Software Component", "tactic": "TA0003"},
    "T1078": {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts", "tactic": "TA0003"},
    "T1098.001": {"id": "T1098.001", "name": "Account Manipulation: Additional Cloud Credentials", "tactic": "TA0003"},

    # --- Privilege Escalation (TA0004) ---
    "T1548": {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "TA0004"},
    "T1134": {"id": "T1134", "name": "Access Token Manipulation", "tactic": "TA0004"},
    "T1547": {"id": "T1547.001", "name": "Boot or Logon Autostart Execution: Registry Run Keys", "tactic": "TA0004"},
    "T1055": {"id": "T1055", "name": "Process Injection", "tactic": "TA0004"},
    "T1068": {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "TA0004"},
    "T1053": {"id": "T1053.005", "name": "Scheduled Task/Job: Windows Task Scheduler", "tactic": "TA0004"},
    "T1078": {"id": "T1078.001", "name": "Valid Accounts: Default Accounts", "tactic": "TA0004"},
    "T1078.002": {"id": "T1078.002", "name": "Valid Accounts: Domain Accounts", "tactic": "TA0004"},
    "T1078.003": {"id": "T1078.003", "name": "Valid Accounts: Local Accounts", "tactic": "TA0004"},
    "T1484": {"id": "T1484.001", "name": "Domain Policy Modification: Group Policy Modification", "tactic": "TA0004"},

    # --- Defense Evasion (TA0005) ---
    "T1134": {"id": "T1134.001", "name": "Access Token Manipulation: Token Impersonation", "tactic": "TA0005"},
    "T1140": {"id": "T1140", "name": "Deobfuscate/Decode Files or Information", "tactic": "TA0005"},
    "T1006": {"id": "T1006", "name": "Direct Volume Access", "tactic": "TA0005"},
    "T1484": {"id": "T1484", "name": "Domain Policy Modification", "tactic": "TA0005"},
    "T1480": {"id": "T1480", "name": "Execution Guardrails", "tactic": "TA0005"},
    "T1211": {"id": "T1211", "name": "Exploitation for Defense Evasion", "tactic": "TA0005"},
    "T1222": {"id": "T1222", "name": "File and Directory Permissions Modification", "tactic": "TA0005"},
    "T1562": {"id": "T1562", "name": "Impair Defenses", "tactic": "TA0005"},
    "T1070": {"id": "T1070", "name": "Indicator Removal", "tactic": "TA0005"},
    "T1202": {"id": "T1202", "name": "Indirect Command Execution", "tactic": "TA0005"},
    "T1112": {"id": "T1112", "name": "Modify Cloud Compute Infrastructure", "tactic": "TA0005"},
    "T1578": {"id": "T1578", "name": "Modify Cloud Compute Infrastructure", "tactic": "TA0005"},
    "T1112": {"id": "T1112.001", "name": "Modify Registry", "tactic": "TA0005"},
    "T1564": {"id": "T1564", "name": "Hide Artifacts", "tactic": "TA0005"},
    "T1027": {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "TA0005"},
    "T1542": {"id": "T1542.001", "name": "Pre-OS Boot: System Firmware", "tactic": "TA0005"},
    "T1218": {"id": "T1218", "name": "System Binary Proxy Execution", "tactic": "TA0005"},
    "T1216": {"id": "T1216", "name": "System Script Proxy Execution", "tactic": "TA0005"},
    "T1127": {"id": "T1127", "name": "Trusted Developer Utilities Proxy Execution", "tactic": "TA0005"},
    "T1535": {"id": "T1535", "name": "Unused/Unsupported Cloud Regions", "tactic": "TA0005"},

    # --- Credential Access (TA0006) ---
    "T1110": {"id": "T1110", "name": "Brute Force", "tactic": "TA0006"},
    "T1552": {"id": "T1552", "name": "Unsecured Credentials", "tactic": "TA0006"},
    "T1555": {"id": "T1555", "name": "Credentials from Password Stores", "tactic": "TA0006"},
    "T1212": {"id": "T1212", "name": "Exploitation for Credential Access", "tactic": "TA0006"},
    "T1187": {"id": "T1187", "name": "Forced Authentication", "tactic": "TA0006"},
    "T1606": {"id": "T1606", "name": "Forge Web Credentials", "tactic": "TA0006"},
    "T1056": {"id": "T1056", "name": "Input Capture", "tactic": "TA0006"},
    "T1557": {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "TA0006"},
    "T1111": {"id": "T1111", "name": "Multi-Factor Authentication Interception", "tactic": "TA0006"},
    "T1003": {"id": "T1003", "name": "OS Credential Dumping", "tactic": "TA0006"},
    "T1528": {"id": "T1528", "name": "Steal Application Access Token", "tactic": "TA0006"},
    "T1539": {"id": "T1539", "name": "Steal Web Session Cookie", "tactic": "TA0006"},
    "T1558": {"id": "T1558", "name": "Steal or Forge Kerberos Tickets", "tactic": "TA0006"},
    "T1557.001": {"id": "T1557.001", "name": "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning", "tactic": "TA0006"},
    "T1003.006": {"id": "T1003.006", "name": "OS Credential Dumping: DCSync", "tactic": "TA0006"},
    "T1558.003": {"id": "T1558.003", "name": "Steal Kerberos Tickets: Kerberoasting", "tactic": "TA0006"},
    "T1558.004": {"id": "T1558.004", "name": "Steal Kerberos Tickets: AS-REP Roasting", "tactic": "TA0006"},
    "T1110.001": {"id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "TA0006"},
    "T1110.003": {"id": "T1110.003", "name": "Brute Force: Password Spraying", "tactic": "TA0006"},

    # --- Discovery (TA0007) ---
    "T1087": {"id": "T1087", "name": "Account Discovery", "tactic": "TA0007"},
    "T1010": {"id": "T1010", "name": "Application Window Discovery", "tactic": "TA0007"},
    "T1217": {"id": "T1217", "name": "Browser Bookmark Discovery", "tactic": "TA0007"},
    "T1580": {"id": "T1580", "name": "Cloud Infrastructure Discovery", "tactic": "TA0007"},
    "T1526": {"id": "T1526", "name": "Cloud Service Discovery", "tactic": "TA0007"},
    "T1619": {"id": "T1619", "name": "Cloud Storage Object Discovery", "tactic": "TA0007"},
    "T1613": {"id": "T1613", "name": "Container and Resource Discovery", "tactic": "TA0007"},
    "T1622": {"id": "T1622", "name": "Debugger Evasion", "tactic": "TA0007"},
    "T1482": {"id": "T1482", "name": "Domain Trust Discovery", "tactic": "TA0007"},
    "T1083": {"id": "T1083", "name": "File and Directory Discovery", "tactic": "TA0007"},
    "T1615": {"id": "T1615", "name": "Group Policy Discovery", "tactic": "TA0007"},
    "T1046": {"id": "T1046", "name": "Network Service Scanning", "tactic": "TA0007"},
    "T1135": {"id": "T1135", "name": "Network Share Discovery", "tactic": "TA0007"},
    "T1040": {"id": "T1040", "name": "Network Sniffing", "tactic": "TA0007"},
    "T1201": {"id": "T1201", "name": "Password Policy Discovery", "tactic": "TA0007"},
    "T1120": {"id": "T1120", "name": "Peripheral Device Discovery", "tactic": "TA0007"},
    "T1069": {"id": "T1069", "name": "Permission Groups Discovery", "tactic": "TA0007"},
    "T1057": {"id": "T1057", "name": "Process Discovery", "tactic": "TA0007"},
    "T1012": {"id": "T1012", "name": "Query Registry", "tactic": "TA0007"},
    "T1018": {"id": "T1018", "name": "Remote System Discovery", "tactic": "TA0007"},
    "T1518": {"id": "T1518", "name": "Software Discovery", "tactic": "TA0007"},
    "T1082": {"id": "T1082", "name": "System Information Discovery", "tactic": "TA0007"},
    "T1016": {"id": "T1016", "name": "System Network Configuration Discovery", "tactic": "TA0007"},
    "T1049": {"id": "T1049", "name": "System Network Connections Discovery", "tactic": "TA0007"},
    "T1033": {"id": "T1033", "name": "System Owner/User Discovery", "tactic": "TA0007"},
    "T1007": {"id": "T1007", "name": "System Service Discovery", "tactic": "TA0007"},
    "T1124": {"id": "T1124", "name": "System Time Discovery", "tactic": "TA0007"},
    "T1087.002": {"id": "T1087.002", "name": "Account Discovery: Domain Account", "tactic": "TA0007"},
    "T1087.004": {"id": "T1087.004", "name": "Account Discovery: Cloud Account", "tactic": "TA0007"},
    "T1069.002": {"id": "T1069.002", "name": "Permission Groups Discovery: Domain Groups", "tactic": "TA0007"},

    # --- Lateral Movement (TA0008) ---
    "T1210": {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "TA0008"},
    "T1534": {"id": "T1534", "name": "Internal Spearphishing", "tactic": "TA0008"},
    "T1570": {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "TA0008"},
    "T1021": {"id": "T1021", "name": "Remote Services", "tactic": "TA0008"},
    "T1091": {"id": "T1091.001", "name": "Replication Through Removable Media", "tactic": "TA0008"},
    "T1072": {"id": "T1072.001", "name": "Software Deployment Tools: Systemd-timers", "tactic": "TA0008"},
    "T1550": {"id": "T1550", "name": "Use Alternate Authentication Material", "tactic": "TA0008"},
    "T1021.002": {"id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares", "tactic": "TA0008"},
    "T1021.004": {"id": "T1021.004", "name": "Remote Services: SSH", "tactic": "TA0008"},
    "T1021.001": {"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol", "tactic": "TA0008"},
    "T1021.006": {"id": "T1021.006", "name": "Remote Services: Windows Remote Management", "tactic": "TA0008"},
    "T1550.002": {"id": "T1550.002", "name": "Use Alternate Authentication Material: Pass the Hash", "tactic": "TA0008"},

    # --- Collection (TA0009) ---
    "T1557": {"id": "T1557.001", "name": "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning", "tactic": "TA0009"},
    "T1560": {"id": "T1560", "name": "Archive Collected Data", "tactic": "TA0009"},
    "T1123": {"id": "T1123", "name": "Audio Capture", "tactic": "TA0009"},
    "T1119": {"id": "T1119", "name": "Automated Collection", "tactic": "TA0009"},
    "T1115": {"id": "T1115", "name": "Clipboard Data", "tactic": "TA0009"},
    "T1530": {"id": "T1530", "name": "Data from Cloud Storage", "tactic": "TA0009"},
    "T1602": {"id": "T1602", "name": "Data from Network Configuration Repository", "tactic": "TA0009"},
    "T1005": {"id": "T1005", "name": "Data from Local System", "tactic": "TA0009"},
    "T1039": {"id": "T1039", "name": "Data from Network Shared Drive", "tactic": "TA0009"},
    "T1025": {"id": "T1025", "name": "Data from Removable Media", "tactic": "TA0009"},
    "T1074": {"id": "T1074", "name": "Data Staged", "tactic": "TA0009"},
    "T1114": {"id": "T1114", "name": "Email Collection", "tactic": "TA0009"},
    "T1056": {"id": "T1056.001", "name": "Input Capture: Keylogging", "tactic": "TA0009"},
    "T1113": {"id": "T1113", "name": "Screen Capture", "tactic": "TA0009"},
    "T1125": {"id": "T1125", "name": "Video Capture", "tactic": "TA0009"},

    # --- Command and Control (TA0011) ---
    "T1071": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "TA0011"},
    "T1092": {"id": "T1092", "name": "Communication Through Removable Media", "tactic": "TA0011"},
    "T1132": {"id": "T1132", "name": "Data Encoding", "tactic": "TA0011"},
    "T1001": {"id": "T1001", "name": "Data Obfuscation", "tactic": "TA0011"},
    "T1568": {"id": "T1568", "name": "Dynamic Resolution", "tactic": "TA0011"},
    "T1573": {"id": "T1573", "name": "Encrypted Channel", "tactic": "TA0011"},
    "T1008": {"id": "T1008", "name": "Fallback Channels", "tactic": "TA0011"},
    "T1105": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "TA0011"},
    "T1104": {"id": "T1104", "name": "Multi-Stage Channels", "tactic": "TA0011"},
    "T1095": {"id": "T1095", "name": "Non-Application Layer Protocol", "tactic": "TA0011"},
    "T1571": {"id": "T1571", "name": "Non-Standard Port", "tactic": "TA0011"},
    "T1572": {"id": "T1572", "name": "Protocol Tunneling", "tactic": "TA0011"},
    "T1090": {"id": "T1090", "name": "Proxy", "tactic": "TA0011"},
    "T1219": {"id": "T1219", "name": "Remote Access Software", "tactic": "TA0011"},
    "T1102": {"id": "T1102", "name": "Web Service", "tactic": "TA0011"},
    "T1071.001": {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "TA0011"},

    # --- Exfiltration (TA0010) ---
    "T1020": {"id": "T1020", "name": "Automated Exfiltration", "tactic": "TA0010"},
    "T1030": {"id": "T1030", "name": "Data Transfer Size Limits", "tactic": "TA0010"},
    "T1048": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "TA0010"},
    "T1041": {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "TA0010"},
    "T1011": {"id": "T1011", "name": "Exfiltration Over Other Network Medium", "tactic": "TA0010"},
    "T1052": {"id": "T1052", "name": "Exfiltration Over Physical Medium", "tactic": "TA0010"},
    "T1567": {"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "TA0010"},
    "T1029": {"id": "T1029", "name": "Scheduled Transfer", "tactic": "TA0010"},
    "T1537": {"id": "T1537", "name": "Transfer Data to Cloud Account", "tactic": "TA0010"},

    # --- Impact (TA0040) ---
    "T1531": {"id": "T1531", "name": "Account Access Removal", "tactic": "TA0040"},
    "T1485": {"id": "T1485", "name": "Data Destruction", "tactic": "TA0040"},
    "T1486": {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "TA0040"},
    "T1565": {"id": "T1565", "name": "Data Manipulation", "tactic": "TA0040"},
    "T1491": {"id": "T1491", "name": "Defacement", "tactic": "TA0040"},
    "T1561": {"id": "T1561", "name": "Disk Wipe", "tactic": "TA0040"},
    "T1499": {"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "TA0040"},
    "T1657": {"id": "T1657", "name": "Financial Theft", "tactic": "TA0040"},
    "T1495": {"id": "T1495", "name": "Firmware Corruption", "tactic": "TA0040"},
    "T1490": {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "TA0040"},
    "T1498": {"id": "T1498", "name": "Network Denial of Service", "tactic": "TA0040"},
    "T1496": {"id": "T1496", "name": "Resource Hijacking", "tactic": "TA0040"},
}

# ============================================================================
# Finding-type → Technique mapping (scanner output → ATT&CK)
# ============================================================================

FINDING_TO_TECHNIQUE: Dict[str, List[str]] = {
    # Web vulnerabilities
    "sql_injection":            ["T1190", "T1059"],
    "blind_sqli":               ["T1190", "T1059"],
    "stored_xss":               ["T1189", "T1204"],
    "reflected_xss":            ["T1189", "T1204"],
    "dom_xss":                  ["T1189", "T1204"],
    "xss":                      ["T1189", "T1204"],
    "csrf":                     ["T1189"],
    "ssrf":                     ["T1190", "T1090"],
    "xxe":                      ["T1190", "T1566"],
    "lfi":                      ["T1190", "T1005"],
    "rfi":                      ["T1190", "T1059"],
    "command_injection":        ["T1190", "T1059"],
    "remote_code_execution":    ["T1190", "T1059"],
    "deserialization":          ["T1190", "T1203"],
    "path_traversal":           ["T1190", "T1083"],
    "open_redirect":            ["T1189"],
    "cors_misconfiguration":    ["T1189", "T1550"],

    # Network / service exposure
    "ftp_open":                 ["T1046", "T1133"],
    "telnet_open":              ["T1046", "T1133"],
    "ssh_open":                 ["T1021.004", "T1046"],
    "rdp_open":                 ["T1021.001", "T1046"],
    "smb_open":                 ["T1021.002", "T1046"],
    "vnc_open":                 ["T1021", "T1046"],
    "mysql_open":               ["T1046", "T1110"],
    "postgres_open":            ["T1046", "T1110"],
    "mssql_open":               ["T1046", "T1110"],
    "oracle_open":              ["T1046", "T1110"],
    "redis_open":               ["T1046", "T1110"],
    "mongo_open":               ["T1046", "T1110"],
    "elasticsearch_open":       ["T1046", "T1526"],
    "memcached_open":           ["T1046"],
    "dns_open":                 ["T1046", "T1071"],
    "snmp_open":                ["T1046", "T1018"],
    "rmi_open":                 ["T1046", "T1190"],
    "ldap_open":                ["T1046", "T1018"],
    "kafka_open":               ["T1046"],
    "zookeeper_open":           ["T1046"],
    "docker_api_open":          ["T1046", "T1611"],
    "kubernetes_api_open":      ["T1046", "T1611"],
    "prometheus_open":          ["T1046", "T1526"],
    "jenkins_open":             ["T1190", "T1046"],
    "tomcat_manager":           ["T1190", "T1110"],
    "weblogic_console":         ["T1190"],
    "solr_open":                ["T1046", "T1190"],
    "nacos_open":               ["T1046", "T1190"],

    # Authentication issues
    "brute_force":              ["T1110.001", "T1110"],
    "password_spray":           ["T1110.003", "T1110"],
    "default_credentials":      ["T1110.001", "T1078"],
    "weak_password":            ["T1110.001"],
    "credential_stored":        ["T1552"],
    "hardcoded_credential":     ["T1552", "T1528"],
    "no_mfa":                   ["T1111"],
    "mfa_bypass":               ["T1111", "T1556"],
    "session_fixation":         ["T1539"],
    "session_hijacking":        ["T1539"],
    "jwt_none_algorithm":       ["T1606", "T1550"],
    "insecure_deserialization": ["T1190", "T1203"],

    # TLS / crypto issues
    "ssl_expired":              ["T1189", "T1573"],
    "ssl_weak_cipher":          ["T1573", "T1557"],
    "ssl_weak_protocol":        ["T1573"],
    "ssl_self_signed":          ["T1573", "T1557"],
    "ssl_cert_expired":         ["T1573"],
    "tls_version_old":          ["T1573"],
    "heartbleed":               ["T1190", "T1557"],
    "poodle":                   ["T1573"],
    "beast":                    ["T1573"],

    # Information disclosure
    "directory_listing":        ["T1083", "T1592"],
    "server_info_disclosure":   ["T1082", "T1592"],
    "stack_trace_disclosure":   ["T1082"],
    "internal_ip_disclosure":   ["T1016", "T1590"],
    "email_disclosure":         ["T1589", "T1530"],
    "source_code_disclosure":   ["T1005", "T1083"],

    # Configuration issues
    "cors_misconfig":           ["T1189", "T1550"],
    "clickjacking":             ["T1189", "T1204"],
    "missing_security_headers": ["T1189", "T1573"],
    "open_proxy":               ["T1090", "T1071"],
    "open_relay":               ["T1557", "T1090"],
    "anonymous_ftp":            ["T1078", "T1133"],
    "anonymous_access":         ["T1078"],
    "unnecessary_service":      ["T1046"],
    "dns_zone_transfer":        ["T1590", "T1046"],
    "snmp_public_community":    ["T1046", "T1018", "T1590"],
    "upnp_enabled":             ["T1046"],

    # Malware / reputation
    "malware_detected":         ["T1059", "T1204"],
    "phishing_link":            ["T1566", "T1189"],
    "drive_by_download":        ["T1189", "T1204"],
    "crypto_miner":             ["T1496", "T1059"],

    # Cloud-specific
    "s3_bucket_public":         ["T1530", "T1078.004"],
    "s3_bucket_listable":       ["T1530"],
    "ec2_public_snapshot":      ["T1580", "T1578"],
    "iam_admin_overuse":        ["T1078.004", "T1098.001"],
    "lambda_permission":        ["T1608", "T1078.004"],
    "cloud_metadata_access":    ["T1552", "T1078.004"],
    "gcp_public_bucket":        ["T1530"],
    "azure_blob_open":          ["T1530"],

    # Container / k8s
    "container_escape":         ["T1611", "T1068"],
    "k8s_dashboard_exposed":    ["T1613", "T1046"],
    "k8s_rbac_misconfig":       ["T1611", "T1078.004"],

    # API
    "api_no_auth":              ["T1190", "T1078"],
    "api_bola":                 ["T1190", "T1083"],
    "api_mass_assignment":      ["T1190", "T1098"],
    "graphql_introspection":    ["T1592", "T1087"],
    "api_rate_limit_missing":   ["T1499", "T1110"],
    "idor":                     ["T1190", "T1083"],
}

# Priority scores for severity weighting (1 = low, 10 = critical)
SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 10.0,
    "high":     8.0,
    "medium":   5.0,
    "low":      3.0,
    "info":     1.0,
    "unknown":  1.0,
}


# ============================================================================
# Dataclasses
# ============================================================================

@dataclass
class TechniqueCoverage:
    """Coverage status for a single ATT&CK technique."""
    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    finding_count: int = 0
    severity_score: float = 0.0
    covered: bool = False
    finding_types: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    risk_level: str = "none"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TacticCoverage:
    """Aggregated coverage for an ATT&CK tactic."""
    tactic_id: str
    tactic_name: str
    tactic_short: str
    total_techniques: int = 0
    covered_techniques: int = 0
    coverage_pct: float = 0.0
    total_findings: int = 0
    severity_score: float = 0.0
    techniques: List[TechniqueCoverage] = field(default_factory=list)
    risk_level: str = "none"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["techniques"] = [t.to_dict() if isinstance(t, TechniqueCoverage) else t
                           for t in self.techniques]
        return d


@dataclass
class Recommendation:
    """Actionable recommendation based on MITRE coverage analysis."""
    priority: str
    title: str
    description: str
    tactic_ids: List[str]
    technique_ids: List[str]
    finding_types: List[str]
    effort: str
    impact: str
    mitre_url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================================
# Core class
# ============================================================================

class MITREHeatmap:
    """Maps attack-surface findings to the MITRE ATT&CK Enterprise matrix.

    Produces technique/tactic coverage, kill-chain analysis, D3.js-ready
    heatmap data, and prioritised hardening recommendations.
    """

    def __init__(self) -> None:
        self._techniques = dict(TECHNIQUES)
        self._tactics = dict(TACTICS)
        self._finding_map = dict(FINDING_TO_TECHNIQUE)
        self._kill_chain = list(KILL_CHAIN_ORDER)
        self._severity_weights = dict(SEVERITY_WEIGHTS)

        # Pre-build tactic → technique index
        self._tactic_techniques: Dict[str, List[str]] = defaultdict(list)
        for tid, tinfo in self._techniques.items():
            tactic_id = tinfo["tactic"]
            if tactic_id not in self._tactic_techniques:
                self._tactic_techniques[tactic_id] = []
            if tid not in self._tactic_techniques[tactic_id]:
                self._tactic_techniques[tactic_id].append(tid)

        logger.debug(
            "MITREHeatmap init: %d techniques across %d tactics, %d finding mappings",
            len(self._techniques), len(self._tactics), len(self._finding_map),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_heatmap(
        self,
        findings: List[Dict[str, Any]],
        scan_results: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build complete heatmap data from findings and optional scan results.

        Args:
            findings: list of finding dicts with keys
                      ``type``, ``severity``, ``target``, ``description``.
            scan_results: optional scanner output (nmap, nuclei, etc.)

        Returns:
            dict with tactics, techniques, summary, kill_chain, recommendations.
        """
        # Merge scan_results into findings if provided
        all_findings = list(findings)
        if scan_results:
            all_findings.extend(self._extract_findings_from_scan(scan_results))

        tech_coverage = self.get_technique_coverage(all_findings)
        tactic_coverage = self.get_tactic_coverage(all_findings)
        kill_chain = self.calculate_kill_chain_coverage(all_findings)
        recommendations = self.get_recommendations(all_findings)

        covered_count = sum(1 for t in tech_coverage.values() if t.covered)
        total_sev = sum(t.severity_score for t in tech_coverage.values())

        summary = {
            "total_findings": len(all_findings),
            "techniques_covered": covered_count,
            "techniques_total": len(self._techniques),
            "tactics_covered": sum(
                1 for tc in tactic_coverage.values() if tc.covered_techniques > 0
            ),
            "tactics_total": len(self._tactics),
            "overall_severity_score": round(total_sev, 2),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        return {
            "summary": summary,
            "tactics": {k: v.to_dict() for k, v in tactic_coverage.items()},
            "techniques": {k: v.to_dict() for k, v in tech_coverage.items()},
            "kill_chain": kill_chain,
            "recommendations": [r.to_dict() for r in recommendations],
        }

    def get_technique_coverage(
        self,
        findings: List[Dict[str, Any]],
    ) -> Dict[str, TechniqueCoverage]:
        """Map findings to ATT&CK techniques and compute coverage.

        Returns:
            dict keyed by technique ID → TechniqueCoverage.
        """
        # Accumulate per-technique
        tech_map: Dict[str, Dict[str, Any]] = {}

        for finding in findings:
            ftype = self._normalise_finding_type(finding.get("type", ""))
            severity = self._normalise_severity(finding.get("severity", "unknown"))
            target = finding.get("target", "unknown")
            description = finding.get("description", ftype)

            technique_ids = self._finding_map.get(ftype, [])
            if not technique_ids:
                # Try fuzzy match against keys
                technique_ids = self._fuzzy_match_finding(ftype)
            if not technique_ids:
                continue

            for tid in technique_ids:
                if tid not in tech_map:
                    tinfo = self._techniques.get(tid)
                    if not tinfo:
                        continue
                    tech_map[tid] = {
                        "technique_id": tid,
                        "technique_name": tinfo["name"],
                        "tactic_id": tinfo["tactic"],
                        "tactic_name": self._tactics.get(tinfo["tactic"], {}).get("name", ""),
                        "finding_count": 0,
                        "severity_score": 0.0,
                        "finding_types": [],
                        "examples": [],
                    }
                tech_map[tid]["finding_count"] += 1
                tech_map[tid]["severity_score"] += self._severity_weights.get(severity, 1.0)
                if ftype not in tech_map[tid]["finding_types"]:
                    tech_map[tid]["finding_types"].append(ftype)
                if len(tech_map[tid]["examples"]) < 5:
                    example_str = f"[{severity}] {target}: {description[:120]}"
                    tech_map[tid]["examples"].append(example_str)

        # Convert to TechniqueCoverage
        result: Dict[str, TechniqueCoverage] = {}
        for tid, data in tech_map.items():
            sev = data["severity_score"]
            risk = self._classify_risk(data["finding_count"], sev)
            tc = TechniqueCoverage(
                technique_id=data["technique_id"],
                technique_name=data["technique_name"],
                tactic_id=data["tactic_id"],
                tactic_name=data["tactic_name"],
                finding_count=data["finding_count"],
                severity_score=round(sev, 2),
                covered=True,
                finding_types=data["finding_types"],
                examples=data["examples"],
                risk_level=risk,
            )
            result[tid] = tc

        return result

    def get_tactic_coverage(
        self,
        findings: List[Dict[str, Any]],
    ) -> Dict[str, TacticCoverage]:
        """Aggregate technique coverage up to tactic level.

        Returns:
            dict keyed by tactic ID → TacticCoverage with coverage_pct.
        """
        tech_coverage = self.get_technique_coverage(findings)
        result: Dict[str, TacticCoverage] = {}

        for tactic_id in self._kill_chain:
            tactic_info = self._tactics[tactic_id]
            technique_ids = self._tactic_techniques.get(tactic_id, [])
            total_techs = len(technique_ids)
            covered_techs = 0
            total_findings = 0
            severity_total = 0.0
            covered_technique_list: List[TechniqueCoverage] = []

            for tid in technique_ids:
                if tid in tech_coverage:
                    covered_techs += 1
                    tc = tech_coverage[tid]
                    total_findings += tc.finding_count
                    severity_total += tc.severity_score
                    covered_technique_list.append(tc)

            coverage_pct = (covered_techs / total_techs * 100) if total_techs > 0 else 0.0
            risk = self._classify_tactic_risk(coverage_pct, total_findings, severity_total)

            tc = TacticCoverage(
                tactic_id=tactic_id,
                tactic_name=tactic_info["name"],
                tactic_short=tactic_info["short"],
                total_techniques=total_techs,
                covered_techniques=covered_techs,
                coverage_pct=round(coverage_pct, 2),
                total_findings=total_findings,
                severity_score=round(severity_total, 2),
                techniques=covered_technique_list,
                risk_level=risk,
            )
            result[tactic_id] = tc

        return result

    def generate_matrix_data(self) -> Dict[str, Any]:
        """Generate D3.js-compatible JSON for the ATT&CK matrix visualisation.

        Returns:
            dict with ``nodes``, ``links``, ``tactics`` arrays ready for D3.
        """
        # Build tactic columns
        tactic_columns: List[Dict[str, Any]] = []
        all_nodes: List[Dict[str, Any]] = []
        node_index: Dict[str, int] = {}
        idx = 0

        for tactic_id in self._kill_chain:
            tactic_info = self._tactics[tactic_id]
            tech_ids = self._tactic_techniques.get(tactic_id, [])
            column = {
                "id": tactic_id,
                "name": tactic_info["name"],
                "short": tactic_info["short"],
                "phase": tactic_info.get("phase", "action"),
                "techniques": [],
            }
            for tid in sorted(tech_ids):
                tinfo = self._techniques[tid]
                node = {
                    "id": tid,
                    "name": tinfo["name"],
                    "tactic": tactic_id,
                    "tactic_name": tactic_info["name"],
                    "x": len(tactic_columns),
                    "y": len(column["techniques"]),
                    "findings": 0,
                    "severity": 0,
                    "risk_level": "none",
                    "finding_types": [],
                }
                column["techniques"].append(tid)
                all_nodes.append(node)
                node_index[tid] = idx
                idx += 1
            tactic_columns.append(column)

        # Sub-technique links (parent → child)
        links: List[Dict[str, Any]] = []
        for tid, tinfo in self._techniques.items():
            parent_id = tid.split(".")[0] if "." in tid else None
            if parent_id and parent_id in node_index and tid in node_index:
                links.append({
                    "source": parent_id,
                    "target": tid,
                    "type": "sub-technique",
                })

        return {
            "nodes": all_nodes,
            "links": links,
            "tactics": tactic_columns,
            "meta": {
                "total_techniques": len(all_nodes),
                "total_tactics": len(tactic_columns),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "version": "ATT&CK v14",
            },
        }

    def annotate_matrix(
        self,
        matrix: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Overlay finding data onto a D3 matrix for heatmap colouring.

        Modifies and returns the matrix dict in place, adding finding
        counts and severity to each node.
        """
        tech_coverage = self.get_technique_coverage(findings)
        node_lookup: Dict[str, Dict[str, Any]] = {
            n["id"]: n for n in matrix.get("nodes", [])
        }
        for tid, tc in tech_coverage.items():
            if tid in node_lookup:
                node = node_lookup[tid]
                node["findings"] = tc.finding_count
                node["severity"] = tc.severity_score
                node["risk_level"] = tc.risk_level
                node["finding_types"] = tc.finding_types
        return matrix

    def get_recommendations(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[Recommendation]:
        """Generate prioritised hardening recommendations.

        Recommendations are ordered by composite risk score (severity ×
        tactic kill-chain position × finding density).
        """
        tech_coverage = self.get_technique_coverage(findings)
        tactic_coverage = self.get_tactic_coverage(findings)
        recs: List[Recommendation] = []

        # Rule-based recommendations
        recs.extend(self._recommend_web_vulns(findings, tech_coverage))
        recs.extend(self._recommend_network_exposure(findings, tech_coverage))
        recs.extend(self._recommend_credential_issues(findings, tech_coverage))
        recs.extend(self._recommend_cloud(findings, tech_coverage))
        recs.extend(self._recommend_c2_detection(findings, tech_coverage))
        recs.extend(self._recommend_defense_gaps(findings, tactic_coverage))

        # Score and sort
        scored = [(self._recommendation_score(r, tactic_coverage), r) for r in recs]
        scored.sort(key=lambda x: x[0], reverse=True)
        return [r for _, r in scored]

    def calculate_kill_chain_coverage(
        self,
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Map coverage onto the kill-chain phases for risk-chain analysis.

        Returns:
            dict with ``phases`` (ordered list), ``overall_coverage``,
            ``weakest_phase``, ``strongest_phase``, and ``chain_score``.
        """
        tech_coverage = self.get_technique_coverage(findings)
        tactic_coverage = self.get_tactic_coverage(findings)

        phases: List[Dict[str, Any]] = []
        weakest_pct = 100.0
        weakest_id = ""
        strongest_pct = 0.0
        strongest_id = ""
        total_severity = 0.0

        for tactic_id in self._kill_chain:
            tc = tactic_coverage.get(tactic_id)
            tactic_info = self._tactics[tactic_id]
            phase = {
                "tactic_id": tactic_id,
                "tactic_name": tactic_info["name"],
                "phase": tactic_info.get("phase", "action"),
                "coverage_pct": tc.coverage_pct if tc else 0.0,
                "findings": tc.total_findings if tc else 0,
                "severity_score": tc.severity_score if tc else 0.0,
                "techniques_covered": tc.covered_techniques if tc else 0,
                "techniques_total": tc.total_techniques if tc else 0,
                "risk_level": tc.risk_level if tc else "none",
            }
            phases.append(phase)
            total_severity += phase["severity_score"]

            pct = phase["coverage_pct"]
            if pct < weakest_pct or (pct == weakest_pct and phase["findings"] > 0):
                weakest_pct = pct
                weakest_id = tactic_id
            if pct > strongest_pct:
                strongest_pct = pct
                strongest_id = tactic_id

        # Overall coverage: weighted average by tactic severity
        active_phases = [p for p in phases if p["findings"] > 0]
        if active_phases:
            overall = sum(p["coverage_pct"] for p in active_phases) / len(active_phases)
        else:
            overall = 0.0

        # Chain score: penalty for gaps in early kill-chain phases
        chain_score = self._compute_chain_score(phases)

        return {
            "phases": phases,
            "overall_coverage": round(overall, 2),
            "weakest_phase": weakest_id,
            "weakest_phase_coverage": round(weakest_pct, 2),
            "strongest_phase": strongest_id,
            "strongest_phase_coverage": round(strongest_pct, 2),
            "total_severity_score": round(total_severity, 2),
            "chain_score": round(chain_score, 2),
            "active_phases": len(active_phases),
            "total_phases": len(phases),
        }

    # ------------------------------------------------------------------
    # Utility / helpers
    # ------------------------------------------------------------------

    def get_all_techniques(self) -> Dict[str, Dict[str, Any]]:
        """Return the full technique database."""
        return dict(self._techniques)

    def get_techniques_for_tactic(self, tactic_id: str) -> List[Dict[str, Any]]:
        """Return all techniques belonging to a given tactic."""
        ids = self._tactic_techniques.get(tactic_id, [])
        return [self._techniques[tid] for tid in ids if tid in self._techniques]

    def get_techniques_for_finding(self, finding_type: str) -> List[str]:
        """Return ATT&CK technique IDs relevant to a finding type."""
        normalised = self._normalise_finding_type(finding_type)
        ids = self._finding_map.get(normalised, [])
        if not ids:
            ids = self._fuzzy_match_finding(normalised)
        return ids

    def export_csv(self, findings: List[Dict[str, Any]]) -> str:
        """Export technique coverage as CSV."""
        tech_coverage = self.get_technique_coverage(findings)
        lines = [
            "technique_id,technique_name,tactic_id,tactic_name,"
            "finding_count,severity_score,risk_level,finding_types",
        ]
        for tid in sorted(tech_coverage.keys()):
            tc = tech_coverage[tid]
            types_str = "|".join(tc.finding_types)
            lines.append(
                f"{tc.technique_id},\"{tc.technique_name}\",{tc.tactic_id},"
                f"\"{tc.tactic_name}\",{tc.finding_count},{tc.severity_score},"
                f"{tc.risk_level},\"{types_str}\""
            )
        return "\n".join(lines)

    def export_json(self, findings: List[Dict[str, Any]], pretty: bool = True) -> str:
        """Export full heatmap as JSON string."""
        data = self.build_heatmap(findings)
        if pretty:
            return json.dumps(data, indent=2, default=str)
        return json.dumps(data, default=str)

    def get_finding_type_coverage(self) -> Dict[str, List[str]]:
        """Return the full finding-type → technique mapping."""
        return dict(self._finding_map)

    def calculate_attack_path_risk(
        self,
        findings: List[Dict[str, Any]],
        path: List[str],
    ) -> Dict[str, Any]:
        """Risk-score an attack path (list of technique IDs).

        Args:
            path: ordered list of technique IDs forming an attack chain.

        Returns:
            dict with ``path``, ``risk_score``, ``phases_covered``,
            ``gaps``, and ``feasibility``.
        """
        tech_coverage = self.get_technique_coverage(findings)
        risk_score = 0.0
        phases_seen: Set[str] = set()
        gaps: List[str] = []

        for tid in path:
            if tid in tech_coverage and tech_coverage[tid].covered:
                tc = tech_coverage[tid]
                risk_score += tc.severity_score
                phases_seen.add(tc.tactic_id)
            else:
                gaps.append(tid)

        base = risk_score / max(len(path), 1)
        feasibility = "high" if not gaps else ("medium" if len(gaps) < len(path) * 0.3 else "low")

        return {
            "path": path,
            "risk_score": round(risk_score, 2),
            "normalised_score": round(base, 2),
            "phases_covered": sorted(phases_seen),
            "phases_count": len(phases_seen),
            "gaps": gaps,
            "feasibility": feasibility,
        }

    def suggest_attack_paths(
        self,
        findings: List[Dict[str, Any]],
        max_paths: int = 5,
    ) -> List[Dict[str, Any]]:
        """Suggest the most dangerous attack paths given current findings."""
        tech_coverage = self.get_technique_coverage(findings)
        if not tech_coverage:
            return []

        # Common attack patterns (ordered tactic chains)
        common_paths: List[Tuple[str, List[str]]] = [
            ("Web Exploit → RCE", ["T1190", "T1059", "T1003", "T1053.005"]),
            ("Brute Force → Lateral", ["T1110.001", "T1021.002", "T1053.005", "T1486"]),
            ("Phish → Cred Dump → Exfil", ["T1566", "T1003", "T1041"]),
            ("Kerberoast → DCSync → Exfil", ["T1558.003", "T1003.006", "T1048"]),
            ("Service Exploit → Priv Esc → Persist",
             ["T1190", "T1068", "T1547.001"]),
            ("SMB Relay → Lateral → Impact",
             ["T1557.001", "T1021.002", "T1486"]),
            ("Open Service → Cred Spray → Access",
             ["T1046", "T1110.003", "T1078"]),
            ("Cloud Misconfig → Data Theft",
             ["T1078.004", "T1530", "T1048"]),
        ]

        scored_paths: List[Dict[str, Any]] = []
        for name, path in common_paths:
            result = self.calculate_attack_path_risk(findings, path)
            result["name"] = name
            scored_paths.append(result)

        scored_paths.sort(key=lambda p: p["risk_score"], reverse=True)
        return scored_paths[:max_paths]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _normalise_finding_type(self, ftype: str) -> str:
        """Normalise a finding type string to match our mapping keys."""
        return ftype.strip().lower().replace(" ", "_").replace("-", "_")

    def _normalise_severity(self, severity: str) -> str:
        """Normalise severity string."""
        s = severity.strip().lower()
        if s in ("crit", "crit", "p1"):
            return "critical"
        if s in ("hi", "p2"):
            return "high"
        if s in ("med", "p3"):
            return "medium"
        if s in ("lo", "p4", "p5"):
            return "low"
        if s in ("informational", "notice", "verbose"):
            return "info"
        return s if s in SEVERITY_WEIGHTS else "unknown"

    def _fuzzy_match_finding(self, ftype: str) -> List[str]:
        """Best-effort substring match when exact mapping is missing."""
        matches: List[str] = []
        ftype_lower = ftype.lower()
        for key, tech_ids in self._finding_map.items():
            if key in ftype_lower or ftype_lower in key:
                matches.extend(tech_ids)
        return list(dict.fromkeys(matches))  # dedupe, preserve order

    def _classify_risk(self, finding_count: int, severity_score: float) -> str:
        """Classify risk level for a technique based on count and severity."""
        combined = finding_count * severity_score
        if combined >= 40:
            return "critical"
        if combined >= 20:
            return "high"
        if combined >= 8:
            return "medium"
        if combined > 0:
            return "low"
        return "none"

    def _classify_tactic_risk(
        self,
        coverage_pct: float,
        finding_count: int,
        severity: float,
    ) -> str:
        """Classify risk for a tactic based on coverage and finding load."""
        if coverage_pct >= 50 and severity >= 30:
            return "critical"
        if coverage_pct >= 30 or severity >= 20:
            return "high"
        if coverage_pct >= 10 or severity >= 5:
            return "medium"
        if finding_count > 0:
            return "low"
        return "none"

    def _compute_chain_score(self, phases: List[Dict[str, Any]]) -> float:
        """Score the kill chain: higher = more dangerous (more gaps filled by attacker).

        A score of 100 means every phase has findings; 0 means none.
        Gaps in early phases get higher penalty (they block later ones).
        """
        if not phases:
            return 0.0

        score = 0.0
        total_weight = 0.0
        n = len(phases)
        for i, phase in enumerate(phases):
            # Earlier phases are weighted higher (prevention-first)
            weight = (n - i) / n
            total_weight += weight
            activity = min(phase["findings"] / max(phase["techniques_total"], 1), 1.0)
            score += activity * weight

        return (score / total_weight * 100) if total_weight > 0 else 0.0

    def _extract_findings_from_scan(
        self,
        scan_results: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Convert scanner output into finding dicts."""
        findings: List[Dict[str, Any]] = []

        # Nmap results
        for host in scan_results.get("nmap", {}).get("hosts", []):
            for port_info in host.get("ports", []):
                port = port_info.get("port", 0)
                service = port_info.get("service", "").lower()
                state = port_info.get("state", "")
                if state != "open":
                    continue
                ftype = self._service_to_finding(service, port)
                if ftype:
                    findings.append({
                        "type": ftype,
                        "severity": "medium" if port in (21, 23, 3389) else "low",
                        "target": host.get("address", "unknown"),
                        "description": f"Open {service}:{port} ({state})",
                    })

        # Nuclei / vulnerability scanner results
        for vuln in scan_results.get("nuclei", {}).get("findings", []):
            findings.append({
                "type": vuln.get("type", "unknown"),
                "severity": vuln.get("severity", "unknown"),
                "target": vuln.get("matched_at", "unknown"),
                "description": vuln.get("name", vuln.get("type", "")),
            })

        # Generic findings list
        for f in scan_results.get("findings", []):
            if isinstance(f, dict):
                findings.append(f)

        return findings

    def _service_to_finding(self, service: str, port: int) -> Optional[str]:
        """Map a network service name/port to a finding type."""
        svc_map: Dict[str, Optional[str]] = {
            "ftp": "ftp_open",
            "telnet": "telnet_open",
            "ssh": "ssh_open",
            "rdp": "rdp_open",
            "ms-wbt-server": "rdp_open",
            "microsoft-ds": "smb_open",
            "netbios-ssn": "smb_open",
            "smb": "smb_open",
            "vnc": "vnc_open",
            "mysql": "mysql_open",
            "postgresql": "postgres_open",
            "ms-sql-s": "mssql_open",
            "oracle": "oracle_open",
            "redis": "redis_open",
            "mongodb": "mongo_open",
            "http": None,  # too generic; skip
            "https": None,
        }
        if service in svc_map:
            return svc_map[service]
        # Port-based fallback
        port_map: Dict[int, str] = {
            21: "ftp_open",
            23: "telnet_open",
            3389: "rdp_open",
            3306: "mysql_open",
            5432: "postgres_open",
            1433: "mssql_open",
            1521: "oracle_open",
            6379: "redis_open",
            27017: "mongo_open",
            9200: "elasticsearch_open",
            11211: "memcached_open",
            8080: "jenkins_open",
            7001: "weblogic_console",
            8443: "docker_api_open",
            6443: "kubernetes_api_open",
            9090: "prometheus_open",
            8848: "nacos_open",
        }
        return port_map.get(port)

    def _recommendation_score(
        self,
        rec: Recommendation,
        tactic_coverage: Dict[str, TacticCoverage],
    ) -> float:
        """Score a recommendation: higher = more urgent."""
        priority_map = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}
        base = priority_map.get(rec.priority, 5)

        # Boost if early kill-chain tactic
        for tid in rec.tactic_ids:
            if tid in self._kill_chain:
                pos = self._kill_chain.index(tid)
                base += (len(self._kill_chain) - pos) * 0.5

        # Boost based on tactic severity
        for tid in rec.tactic_ids:
            if tid in tactic_coverage:
                base += tactic_coverage[tid].severity_score * 0.1

        return base

    # ------------------------------------------------------------------
    # Recommendation generators
    # ------------------------------------------------------------------

    def _recommend_web_vulns(
        self,
        findings: List[Dict[str, Any]],
        tech_coverage: Dict[str, TechniqueCoverage],
    ) -> List[Recommendation]:
        recs: List[Recommendation] = []
        web_types = {"sql_injection", "blind_sqli", "stored_xss", "reflected_xss",
                     "dom_xss", "xss", "command_injection", "remote_code_execution",
                     "deserialization", "ssrf", "xxe", "csrf", "lfi", "rfi"}
        web_findings = [f for f in findings
                        if self._normalise_finding_type(f.get("type", "")) in web_types]
        if web_findings:
            types_found = {self._normalise_finding_type(f.get("type", "")) for f in web_findings}
            recs.append(Recommendation(
                priority="critical",
                title="Remediate critical web application vulnerabilities",
                description=(
                    f"Detected {len(web_findings)} web vulnerability findings across "
                    f"{len(types_found)} types. Apply input validation, parameterised "
                    "queries, CSP headers, and WAF rules."
                ),
                tactic_ids=["TA0001", "TA0002"],
                technique_ids=["T1190", "T1189", "T1059"],
                finding_types=sorted(types_found),
                effort="medium",
                impact="high",
                mitre_url="https://attack.mitre.org/techniques/T1190",
            ))
        return recs

    def _recommend_network_exposure(
        self,
        findings: List[Dict[str, Any]],
        tech_coverage: Dict[str, TechniqueCoverage],
    ) -> List[Recommendation]:
        recs: List[Recommendation] = []
        net_types = {"ftp_open", "telnet_open", "smb_open", "rdp_open", "vnc_open",
                     "redis_open", "mongo_open", "elasticsearch_open", "mysql_open",
                     "postgres_open", "mssql_open", "snmp_open"}
        net_findings = [f for f in findings
                        if self._normalise_finding_type(f.get("type", "")) in net_types]
        if net_findings:
            recs.append(Recommendation(
                priority="high",
                title="Close unnecessary open services",
                description=(
                    f"Detected {len(net_findings)} open network services that expose "
                    "internal infrastructure. Disable or firewall unused services."
                ),
                tactic_ids=["TA0007", "TA0001"],
                technique_ids=["T1046", "T1021", "T1133"],
                finding_types=sorted(net_types & {
                    self._normalise_finding_type(f.get("type", "")) for f in net_findings
                }),
                effort="low",
                impact="high",
                mitre_url="https://attack.mitre.org/techniques/T1046",
            ))
        return recs

    def _recommend_credential_issues(
        self,
        findings: List[Dict[str, Any]],
        tech_coverage: Dict[str, TechniqueCoverage],
    ) -> List[Recommendation]:
        recs: List[Recommendation] = []
        cred_types = {"brute_force", "password_spray", "default_credentials",
                      "weak_password", "no_mfa", "mfa_bypass"}
        cred_findings = [f for f in findings
                         if self._normalise_finding_type(f.get("type", "")) in cred_types]
        if cred_findings:
            recs.append(Recommendation(
                priority="critical",
                title="Strengthen authentication controls",
                description=(
                    f"Detected {len(cred_findings)} credential-related weaknesses. "
                    "Enforce MFA, implement account lockout, and rotate default passwords."
                ),
                tactic_ids=["TA0006"],
                technique_ids=["T1110", "T1111", "T1552"],
                finding_types=sorted(cred_types & {
                    self._normalise_finding_type(f.get("type", "")) for f in cred_findings
                }),
                effort="medium",
                impact="high",
                mitre_url="https://attack.mitre.org/techniques/T1110",
            ))
        return recs

    def _recommend_cloud(
        self,
        findings: List[Dict[str, Any]],
        tech_coverage: Dict[str, TechniqueCoverage],
    ) -> List[Recommendation]:
        recs: List[Recommendation] = []
        cloud_types = {"s3_bucket_public", "s3_bucket_listable", "ec2_public_snapshot",
                       "iam_admin_overuse", "lambda_permission", "cloud_metadata_access",
                       "gcp_public_bucket", "azure_blob_open"}
        cloud_findings = [f for f in findings
                          if self._normalise_finding_type(f.get("type", "")) in cloud_types]
        if cloud_findings:
            recs.append(Recommendation(
                priority="high",
                title="Harden cloud configuration",
                description=(
                    f"Detected {len(cloud_findings)} cloud misconfigurations. Audit IAM "
                    "policies, restrict bucket access, and enable cloud logging."
                ),
                tactic_ids=["TA0001", "TA0006"],
                technique_ids=["T1078.004", "T1530", "T1552"],
                finding_types=sorted(cloud_types & {
                    self._normalise_finding_type(f.get("type", "")) for f in cloud_findings
                }),
                effort="medium",
                impact="high",
                mitre_url="https://attack.mitre.org/techniques/T1530",
            ))
        return recs

    def _recommend_c2_detection(
        self,
        findings: List[Dict[str, Any]],
        tech_coverage: Dict[str, TechniqueCoverage],
    ) -> List[Recommendation]:
        recs: List[Recommendation] = []
        # If C2-related techniques are covered, recommend detection rules
        c2_techs = {"T1071", "T1573", "T1105", "T1568", "T1095", "T1572"}
        covered_c2 = c2_techs & set(tech_coverage.keys())
        if covered_c2:
            recs.append(Recommendation(
                priority="medium",
                title="Deploy C2 detection and EDR coverage",
                description=(
                    f"Findings map to {len(covered_c2)} C2-related ATT&CK techniques. "
                    "Deploy network monitoring, DNS analysis, and EDR with C2 detection rules."
                ),
                tactic_ids=["TA0011"],
                technique_ids=sorted(covered_c2),
                finding_types=[],
                effort="medium",
                impact="medium",
                mitre_url="https://attack.mitre.org/tactics/TA0011",
            ))
        return recs

    def _recommend_defense_gaps(
        self,
        findings: List[Dict[str, Any]],
        tactic_coverage: Dict[str, TacticCoverage],
    ) -> List[Recommendation]:
        recs: List[Recommendation] = []
        for tactic_id in self._kill_chain:
            tc = tactic_coverage.get(tactic_id)
            if not tc:
                continue
            if tc.covered_techniques > 0 and tc.risk_level in ("critical", "high"):
                recs.append(Recommendation(
                    priority=tc.risk_level,
                    title=f"Address ATT&CK gaps in {tc.tactic_name}",
                    description=(
                        f"{tc.covered_techniques}/{tc.total_techniques} techniques in "
                        f"{tc.tactic_name} are relevant ({tc.coverage_pct:.0f}% coverage) "
                        f"with severity score {tc.severity_score:.1f}."
                    ),
                    tactic_ids=[tactic_id],
                    technique_ids=[t.technique_id for t in tc.techniques],
                    finding_types=[],  # aggregated
                    effort="low",
                    impact="medium",
                    mitre_url=f"https://attack.mitre.org/tactics/{tactic_id}",
                ))
        return recs


# ============================================================================
# Module-level convenience
# ============================================================================

def quick_heatmap(
    findings: List[Dict[str, Any]],
    scan_results: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """One-call heatmap generation."""
    hm = MITREHeatmap()
    return hm.build_heatmap(findings, scan_results)


def finding_to_techniques(finding_type: str) -> List[str]:
    """Look up ATT&CK technique IDs for a finding type."""
    hm = MITREHeatmap()
    return hm.get_techniques_for_finding(finding_type)


# ============================================================================
# Self-test
# ============================================================================

if __name__ == "__main__":
    import sys

    test_findings = [
        {"type": "sql_injection", "severity": "critical", "target": "10.0.0.1",
         "description": "UNION-based SQLi in /login endpoint"},
        {"type": "xss", "severity": "high", "target": "10.0.0.1",
         "description": "Reflected XSS in search parameter"},
        {"type": "brute_force", "severity": "high", "target": "10.0.0.2",
         "description": "SSH brute force detected"},
        {"type": "ftp_open", "severity": "medium", "target": "10.0.0.3",
         "description": "FTP service on port 21"},
        {"type": "s3_bucket_public", "severity": "critical", "target": "s3://prod-bucket",
         "description": "Public S3 bucket with sensitive data"},
        {"type": "default_credentials", "severity": "critical", "target": "10.0.0.4",
         "description": "Default admin:admin on Tomcat manager"},
        {"type": "rdp_open", "severity": "medium", "target": "10.0.0.5",
         "description": "RDP open on port 3389"},
        {"type": "ssl_weak_cipher", "severity": "medium", "target": "10.0.0.1",
         "description": "RC4 cipher supported"},
    ]

    hm = MITREHeatmap()
    heatmap = hm.build_heatmap(test_findings)

    print("=" * 70)
    print("MITRE ATT&CK Heatmap Summary")
    print("=" * 70)
    s = heatmap["summary"]
    print(f"  Findings processed : {s['total_findings']}")
    print(f"  Techniques covered : {s['techniques_covered']}/{s['techniques_total']}")
    print(f"  Tactics covered    : {s['tactics_covered']}/{s['tactics_total']}")
    print(f"  Severity score     : {s['overall_severity_score']}")

    print("\n--- Kill Chain ---")
    kc = heatmap["kill_chain"]
    print(f"  Overall coverage   : {kc['overall_coverage']}%")
    print(f"  Weakest phase      : {kc['weakest_phase']}")
    print(f"  Chain score        : {kc['chain_score']}")

    print("\n--- Top Recommendations ---")
    for r in heatmap["recommendations"][:5]:
        print(f"  [{r['priority'].upper():8s}] {r['title']}")

    print("\n--- D3 Matrix ---")
    d3 = hm.generate_matrix_data()
    print(f"  Nodes: {len(d3['nodes'])}, Tactics: {len(d3['tactics'])}, "
          f"Links: {len(d3['links'])}")

    matrix = hm.annotate_matrix(d3, test_findings)
    active_nodes = [n for n in matrix["nodes"] if n["findings"] > 0]
    print(f"  Active (coloured) nodes: {len(active_nodes)}")

    # Attack path suggestion
    print("\n--- Suggested Attack Paths ---")
    paths = hm.suggest_attack_paths(test_findings, max_paths=3)
    for p in paths:
        print(f"  {p['name']}: score={p['risk_score']}, "
              f"feasibility={p['feasibility']}, gaps={len(p['gaps'])}")

    # CSV export
    csv_output = hm.export_csv(test_findings)
    csv_lines = csv_output.strip().split("\n")
    print(f"\n--- CSV Export: {len(csv_lines)} rows (including header) ---")

    # Technique count verification
    all_techs = hm.get_all_techniques()
    print(f"\n--- Technique DB: {len(all_techs)} techniques ---")

    # Tactic coverage detail
    print("\n--- Tactic Coverage ---")
    for tid in KILL_CHAIN_ORDER:
        tc = heatmap["tactics"].get(tid)
        if tc:
            print(f"  {tc['tactic_name']:30s} {tc['coverage_pct']:5.1f}% "
                  f"({tc['covered_techniques']}/{tc['total_techniques']}) "
                  f"[{tc['risk_level']}]")

    print("\n[PASS] MITREHeatmap self-test complete.")
    sys.exit(0)
