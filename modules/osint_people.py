"""osint_people.py — OSINT People Intelligence.

Collects people-related intelligence for red team targeting:
  - Username pivoting across platforms
  - Email harvesting and breach correlation
  - Photo metadata extraction (EXIF)
  - People search aggregation

All functions return structured data for the dashboard advisor.
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AttackSurface.OSINTPeople")


# ── Username pivoting ────────────────────────────────────────────
# Platforms to check for username presence
PLATFORMS = {
    "github": {"url": "https://github.com/{username}", "check": "status"},
    "twitter": {"url": "https://twitter.com/{username}", "check": "status"},
    "instagram": {"url": "https://instagram.com/{username}", "check": "status"},
    "reddit": {"url": "https://reddit.com/user/{username}", "check": "status"},
    "linkedin": {"url": "https://linkedin.com/in/{username}", "check": "status"},
    "pinterest": {"url": "https://pinterest.com/{username}", "check": "status"},
    "tiktok": {"url": "https://tiktok.com/@{username}", "check": "status"},
    "youtube": {"url": "https://youtube.com/@{username}", "check": "status"},
    "telegram": {"url": "https://t.me/{username}", "check": "status"},
    "keybase": {"url": "https://keybase.io/{username}", "check": "status"},
    "steam": {"url": "https://steamcommunity.com/id/{username}", "check": "status"},
    "twitch": {"url": "https://twitch.tv/{username}", "check": "status"},
    "aboutme": {"url": "https://about.me/{username}", "check": "status"},
    "flickr": {"url": "https://flickr.com/people/{username}", "check": "status"},
    "deviantart": {"url": "https://deviantart.com/{username}", "check": "status"},
}


def check_username(username: str, timeout: int = 5) -> List[Dict[str, Any]]:
    """Check username presence across multiple platforms.

    Returns list of {platform, url, found, status_code}.
    """
    results = []
    for platform, config in PLATFORMS.items():
        url = config["url"].format(username=username)
        try:
            # Use curl with realistic UA and short timeout
            r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 "
                        "Safari/537.36",
                 "-L", "--max-time", str(timeout), url],
                capture_output=True, text=True, timeout=timeout + 2,
            )
            status = int(r.stdout.strip()) if r.stdout.strip().isdigit() else 0
            found = status == 200
            results.append({
                "platform": platform,
                "url": url,
                "found": found,
                "status_code": status,
            })
        except Exception as e:
            results.append({
                "platform": platform,
                "url": url,
                "found": False,
                "status_code": 0,
                "error": str(e)[:50],
            })
    return results


# ── Email harvesting ─────────────────────────────────────────────
def harvest_emails_from_domain(domain: str) -> List[Dict[str, Any]]:
    """Harvest email addresses from a domain using multiple sources.

    Sources: DNS records, website scraping, search engines.
    """
    emails = []

    # 1. Check MX records for email provider hints
    try:
        r = subprocess.run(["nslookup", "-type=MX", domain],
                           capture_output=True, text=True, timeout=10)
        mx_lines = r.stdout
        if "mail exchanger" in mx_lines.lower():
            emails.append({
                "email": f"admin@{domain}",
                "source": "mx_record",
                "confidence": 0.4,
                "note": "MX record exists — admin@ likely valid",
            })
    except Exception:
        pass

    # 2. Check common email patterns
    common_patterns = ["admin", "info", "contact", "support", "sales",
                       "marketing", "hr", "jobs", "billing", "security",
                       "webmaster", "postmaster", "hostmaster"]
    for pattern in common_patterns:
        emails.append({
            "email": f"{pattern}@{domain}",
            "source": "pattern_guess",
            "confidence": 0.2,
            "note": f"Common pattern: {pattern}@",
        })

    # 3. Try to find emails in website HTML
    try:
        r = subprocess.run(
            ["curl", "-s", "-L", "--max-time", "10",
             "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/131.0.0.0",
             f"https://{domain}"],
            capture_output=True, text=True, timeout=15,
        )
        html = r.stdout
        found_emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html))
        for email in found_emails:
            if domain in email:
                emails.append({
                    "email": email,
                    "source": "website_scrape",
                    "confidence": 0.8,
                    "note": "Found in website HTML",
                })
    except Exception:
        pass

    # Deduplicate by email
    seen = set()
    unique = []
    for e in emails:
        if e["email"] not in seen:
            seen.add(e["email"])
            unique.append(e)
    return unique


# ── EXIF metadata extraction ─────────────────────────────────────
def extract_exif(image_path: str) -> Dict[str, Any]:
    """Extract EXIF metadata from an image file.

    Returns GPS location, camera info, timestamps, etc.
    """
    try:
        r = subprocess.run(["exiftool", "-json", image_path],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            data = json.loads(r.stdout)
            return data[0] if data else {}
    except Exception:
        pass
    return {}


def parse_exif_for_intel(exif_data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse EXIF data into actionable OSINT intelligence."""
    intel = {
        "gps_location": None,
        "camera": None,
        "software": None,
        "created_date": None,
        "has_gps": False,
        "risk_level": "low",
    }

    # GPS coordinates
    gps_lat = exif_data.get("GPSLatitude")
    gps_lon = exif_data.get("GPSLongitude")
    gps_ref = exif_data.get("GPSLatitudeRef", "N")
    if gps_lat and gps_lon:
        try:
            # Parse DMS format if needed
            if isinstance(gps_lat, str):
                parts = re.findall(r'[\d.]+', gps_lat)
                if len(parts) >= 3:
                    lat = float(parts[0]) + float(parts[1])/60 + float(parts[2])/3600
                    if gps_ref == "S":
                        lat = -lat
                    lon_parts = re.findall(r'[\d.]+', str(gps_lon))
                    if len(lon_parts) >= 3:
                        lon = float(lon_parts[0]) + float(lon_parts[1])/60 + float(lon_parts[2])/3600
                        if exif_data.get("GPSLongitudeRef") == "W":
                            lon = -lon
                        intel["gps_location"] = {"lat": lat, "lon": lon}
                        intel["has_gps"] = True
                        intel["risk_level"] = "high"
        except (ValueError, IndexError):
            pass

    # Camera info
    make = exif_data.get("Make", "")
    model = exif_data.get("Model", "")
    if make or model:
        intel["camera"] = f"{make} {model}".strip()

    # Software
    intel["software"] = exif_data.get("Software", "")

    # Date
    intel["created_date"] = exif_data.get("DateTimeOriginal",
                                           exif_data.get("CreateDate", ""))

    return intel


# ── People search aggregation ────────────────────────────────────
def search_people(
    name: str,
    organization: str = "",
    location: str = "",
) -> Dict[str, Any]:
    """Aggregate people search from multiple sources.

    Returns structured data for targeting decisions.
    """
    result = {
        "query": {"name": name, "organization": organization, "location": location},
        "social_profiles": [],
        "email_candidates": [],
        "breach_exposure": [],
        "risk_assessment": {},
    }

    # 1. Check social profiles by name-derived username
    username_guesses = []
    if name:
        parts = name.lower().split()
        if len(parts) >= 2:
            username_guesses.append(f"{parts[0]}{parts[1]}")
            username_guesses.append(f"{parts[0]}.{parts[1]}")
            username_guesses.append(f"{parts[0]}_{parts[1]}")
            username_guesses.append(parts[0])
        else:
            username_guesses.append(parts[0] if parts else name.lower())

    for username in username_guesses[:2]:  # limit to 2 guesses
        profiles = check_username(username)
        found_profiles = [p for p in profiles if p.get("found")]
        if found_profiles:
            result["social_profiles"].append({
                "username": username,
                "profiles_found": len(found_profiles),
                "platforms": [p["platform"] for p in found_profiles],
                "urls": [p["url"] for p in found_profiles],
            })

    # 2. Email candidates
    if organization:
        org_domain = organization.lower().replace(" ", "") + ".com"
        result["email_candidates"].append({
            "pattern": f"{name.split()[0].lower()}@{org_domain}" if name else "",
            "source": "organization_email",
            "confidence": 0.5,
        })

    # 3. Risk assessment
    total_profiles = sum(p["profiles_found"] for p in result["social_profiles"])
    result["risk_assessment"] = {
        "digital_footprint_size": total_profiles,
        "phishing_susceptibility": "high" if total_profiles > 5 else (
            "medium" if total_profiles > 2 else "low"),
        "social_engineering_risk": "high" if total_profiles > 10 else (
            "medium" if total_profiles > 3 else "low"),
        "recommendation": (
            "Target has large digital footprint — spear-phish likely effective"
            if total_profiles > 5 else
            "Limited digital footprint — use traditional phishing"
        ),
    }

    return result


# ── Full people intel report ─────────────────────────────────────
def people_intel_report(
    domain: str = "",
    person_name: str = "",
    username: str = "",
    organization: str = "",
) -> Dict[str, Any]:
    """Generate a complete people intelligence report.

    Combines username pivoting, email harvesting, and people search.
    """
    report = {
        "target": {"domain": domain, "person": person_name,
                   "username": username, "organization": organization},
        "username_pivot": [],
        "email_harvest": [],
        "people_search": None,
        "summary": "",
    }

    # Username pivot
    if username:
        report["username_pivot"] = check_username(username)

    # Email harvest
    if domain:
        report["email_harvest"] = harvest_emails_from_domain(domain)

    # People search
    if person_name:
        report["people_search"] = search_people(
            person_name, organization=organization)

    # Summary
    pivot_found = len([p for p in report["username_pivot"] if p.get("found")])
    emails_found = len(report["email_harvest"])
    summary_parts = []
    if pivot_found:
        summary_parts.append(f"Username found on {pivot_found} platform(s)")
    if emails_found:
        summary_parts.append(f"{emails_found} email candidate(s)")
    if report["people_search"]:
        risk = report["people_search"].get("risk_assessment", {})
        summary_parts.append(f"Phishing risk: {risk.get('phishing_susceptibility', 'unknown')}")
    report["summary"] = " | ".join(summary_parts) if summary_parts else "No people intel collected"

    return report
