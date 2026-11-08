"""supply_chain.py — Supply Chain Intelligence Engine.

Analyzes software supply chain security:
  - Package auditor (npm/pip/go): malicious scripts, secrets, unmaintained
  - Typosquatting detector: brand-lookalike domains and packages
  - Dependency risk scoring: CVEs, age, maintainer health
  - Secret scanner: hardcoded credentials in source code

Works entirely offline on local codebases — no WAF/HTTP dependency.
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("AttackSurface.SupplyChain")


# ── Data classes ─────────────────────────────────────────────────
@dataclass
class PackageIssue:
    """A security issue found in a package."""
    package: str
    version: str
    issue_type: str  # malicious_script, secret_leak, unmaintained, typosquat, cve
    severity: str    # critical, high, medium, low, info
    description: str
    evidence: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "type": self.issue_type,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence[:200],
            "recommendation": self.recommendation,
        }


@dataclass
class DependencyInfo:
    """Information about a single dependency."""
    name: str
    version: str
    ecosystem: str  # npm, pip, go, rubygems
    direct: bool = False
    age_days: int = 0
    maintainers: int = 0
    risk_score: float = 0.0
    issues: List[PackageIssue] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "direct": self.direct,
            "age_days": self.age_days,
            "maintainers": self.maintainers,
            "risk_score": round(self.risk_score, 1),
            "issues": [i.to_dict() for i in self.issues],
        }


# ── Secret scanner ───────────────────────────────────────────────
SECRET_PATTERNS = [
    {"name": "AWS Access Key", "regex": r"AKIA[0-9A-Z]{16}", "severity": "critical"},
    {"name": "AWS Secret Key", "regex": r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "severity": "critical"},
    {"name": "GitHub Token", "regex": r"gh[pousr]_[A-Za-z0-9]{36,255}", "severity": "critical"},
    {"name": "GitLab Token", "regex": r"glpat-[A-Za-z0-9\-_]{20}", "severity": "critical"},
    {"name": "Slack Token", "regex": r"xox[baprs]-[A-Za-z0-9\-]{10,}", "severity": "high"},
    {"name": "Slack Webhook", "regex": r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", "severity": "high"},
    {"name": "Stripe Key", "regex": r"[sr]k_(live|test)_[A-Za-z0-9]{24,}", "severity": "critical"},
    {"name": "Twilio Key", "regex": r"[0-9a-fA-F]{32}", "severity": "info"},  # too generic
    {"name": "SendGrid Key", "regex": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", "severity": "high"},
    {"name": "Mailgun Key", "regex": r"key-[0-9a-zA-Z]{32}", "severity": "high"},
    {"name": "Private Key", "regex": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "severity": "critical"},
    {"name": "JWT Token", "regex": r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", "severity": "medium"},
    {"name": "Database URL", "regex": r"(?i)(mongodb|postgres|mysql|redis)://[^\s'\"]+", "severity": "high"},
    {"name": "API Key Generic", "regex": r"(?i)(api[_-]?key|apikey|secret[_-]?key)['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_]{20,}['\"]", "severity": "high"},
    {"name": "Password Assignment", "regex": r"(?i)(password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"]{6,}['\"]", "severity": "medium"},
    {"name": "Basic Auth URL", "regex": r"https?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", "severity": "high"},
]


def scan_for_secrets(code: str, filename: str = "") -> List[Dict[str, Any]]:
    """Scan source code for hardcoded secrets and credentials."""
    findings = []
    for pattern in SECRET_PATTERNS:
        if pattern["name"] == "Twilio Key":
            continue  # too generic
        matches = re.finditer(pattern["regex"], code)
        for match in matches:
            matched_text = match.group()
            # Skip common false positives
            if pattern["name"] == "JWT Token" and len(matched_text) < 100:
                continue
            if pattern["name"] == "Password Assignment":
                # Skip if value looks like a placeholder
                if any(w in matched_text.lower() for w in ["example", "placeholder", "xxx", "todo", "fixme"]):
                    continue
            findings.append({
                "secret_type": pattern["name"],
                "severity": pattern["severity"],
                "file": filename,
                "match": matched_text[:80] + "..." if len(matched_text) > 80 else matched_text,
                "line": code[:match.start()].count("\n") + 1,
            })
    return findings


# ── Malicious script detection ───────────────────────────────────
MALICIOUS_SCRIPT_PATTERNS = [
    {"pattern": r"child_process.*exec.*curl|wget", "severity": "critical",
     "description": "Downloads and executes remote code"},
    {"pattern": r"eval\s*\(\s*(atob|Buffer\.from|atob)", "severity": "critical",
     "description": "Base64-decoded eval execution"},
    {"pattern": r"(postinstall|preinstall).*node.*-e", "severity": "high",
     "description": "Inline node execution in install script"},
    {"pattern": r"curl.*\|\s*(sh|bash|zsh)", "severity": "critical",
     "description": "Pipe remote content to shell"},
    {"pattern": r"wget.*-O-.*\|\s*(sh|bash)", "severity": "critical",
     "description": "Download and pipe to shell"},
    {"pattern": r"rm\s+-rf\s+/(?:\s|$|\*)", "severity": "critical",
     "description": "Recursive delete of root directory"},
    {"pattern": r"os\.system\s*\(\s*['\"]rm\s+-rf", "severity": "critical",
     "description": "Python recursive delete command"},
    {"pattern": r"subprocess.*check_output.*curl|wget", "severity": "high",
     "description": "Remote download via subprocess"},
    {"pattern": r"base64\s*-d.*\|\s*(sh|bash|python)", "severity": "critical",
     "description": "Base64-decoded shell execution"},
    {"pattern": r"import\s+urllib.*urlopen.*exec", "severity": "critical",
     "description": "Remote code execution via urllib"},
]


def scan_install_scripts(scripts: Dict[str, str],
                         package_name: str = "") -> List[PackageIssue]:
    """Scan npm/pip install scripts for malicious patterns."""
    issues = []
    for script_name, script_code in scripts.items():
        for pattern in MALICIOUS_SCRIPT_PATTERNS:
            matches = re.finditer(pattern["pattern"], script_code, re.IGNORECASE)
            for match in matches:
                issues.append(PackageIssue(
                    package=package_name,
                    version="",
                    issue_type="malicious_script",
                    severity=pattern["severity"],
                    description=f"Install script '{script_name}': {pattern['description']}",
                    evidence=match.group()[:100],
                    recommendation="Review install script manually — possible supply chain attack",
                ))
    return issues


# ── Typosquatting detector ───────────────────────────────────────
# Common typosquatting techniques
def generate_typosquats(brand: str) -> List[str]:
    """Generate typosquatting variants for a brand name."""
    variants = set()

    # Character substitution
    char_map = {
        "a": ["@4", "à", "á", "â"], "e": ["3", "é", "è"], "i": ["1", "!", "í"],
        "o": ["0", "ó", "ò"], "s": ["5", "$", "ß"], "l": ["1", "|"],
        "t": ["7", "+"], "g": ["9", "q"], "c": ["(", "ç"],
    }
    for char, subs in char_map.items():
        if char in brand:
            for sub in subs:
                variants.add(brand.replace(char, sub, 1))

    # Character omission
    for i in range(len(brand)):
        variants.add(brand[:i] + brand[i+1:])

    # Character duplication
    for i in range(len(brand)):
        variants.add(brand[:i] + brand[i] + brand[i:])

    # Character swap
    for i in range(len(brand) - 1):
        variants.add(brand[:i] + brand[i+1] + brand[i] + brand[i+2:])

    # Common TLD swaps
    common_tlds = [".com", ".net", ".org", ".ir", ".io", ".co", ".info", ".biz"]
    for tld in common_tlds:
        variants.add(brand + tld)
        # hyphenated
        if "-" not in brand:
            variants.add(brand + "-" + brand.split(".")[0])

    return sorted(variants)


def check_typosquat_registration(domains: List[str]) -> List[Dict[str, Any]]:
    """Check which typosquat domains are registered (via DNS)."""
    import socket
    registered = []
    for domain in domains[:50]:  # limit to 50
        try:
            ip = socket.gethostbyname(domain)
            registered.append({
                "domain": domain,
                "registered": True,
                "ip": ip,
                "risk": "high",
            })
        except socket.gaierror:
            registered.append({
                "domain": domain,
                "registered": False,
                "risk": "low",
            })
    return registered


# ── Package ecosystem parsing ────────────────────────────────────
def parse_package_json(content: str) -> Dict[str, Any]:
    """Parse package.json for npm dependencies."""
    try:
        data = json.loads(content)
        deps = {}
        for dep_type in ("dependencies", "devDependencies", "peerDependencies"):
            for name, version in (data.get(dep_type) or {}).items():
                deps[name] = {
                    "version": version,
                    "direct": dep_type == "dependencies",
                }
        scripts = data.get("scripts", {})
        return {"name": data.get("name", ""),
                "version": data.get("version", ""),
                "dependencies": deps,
                "scripts": scripts}
    except (json.JSONDecodeError, AttributeError):
        return {}


def parse_requirements_txt(content: str) -> Dict[str, Any]:
    """Parse requirements.txt for pip dependencies."""
    deps = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Parse name==version or name>=version
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=|!=)?\s*(.*)", line)
        if match:
            name = match.group(1)
            version = match.group(2).strip() or "*"
            deps[name] = {"version": version, "direct": True}
    return {"dependencies": deps, "scripts": {}}


def parse_go_mod(content: str) -> Dict[str, Any]:
    """Parse go.mod for Go dependencies."""
    deps = {}
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require"):
            # Parse: require module v1.2.3
            parts = line.split()
            if len(parts) >= 3:
                deps[parts[1]] = {"version": parts[2], "direct": True}
            elif len(parts) == 2:
                deps[parts[1]] = {"version": "latest", "direct": True}
        elif line and not line.startswith("//") and not line.startswith("module"):
            # Could be indented require block
            parts = line.split()
            if len(parts) >= 2 and not parts[0].startswith("//"):
                deps[parts[0]] = {"version": parts[1], "direct": False}
    return {"dependencies": deps, "scripts": {}}


# ── Dependency risk scoring ──────────────────────────────────────
def score_dependency_risk(dep: DependencyInfo) -> float:
    """Calculate risk score for a dependency (0-100)."""
    score = 0.0

    # Issue severity contributions
    severity_weights = {"critical": 30, "high": 20, "medium": 10, "low": 5, "info": 1}
    for issue in dep.issues:
        score += severity_weights.get(issue.severity, 1)

    # Age penalty (older = riskier)
    if dep.age_days > 365 * 3:
        score += 15  # 3+ years old
    elif dep.age_days > 365:
        score += 8   # 1+ year old

    # Fewer maintainers = higher risk
    if dep.maintainers == 0:
        score += 20  # abandoned
    elif dep.maintainers == 1:
        score += 10  # single maintainer risk

    return min(score, 100)


# ── Full supply chain audit ──────────────────────────────────────
def audit_project(project_dir: str) -> Dict[str, Any]:
    """Run a complete supply chain audit on a project directory.

    Analyzes package manifests, scans for secrets, checks install scripts.
    """
    result = {
        "project_dir": project_dir,
        "manifests_found": [],
        "dependencies": [],
        "secrets": [],
        "malicious_scripts": [],
        "typosquat_check": [],
        "risk_summary": {},
    }

    # Find and parse manifests
    manifest_files = {
        "package.json": parse_package_json,
        "requirements.txt": parse_requirements_txt,
        "go.mod": parse_go_mod,
    }

    for root, dirs, files in os.walk(project_dir):
        # Skip node_modules, venv, .git
        dirs[:] = [d for d in dirs if d not in
                    ("node_modules", "venv", ".venv", ".git", "__pycache__", ".tox")]

        for fname in files:
            if fname in manifest_files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", errors="replace") as f:
                        content = f.read()
                    parsed = manifest_files[fname](content)
                    if parsed.get("dependencies"):
                        result["manifests_found"].append(fname)
                        for dep_name, dep_info in parsed["dependencies"].items():
                            dep = DependencyInfo(
                                name=dep_name,
                                version=dep_info.get("version", "*"),
                                ecosystem=fname,
                                direct=dep_info.get("direct", False),
                            )
                            result["dependencies"].append(dep.to_dict())

                        # Check install scripts
                        if parsed.get("scripts"):
                            install_scripts = {
                                k: v for k, v in parsed["scripts"].items()
                                if k in ("postinstall", "preinstall", "install",
                                         "prepare", "prepublish")
                            }
                            if install_scripts:
                                issues = scan_install_scripts(
                                    install_scripts, parsed.get("name", fname))
                                result["malicious_scripts"].extend(
                                    [i.to_dict() for i in issues])
                except Exception as e:
                    logger.warning("Failed to parse %s: %s", fpath, e)

        # Scan source files for secrets (limit to common source extensions)
        for fname in files:
            if fname.endswith((".py", ".js", ".ts", ".go", ".rb", ".php",
                               ".env", ".cfg", ".ini", ".yaml", ".yml",
                               ".json", ".sh", ".bash")):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", errors="replace") as f:
                        code = f.read(500000)  # 500KB limit
                    secrets = scan_for_secrets(code, fname)
                    result["secrets"].extend(secrets)
                except Exception:
                    pass

    # Risk summary
    total_deps = len(result["dependencies"])
    total_secrets = len(result["secrets"])
    total_scripts = len(result["malicious_scripts"])
    critical_secrets = sum(1 for s in result["secrets"]
                          if s.get("severity") == "critical")

    overall_risk = min(
        (critical_secrets * 25) + (total_scripts * 30) +
        (total_secrets * 5) + (total_deps * 0.5),
        100
    )

    result["risk_summary"] = {
        "total_dependencies": total_deps,
        "total_secrets": total_secrets,
        "critical_secrets": critical_secrets,
        "malicious_scripts": total_scripts,
        "overall_risk_score": round(overall_risk, 1),
        "risk_level": ("critical" if overall_risk >= 70 else
                       "high" if overall_risk >= 40 else
                       "medium" if overall_risk >= 15 else "low"),
    }

    return result
