"""cloud_attack.py — Cloud Attack Path Intelligence.

Discovers and analyzes cloud infrastructure attack paths:
  - Cloud asset discovery (DNS-based, no HTTP scanning)
  - Bucket/instance enumeration
  - IAM policy analysis
  - Container/K8s exposure detection
  - SSRF and metadata endpoint discovery

Works via DNS and API reconnaissance — no WAF/HTTP dependency.
"""
from __future__ import annotations

import json
import logging
import re
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("AttackSurface.CloudAttack")


# ── Cloud provider detection ─────────────────────────────────────
CLOUD_CNAME_PATTERNS = {
    "aws": ["cloudfront.net", "amazonaws.com", "elasticbeanstalk.com",
            "s3.amazonaws.com", "cloudfront.amazonaws.com"],
    "azure": ["azurewebsites.net", "cloudapp.azure.com", "blob.core.windows.net",
              "azureedge.net", "trafficmanager.net"],
    "gcp": ["appspot.com", "storage.googleapis.com", "cloudfunctions.net",
            "run.app", "firebaseapp.com"],
    "digitalocean": ["digitalocean.com", "digitaloceanspaces.com"],
    "cloudflare": ["cdn.cloudflare.net", "workers.dev"],
}


@dataclass
class CloudAsset:
    """A discovered cloud asset."""
    asset_type: str  # bucket, instance, function, cdn, database
    provider: str    # aws, azure, gcp, digitalocean
    identifier: str  # bucket name, instance ID, function name
    url: str = ""
    ip: str = ""
    public: bool = False
    risk_score: float = 0.0
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.asset_type,
            "provider": self.provider,
            "identifier": self.identifier,
            "url": self.url,
            "ip": self.ip,
            "public": self.public,
            "risk_score": round(self.risk_score, 1),
            "findings": self.findings,
        }


# ── DNS-based cloud asset discovery ──────────────────────────────
def detect_cloud_provider(cname: str) -> Optional[str]:
    """Detect cloud provider from CNAME record."""
    cname_lower = cname.lower()
    for provider, patterns in CLOUD_CNAME_PATTERNS.items():
        for pattern in patterns:
            if pattern in cname_lower:
                return provider
    return None


def discover_cloud_assets(domain: str) -> List[CloudAsset]:
    """Discover cloud assets for a domain via DNS records.

    Checks CNAME, A, and TXT records to identify cloud services.
    """
    assets = []
    seen = set()

    # Check CNAME records for cloud provider fingerprints
    try:
        import dns.resolver
        # CNAME check
        try:
            answers = dns.resolver.resolve(domain, "CNAME")
            for rdata in answers:
                cname = str(rdata.target).rstrip(".")
                provider = detect_cloud_provider(cname)
                if provider:
                    key = f"cdn:{cname}"
                    if key not in seen:
                        seen.add(key)
                        assets.append(CloudAsset(
                            asset_type="cdn",
                            provider=provider,
                            identifier=cname,
                            url=f"https://{domain}",
                            public=True,
                            risk_score=30,
                            findings=[f"CDN detected via CNAME → {provider}"],
                        ))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass

        # A record check (IP-based provider detection)
        try:
            answers = dns.resolver.resolve(domain, "A")
            for rdata in answers:
                ip = str(rdata)
                # AWS IP ranges
                if ip.startswith(("3.", "13.", "15.", "18.", "52.", "54.", "99.")):
                    assets.append(CloudAsset(
                        asset_type="host", provider="aws",
                        identifier=ip, ip=ip,
                        risk_score=20,
                        findings=["AWS IP range detected"],
                    ))
                # Azure IP ranges
                elif ip.startswith(("20.", "40.", "104.", "157.", "168.")):
                    assets.append(CloudAsset(
                        asset_type="host", provider="azure",
                        identifier=ip, ip=ip,
                        risk_score=20,
                        findings=["Azure IP range detected"],
                    ))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
    except ImportError:
        # Fallback: use nslookup
        return _discover_via_nslookup(domain)

    # Check common cloud subdomains
    cloud_subdomains = [
        ("s3", "aws"), ("storage", "gcp"), ("blob", "azure"),
        ("cdn", None), ("static", None), ("assets", None),
        ("api", None), ("app", None), ("admin", None),
        ("staging", None), ("dev", None), ("test", None),
    ]
    for sub, provider_hint in cloud_subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            provider = provider_hint or "unknown"
            key = f"sub:{subdomain}"
            if key not in seen:
                seen.add(key)
                assets.append(CloudAsset(
                    asset_type="subdomain",
                    provider=provider,
                    identifier=subdomain,
                    ip=ip,
                    public=True,
                    risk_score=25,
                    findings=[f"Cloud-related subdomain: {subdomain}"],
                ))
        except socket.gaierror:
            pass

    return assets


def _discover_via_nslookup(domain: str) -> List[CloudAsset]:
    """Fallback cloud discovery using nslookup."""
    assets = []
    try:
        r = subprocess.run(["nslookup", "-type=CNAME", domain],
                           capture_output=True, text=True, timeout=10)
        for line in r.stdout.splitlines():
            if "canonical name" in line.lower():
                cname = line.split("=", 1)[-1].strip()
                provider = detect_cloud_provider(cname)
                if provider:
                    assets.append(CloudAsset(
                        asset_type="cdn", provider=provider,
                        identifier=cname, public=True,
                        risk_score=30,
                        findings=[f"CDN via nslookup → {provider}"],
                    ))
    except Exception:
        pass
    return assets


# ── S3 bucket enumeration ────────────────────────────────────────
def enumerate_s3_buckets(domain: str) -> List[Dict[str, Any]]:
    """Enumerate potential S3 bucket names for a domain.

    Uses HTTP status check — AWS wildcard DNS resolves all *.s3.amazonaws.com,
    so DNS alone gives false positives. Real buckets return 200/403;
    non-existent return 404.
    """
    import subprocess
    bucket_names = [
        domain,
        domain.replace(".", "-"),
        domain.replace(".", ""),
        f"{domain}-assets",
        f"{domain}-static",
        f"{domain}-media",
        f"{domain}-backup",
        f"{domain}-data",
        f"{domain}-logs",
        f"{domain}-uploads",
        f"{domain}-public",
        f"www-{domain}",
    ]

    buckets = []
    for name in bucket_names:
        url = f"https://{name}.s3.amazonaws.com"
        try:
            r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", "8", url],
                capture_output=True, text=True, timeout=10,
            )
            status = r.stdout.strip()
            if status in ("200", "403"):  # 403 = exists but private
                buckets.append({
                    "bucket": name,
                    "url": url,
                    "exists": True,
                    "http_status": status,
                    "access": "public" if status == "200" else "private",
                    "risk": "high" if status == "200" else "medium",
                })
            else:
                buckets.append({
                    "bucket": name,
                    "url": url,
                    "exists": False,
                    "http_status": status,
                    "risk": "low",
                })
        except Exception:
            buckets.append({
                "bucket": name,
                "url": url,
                "exists": False,
                "risk": "low",
            })
    return buckets


# ── Metadata endpoint detection ──────────────────────────────────
def detect_metadata_endpoints(ip: str) -> List[Dict[str, Any]]:
    """Check if an IP has cloud metadata endpoints exposed.

    SSRF attack path: if metadata is reachable, credentials can be stolen.
    """
    endpoints = [
        {"provider": "AWS", "url": "http://169.254.169.254/latest/meta-data/",
         "credential_path": "/latest/meta-data/iam/security-credentials/"},
        {"provider": "GCP", "url": "http://169.254.169.254/computeMetadata/v1/",
         "credential_path": "/computeMetadata/v1/instance/service-accounts/default/token",
         "header_required": "Metadata-Flavor: Google"},
        {"provider": "Azure", "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
         "credential_path": "/metadata/instance/compute/userData",
         "header_required": "Metadata: true"},
        {"provider": "DigitalOcean", "url": "http://169.254.169.254/metadata/v1.json",
         "credential_path": "/metadata/v1.json"},
    ]

    # Metadata is only reachable from within the instance — we can't probe it
    # from outside. But we can note that SSRF vulnerabilities could reach it.
    return [{
        **ep,
        "note": "Metadata endpoint — reachable only via SSRF from within the cloud instance",
        "attack_vector": "SSRF → metadata endpoint → credential theft",
    } for ep in endpoints]


# ── Kubernetes exposure detection ────────────────────────────────
def detect_k8s_exposure(domain: str) -> List[Dict[str, Any]]:
    """Detect exposed Kubernetes API servers and dashboards."""
    k8s_indicators = [
        {"subdomain": "kubernetes", "port": 6443, "type": "api_server",
         "risk": "critical"},
        {"subdomain": "k8s", "port": 6443, "type": "api_server",
         "risk": "critical"},
        {"subdomain": "kubernetes-dashboard", "port": 8443, "type": "dashboard",
         "risk": "high"},
        {"subdomain": "kube", "port": 10250, "type": "kubelet",
         "risk": "high"},
    ]

    exposed = []
    for indicator in k8s_indicators:
        subdomain = f"{indicator['subdomain']}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            exposed.append({
                "subdomain": subdomain,
                "ip": ip,
                "port": indicator["port"],
                "type": indicator["type"],
                "risk": indicator["risk"],
                "finding": f"Exposed K8s {indicator['type']}: {subdomain}:{indicator['port']}",
            })
        except socket.gaierror:
            pass

    return exposed


# ── IAM policy analyzer ──────────────────────────────────────────
def analyze_iam_policy(policy_json: str) -> List[Dict[str, Any]]:
    """Analyze an IAM policy for security issues.

    Detects: wildcard permissions, privilege escalation paths,
    overly permissive cross-account access.
    """
    issues = []
    try:
        policy = json.loads(policy_json)
    except json.JSONDecodeError:
        return [{"issue": "Invalid JSON", "severity": "info"}]

    # Check statements
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        effect = stmt.get("Effect", "Allow")

        # Wildcard action check
        for action in actions:
            if action == "*":
                issues.append({
                    "issue": "Wildcard action (*) in policy",
                    "severity": "critical",
                    "recommendation": "Replace wildcard with specific actions",
                })
            elif action.endswith(":*"):
                issues.append({
                    "issue": f"Service wildcard: {action}",
                    "severity": "high",
                    "recommendation": f"Replace {action} with specific actions",
                })

        # Wildcard resource check
        for resource in resources:
            if resource == "*":
                issues.append({
                    "issue": "Wildcard resource (*) in policy",
                    "severity": "critical",
                    "recommendation": "Restrict resource ARN",
                })

        # Privilege escalation check
        escalatory_actions = [
            "iam:CreatePolicy", "iam:AttachRolePolicy",
            "iam:PutRolePolicy", "iam:CreateRole",
            "iam:PassRole", "sts:AssumeRole",
        ]
        for action in actions:
            if action in escalatory_actions and effect == "Allow":
                issues.append({
                    "issue": f"Privilege escalation possible: {action}",
                    "severity": "high",
                    "recommendation": f"Review if {action} is necessary",
                })

    return issues


# ── Cloud attack path builder ────────────────────────────────────
def build_cloud_attack_path(domain: str) -> Dict[str, Any]:
    """Build a complete cloud attack path for a domain.

    Combines asset discovery, bucket enumeration, K8s detection,
    and metadata endpoint mapping.
    """
    # Discover cloud assets
    assets = discover_cloud_assets(domain)
    s3_buckets = enumerate_s3_buckets(domain)
    k8s_exposed = detect_k8s_exposure(domain)
    metadata_eps = detect_metadata_endpoints("")

    # Build attack paths
    attack_paths = []

    # Path 1: CDN → Origin
    cdn_assets = [a for a in assets if a.asset_type == "cdn"]
    if cdn_assets:
        attack_paths.append({
            "path": "CDN → Origin Server",
            "description": "Bypass CDN to reach origin server directly",
            "technique": "Origin IP discovery",
            "mitre_id": "T1595.003",
            "steps": [
                "Historical DNS records (crt.sh, DNSDumpster)",
                "Direct IP connection bypassing CDN",
                "Host header manipulation",
            ],
            "risk": "medium",
        })

    # Path 2: S3 Bucket → Data Exfil
    existing_buckets = [b for b in s3_buckets if b.get("exists")]
    if existing_buckets:
        attack_paths.append({
            "path": "S3 Bucket → Data Exfiltration",
            "description": "Access misconfigured S3 buckets",
            "technique": "S3 bucket enumeration + access",
            "mitre_id": "T1530",
            "steps": [
                "Enumerate bucket names",
                "Check bucket permissions (list, read)",
                "Download exposed objects",
            ],
            "risk": "high",
            "buckets_found": len(existing_buckets),
        })

    # Path 3: SSRF → Metadata → Credential Theft
    attack_paths.append({
        "path": "SSRF → Cloud Metadata → Credential Theft",
        "description": "Exploit SSRF to access cloud metadata endpoints",
        "technique": "SSRF to 169.254.169.254",
        "mitre_id": "T1552.005",
        "steps": [
            "Find SSRF vulnerability in web application",
            "Access http://169.254.169.254/latest/meta-data/",
            "Extract IAM credentials from metadata",
            "Use credentials for cloud API access",
        ],
        "risk": "critical",
    })

    # Path 4: K8s API → Cluster Compromise
    if k8s_exposed:
        attack_paths.append({
            "path": "K8s API → Cluster Compromise",
            "description": "Access exposed Kubernetes API server",
            "technique": "K8s API abuse",
            "mitre_id": "T1613",
            "steps": [
                "Access K8s API server (if unauthenticated)",
                "Enumerate pods, services, secrets",
                "Deploy malicious pod for persistence",
                "Access host filesystem via privileged pod",
            ],
            "risk": "critical",
        })

    # Path 5: Container Registry → Malicious Image
    attack_paths.append({
        "path": "Container Registry → Malicious Image",
        "description": "Push malicious image to container registry",
        "technique": "Registry credential abuse",
        "mitre_id": "T1525",
        "steps": [
            "Compromise registry credentials",
            "Push backdoored image",
            "Wait for deployment (CI/CD trigger)",
            "Execute code inside cluster",
        ],
        "risk": "high",
    })

    return {
        "domain": domain,
        "cloud_assets": [a.to_dict() for a in assets],
        "s3_buckets": s3_buckets,
        "k8s_exposed": k8s_exposed,
        "metadata_endpoints": metadata_eps,
        "attack_paths": attack_paths,
        "summary": (
            f"Cloud analysis for {domain}: "
            f"{len(assets)} asset(s), "
            f"{len(existing_buckets)} S3 bucket(s), "
            f"{len(k8s_exposed)} K8s exposure(s), "
            f"{len(attack_paths)} attack path(s)."
        ),
    }
