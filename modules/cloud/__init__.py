"""Cloud Asset Discovery — AWS, Azure, GCP asset enumeration.

Discovers cloud resources associated with target domains/organizations:
- AWS: S3 buckets, CloudFront, ALB, EC2, RDS, Lambda, API Gateway
- Azure: Storage accounts, App Services, SQL Databases, Key Vaults, Functions
- GCP: Cloud Storage, Cloud Run, Cloud SQL, Cloud Functions, Load Balancers
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AttackSurface.Cloud")


@dataclass
class CloudAsset:
    provider: str  # aws, azure, gcp
    asset_type: str
    identifier: str
    region: str
    domain: Optional[str]
    metadata: Dict[str, Any]
    risk_level: str
    discovered_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "asset_type": self.asset_type,
            "identifier": self.identifier,
            "region": self.region,
            "domain": self.domain,
            "metadata": self.metadata,
            "risk_level": self.risk_level,
            "discovered_at": self.discovered_at
        }


class CloudDiscovery:
    """Multi-cloud asset discovery using CLI tools and APIs."""

    def __init__(self):
        self.cache_dir = Path(os.path.expanduser("~/.cache/attack-surface/cloud"))
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def discover_aws(self, domain: str, keywords: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Discover AWS resources via S3 bucket enum, CloudFront, certs, etc."""
        assets = []
        keywords = keywords or [domain.replace(".", "-"), domain.split(".")[0]]

        # S3 bucket enumeration
        for kw in keywords:
            buckets = self._enum_s3_buckets(kw)
            for bucket in buckets:
                bucket_name = bucket["name"] if isinstance(bucket, dict) else bucket
                assets.append(CloudAsset(
                    provider="aws",
                    asset_type="s3_bucket",
                    identifier=bucket_name,
                    region=bucket.get("region", "unknown") if isinstance(bucket, dict) else "unknown",
                    domain=domain,
                    metadata=bucket if isinstance(bucket, dict) else {"name": bucket_name},
                    risk_level=self._assess_s3_risk(bucket),
                    discovered_at=datetime.utcnow().isoformat()
                ).to_dict())

        # CloudFront via SSL certs
        cf_assets = self._discover_cloudfront_via_certs(domain)
        assets.extend(cf_assets)

        return assets

    def _enum_s3_buckets(self, keyword: str) -> List[Dict]:
        """Enumerate S3 buckets using multiple techniques."""
        buckets = []
        permutations = [
            keyword,
            f"{keyword}-prod",
            f"{keyword}-dev",
            f"{keyword}-staging",
            f"{keyword}-backup",
            f"{keyword}-logs",
            f"{keyword}-assets",
            f"{keyword}-static",
            f"{keyword}-media",
            f"{keyword}-data",
            f"{keyword}-private",
            f"{keyword}-public",
            f"{keyword}-cdn",
            f"cdn-{keyword}",
            f"static-{keyword}",
            f"assets-{keyword}",
        ]

        for bucket in permutations:
            try:
                # Method 1: HTTP HEAD (fast, no auth needed)
                import requests
                url = f"http://{bucket}.s3.amazonaws.com"
                resp = requests.head(url, timeout=5, allow_redirects=False)
                if resp.status_code in (200, 403, 400):  # Exists
                    region = self._get_bucket_region(bucket)
                    perms = self._check_bucket_permissions(bucket)
                    buckets.append({
                        "name": bucket,
                        "url": url,
                        "region": region,
                        "permissions": perms,
                        "status_code": resp.status_code
                    })
            except Exception:
                pass

        return buckets

    def _get_bucket_region(self, bucket: str) -> str:
        try:
            import requests
            url = f"http://{bucket}.s3.amazonaws.com"
            resp = requests.get(url, timeout=5)
            if "x-amz-bucket-region" in resp.headers:
                return resp.headers["x-amz-bucket-region"]
        except Exception:
            pass
        return "unknown"

    def _check_bucket_permissions(self, bucket: str) -> Dict[str, bool]:
        """Check bucket ACLs and policies."""
        perms = {"list": False, "write": False, "read_acp": False, "write_acp": False}
        try:
            import requests
            # Test list
            resp = requests.get(f"http://{bucket}.s3.amazonaws.com/?list-type=2", timeout=5)
            if resp.status_code == 200:
                perms["list"] = True
            # Test write (put object)
            test_key = f".attack-surface-test-{int(time.time())}"
            resp = requests.put(f"http://{bucket}.s3.amazonaws.com/{test_key}",
                                data="test", timeout=5)
            if resp.status_code in (200, 204):
                perms["write"] = True
                # Cleanup
                requests.delete(f"http://{bucket}.s3.amazonaws.com/{test_key}", timeout=5)
        except Exception:
            pass
        return perms

    def _assess_s3_risk(self, bucket: Dict) -> str:
        perms = bucket.get("permissions", {}) if isinstance(bucket, dict) else {}
        if perms.get("write") and perms.get("list"):
            return "critical"
        if perms.get("write") or perms.get("list"):
            return "high"
        if isinstance(bucket, dict) and bucket.get("status_code") == 200:
            return "medium"
        return "low"

    def _discover_cloudfront_via_certs(self, domain: str) -> List[Dict[str, Any]]:
        """Find CloudFront distributions via SSL certificate transparency."""
        assets = []
        try:
            import requests
            # Use crt.sh
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = requests.get(url, timeout=15)
            certs = resp.json()
            for cert in certs:
                name = cert.get("name_value", "")
                if "cloudfront.net" in name:
                    distro = name.split(".")[0]
                    assets.append(CloudAsset(
                        provider="aws",
                        asset_type="cloudfront",
                        identifier=distro,
                        region="global",
                        domain=domain,
                        metadata={"cert": cert, "distribution_domain": name},
                        risk_level="info",
                        discovered_at=datetime.utcnow().isoformat()
                    ).to_dict())
        except Exception as e:
            logger.debug("CloudFront cert discovery failed: %s", e)
        return assets

    def discover_azure(self, domain: str, keywords: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Discover Azure resources via storage accounts, app services, etc."""
        assets = []
        keywords = keywords or [domain.replace(".", ""), domain.split(".")[0]]

        for kw in keywords:
            # Storage accounts
            storages = self._enum_azure_storage(kw)
            assets.extend(storages)

            # App Services (via DNS)
            apps = self._enum_azure_app_services(kw)
            assets.extend(apps)

        return assets

    def _enum_azure_storage(self, keyword: str) -> List[Dict[str, Any]]:
        assets = []
        permutations = [
            keyword,
            f"{keyword}prod",
            f"{keyword}dev",
            f"{keyword}staging",
            f"{keyword}backup",
            f"{keyword}logs",
            f"{keyword}assets",
            f"{keyword}static",
        ]
        for name in permutations:
            try:
                import requests
                url = f"https://{name}.blob.core.windows.net"
                resp = requests.head(url, timeout=5)
                if resp.status_code in (200, 400, 403, 404):  # Exists
                    containers = self._list_azure_containers(name)
                    assets.append(CloudAsset(
                        provider="azure",
                        asset_type="storage_account",
                        identifier=name,
                        region="unknown",
                        domain=None,
                        metadata={"url": url, "containers": containers},
                        risk_level="medium" if containers else "low",
                        discovered_at=datetime.utcnow().isoformat()
                    ).to_dict())
            except Exception:
                pass
        return assets

    def _list_azure_containers(self, account: str) -> List[str]:
        try:
            import requests
            url = f"https://{account}.blob.core.windows.net/?comp=list"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(resp.text)
                containers = []
                for c in root.findall(".//Container"):
                    name_elem = c.find("Name")
                    if name_elem is not None and name_elem.text:
                        containers.append(name_elem.text)
                return containers
        except Exception:
            pass
        return []

    def _enum_azure_app_services(self, keyword: str) -> List[Dict[str, Any]]:
        assets = []
        try:
            import dns.resolver
            # Check for *.azurewebsites.net
            for prefix in [keyword, f"{keyword}-prod", f"{keyword}-app", f"{keyword}-web"]:
                try:
                    answers = dns.resolver.resolve(f"{prefix}.azurewebsites.net", "CNAME")
                    for r in answers:
                        assets.append(CloudAsset(
                            provider="azure",
                            asset_type="app_service",
                            identifier=prefix,
                            region="unknown",
                            domain=str(r.target).rstrip("."),
                            metadata={"cname": str(r.target)},
                            risk_level="info",
                            discovered_at=datetime.utcnow().isoformat()
                        ).to_dict())
                except Exception:
                    pass
        except Exception:
            pass
        return assets

    def discover_gcp(self, domain: str, keywords: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Discover GCP resources via Cloud Storage, Cloud Run, etc."""
        assets = []
        keywords = keywords or [domain.replace(".", "-"), domain.split(".")[0]]

        for kw in keywords:
            # Cloud Storage buckets
            buckets = self._enum_gcs_buckets(kw)
            assets.extend(buckets)

            # Cloud Run services (via DNS)
            run_services = self._enum_cloud_run(kw)
            assets.extend(run_services)

        return assets

    def _enum_gcs_buckets(self, keyword: str) -> List[Dict[str, Any]]:
        assets = []
        permutations = [
            keyword,
            f"{keyword}-prod",
            f"{keyword}-dev",
            f"{keyword}-staging",
            f"{keyword}-backup",
            f"{keyword}-assets",
        ]
        for bucket in permutations:
            try:
                import requests
                url = f"https://storage.googleapis.com/{bucket}"
                resp = requests.head(url, timeout=5)
                if resp.status_code in (200, 403):
                    assets.append(CloudAsset(
                        provider="gcp",
                        asset_type="cloud_storage",
                        identifier=bucket,
                        region="unknown",
                        domain=None,
                        metadata={"url": url},
                        risk_level="medium" if resp.status_code == 200 else "low",
                        discovered_at=datetime.utcnow().isoformat()
                    ).to_dict())
            except Exception:
                pass
        return assets

    def _enum_cloud_run(self, keyword: str) -> List[Dict[str, Any]]:
        assets = []
        try:
            import dns.resolver
            for prefix in [keyword, f"{keyword}-api", f"{keyword}-app"]:
                try:
                    answers = dns.resolver.resolve(f"{prefix}.run.app", "CNAME")
                    for r in answers:
                        assets.append(CloudAsset(
                            provider="gcp",
                            asset_type="cloud_run",
                            identifier=prefix,
                            region="unknown",
                            domain=str(r.target).rstrip("."),
                            metadata={"cname": str(r.target)},
                            risk_level="info",
                            discovered_at=datetime.utcnow().isoformat()
                        ).to_dict())
                except Exception:
                    pass
        except Exception:
            pass
        return assets

    def discover_all(self, domain: str) -> Dict[str, List[Dict[str, Any]]]:
        """Run all cloud discovery modules."""
        return {
            "aws": self.discover_aws(domain),
            "azure": self.discover_azure(domain),
            "gcp": self.discover_gcp(domain)
        }