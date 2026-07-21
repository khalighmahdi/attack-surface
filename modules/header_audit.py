# modules/header_audit.py

import logging
import requests
from typing import List, Dict

try:
    # NDJSON stream is optional (backward compatible)
    from core.stream import ndjson_emit
except Exception:
    ndjson_emit = None


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s - %(message)s"
)


def audit_headers(alive_hosts: List[dict]) -> Dict[str, dict]:
    """
    Audits security headers for alive hosts.
    Returns a structured dictionary for JSON / HTML reporting.
    """

    header_results = {}
    logging.info("Starting security header audit for %d hosts...", len(alive_hosts))

    for host_info in alive_hosts:
        domain = host_info.get("domain")
        protocol = host_info.get("protocol", "http")
        target_url = f"{protocol}://{domain}"

        try:
            # Respect the global rate limiter
            try:
                from core.rate_limiter import get_limiter
                get_limiter().acquire()
            except Exception:
                pass
            response = requests.get(
                target_url,
                timeout=5,
                allow_redirects=True
            )

            headers = response.headers

            security_headers = {
                "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
                "Content-Security-Policy": headers.get("Content-Security-Policy"),
                "X-Frame-Options": headers.get("X-Frame-Options"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
                "Referrer-Policy": headers.get("Referrer-Policy"),
                "Permissions-Policy": headers.get("Permissions-Policy"),
                "Expect-CT": headers.get("Expect-CT"),
                "X-XSS-Protection": headers.get("X-XSS-Protection"),
            }

            issues = []

            if not security_headers.get("Strict-Transport-Security"):
                issues.append("Missing HSTS header")

            if not security_headers.get("Content-Security-Policy"):
                issues.append("Missing Content-Security-Policy header")

            if security_headers.get("X-Frame-Options") not in ("DENY", "SAMEORIGIN"):
                issues.append("X-Frame-Options not set to DENY or SAMEORIGIN")

            if security_headers.get("X-Content-Type-Options") != "nosniff":
                issues.append("X-Content-Type-Options not set to nosniff")

            if not security_headers.get("Referrer-Policy"):
                issues.append("Missing Referrer-Policy header")

            if security_headers.get("X-XSS-Protection") != "1; mode=block":
                issues.append("X-XSS-Protection not set to '1; mode=block'")

            # ✅ NDJSON streaming (per host)
            if ndjson_emit:
                ndjson_emit({
                    "type": "header_audit",
                    "domain": domain,
                    "url": response.url,
                    "status_code": response.status_code,
                    "issues": issues,
                    "issue_count": len(issues)
                })

            header_results[domain] = {
                "url": response.url,
                "status_code": response.status_code,
                "all_headers": dict(headers),
                "security_headers": security_headers,
                "issues": issues
            }

            logging.debug(
                "Audited headers for %s: %d issues found",
                domain,
                len(issues)
            )

        except requests.exceptions.RequestException as e:
            logging.warning("Could not audit headers for %s: %s", domain, e)

            if ndjson_emit:
                ndjson_emit({
                    "type": "header_audit_error",
                    "domain": domain,
                    "url": target_url,
                    "error": str(e)
                })

            header_results[domain] = {
                "error": str(e),
                "all_headers": {},
                "security_headers": {},
                "issues": []
            }

        except Exception as e:
            logging.error(
                "Unexpected error during header audit for %s: %s",
                domain,
                e
            )

            if ndjson_emit:
                ndjson_emit({
                    "type": "header_audit_exception",
                    "domain": domain,
                    "url": target_url,
                    "error": str(e)
                })

            header_results[domain] = {
                "error": str(e),
                "all_headers": {},
                "security_headers": {},
                "issues": []
            }

    logging.info("Security header audit completed.")
    return header_results


# Example standalone test
if __name__ == "__main__":
    import json

    test_hosts = [
        {"domain": "google.com", "ip": "142.250.190.174", "protocol": "https"},
        {"domain": "example.com", "ip": "93.184.216.34", "protocol": "http"},
    ]

    results = audit_headers(test_hosts)
    print(json.dumps(results, indent=2))

