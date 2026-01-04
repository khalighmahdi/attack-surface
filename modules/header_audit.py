# modules/header_audit.py
import logging

logger = logging.getLogger("AttackSurface")

REQUIRED_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy"
]

INFO_LEAK_HEADERS = [
    "server", 
    "x-powered-by",
    "x-aspnet-version"
]

def scan_headers(headers: dict) -> dict:
    """
    Audits security headers for missing components and information leaks.
    """
    results = {
        "missing": [],
        "info_leaks": []
    }

    # 1. Check for Missing Security Headers
    for header in REQUIRED_SECURITY_HEADERS:
        if header not in headers:
            results["missing"].append(f"Missing Security Header: {header}")

    # 2. Check for Information Leaks
    for header in INFO_LEAK_HEADERS:
        if header in headers:
            results["info_leaks"].append(
                f"Information Leak (Header: {header}, Value: {headers[header]})"
            )
            
    logger.debug(f"Header audit results: {results}")
    return results

