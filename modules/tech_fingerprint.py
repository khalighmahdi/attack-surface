# modules/tech_fingerprint.py
import logging

logger = logging.getLogger("AttackSurface")

# Simple, non-exhaustive mapping based on common headers
KNOWN_TECH_MAP = {
    "server": {
        "nginx": "NGINX Web Server",
        "apache": "Apache HTTP Server",
        "iis": "Microsoft IIS",
        "cloudflare": "Cloudflare CDN/WAF",
    },
    "x-powered-by": {
        "php": "PHP Language",
        "asp.net": "ASP.NET Framework",
        "express": "Node.js/Express Framework",
    },
    "set-cookie": {
        "laravel_session": "Laravel Framework",
        "wordpress_": "WordPress CMS",
        "jsessionid": "Java/JSP Application",
    }
}

def fingerprint_from_headers(headers: dict) -> list:
    """
    Identifies technologies based on HTTP response headers.
    """
    detected_tech = set()
    
    for header_name, mappings in KNOWN_TECH_MAP.items():
        header_value = headers.get(header_name)
        if header_value:
            for keyword, tech_name in mappings.items():
                if keyword in header_value.lower():
                    detected_tech.add(tech_name)
                    
    logger.debug(f"Technologies detected: {list(detected_tech)}")
    return list(detected_tech)

