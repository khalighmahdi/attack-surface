# modules/headers.py
import requests
import logging

logger = logging.getLogger("AttackSurface")

def fetch_headers(host: str) -> dict:
    """
    Fetches HTTP/HTTPS headers for a given host.
    Attempts HTTPS first, then falls back to HTTP.
    """
    
    schemes = ["https://", "http://"]
    
    for scheme in schemes:
        url = f"{scheme}{host}"
        try:
            # Setting up session and settings for security scans
            response = requests.get(
                url, 
                timeout=10, 
                allow_redirects=True, 
                verify=False, # Ignore SSL certificate warnings for self-signed or internal certs
                headers={'User-Agent': 'AttackSurfaceScanner/2.0'}
            )
            
            # Return normalized headers (lowercase keys)
            return {k.lower(): v for k, v in response.headers.items()}

        except requests.exceptions.RequestException as e:
            logger.debug(f"Failed to fetch {url}: {e}")
            continue
            
    # If both attempts fail
    logger.warning(f"Could not fetch headers for {host} after trying both HTTP and HTTPS.")
    return {}

