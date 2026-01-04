# modules/alive.py
import requests
import logging

logger = logging.getLogger("AttackSurface")

def check_alive(hosts: list) -> list:
    """
    Checks if a list of hosts (subdomains) are alive and accessible via HTTP/HTTPS.
    """
    alive_hosts = []
    
    # We will prioritize HTTPS check
    schemes = ["https://", "http://"]

    for host in hosts:
        for scheme in schemes:
            url = f"{scheme}{host}"
            try:
                # Use a short timeout and allow redirects
                response = requests.get(
                    url, timeout=5, allow_redirects=True, verify=False
                )
                
                # Check for standard success codes
                if 200 <= response.status_code < 400:
                    # Append the host (not the URL) and break to process next host
                    alive_hosts.append(host)
                    logger.debug(f"{host} is alive via {scheme}")
                    break 
            except requests.exceptions.RequestException:
                # This host is not alive with the current scheme
                continue
        
    return list(set(alive_hosts))

