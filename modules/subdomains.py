# modules/subdomains.py
import logging
import requests
import json

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def enumerate_subdomains(domain: str) -> list:
    """
    Performs basic subdomain enumeration using a few public sources.
    This is a placeholder for a more comprehensive subdomain enumeration module.
    """
    subdomains = {domain} # Always include the main domain
    logging.info("Starting subdomain enumeration for %s", domain)

    # Example 1: Use cert.sh (certificate transparency logs)
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = json.loads(response.text)
            for entry in data:
                name_value = entry.get('name_value')
                if name_value:
                    # Clean up entries like "*.sub.domain.com" to "sub.domain.com"
                    cleaned_name = name_value.replace('*.', '')
                    if cleaned_name.endswith(domain) and cleaned_name not in subdomains:
                        subdomains.add(cleaned_name)
        logging.debug("Found %d subdomains from crt.sh", len(subdomains))
    except requests.exceptions.RequestException as e:
        logging.warning("Error fetching subdomains from crt.sh: %s", e)
    except json.JSONDecodeError as e:
        logging.warning("Error decoding JSON from crt.sh: %s", e)

    # Example 2: Add common subdomains (bruteforce-like)
    try:
        from core.wordlists import load_prefixes
        common_prefixes = load_prefixes()
        logging.info("using wordlist prefixes: %d", len(common_prefixes))
    except Exception:
        common_prefixes = ["www", "mail", "ftp", "dev", "test", "admin", "blog", "api"]
    for prefix in common_prefixes:
        subdomains.add(f"{prefix}.{domain}")

    # Optional Kali-tool enrichment (amass/subfinder) - fail-soft
    try:
        from modules.external_tools import enrich_subdomains
        enrich_subdomains(domain, subdomains)
    except Exception as e:
        logging.debug("external enrichment skipped: %s", e)

    logging.info("Subdomain enumeration completed. Found %d unique subdomains.", len(subdomains))
    return sorted(list(subdomains))

# Example Usage (for testing)
if __name__ == "__main__":
    test_domain = "google.com"
    results = enumerate_subdomains(test_domain)
    print(f"Subdomains for {test_domain}:")
    for s in results:
        print(s)

