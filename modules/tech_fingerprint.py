import logging
import requests

try:
    from core.stream import ndjson_emit
except Exception:
    ndjson_emit = None

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s - %(message)s"
)


def fingerprint_technologies(alive_hosts: list) -> dict:
    """
    Performs basic technology fingerprinting for alive hosts.
    Returns:
        {
            domain: {
                url,
                status_code,
                technologies: []
            }
        }
    """

    tech_results = {}
    logging.info("Starting technology fingerprinting for %d hosts...", len(alive_hosts))

    for host_info in alive_hosts:
        domain = host_info.get("domain")
        ip = host_info.get("ip")

        target_url = domain
        if not domain.startswith(("http://", "https://")):
            target_url = f"https://{domain}"

        detected_techs = []

        try:
            # Respect the global rate limiter
            try:
                from core.rate_limiter import get_limiter
                get_limiter().wait()
            except Exception:
                pass
            response = requests.get(
                target_url,
                timeout=5,
                allow_redirects=True
            )

            body = response.text.lower()
            server = response.headers.get("server", "").lower()

            # -------------------------
            # Basic fingerprinting
            # -------------------------
            if "wordpress" in body:
                detected_techs.append("WordPress")

            if "nginx" in server:
                detected_techs.append("Nginx")

            if "apache" in server:
                detected_techs.append("Apache")

            if "<!doctype html>" in body or "<html" in body:
                detected_techs.append("HTML")

            # -------------------------
            # JS Frameworks (simple)
            # -------------------------
            if "vue.js" in body or "nuxt" in body:
                detected_techs.append("Vue.js / Nuxt.js")

            if "react" in body:
                detected_techs.append("React")

            if "angular" in body:
                detected_techs.append("Angular")

            # -------------------------
            # X-Powered-By
            # -------------------------
            powered_by = response.headers.get("x-powered-by", "").lower()
            if "php" in powered_by:
                detected_techs.append("PHP")
            elif "asp.net" in powered_by:
                detected_techs.append("ASP.NET")

            # -------------------------
            # Cookies
            # -------------------------
            cookies = response.headers.get("set-cookie", "").lower()
            if "wordpress" in cookies:
                detected_techs.append("WordPress Cookie")

            if "jsessionid" in cookies:
                detected_techs.append("Java/JSP Session")

            detected_techs = sorted(set(detected_techs))

            tech_results[domain] = {
                "url": response.url,
                "status_code": response.status_code,
                "technologies": detected_techs
            }

            # -------------------------
            # NDJSON event
            # -------------------------
            if ndjson_emit:
                ndjson_emit({
                    "type": "technology_fingerprint",
                    "domain": domain,
                    "ip": ip,
                    "url": response.url,
                    "status_code": response.status_code,
                    "technologies": detected_techs
                })

            logging.debug(
                "Fingerprinted %s → %s",
                domain,
                ", ".join(detected_techs) if detected_techs else "none"
            )

        except requests.RequestException as e:
            logging.warning("Could not fingerprint %s: %s", domain, e)
            tech_results[domain] = {
                "error": str(e),
                "technologies": []
            }

            if ndjson_emit:
                ndjson_emit({
                    "type": "technology_fingerprint",
                    "domain": domain,
                    "ip": ip,
                    "error": str(e)
                })

        except Exception as e:
            logging.error("Unexpected error during fingerprinting %s: %s", domain, e)
            tech_results[domain] = {
                "error": str(e),
                "technologies": []
            }

            if ndjson_emit:
                ndjson_emit({
                    "type": "technology_fingerprint",
                    "domain": domain,
                    "ip": ip,
                    "error": str(e)
                })

    logging.info("Technology fingerprinting completed.")
    return tech_results

