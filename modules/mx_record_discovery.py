import dns.resolver
import dns.name


def discover_mx_records(domain: str) -> dict:
    results = {
        "domain": domain,
        "mx_records": [],
        "error": None
    }

    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.timeout = 5
        resolver.lifetime = 5

        qname = dns.name.from_text(domain)
        answers = resolver.resolve(qname, "MX")

        for rdata in answers:
            results["mx_records"].append({
                "priority": rdata.preference,
                "host": str(rdata.exchange).rstrip(".")
            })

    except Exception as e:
        results["error"] = str(e)

    return results

