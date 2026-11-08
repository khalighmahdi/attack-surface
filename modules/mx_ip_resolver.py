import dns.resolver
import dns.name


def resolve_mx_ips(mx_records: list) -> dict:
    results = {
        "ips": [],
        "error": None
    }

    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.timeout = 5
        resolver.lifetime = 5

        for mx in mx_records:
            host = mx.get("host")
            if not host:
                continue

            qname = dns.name.from_text(host)

            # A records
            try:
                answers = resolver.resolve(qname, "A")
                for rdata in answers:
                    results["ips"].append({
                        "host": host,
                        "type": "A",
                        "ip": rdata.address
                    })
            except Exception:
                pass

            # AAAA records
            try:
                answers = resolver.resolve(qname, "AAAA")
                for rdata in answers:
                    results["ips"].append({
                        "host": host,
                        "type": "AAAA",
                        "ip": rdata.address
                    })
            except Exception:
                pass

    except Exception as e:
        results["error"] = str(e)

    return results
