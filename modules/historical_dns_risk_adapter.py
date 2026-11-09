def historical_findings_to_events(scan_result):
    """
    Internal adapter:
    Converts historical DNS findings into risk events.
    Supports both dict and list outputs.
    """
    events = []

    # ✅ Normalize input type
    if isinstance(scan_result, list):
        findings = scan_result
    elif isinstance(scan_result, dict):
        findings = scan_result.get("findings", [])
    else:
        return events

    for item in findings:
        if not isinstance(item, dict):
            continue

        if item.get("origin_candidate") is True:
            events.append({
                "type": "origin_ip_leak_historical",
                "severity": "critical",
                "confidence": "high",
                "asset": item.get("subdomain"),
                "ip": item.get("ip"),
                "vector": "historical_dns"
            })

    return events


def historical_dns_to_events(domain: str, scan_result):
    """
    ✅ Public API expected by attack_surface.py

    domain: kept for future context / reporting
    scan_result: output of historical DNS discovery
    """
    return historical_findings_to_events(scan_result)

