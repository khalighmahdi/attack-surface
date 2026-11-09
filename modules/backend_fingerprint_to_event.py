def backend_fingerprint_to_event(fp_result: dict):
    if not fp_result:
        return None

    http = fp_result.get("http", {})
    headers = http.get("headers", {})

    if (
        http.get("status_code") == 200
        and headers.get("Server") == "ZarinPal"
    ):
        return {
            "type": "ORIGIN_BACKEND_DIRECT_ACCESS",
            "host": fp_result.get("host"),
            "origin_ip": fp_result.get("origin_ip"),
            "severity": "critical",
            "evidence": {
                "server": headers.get("Server"),
                "tls": fp_result.get("tls"),
                "body_hash": http.get("body_hash"),
            },
        }

    return None


def backend_fingerprint_to_events(scan_result: dict):
    """
    Public API expected by pipeline
    """
    event = backend_fingerprint_to_event(scan_result)
    return [event] if event else []
