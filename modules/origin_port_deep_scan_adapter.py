def origin_port_scan_to_events(scan_result: dict) -> list:
    events = []

    origin_ip = scan_result.get("origin_ip")

    for port in scan_result.get("open_ports", []):
        events.append({
            "type": "origin_open_management_port",
            "origin_ip": origin_ip,
            "port": port.get("port"),
            "service": port.get("service"),
        })

    return events
