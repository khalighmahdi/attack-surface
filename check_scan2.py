import db_store
# Get the latest scan
scans = db_store.list_scans()
if scans:
    latest = scans[0]
    scan = db_store.get_scan(latest["id"])
    print(f"Scan ID: {latest['id']}")
    print("Cloud assets:", list(scan.get("cloud_assets", {}).keys()) if scan.get("cloud_assets") else "None")
    print("API endpoints:", len(scan.get("api_endpoints", [])))
    print("MITRE coverage:", scan.get("mitre_coverage"))
    print("MITRE layer:", "present" if scan.get("mitre_layer") else "none")
    print("Sections:", list(scan.get("sections", {}).keys()))
    print("SBOM:", scan.get("sbom_analysis"))
    print("Auth:", scan.get("auth_session"))
else:
    print("No scans found")