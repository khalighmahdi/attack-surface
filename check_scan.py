import db_store
scan = db_store.get_scan(25)
print("Cloud assets:", scan.get("cloud_assets"))
print("API endpoints:", scan.get("api_endpoints"))
print("MITRE coverage:", scan.get("mitre_coverage"))
print("MITRE layer:", "present" if scan.get("mitre_layer") else "none")
print("Sections:", list(scan.get("sections", {}).keys()))