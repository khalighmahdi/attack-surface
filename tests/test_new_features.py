import os
import sys
import unittest

os.environ.setdefault("ATTACK_SURFACE_NO_AUTOTERM", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAttackGraph(unittest.TestCase):
    def test_build_graph_from_scan_data(self):
        from modules.attack_graph import build_graph
        scan = {
            "domain": "victim.example",
            "hosts": [{"host": "victim.example", "ip": "203.0.113.10",
                       "ports": '[{"port":22,"service":"ssh"},{"port":3306,"service":"mysql"}]',
                       "tech": '["nginx"]'}],
            "subdomains": ["victim.example", "admin.victim.example"],
            "findings": [{"host": "victim.example",
                          "title": "**Public Exposure**: SSH open on port 22"}],
            "sections": {"admin_panels": {"victim.example": [
                {"name": "cPanel", "url": "https://victim.example:2083"}]},
                "msf_suggestions": [{"host": "victim.example",
                                     "module": "exploit/unix/ssh/openssh_userenum_timing",
                                     "stage": "exploit"}]},
        }
        g = build_graph(scan)
        self.assertGreater(g["stats"]["nodes"], 3)
        self.assertGreater(g["stats"]["edges"], 2)
        types = {n["type"] for n in g["nodes"]}
        self.assertIn("Subdomain", types)
        self.assertIn("Service", types)
        self.assertIn("Vulnerability", types)
        self.assertIn("AdminPanel", types)

    def test_graph_empty_scan(self):
        from modules.attack_graph import build_graph
        g = build_graph({"domain": "x.com", "hosts": [], "subdomains": [],
                         "findings": [], "sections": {}})
        self.assertGreater(g["stats"]["nodes"], 0)  # at least domain node


class TestCredEngine(unittest.TestCase):
    def test_detect_service(self):
        from modules.cred_engine import detect_service
        ports = [{"port": 22, "service": "ssh", "service_versioned": "ssh — OpenSSH 8.9"},
                 {"port": 3306, "service": "mysql", "service_versioned": "mysql — MariaDB"},
                 {"port": 80, "service": "http", "service_versioned": "http — nginx"}]
        svcs = detect_service("h.example", ports)
        self.assertIn("ssh", svcs)
        self.assertIn("mysql", svcs)
        self.assertNotIn("http-get", svcs)  # plain http without form info

    def test_generate_default_creds(self):
        from modules.cred_engine import generate_commands
        cmds = generate_commands("t.example", ["ftp"], mode="default_creds")
        self.assertGreater(len(cmds), 0)
        self.assertIn("hydra", cmds[0]["cmd"])
        self.assertIn("ftp", cmds[0]["cmd"])
        self.assertFalse(cmds[0]["safe"])

    def test_generate_default_mode(self):
        from modules.cred_engine import generate_commands
        cmds = generate_commands("t.example", ["ssh"], mode="default")
        self.assertEqual(len(cmds), 1)
        self.assertIn("-L", cmds[0]["cmd"])
        self.assertIn("-P", cmds[0]["cmd"])
        self.assertIn("rockyou", cmds[0]["cmd"])

    def test_generate_quick_mode(self):
        from modules.cred_engine import generate_commands
        cmds = generate_commands("t.example", ["ssh"], mode="quick")
        self.assertEqual(len(cmds), 1)
        self.assertIn("john.lst", cmds[0]["cmd"])

    def test_analyze_scan(self):
        from modules.cred_engine import analyze_scan_for_creds
        scan = {"domain": "x.example", "hosts": [
            {"host": "x.example",
             "ports": '[{"port":22,"service":"ssh"},{"port":21,"service":"ftp"}]'}]}
        sugs = analyze_scan_for_creds(scan)
        svcs = {s["service"] for s in sugs}
        self.assertIn("ssh", svcs)
        self.assertIn("ftp", svcs)


class TestOriginHunter(unittest.TestCase):
    def test_detect_cdn_integration(self):
        from modules.origin_hunter import _is_cdn_ip
        self.assertEqual(_is_cdn_ip("104.16.1.1"), "Cloudflare")
        self.assertIsNone(_is_cdn_ip("203.0.113.10"))

    def test_correlate_subdomain_ips(self):
        from modules.origin_hunter import correlate_subdomain_ips
        sub_ips = {
            "a.example": ["203.0.113.10"],
            "b.example": ["203.0.113.10"],
            "c.example": ["203.0.113.10"],
            "cdn.example": ["104.16.1.1"],  # Cloudflare — excluded
        }
        cands = correlate_subdomain_ips("example.com", sub_ips)
        ips = [c["ip"] for c in cands]
        self.assertIn("203.0.113.10", ips)
        self.assertNotIn("104.16.1.1", ips)

    def test_hunt_origin_no_cdn(self):
        from modules.origin_hunter import hunt_origin
        # non-CDN target: should return few/no CDN-origin candidates
        result = hunt_origin("example.com", {"example.com": ["93.184.216.34"]})
        self.assertIn("candidates", result)
        self.assertIn("methods_used", result)


class TestDashboardNewTabs(unittest.TestCase):
    def test_html_has_new_tabs(self):
        from modules.dashboard import _HTML
        self.assertIn("tab-graph", _HTML)
        self.assertIn("tab-creds", _HTML)
        self.assertIn("tab-origin", _HTML)
        self.assertIn("graphBuild", _HTML)
        self.assertIn("credsAnalyze", _HTML)
        self.assertIn("originHunt", _HTML)
        self.assertIn("graph-canvas", _HTML)


if __name__ == "__main__":
    unittest.main()
