import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.vuln_intel import enrich_cve
from modules.html_report import build_html_report, _sev_of


class TestIntel(unittest.TestCase):
    def test_kev_dominates(self):
        e = enrich_cve("CVE-2021-44228", 10.0, {"CVE-2021-44228": {"dateAdded": "2021-12-10"}})
        self.assertTrue(e["kev"])
        self.assertGreaterEqual(e["contextual_risk"], 90.0)

    def test_non_kev_scales_by_epss(self):
        # no network: epss None → risk == cvss
        e = enrich_cve("CVE-2099-0001", 8.0, {})
        self.assertFalse(e["kev"])
        self.assertEqual(e["contextual_risk"], 8.0)
        self.assertIn("exploitdb", e)


class TestHTML(unittest.TestCase):
    def test_build(self):
        results = {
            "risk": {"overall_score": 100, "overall_level": "Critical"},
            "findings": {"h1.com": [
                {"title": "DATABASE_PORT_EXPOSED (critical)"},
                "Missing HSTS header (medium)"]},
            "hosts": [{"host": "h1.com", "ip": "1.1.1.1"}],
            "subdomains": ["a.com", "b.com"],
        }
        out = build_html_report(results, "test.com", "/tmp/test_rep.html")
        html = open(out).read()
        self.assertIn("Executive Summary", html)
        self.assertIn("KEV", html)
        self.assertIn("Remediation", html)
        self.assertIn("DATABASE_PORT_EXPOSED", html)
        os.unlink(out)

    def test_sev_detection(self):
        self.assertEqual(_sev_of("DATABASE_PORT_EXPOSED (critical)"), "critical")
        self.assertEqual(_sev_of("Missing HSTS header (medium)"), "medium")
        # "note" keyword → low band (acceptable heuristic default)
        self.assertIn(_sev_of("random note"), ("low", "info"))


if __name__ == "__main__":
    unittest.main()
