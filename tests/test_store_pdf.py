import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.pdf_report import build_pdf  # noqa: E402
import db_store  # noqa: E402


class TestPDF(unittest.TestCase):
    def test_build_pdf_writes_file(self):
        results = {
            "risk": {"overall_score": 42, "overall_level": "High"},
            "findings": {
                "example.com": [
                    {"title": "Missing HSTS", "severity": "medium",
                     "detail": "HSTS header not set. Recommendation: enable HSTS."}
                ]
            },
            "hosts": [{"host": "example.com", "ip": "1.2.3.4", "protocol": "https"}],
            "subdomains": ["example.com", "www.example.com"],
        }
        out = "/tmp/test_report.pdf"
        build_pdf(results, "example.com", out)
        self.assertTrue(os.path.exists(out))
        head = open(out, "rb").read(5)
        self.assertEqual(head, b"%PDF-")
        os.unlink(out)


class TestDB(unittest.TestCase):
    def _clean(self):
        if os.path.exists("/tmp/as_test.db"):
            os.unlink("/tmp/as_test.db")

    def test_save_list_compare(self):
        self._clean()
        dbp = "/tmp/as_test.db"
        r1 = {
            "risk": {"overall_score": 30, "overall_level": "Medium"},
            "findings": {"h1.com": [{"title": "open port", "severity": "medium"}]},
            "hosts": [{"host": "h1.com", "ip": "1.1.1.1"}],
            "subdomains": ["a.com", "b.com"],
        }
        r2 = {
            "risk": {"overall_score": 55, "overall_level": "High"},
            "findings": {"h1.com": [{"title": "open port", "severity": "medium"},
                                    {"title": "new vuln", "severity": "high"}]},
            "hosts": [{"host": "h1.com", "ip": "1.1.1.1"}],
            "subdomains": ["b.com", "c.com"],
        }
        id1 = db_store.save_scan(r1, "test.com", "0.11.0", dbp)
        id2 = db_store.save_scan(r2, "test.com", "0.11.0", dbp)
        scans = db_store.list_scans(dbp)
        self.assertEqual(len(scans), 2)
        cmp = db_store.compare(id1, id2, dbp)
        self.assertEqual(cmp["new_subdomains"], ["c.com"])
        self.assertEqual(cmp["gone_subdomains"], ["a.com"])
        self.assertEqual(cmp["new_findings"], [("h1.com", "new vuln")])
        self.assertEqual(cmp["score_delta"], 25)

    def tearDown(self):
        self._clean()


if __name__ == "__main__":
    unittest.main()
