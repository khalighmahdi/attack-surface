"""Tests for the ops report adapter (modules/ops_report).

modules/reporting already knew how to render a report; this adapter turns
what the scanner and Knull actually produced into that shape, and adds the
two sections only we can write: the coverage verdict and the agent's
session summary.
"""

import os
import tempfile
import unittest

import db_store
import modules.ops_report as ops


class TestSeverityAndCategory(unittest.TestCase):
    def test_severity_is_normalised(self):
        for raw, want in [("HIGH", "high"), ("Critical", "critical"),
                          ("? ", "info"), (None, "info"), ("bogus", "info")]:
            self.assertEqual(ops._severity(raw), want)

    def test_category_from_title(self):
        cases = [
            ("**Public Exposure**: FTP is open on port 21", "", "Service Exposure"),
            ("**Missing Security Headers**: HSTS absent", "", "Missing Security Header"),
            ("CVE-2021-41773 in Apache", "", "Known Vulnerability"),
            ("**Scan Coverage**: UNREACHABLE", "", "Scan Coverage"),
            ("The host presents a **HIGH** risk score", "", "Risk Summary"),
            ("anything else", "Custom Thing", "Custom Thing"),
        ]
        for title, cat, want in cases:
            self.assertEqual(ops._category_of(title, cat), want, title)


class TestFindingsOf(unittest.TestCase):
    def test_scan_findings_are_shaped_and_cleaned(self):
        scan = {"domain": "h.example", "findings": [
            {"host": "h.example", "title": "**Public Exposure**: FTP open",
             "severity": "HIGH", "category": "exposure",
             "detail": '"**Public Exposure**: FTP open"'}]}
        out = ops._findings_of(scan)
        f = out["h.example"][0]
        self.assertEqual(f["title"], "Public Exposure: FTP open")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["evidence"], "Public Exposure: FTP open")
        self.assertNotIn("**", f["description"])

    def test_cves_are_added_with_their_match_type(self):
        scan = {"domain": "h.example", "findings": [], "sections": {"cves": {
            "h.example": [
                {"tech": "Apache 2.4.49", "match": "cpe_exact",
                 "cves": [{"id": "CVE-2021-41773", "cvss": 7.5}]},
                {"tech": "GA", "match": "keyword",
                 "cves": [{"cve": "CVE-2024-1203", "cvss": 8.8}]},
            ]}}}
        rows = ops._findings_of(scan)["h.example"]
        self.assertEqual(len(rows), 2)
        exact = next(r for r in rows if "CVE-2021-41773" in r["title"])
        kw = next(r for r in rows if "CVE-2024-1203" in r["title"])
        self.assertIn("exact CPE match", exact["type"])
        self.assertIn("keyword match", kw["type"])
        self.assertEqual(exact["severity"], "high")
        self.assertIn("verify the version", kw["description"])


class TestBuildContext(unittest.TestCase):
    def setUp(self):
        fd, self._db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db_store.save_scan(
            {"risk": {"overall_score": 40.0, "overall_level": "High"},
             "findings": {"h.example": ["**Public Exposure**: FTP open"]},
             "hosts": [], "subdomains": ["h.example"], "sections": {}},
            "h.example", "test", db_path=self._db)

    def tearDown(self):
        for s in ("", "-wal", "-shm"):
            try:
                os.unlink(self._db + s)
            except OSError:
                pass

    def test_latest_scan_is_used(self):
        ctx = ops.build_report_context(db_path=self._db)
        self.assertEqual(ctx["meta"]["target"], "h.example")
        self.assertEqual(ctx["analysis"]["risk"]["score"], 40.0)
        self.assertEqual(ctx["analysis"]["risk"]["level"], "High")
        self.assertIn("h.example", ctx["analysis"]["findings"])

    def test_agent_summary_is_included(self):
        kn = ops._knull_summary(db_path=self._db)
        self.assertEqual(kn["sessions"], 0)
        self.assertEqual(kn["decided"], 0)
        self.assertFalse(kn["running"])
        self.assertEqual(kn["worn_out"], [])

    def test_empty_db_returns_nothing(self):
        fd, db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            self.assertEqual(ops.build_report_context(db_path=db), {})
        finally:
            for s in ("", "-wal", "-shm"):
                try:
                    os.unlink(db + s)
                except OSError:
                    pass


class TestGenerate(unittest.TestCase):
    def setUp(self):
        fd, self._db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db_store.save_scan(
            {"risk": {"overall_score": 40.0, "overall_level": "High"},
             "findings": {"h.example": ["**Public Exposure**: FTP open"]},
             "hosts": [], "subdomains": ["h.example"],
             "sections": {"reachability": {
                 "state": "reachable", "reachable": True, "http_hosts": 1,
                 "hosts_checked": 2, "open_ports": 3, "note": ""}}},
            "h.example", "test", db_path=self._db)
        self.out = tempfile.mkdtemp()

    def tearDown(self):
        for s in ("", "-wal", "-shm"):
            try:
                os.unlink(self._db + s)
            except OSError:
                pass

    def test_all_three_reports_are_written(self):
        res = ops.generate(db_path=self._db, template="all",
                           output_dir=self.out)
        self.assertTrue(res["ok"], res.get("error"))
        self.assertEqual(set(res["paths"]),
                         {"executive", "technical", "compliance"})
        for p in res["paths"].values():
            self.assertTrue(os.path.isfile(p), p)
            self.assertGreater(os.path.getsize(p), 500)

    def test_technical_report_carries_the_knull_section(self):
        res = ops.generate(db_path=self._db, template="technical",
                           output_dir=self.out)
        html = open(res["paths"]["technical"], encoding="utf-8").read()
        self.assertIn("Autonomous agent (Knull)", html)
        self.assertIn("Scan Coverage", html)
        self.assertIn("Public Exposure", html)
        self.assertNotIn("**Public", html)  # markdown stripped

    def test_no_data_is_an_error_not_a_crash(self):
        fd, db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            res = ops.generate(db_path=db, template="all",
                               output_dir=self.out)
            self.assertFalse(res["ok"])
            self.assertIn("no scan data", res["error"])
        finally:
            for s in ("", "-wal", "-shm"):
                try:
                    os.unlink(db + s)
                except OSError:
                    pass


class TestReadReport(unittest.TestCase):
    def test_traversal_is_refused(self):
        self.assertIsNone(ops.read_report("../../etc/passwd"))
        self.assertIsNone(ops.read_report("/etc/passwd"))
        self.assertIsNone(ops.read_report(""))

    def test_missing_file_is_none(self):
        self.assertIsNone(ops.read_report("does-not-exist.html"))

    def test_real_file_is_read(self):
        out = tempfile.mkdtemp()
        p = os.path.join(out, "x.html")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("<html>ok</html>")
        self.assertEqual(ops.read_report("x.html", output_dir=out),
                         "<html>ok</html>")


if __name__ == "__main__":
    unittest.main()
