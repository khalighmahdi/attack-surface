"""Tests for nuclei ingestion, the learning scoreboard and impact proof."""

import os
import tempfile
import unittest

import db_store
from modules.attack_advisor import (extract_target_properties,
                                    recommend_attacks)
from modules.attack_graph import build_graph
from modules.knull import Knull

NUCLEI = [
    {"url": "https://target.example/login",
     "matched_at": "https://target.example/login",
     "template_id": "cve-2021-44228", "name": "Log4j RCE",
     "severity": "critical", "type": "http", "cve": "CVE-2021-44228",
     "waf_detected": False},
    {"url": "https://other.example/", "matched_at": "https://other.example/",
     "template_id": "exposed-panel", "name": "Exposed panel",
     "severity": "info", "type": "http", "cve": "",
     "waf_detected": False},
]


def _scan():
    return {
        "domain": "target.example",
        "hosts": [{"host": "target.example", "ip": "10.0.0.7",
                   "ports": [{"port": 80, "service": "http"}],
                   "tech": []}],
        "subdomains": ["target.example"],
        "findings": [],
        "sections": {"nuclei": NUCLEI},
    }


class TestNucleiIngestion(unittest.TestCase):
    def test_cve_hit_sets_cve_detected(self):
        targets = extract_target_properties(_scan())
        props = next(t for t in targets if t["host"] == "target.example")
        self.assertTrue(props["cve_detected"])

    def test_info_only_hit_does_not(self):
        scan = _scan()
        scan["sections"]["nuclei"] = [NUCLEI[1]]
        props = extract_target_properties(scan)[0]
        self.assertFalse(props["cve_detected"])

    def test_host_scope_is_respected(self):
        """A CVE on another host must not mark this one vulnerable."""
        scan = _scan()
        scan["sections"]["nuclei"] = [dict(NUCLEI[0],
                                           url="https://elsewhere.example/")]
        props = extract_target_properties(scan)[0]
        self.assertFalse(props["cve_detected"])

    def test_unscoped_scan_is_unaffected(self):
        rows = extract_target_properties(
            {"domain": "z.example",
             "hosts": [{"host": "z.example", "ip": "", "ports": [],
                        "tech": []}],
             "subdomains": [], "findings": [], "sections": {}})
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["cve_detected"])

    def test_cve_exploit_becomes_recommendable(self):
        order = recommend_attacks(_scan()).get("execution_order", [])
        self.assertIn("cve_exploit", {p["technique_key"] for p in order})

    def test_nuclei_become_severity_graded_nodes(self):
        g = build_graph(_scan())
        nuc = [n for n in g["nodes"] if str(n["id"]).startswith("nuc:")]
        self.assertEqual(len(nuc), 2)
        crit = next(n for n in nuc if n.get("cve") == "CVE-2021-44228")
        self.assertEqual(crit["risk"], 95)
        self.assertEqual(crit["severity"], "critical")
        edge = next(e for e in g["edges"] if e["target"] == crit["id"])
        self.assertEqual(edge["type"], "vulnerable_to")


class TestScoreboard(unittest.TestCase):
    def setUp(self):
        fd, self._db = tempfile.mkstemp(suffix=".db")
        os.close(fd)

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(self._db + suffix)
            except OSError:
                pass

    def _seed(self):
        db_store.knull_remember("SQL Injection", "success", domain="a.test",
                                detail="[brain] good call", db_path=self._db)
        db_store.knull_remember("SQL Injection", "failure", domain="a.test",
                                detail="[brain] bad call", db_path=self._db)
        db_store.knull_remember("FTP Brute Force", "failure", domain="a.test",
                                detail="plain advisor pick", db_path=self._db)
        db_store.knull_remember("FTP Brute Force", "failure", domain="a.test",
                                detail="plain advisor pick", db_path=self._db)
        db_store.knull_remember("FTP Brute Force", "failure", domain="a.test",
                                detail="[fired] operator shot", db_path=self._db)
        db_store.knull_remember("SSH Brute Force", "impact", domain="a.test",
                                detail="[impact] findings 3 new", db_path=self._db)
        db_store.knull_remember("SMB Null Session", "pending", domain="a.test",
                                detail="dry run", db_path=self._db)

    def test_sources_are_split(self):
        self._seed()
        sb = db_store.knull_scoreboard(domain="a.test", db_path=self._db)
        self.assertEqual(set(sb["by_source"]),
                         {"brain", "advisor", "fired", "impact"})
        self.assertEqual(sb["by_source"]["brain"]["decided"], 2)
        self.assertEqual(sb["by_source"]["brain"]["success"], 1)

    def test_impact_is_bucketed_separately(self):
        self._seed()
        sb = db_store.knull_scoreboard(domain="a.test", db_path=self._db)
        ssh = next(t for t in sb["by_technique"]
                   if t["technique"] == "SSH Brute Force")
        self.assertEqual(ssh["impact"], 1)
        # impact is a *measurement* of a shot, not a shot — so it must
        # not inflate the attempt count or double the decision.
        self.assertEqual(ssh["attempts"], 0)
        self.assertEqual(ssh["decided"], 0)

    def test_worn_out_techniques_are_flagged(self):
        self._seed()
        sb = db_store.knull_scoreboard(domain="a.test", db_path=self._db)
        self.assertEqual(sb["worn_out"], ["FTP Brute Force"])

    def test_totals_match_records(self):
        self._seed()
        sb = db_store.knull_scoreboard(domain="a.test", db_path=self._db)
        self.assertEqual(sb["n_records"], 7)
        self.assertEqual(sb["totals"]["success"], 1)
        self.assertEqual(sb["totals"]["failure"], 4)
        self.assertEqual(sb["totals"]["pending"], 1)
        self.assertEqual(sb["totals"]["impact"], 1)

    def test_empty_memory_is_safe(self):
        sb = db_store.knull_scoreboard(db_path=self._db)
        self.assertEqual(sb["n_records"], 0)
        self.assertEqual(sb["worn_out"], [])


class TestOperatorRecord(unittest.TestCase):
    def setUp(self):
        fd, self._db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        # records are engagement-scoped: the domain must be declared
        self.k = Knull(db_path=self._db, use_brain=False,
                       target_domain="target.example")

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(self._db + suffix)
            except OSError:
                pass

    def test_success_is_tagged_and_advances(self):
        out = self.k.record_attempt("SSH Brute Force", "target.example",
                                    "success", output="login successful")
        self.assertTrue(out["ok"])
        self.assertEqual(self.k.kill_chain["credential_access"].status,
                         "success")
        rows = db_store.knull_memory(db_path=self._db)
        self.assertEqual(rows[0]["detail"].split(" ", 1)[0], "[operator]")
        self.assertEqual(db_store.memory_source(rows[0]["detail"]), "operator")

    def test_failure_does_not_advance(self):
        self.k.record_attempt("SSH Brute Force", "target.example", "failure")
        self.assertEqual(self.k.kill_chain["credential_access"].status,
                         "pending")

    def test_invalid_outcome_rejected(self):
        out = self.k.record_attempt("SSH Brute Force", "t", "exploded")
        self.assertFalse(out["ok"])
        self.assertEqual(db_store.knull_memory(db_path=self._db), [])

    def test_missing_technique_rejected(self):
        self.assertFalse(self.k.record_attempt("", "t", "success")["ok"])

    def test_no_agent_side_effect_on_bad_input(self):
        self.k.record_attempt("X", "target.example", "success",
                              output="")  # unknown tech, still recorded
        rows = db_store.knull_memory(db_path=self._db)
        self.assertEqual(len(rows), 1)  # still recorded, just un-mapped


class TestImpactProof(unittest.TestCase):
    def setUp(self):
        fd, self._db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.k = Knull(db_path=self._db, use_brain=False)

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(self._db + suffix)
            except OSError:
                pass

    def test_changed_diff_is_recorded_as_impact(self):
        diff = {"new_findings": [{"host": "t", "title": "new"}],
                "new_subdomains": [], "score_delta": 0}
        out = self.k.record_impact("FTP Anonymous Login", "t.example", diff)
        self.assertTrue(out["changed"])
        rows = db_store.knull_memory(db_path=self._db)
        self.assertEqual(rows[0]["outcome"], "impact")
        self.assertTrue(rows[0]["detail"].startswith("[impact]"))

    def test_unchanged_diff_counts_against_the_technique(self):
        diff = {"new_findings": [], "new_subdomains": [], "score_delta": 0}
        out = self.k.record_impact("FTP Anonymous Login", "t.example", diff)
        self.assertFalse(out["changed"])
        rows = db_store.knull_memory(db_path=self._db)
        self.assertEqual(rows[0]["outcome"], "failure")
        self.assertIn("no measurable change", rows[0]["detail"])

    def test_score_delta_alone_counts_as_change(self):
        diff = {"new_findings": [], "new_subdomains": [], "score_delta": -10}
        self.assertTrue(
            self.k.record_impact("SQL Injection", "t.example", diff)["changed"])


class TestCompareUsedByImpact(unittest.TestCase):
    def test_compare_reports_new_findings(self):
        fd, db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            a = db_store.save_scan(
                {"risk": {"overall_score": 50, "overall_level": "High"},
                 "findings": {"h.example": ["old"]},
                 "hosts": [], "subdomains": ["s.example"]},
                "t.example", "test", db_path=db)
            b = db_store.save_scan(
                {"risk": {"overall_score": 70, "overall_level": "High"},
                 "findings": {"h.example": ["old", "brand new one"]},
                 "hosts": [], "subdomains": ["s.example", "n.example"]},
                "t.example", "test", db_path=db)
            d = db_store.compare(a, b, db)
            self.assertEqual(len(d["new_findings"]), 1)
            self.assertEqual(d["new_subdomains"], ["n.example"])
            self.assertEqual(d["score_delta"], 20)
        finally:
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.unlink(db + suffix)
                except OSError:
                    pass


if __name__ == "__main__":
    unittest.main()
