"""Tests for the permission gate and the smarter (re-asking) Knull brain."""

import os
import tempfile
import unittest
from unittest import mock

import db_store
from modules.knull import Knull

SCAN = {"domain": "t.example",
        "hosts": [{"host": "t.example", "ip": "10.0.0.9",
                   "ports": [{"port": 80, "service": "http"}], "tech": []}],
        "subdomains": ["t.example"], "findings": [], "sections": {}}

PATH = {"order": 1, "target": "t.example", "technique": "SQL Injection",
        "technique_key": "sqli", "score": 8.5, "probability": 0.24,
        "command": "sqlmap -u 'http://t.example/?id=1' --batch"}

PLAN = {"technique": "sqli", "target": "t.example",
        "hypothesis": "test hypothesis", "skip": [], "confidence": 0.9}


def _knull(**kw):
    fd, db = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    kw.setdefault("target_domain", "t.example")
    kw.setdefault("use_brain", True)
    kw.setdefault("brain_cooldown", 0.0)
    return Knull(db_path=db, **kw), db


def _cleanup(db):
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(db + suffix)
        except OSError:
            pass


class TestScopeGate(unittest.TestCase):
    def setUp(self):
        self.k, self.db = _knull(extra_scope=["lab.local"])

    def tearDown(self):
        _cleanup(self.db)

    def test_scope_matrix(self):
        cases = [
            ("t.example", True),
            ("sub.t.example", True),
            ("https://a.t.example/path?q=1", True),
            ("cdn.t.example:443", True),
            ("T.EXAMPLE", True),
            ("lab.local", True),
            ("evil.com", False),
            ("nott.example.com", False),
            ("sub.t.example.evil.com", False),
            ("t.example.evil.com", False),
            ("8.8.8.8", False),
            ("", False),
        ]
        for target, want in cases:
            self.assertEqual(self.k._in_scope(target), want,
                             f"_in_scope({target!r})")

    def test_scan_seen_host_is_in_scope(self):
        self.k._scope_hosts.add("10.0.0.9")
        self.assertTrue(self.k._in_scope("10.0.0.9"))

    def test_fire_refuses_out_of_scope_and_does_not_run(self):
        self.k._emit("execute", "command_prepared", "cmd",
                     data={"command": "echo pwn", "technique": "SQL Injection",
                           "target": "evil.com",
                           "target_key": "evil.com:SQL Injection"})
        with mock.patch.object(Knull, "_run_in_kali") as run:
            out = self.k.fire("evil.com:SQL Injection")
        self.assertFalse(out["ok"])
        self.assertIn("out of scope", out["error"])
        run.assert_not_called()
        self.assertNotIn("evil.com:SQL Injection", self.k._fired)
        self.assertTrue(any(e.action == "fire_blocked"
                            for e in self.k.events))

    def test_fire_allows_in_scope_target(self):
        self.k._emit("execute", "command_prepared", "cmd",
                     data={"command": "echo hi", "technique": "SQL Injection",
                           "target": "t.example",
                           "target_key": "t.example:SQL Injection"})
        with mock.patch.object(
                Knull, "_run_in_kali",
                return_value={"exit_code": 0, "stdout": "ok", "stderr": ""}):
            out = self.k.fire("t.example:SQL Injection")
        self.assertTrue(out["ok"], out)

    def test_record_refuses_out_of_scope(self):
        out = self.k.record_attempt("SQL Injection", "evil.com", "success")
        self.assertFalse(out["ok"])
        self.assertIn("out of scope", out["error"])
        self.assertEqual(db_store.knull_memory(db_path=self.db), [])


class TestBrainReasks(unittest.TestCase):
    def setUp(self):
        self.k, self.db = _knull(max_brain_calls=3)

    def tearDown(self):
        _cleanup(self.db)

    def test_asks_once_then_waits_for_new_information(self):
        with mock.patch("modules.knull_brain.available", return_value=True), \
                mock.patch("modules.knull_brain.hypothesize_options",
                           return_value=[dict(PLAN)]) as ask:
            self.k._ask_brain(SCAN)
            self.k._ask_brain(SCAN)          # nothing happened yet
            self.assertEqual(ask.call_count, 1)
            self.k._outcomes_seen += 1       # an attempt produced a result
            self.k._ask_brain(SCAN)
            self.assertEqual(ask.call_count, 2)

    def test_budget_is_respected(self):
        k, db = _knull(max_brain_calls=2, brain_cooldown=0.0)
        try:
            with mock.patch("modules.knull_brain.available",
                            return_value=True), \
                    mock.patch("modules.knull_brain.hypothesize_options",
                               return_value=[dict(PLAN)]) as ask:
                for _ in range(6):
                    k._outcomes_seen += 1
                    k._ask_brain(SCAN)
                self.assertEqual(ask.call_count, 2)
        finally:
            _cleanup(db)

    def test_budget_zero_never_calls(self):
        k, db = _knull(max_brain_calls=0)
        try:
            with mock.patch("modules.knull_brain.available",
                            return_value=True), \
                    mock.patch("modules.knull_brain.hypothesize_options",
                               return_value=[dict(PLAN)]) as ask:
                k._ask_brain(SCAN)
            ask.assert_not_called()
        finally:
            _cleanup(db)

    def test_hypotheses_are_stored_as_a_ranked_list(self):
        with mock.patch("modules.knull_brain.available", return_value=True), \
                mock.patch("modules.knull_brain.hypothesize_options",
                           return_value=[dict(PLAN),
                                         dict(PLAN, technique="ssh_brute",
                                              confidence=0.4)]):
            self.k._ask_brain(SCAN)
        self.assertEqual(len(self.k._brain_plans), 2)
        self.assertEqual(self.k._brain_plans[0]["technique"], "sqli")


class TestBrainConfidenceGate(unittest.TestCase):
    def setUp(self):
        self.k, self.db = _knull(brain_min_confidence=0.5)

    def tearDown(self):
        _cleanup(self.db)

    def test_low_confidence_defers_to_the_chain(self):
        self.k._brain_plans = [dict(PLAN, confidence=0.2)]
        out = self.k._next_brain_step([PATH])
        self.assertIsNone(out)
        self.assertTrue(any(e.action == "brain_low_confidence"
                            for e in self.k.events))
        self.assertFalse(self.k._current_from_brain)

    def test_confident_plan_is_taken(self):
        self.k._brain_plans = [dict(PLAN, confidence=0.9)]
        out = self.k._next_brain_step([PATH])
        self.assertIsNotNone(out)
        self.assertEqual(out["technique_key"], "sqli")
        self.assertTrue(self.k._current_from_brain)

    def test_falls_through_to_an_alternative(self):
        """Primary is not scored as viable → the next option is used."""
        self.k._brain_plans = [
            dict(PLAN, technique="cve_exploit", confidence=0.95),
            dict(PLAN, confidence=0.7),
        ]
        out = self.k._next_brain_step([PATH])
        self.assertIsNotNone(out)
        self.assertEqual(out["technique_key"], "sqli")

    def test_all_unviable_defers(self):
        self.k._brain_plans = [dict(PLAN, technique="cve_exploit")]
        out = self.k._next_brain_step([PATH])
        self.assertIsNone(out)
        self.assertTrue(any(e.action == "brain_unviable"
                            for e in self.k.events))

    def test_already_attempted_is_skipped(self):
        self.k._brain_plans = [dict(PLAN, confidence=0.9)]
        self.k._emit("decide", "brain_step", "prior",
                     data={"target_key": "t.example:SQL Injection"})
        self.assertIsNone(self.k._next_brain_step([PATH]))


class TestBrainHistoryInBrief(unittest.TestCase):
    def setUp(self):
        self.k, self.db = _knull()

    def tearDown(self):
        _cleanup(self.db)

    def test_refuted_ideas_are_fed_back_to_the_model(self):
        db_store.knull_remember("SQL Injection", "failure",
                                domain="t.example", target="t.example",
                                detail="[brain] tried SQLi, blocked by WAF",
                                db_path=self.db)
        db_store.knull_remember("FTP Brute Force", "pending",
                                domain="t.example", target="t.example",
                                detail="plain advisor pick",
                                db_path=self.db)
        brief = self.k._brain_brief(SCAN)
        hist = brief["brain_history"]
        self.assertEqual(len(hist), 1)
        self.assertIn("SQL Injection", hist[0])
        self.assertIn("failure", hist[0])

    def test_prompt_shows_the_history_section(self):
        from modules.knull_brain import _build_prompt
        prompt = _build_prompt({"domain": "t.example",
                                "hosts": [{"host": "t.example"}],
                                "techniques": ["sqli"],
                                "brain_history": ["SQL Injection -> failure"]})
        self.assertIn("YOUR OWN PAST HYPOTHESES", prompt)
        self.assertIn("SQL Injection -> failure", prompt)
        self.assertIn("alternatives", prompt)


class TestCveWatchlistMerge(unittest.TestCase):
    def test_exact_hits_survive_the_keyword_pass(self):
        from core.runner import _merge_cve_watchlist

        class Ctx:
            cve_watchlist = None

        ctx = Ctx()
        _merge_cve_watchlist(ctx, {
            "h.example": [{"tech": "Apache 2.4.49", "match": "cpe_exact",
                           "cves": [{"cve": "CVE-2021-41773"}]}]})
        _merge_cve_watchlist(ctx, {
            "h.example": [{"tech": "apache", "match": "keyword",
                           "cves": [{"cve": "CVE-2019-0211"}]}],
            "other.example": [{"tech": "nginx", "match": "keyword",
                               "cves": [{"cve": "CVE-2013-2028"}]}]})
        self.assertEqual(len(ctx.cve_watchlist["h.example"]), 2)
        self.assertEqual(ctx.cve_watchlist["h.example"][0]["match"], "cpe_exact")
        self.assertIn("other.example", ctx.cve_watchlist)

    def test_duplicate_tech_is_not_added_twice(self):
        from core.runner import _merge_cve_watchlist

        class Ctx:
            cve_watchlist = None

        ctx = Ctx()
        _merge_cve_watchlist(ctx, {"h": [{"tech": "nginx", "cves": []}]})
        _merge_cve_watchlist(ctx, {"h": [{"tech": "Nginx", "cves": []}]})
        self.assertEqual(len(ctx.cve_watchlist["h"]), 1)

    def test_same_tech_rows_are_unioned_not_dropped(self):
        """deep writes {id:...}, keyword writes {cve:...} + enrichment."""
        from core.runner import _merge_cve_watchlist

        class Ctx:
            cve_watchlist = None

        ctx = Ctx()
        _merge_cve_watchlist(ctx, {
            "h": [{"tech": "Apache", "match": "cpe_exact",
                   "cpe": "cpe:2.3:a:apache:http_server:2.4.49",
                   "cves": [{"id": "CVE-2021-41773", "cvss": 7.5}]}]})
        _merge_cve_watchlist(ctx, {
            "h": [{"tech": "Apache", "match": "keyword",
                   "cves": [{"cve": "CVE-2021-41773"},
                            {"cve": "CVE-2019-0211"}],
                   "epss": 0.4, "kev": True}]})
        row = ctx.cve_watchlist["h"][0]
        self.assertEqual(len(ctx.cve_watchlist["h"]), 1)
        self.assertEqual(row["match"], "cpe_exact")
        self.assertEqual(row["epss"], 0.4)
        self.assertTrue(row["kev"])
        ids = [c.get("id") or c.get("cve") for c in row["cves"]]
        self.assertEqual(sorted(ids), ["CVE-2019-0211", "CVE-2021-41773"])

    def test_log_distinguishes_exact_from_keyword(self):
        import logging
        from core.runner import _log_cve_total

        class Ctx:
            cve_watchlist = {"h": [
                {"tech": "A", "match": "cpe_exact", "cves": [{"id": "CVE-1"}]},
                {"tech": "B", "match": "keyword", "cves": [{"cve": "CVE-2"}]},
            ]}

        with self.assertLogs("AttackSurface.Runner", level="INFO") as log:
            _log_cve_total(Ctx(), "label")
        line = log.output[0]
        self.assertIn("2 CVE(s)", line)
        self.assertIn("1 exact CPE, 1 keyword", line)


if __name__ == "__main__":
    unittest.main()
