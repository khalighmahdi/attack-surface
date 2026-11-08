"""Tests for Knull's non-destructive verification (the verdict loop).

Without a passive check every memory row stayed 'pending', so the
scoreboard, the worn-out list and the brain's feedback never saw a single
decision. These tests pin the semantics: read-only probes produce real
True/False verdicts, unverifiable techniques honestly stay pending, and
the record tag never leaks between attempts.
"""

import os
import tempfile
import unittest
from unittest import mock

import db_store
from modules.knull import Knull

FTP_TARGET = {"technique": "FTP Anonymous Login", "technique_key": "ftp_anonymous",
              "target": "t.example", "command": "ftp -n t.example", "score": 12.3}
SQLI_TARGET = {"technique": "SQL Injection", "technique_key": "sqli",
               "target": "t.example",
               "command": "sqlmap -u 'http://t.example/?id=1' --batch",
               "score": 8.5}
SSH_TARGET = {"technique": "SSH Brute Force", "technique_key": "ssh_brute",
              "target": "t.example", "command": "hydra ...", "score": 4.4}


def _knull(**kw):
    fd, db = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    kw.setdefault("target_domain", "t.example")
    kw.setdefault("use_brain", False)
    kw.setdefault("auto_execute", False)
    return Knull(db_path=db, **kw), db


def _cleanup(db):
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(db + suffix)
        except OSError:
            pass


class TestSafeVerifySelection(unittest.TestCase):
    def setUp(self):
        self.k, self.db = _knull()

    def tearDown(self):
        _cleanup(self.db)

    def test_unverifiable_technique_returns_none_without_probing(self):
        with mock.patch.object(Knull, "_run_in_kali") as run:
            self.assertIsNone(self.k._safe_verify(SSH_TARGET))
        run.assert_not_called()

    def test_ftp_probe_is_read_only_and_runs(self):
        with mock.patch.object(
                Knull, "_run_in_kali",
                return_value={"exit_code": 0, "stdout": "file1.txt\n",
                              "stderr": ""}) as run:
            self.assertTrue(self.k._safe_verify(FTP_TARGET))
        cmd = run.call_args[0][0]
        self.assertIn("ftp://t.example/", cmd)
        self.assertIn("anonymous", cmd)
        self.assertNotIn("STOR", cmd.upper())  # LIST only, nothing written

    def test_ftp_refusal_is_a_real_negative(self):
        with mock.patch.object(
                Knull, "_run_in_kali",
                return_value={"exit_code": 67, "stdout": "",
                              "stderr": "530 Access denied"}):
            self.assertFalse(self.k._safe_verify(FTP_TARGET))

    def test_ftp_timeout_is_inconclusive_not_failure(self):
        with mock.patch.object(
                Knull, "_run_in_kali",
                return_value={"exit_code": 28, "stdout": "",
                              "stderr": "curl: (28) timed out"}):
            self.assertIsNone(self.k._safe_verify(FTP_TARGET))

    def test_out_of_scope_is_refused_before_probing(self):
        self.k.target_domain = "other.example"
        with mock.patch.object(Knull, "_run_in_kali") as run:
            self.assertIsNone(self.k._safe_verify(FTP_TARGET))
        run.assert_not_called()
        self.assertTrue(any(e.action == "verify_blocked"
                            for e in self.k.events))

    def test_sqli_uses_the_existing_safe_probe(self):
        with mock.patch("modules.sqli_probe.probe_url",
                        return_value={"url": "x", "db_signatures": ["MySQL"]}) as p:
            self.assertTrue(self.k._safe_verify(SQLI_TARGET))
        self.assertIn("http://t.example/?id=1", p.call_args[0][0])


class TestVerdictReachesMemory(unittest.TestCase):
    def setUp(self):
        self.k, self.db = _knull()

    def tearDown(self):
        _cleanup(self.db)

    def _run_with_verdict(self, target, verdict):
        with mock.patch.object(Knull, "_safe_verify",
                               return_value=verdict):
            result = self.k._execute(dict(target))
            verified = self.k._verify(result)
            if verified is True:
                self.k._on_success(dict(target), result)
            elif verified is False:
                self.k._on_failure(dict(target), result)
            else:
                self.k._remember(dict(target), "pending", detail="x")
        return verified

    def test_confirmed_claim_is_recorded_as_success(self):
        verified = self._run_with_verdict(FTP_TARGET, True)
        self.assertIs(verified, True)
        rows = db_store.knull_memory(db_path=self.db)
        self.assertEqual(rows[0]["outcome"], "success")
        self.assertTrue(rows[0]["detail"].startswith("[verify]"))
        self.assertEqual(db_store.memory_source(rows[0]["detail"]), "verify")
        self.assertEqual(self.k.kill_chain["initial_access"].status, "success")

    def test_refuted_claim_is_recorded_as_failure(self):
        verified = self._run_with_verdict(SQLI_TARGET, False)
        self.assertIs(verified, False)
        rows = db_store.knull_memory(db_path=self.db)
        self.assertEqual(rows[0]["outcome"], "failure")
        self.assertEqual(self.k.kill_chain["initial_access"].status, "pending")

    def test_inconclusive_stays_pending(self):
        verified = self._run_with_verdict(SSH_TARGET, None)
        self.assertIsNone(verified)
        rows = db_store.knull_memory(db_path=self.db)
        self.assertEqual(rows[0]["outcome"], "pending")

    def test_verify_tag_does_not_leak_into_the_next_attempt(self):
        self._run_with_verdict(FTP_TARGET, True)
        # a subsequent real execution must not be tagged as a passive verify
        with mock.patch.object(Knull, "_run_in_kali",
                               return_value={"exit_code": 0,
                                             "stdout": "login successful",
                                             "stderr": ""}):
            result = self.k._execute(dict(SSH_TARGET), force=True)
        self.assertTrue(result["executed"])
        verified = self.k._verify(result)
        self.assertTrue(verified)
        self.k._on_success(dict(SSH_TARGET), result)
        rows = db_store.knull_memory(db_path=self.db)
        self.assertFalse(rows[0]["detail"].startswith("[verify]"),
                         f"stale tag leaked: {rows[0]['detail']}")

    def test_scoreboard_sees_the_verify_source_and_decides(self):
        self._run_with_verdict(SQLI_TARGET, False)
        sb = db_store.knull_scoreboard(domain="t.example", db_path=self.db)
        self.assertIn("verify", sb["by_source"])
        self.assertEqual(sb["by_source"]["verify"]["decided"], 1)
        self.assertEqual(sb["totals"]["decided"], 1)


class TestScoreboardSources(unittest.TestCase):
    def test_verify_prefix_is_recognised(self):
        import db_store as ds
        self.assertEqual(ds.memory_source("[verify] FTP ok"), "verify")
        self.assertEqual(ds.memory_source("[fired] shot"), "fired")
        self.assertEqual(ds.memory_source("no tag here"), "advisor")


if __name__ == "__main__":
    unittest.main()
