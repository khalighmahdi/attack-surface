"""Tests for the evidence vault and LLM retry."""

import os
import tempfile
import unittest
from unittest import mock

import db_store
from modules.knull import Knull
from modules.knull_brain import post_chat


def _knull(**kw):
    fd, db = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    kw.setdefault("target_domain", "t.example")
    kw.setdefault("use_brain", False)
    return Knull(db_path=db, **kw), db


def _cleanup(db):
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(db + suffix)
        except OSError:
            pass


TARGET = {"technique": "FTP Anonymous Login", "technique_key": "ftp_anonymous",
          "target": "t.example", "command": "ftp -n t.example", "score": 1.0}


class TestEvidenceVault(unittest.TestCase):
    def setUp(self):
        self.k, self.db = _knull()

    def tearDown(self):
        _cleanup(self.db)

    def test_passive_verification_keeps_the_raw_listing(self):
        with mock.patch.object(
                Knull, "_run_in_kali",
                return_value={"exit_code": 0, "stdout": "pub\npriv\n",
                              "stderr": ""}):
            result = self.k._execute(dict(TARGET))
        self.assertTrue(self.k._verify(result))
        rows = db_store.list_evidence(db_path=self.db)
        self.assertEqual(len(rows), 1)
        e = rows[0]
        self.assertEqual(e["source"], "verify")
        self.assertEqual(e["outcome"], "confirmed")
        self.assertEqual(e["output"], "pub\npriv\n")
        self.assertEqual(e["target"], "t.example")

    def test_fired_command_keeps_exit_code_and_stderr(self):
        with mock.patch.object(
                Knull, "_run_in_kali",
                return_value={"exit_code": 254, "stdout": "",
                              "stderr": "permission denied"}):
            self.k._execute(dict(TARGET), force=True)
        rows = db_store.list_evidence(db_path=self.db)
        self.assertEqual(rows[0]["source"], "fired")
        self.assertEqual(rows[0]["exit_code"], 254)
        self.assertIn("permission denied", rows[0]["output"])

    def test_operator_output_is_kept(self):
        self.k.record_attempt("SQL Injection", "t.example", "failure",
                              output="mysql error 1064 near syntax")
        rows = db_store.list_evidence(db_path=self.db)
        self.assertEqual(rows[0]["source"], "operator")
        self.assertEqual(rows[0]["outcome"], "failure")
        self.assertIn("1064", rows[0]["output"])

    def test_nothing_to_store_is_skipped(self):
        self.k._store_evidence(dict(TARGET), "no_verdict", output="")
        self.assertEqual(db_store.list_evidence(db_path=self.db), [])

    def test_out_of_scope_record_keeps_no_evidence(self):
        self.k.record_attempt("SQL Injection", "evil.com", "failure",
                              output="x")
        self.assertEqual(db_store.list_evidence(db_path=self.db), [])

    def test_evidence_never_breaks_a_run(self):
        k = Knull(db_path="/nonexistent-dir/x.db", target_domain="t.example",
                  use_brain=False)
        k._store_evidence(dict(TARGET), "confirmed", output="proof")  # no raise

    def test_summary_counts_sources(self):
        self.k.record_attempt("SQL Injection", "t.example", "failure",
                              output="boom")
        self.k._store_evidence(dict(TARGET), "confirmed", output="ok",
                               source="verify")
        summary = db_store.evidence_summary(db_path=self.db)
        self.assertEqual(summary["operator"]["failure"], 1)
        self.assertEqual(summary["verify"]["confirmed"], 1)

    def test_evidence_is_scoped_by_target(self):
        self.k.record_attempt("SQL Injection", "t.example", "failure",
                              output="a")
        self.k.record_attempt("SQL Injection", "other.t.example", "failure",
                              output="b")
        self.assertEqual(len(db_store.list_evidence(
            target="t.example", db_path=self.db)), 1)


class TestLlmRetry(unittest.TestCase):
    def _resp(self, status, payload=None):
        r = mock.Mock()
        r.status_code = status
        r.json.return_value = payload or {}
        r.text = "err"
        return r

    def test_success_on_the_first_try(self):
        with mock.patch("requests.post",
                        return_value=self._resp(200, {"choices": []})) as p:
            self.assertEqual(post_chat({"m": 1})["choices"], [])
        self.assertEqual(p.call_count, 1)

    def test_transient_error_is_retried_once(self):
        with mock.patch("requests.post",
                        side_effect=[self._resp(503), self._resp(200, {"ok": 1})]) as p:
            self.assertEqual(post_chat({"m": 1}, retries=1), {"ok": 1})
        self.assertEqual(p.call_count, 2)

    def test_410_is_retried(self):
        """The provider answered 410 for a deprecated model once."""
        with mock.patch("requests.post",
                        side_effect=[self._resp(410), self._resp(200, {"ok": 2})]):
            self.assertEqual(post_chat({"m": 1}), {"ok": 2})

    def test_permanent_error_gives_up_after_the_budget(self):
        err: list = []
        with mock.patch("requests.post",
                        return_value=self._resp(500)) as p:
            self.assertIsNone(post_chat({"m": 1}, retries=2, last_error=err))
        self.assertEqual(p.call_count, 3)  # 1 + 2 retries
        self.assertEqual(err, ["HTTP 500"])

    def test_non_retryable_status_stops_immediately(self):
        with mock.patch("requests.post",
                        return_value=self._resp(401)) as p:
            self.assertIsNone(post_chat({"m": 1}, retries=3))
        self.assertEqual(p.call_count, 1)

    def test_network_error_is_retried(self):
        with mock.patch("requests.post",
                        side_effect=[ConnectionError("boom"),
                                     self._resp(200, {"ok": 3})]):
            self.assertEqual(post_chat({"m": 1}), {"ok": 3})

    def test_no_key_short_circuits(self):
        with mock.patch.dict(os.environ,
                             {"ATTACK_SURFACE_LLM_API_KEY": "",
                              "KNOLL_LLM_API_KEY": ""}):
            with mock.patch("requests.post") as p:
                self.assertIsNone(post_chat({"m": 1}))
            p.assert_not_called()


if __name__ == "__main__":
    unittest.main()
