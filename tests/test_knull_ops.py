"""Tests for the ops console (runtime settings on a live Knull session)."""

import os
import tempfile
import unittest
from unittest import mock

from modules.knull import Knull


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


class TestConfigure(unittest.TestCase):
    def setUp(self):
        self.k, self.db = _knull()

    def tearDown(self):
        _cleanup(self.db)

    def test_defaults_are_reported(self):
        c = self.k.config()
        self.assertEqual(c["use_brain"], False)
        self.assertEqual(c["safe_verify"], True)
        self.assertEqual(c["auto_execute"], False)  # shots stay manual
        self.assertEqual(c["extra_scope"], [])

    def test_bools_apply(self):
        out = self.k.configure({"use_brain": True, "safe_verify": False})
        self.assertTrue(out["ok"])
        self.assertFalse(self.k.use_brain is False)
        self.assertFalse(self.k.safe_verify)

    def test_numbers_are_clamped(self):
        self.k.configure({"brain_min_confidence": 9.9,
                          "max_brain_calls": 99,
                          "max_iterations": -5,
                          "brain_cooldown": -1})
        self.assertEqual(self.k.brain_min_confidence, 1.0)
        self.assertEqual(self.k.max_brain_calls, 10)
        self.assertEqual(self.k.max_iterations, 1)
        self.assertEqual(self.k.brain_cooldown, 0.0)

    def test_wrong_type_is_reported_and_ignored(self):
        out = self.k.configure({"use_brain": "yes",
                                "max_brain_calls": "three"})
        self.assertFalse(out["ok"])
        self.assertEqual(out["applied"], {})
        self.assertIn("use_brain must be true/false", out["errors"])
        self.assertIn("max_brain_calls must be a number", out["errors"])
        self.assertFalse(self.k.use_brain)

    def test_unknown_setting_is_reported(self):
        out = self.k.configure({"rm_rf": True})
        self.assertFalse(out["ok"])
        self.assertIn("unknown setting: rm_rf", out["errors"])
        self.assertEqual(out["applied"], {})

    def test_extra_scope_is_normalised(self):
        self.k.configure({"extra_scope": " Lab.Local , staging.example "})
        self.assertEqual(self.k.extra_scope,
                         ["lab.local", "staging.example"])
        self.assertTrue(self.k._in_scope("deep.lab.local"))
        self.assertFalse(self.k._in_scope("evil.com"))

    def test_extra_scope_accepts_a_list(self):
        self.k.configure({"extra_scope": ["A.example", "b.example"]})
        self.assertEqual(self.k.extra_scope, ["a.example", "b.example"])

    def test_a_change_is_announced_in_the_event_log(self):
        self.k.configure({"max_brain_calls": 2})
        ev = [e for e in self.k.events if e.action == "config_changed"]
        self.assertEqual(len(ev), 1)
        self.assertIn("max_brain_calls=2", ev[0].detail)

    def test_safe_verify_can_be_switched_off(self):
        """Turning passive checks off leaves dry runs pending again."""
        self.k.configure({"safe_verify": False})
        target = dict(technique="FTP Anonymous Login",
                      technique_key="ftp_anonymous", target="t.example",
                      command="ftp -n t.example", score=1.0)
        with mock.patch.object(Knull, "_probe_ftp_anonymous") as probe:
            result = self.k._execute(target)
        probe.assert_not_called()
        self.assertIsNone(result.get("safe_verdict"))
        self.assertIsNone(self.k._verify(result))

    def test_status_exposes_the_config(self):
        st = self.k.get_status()
        self.assertIn("config", st)
        self.assertEqual(st["config"]["auto_execute"], False)


if __name__ == "__main__":
    unittest.main()
