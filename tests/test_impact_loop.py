"""Tests for the impact-proof loop wiring in the dashboard worker."""

import os
import tempfile
import unittest

import db_store
import modules.dashboard as dash


class TestFinishImpact(unittest.TestCase):
    """_finish_impact must diff the re-scan and feed the result to memory."""

    def setUp(self):
        fd, self._db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._old_db = dash._DB
        self._old_agent = dash._agent_instance
        self._old_impact = dash._STATE.get("impact")
        dash._DB = self._db
        dash._agent_instance = None

    def tearDown(self):
        dash._DB = self._old_db
        dash._agent_instance = self._old_agent
        if self._old_impact is None:
            dash._STATE.pop("impact", None)
        else:
            dash._STATE["impact"] = self._old_impact
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(self._db + suffix)
            except OSError:
                pass

    def _two_scans(self):
        """Baseline scan, then a re-scan with one extra finding."""
        base = db_store.save_scan(
            {"risk": {"overall_score": 40, "overall_level": "Medium"},
             "findings": {"h.example": ["existing finding"]},
             "hosts": [], "subdomains": ["s.example"]},
            "t.example", "test", db_path=self._db)
        after = db_store.save_scan(
            {"risk": {"overall_score": 65, "overall_level": "High"},
             "findings": {"h.example": ["existing finding",
                                        "brand new finding"]},
             "hosts": [], "subdomains": ["s.example"]},
            "t.example", "test", db_path=self._db)
        return base, after

    def _arm(self, baseline):
        dash._STATE["impact"] = {
            "phase": "running", "baseline": baseline,
            "target_key": "t.example:FTP Anonymous Login",
            "technique": "FTP Anonymous Login", "target": "t.example",
            "domain": "t.example", "started": 0, "changed": None,
            "summary": "", "diff": None, "error": None,
        }

    def test_confirmed_change_is_diffed_and_remembered(self):
        base, after = self._two_scans()
        self._arm(base)
        dash._finish_impact(0, "t.example")
        imp = dash._STATE["impact"]
        self.assertEqual(imp["phase"], "done")
        self.assertTrue(imp["changed"])
        self.assertEqual(imp["after_scan"], after)
        self.assertEqual(imp["diff"]["score_delta"], 25)
        rows = db_store.knull_memory(db_path=self._db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["outcome"], "impact")
        self.assertTrue(rows[0]["detail"].startswith("[impact]"))
        self.assertEqual(db_store.memory_source(rows[0]["detail"]), "impact")

    def test_killed_rescan_reports_error_instead_of_fake_result(self):
        base, _ = self._two_scans()
        self._arm(base)
        dash._finish_impact(-9, "t.example")
        imp = dash._STATE["impact"]
        self.assertEqual(imp["phase"], "error")
        self.assertIn("-9", str(imp["error"]))
        self.assertIsNone(imp["changed"])
        self.assertEqual(db_store.knull_memory(db_path=self._db), [])

    def test_no_new_scan_row_is_an_error(self):
        base, _ = self._two_scans()
        self._arm(base)
        # delete the newer row so nothing can be compared
        con, _ = db_store._connect(self._db)
        con.execute("DELETE FROM scans WHERE id>?", (base,))
        con.commit()
        con.close()
        dash._finish_impact(0, "t.example")
        imp = dash._STATE["impact"]
        self.assertEqual(imp["phase"], "error")
        self.assertIn("no new scan", imp["error"])

    def test_noop_when_loop_not_armed(self):
        dash._STATE.pop("impact", None)
        dash._finish_impact(0, "t.example")
        self.assertIsNone(dash._STATE.get("impact"))


class TestImpactBudget(unittest.TestCase):
    def test_impact_rescan_gets_a_larger_budget(self):
        """A full-pipeline re-scan must not be killed at 30 minutes."""
        import inspect
        src = inspect.getsource(dash)
        self.assertIn("timeout_s=int(b.get(\"timeout_s\") or 2700)", src)
        sig = inspect.signature(dash._start_scan)
        self.assertIn("timeout_s", sig.parameters)
        self.assertEqual(sig.parameters["timeout_s"].default, 1800)


if __name__ == "__main__":
    unittest.main()
