"""Tests for Knull's manual fire queue (execution stays operator-driven)."""

import os
import tempfile
import unittest
from unittest import mock

from modules.knull import Knull


TARGET = {"technique": "FTP Anonymous Login", "technique_key": "ftp_anonymous",
          "target": "test.local", "command": "echo login successful",
          "score": 1.0}
KEY = "test.local:FTP Anonymous Login"


class TestFireQueue(unittest.TestCase):
    def setUp(self):
        fd, self._db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        # scope: an engagement is always authorized against its own domain
        self.k = Knull(db_path=self._db, auto_execute=False, use_brain=False,
                       target_domain="test.local")

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(self._db + suffix)
            except OSError:
                pass

    def _prepare(self):
        return self.k._execute(dict(TARGET))

    @staticmethod
    def _kali_ok(*args, **kwargs):
        return {"exit_code": 0, "stdout": "login successful", "stderr": ""}

    def test_dry_run_loop_never_executes(self):
        """Default mode prepares the command but runs nothing."""
        result = self._prepare()
        self.assertFalse(result["executed"])
        self.assertEqual(result["output"], "")
        self.assertEqual(self.k.kill_chain["initial_access"].status,
                         "pending")

    def test_prepared_queue_lists_unfired_command(self):
        self._prepare()
        queue = self.k.prepared_commands()
        self.assertEqual(len(queue), 1)
        self.assertEqual(queue[0]["target_key"], KEY)
        self.assertFalse(queue[0]["fired"])

    def test_fire_runs_and_records(self):
        self._prepare()
        with mock.patch.object(Knull, "_run_in_kali", side_effect=self._kali_ok):
            out = self.k.fire(KEY)
        self.assertTrue(out["ok"])
        self.assertTrue(out["executed"])
        self.assertTrue(out["verified"])
        # the shot advanced the kill chain and was remembered
        self.assertEqual(self.k.kill_chain["initial_access"].status, "success")
        import db_store
        rows = db_store.knull_memory(db_path=self._db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["outcome"], "success")
        self.assertTrue(rows[0]["detail"].startswith("[fired]"))

    def test_fire_marks_queue_item_as_fired(self):
        self._prepare()
        with mock.patch.object(Knull, "_run_in_kali", side_effect=self._kali_ok):
            self.k.fire(KEY)
        self.assertTrue(self.k.prepared_commands()[0]["fired"])

    def test_second_shot_is_refused(self):
        self._prepare()
        with mock.patch.object(Knull, "_run_in_kali", side_effect=self._kali_ok):
            self.k.fire(KEY)
            again = self.k.fire(KEY)
        self.assertFalse(again["ok"])
        self.assertIn("already fired", again["error"])

    def test_unknown_key_is_refused(self):
        """Only commands Knull prepared can be fired — no arbitrary exec."""
        self._prepare()
        with mock.patch.object(Knull, "_run_in_kali") as run:
            out = self.k.fire("some/other/command --flag")
        self.assertFalse(out["ok"])
        run.assert_not_called()

    def test_fire_without_anything_prepared(self):
        with mock.patch.object(Knull, "_run_in_kali") as run:
            out = self.k.fire(KEY)
        self.assertFalse(out["ok"])
        run.assert_not_called()

    def test_failed_shot_is_remembered_as_failure(self):
        self._prepare()

        def kali_fail(*a, **k):
            return {"exit_code": 255, "stdout": "", "stderr": "no route"}

        with mock.patch.object(Knull, "_run_in_kali", side_effect=kali_fail):
            out = self.k.fire(KEY)
        self.assertTrue(out["ok"])
        self.assertFalse(out["verified"])
        self.assertEqual(self.k.kill_chain["initial_access"].status, "pending")

    def test_status_exposes_the_queue(self):
        self._prepare()
        st = self.k.get_status()
        self.assertIn("prepared", st)
        self.assertEqual(st["prepared"][0]["target_key"], KEY)


if __name__ == "__main__":
    unittest.main()
