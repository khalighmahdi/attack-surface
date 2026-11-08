"""Tests for Knull session persistence (knull_runs).

The in-memory agent dies with the dashboard; these rows are what keep a
session reviewable afterwards, and what lets the chat say what the
previous runs actually did.
"""

import os
import tempfile
import unittest

import db_store
from modules.knull import Knull


def _db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return path


def _cleanup(path):
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(path + suffix)
        except OSError:
            pass


class TestRunStore(unittest.TestCase):
    def setUp(self):
        self.db = _db()

    def tearDown(self):
        _cleanup(self.db)

    def test_save_and_read_back(self):
        db_store.save_knull_run({
            "agent_id": "abc123", "ts_start": "2026-01-01T00:00:00",
            "ts_end": "2026-01-01T00:05:00", "domain": "t.example",
            "scan_id": 7, "state": "done", "iteration": 3,
            "max_iterations": 10, "brain_calls": 2, "prepared": 4,
            "fired": 1, "credentials": 0,
            "kill_chain": {"initial_access": {"status": "success"}},
            "moves": ["t.example:SQL Injection"],
            "events": [{"action": "advisor_result", "detail": "9 paths"}],
        }, db_path=self.db)
        runs = db_store.list_knull_runs(db_path=self.db)
        self.assertEqual(len(runs), 1)
        r = runs[0]
        self.assertEqual(r["agent_id"], "abc123")
        self.assertEqual(r["domain"], "t.example")
        self.assertEqual(r["scan_id"], 7)
        self.assertEqual(r["brain_calls"], 2)
        self.assertEqual(r["moves"], ["t.example:SQL Injection"])
        self.assertNotIn("events", r)  # list view stays light

        full = db_store.get_knull_run("abc123", db_path=self.db)
        self.assertEqual(len(full["events"]), 1)
        self.assertEqual(full["kill_chain"]["initial_access"]["status"],
                         "success")

    def test_second_save_updates_the_same_row(self):
        for state in ("running", "done"):
            db_store.save_knull_run({"agent_id": "x", "state": state,
                                     "domain": "t.example"},
                                    db_path=self.db)
        runs = db_store.list_knull_runs(db_path=self.db)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["state"], "done")

    def test_newest_first_and_limited(self):
        for i in range(5):
            db_store.save_knull_run({"agent_id": f"a{i}", "iteration": i},
                                    db_path=self.db)
        runs = db_store.list_knull_runs(limit=2, db_path=self.db)
        self.assertEqual([r["agent_id"] for r in runs], ["a4", "a3"])

    def test_unknown_agent_is_none(self):
        self.assertIsNone(db_store.get_knull_run("nope", db_path=self.db))

    def test_empty_agent_id_is_ignored(self):
        db_store.save_knull_run({}, db_path=self.db)
        db_store.save_knull_run({"agent_id": ""}, db_path=self.db)
        self.assertEqual(db_store.list_knull_runs(db_path=self.db), [])

    def test_malformed_json_does_not_crash(self):
        db_store.init_db(self.db)
        con, _ = db_store._connect(self.db)
        con.execute("INSERT INTO knull_runs (agent_id, moves, events, "
                    "kill_chain) VALUES ('bad', 'not json', 'x', 'y')")
        con.commit()
        con.close()
        run = db_store.get_knull_run("bad", db_path=self.db)
        self.assertEqual(run["moves"], [])
        self.assertEqual(run["kill_chain"], {})


class TestKnullPersistsItsRun(unittest.TestCase):
    def setUp(self):
        self.db = _db()

    def tearDown(self):
        _cleanup(self.db)

    def test_run_is_written_when_start_finishes(self):
        k = Knull(db_path=self.db, target_domain="t.example",
                  use_brain=False, max_iterations=2)
        k.start()
        runs = db_store.list_knull_runs(db_path=self.db)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["domain"], "t.example")
        self.assertEqual(runs[0]["state"], "done")
        self.assertGreaterEqual(runs[0]["iteration"], 0)

    def test_run_is_written_on_stop(self):
        k = Knull(db_path=self.db, target_domain="t.example",
                  use_brain=False)
        k.stop()
        runs = db_store.list_knull_runs(db_path=self.db)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["state"], "idle")

    def test_decisions_are_recorded_as_moves(self):
        k = Knull(db_path=self.db, target_domain="t.example",
                  use_brain=False, max_iterations=1)
        k._emit("decide", "target_selected", "pick",
                data={"target_key": "t.example:SQL Injection"})
        k._persist_run()
        run = db_store.get_knull_run(k.agent_id, db_path=self.db)
        self.assertEqual(run["moves"], ["t.example:SQL Injection"])

    def test_history_survives_a_fresh_instance(self):
        """The whole point: a restart must not lose the session."""
        k = Knull(db_path=self.db, target_domain="t.example",
                  use_brain=False, max_iterations=1)
        k.start()
        agent_id = k.agent_id
        del k  # simulate the dashboard going away
        runs = db_store.list_knull_runs(db_path=self.db)
        self.assertEqual(runs[0]["agent_id"], agent_id)

    def test_a_persist_failure_never_breaks_the_run(self):
        k = Knull(db_path="/nonexistent-dir/none.db", target_domain="t.example",
                  use_brain=False)
        k._persist_run()  # must not raise


if __name__ == "__main__":
    unittest.main()
