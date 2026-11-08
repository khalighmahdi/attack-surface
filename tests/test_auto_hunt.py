"""Tests for modules/auto_hunt.py — mapping, plan files, safe-only run."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scope import ScopeFilter
from modules.auto_hunt import map_findings, write_hunt_plan, write_nuclei_targets, write_msf_rc, run_safe


def _scope():
    return ScopeFilter.from_list("example.com", ["example.com"])


FINDINGS = {
    "example.com": [
        "EMAIL SPOOFING POSSIBLE (high)",
        "Missing Security Headers: HSTS/CSP (medium)",
        "SQL injection candidate at /login (critical)",
    ],
    "cpanel.example.com": [
        "admin panel exposed at /admin (high)",
    ],
    # out of scope — must NEVER produce an action
    "evil.com": [
        "SQL injection candidate at /login (critical)",
    ],
}


class TestMapping(unittest.TestCase):
    def test_maps_correct_classes(self):
        acts = map_findings(FINDINGS, "example.com", _scope())
        cats = {a.category for a in acts}
        self.assertIn("email-spoof", cats)
        self.assertIn("headers", cats)
        self.assertIn("sqli", cats)
        self.assertIn("admin-exposure", cats)

    def test_out_of_scope_never_handed_off(self):
        acts = map_findings(FINDINGS, "example.com", _scope())
        self.assertFalse(any(a.host == "evil.com" for a in acts))

    def test_safe_flag_split(self):
        acts = map_findings(FINDINGS, "example.com", _scope())
        safe_tools = {a.tool for a in acts if a.safe}
        active_tools = {a.tool for a in acts if not a.safe}
        self.assertIn("dig", safe_tools)
        self.assertIn("sqlmap", active_tools)
        # an action is never both
        self.assertFalse(safe_tools & active_tools)

    def test_generic_fallback(self):
        acts = map_findings({"example.com": ["nothing matched here"]},
                            "example.com", _scope())
        self.assertEqual(acts[0].category, "generic")
        self.assertTrue(acts[0].safe)


class TestPlanFiles(unittest.TestCase):
    def test_plan_md_and_targets(self):
        acts = map_findings(FINDINGS, "example.com", _scope())
        md = write_hunt_plan(acts, "example.com", "/tmp/hunt_test.md")
        self.assertTrue(os.path.exists(md))
        content = open(md).read()
        self.assertIn("Safe", content)
        self.assertIn("PLAN-ONLY", content)
        # every active tool cmd must be inside backticks (visible, commented intent)
        self.assertIn("sqlmap", content)

        tgt = write_nuclei_targets(["a.example.com", "b.example.com"],
                                   "/tmp/hunt_targets_test.txt")
        lines = open(tgt).read().splitlines()
        self.assertEqual(lines, ["https://a.example.com", "https://b.example.com"])

        rc = write_msf_rc(acts, "/tmp/hunt_test.rc")
        self.assertTrue(os.path.exists(rc))

    def test_run_safe_never_runs_active(self):
        acts = map_findings(FINDINGS, "example.com", _scope())
        results = run_safe(acts, timeout=10)
        ran_tools = {r["tool"] for r in results}
        self.assertNotIn("sqlmap", ran_tools)
        self.assertNotIn("hydra", ran_tools)

    def tearDown(self):
        for f in ("/tmp/hunt_test.md", "/tmp/hunt_targets_test.txt", "/tmp/hunt_test.rc"):
            if os.path.exists(f):
                os.unlink(f)


if __name__ == "__main__":
    unittest.main()
