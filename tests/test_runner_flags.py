"""Regression guard: independent feature flags must not be chained.

`elif self.map_cves` bound the NVD CVE mapping to `if self.critical_web`.
critical_web defaults to ON, so its branch always ran and the `elif` was
dead code — `--cves` never executed in any scan ever taken and
sections['cves'] stayed empty even with the flag passed.

These tests fail if any feature flag becomes an elif again.
"""

import ast
import inspect
import unittest

import core.runner as runner_mod

# Flags that must each control an INDEPENDENT branch of the pipeline.
FEATURE_FLAGS = (
    "map_cves", "cve_deep", "critical_web", "use_baseline",
    "enable_httpx", "enable_nuclei", "skip_admin", "skip_origin",
)


class TestFeatureFlagsAreIndependent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse(inspect.getsource(runner_mod))

    def _chained_flags(self):
        chained = []
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.If):
                continue
            for branch in node.orelse:
                if isinstance(branch, ast.If):
                    test = ast.unparse(branch.test)
                    for flag in FEATURE_FLAGS:
                        if f"self.{flag}" in test:
                            chained.append((branch.lineno, test))
        return chained

    def test_no_feature_flag_is_an_elif(self):
        self.assertEqual(
            self._chained_flags(), [],
            "feature flags were chained with elif: enabling one silently "
            "disables the other")

    def test_map_cves_has_its_own_if(self):
        """--cves must be reachable when critical_web is also on."""
        found = False
        for node in ast.walk(self.tree):
            if isinstance(node, ast.If) and "self.map_cves" in ast.unparse(node.test):
                found = True
        self.assertTrue(found, "map_cves branch is missing entirely")

    def test_map_cves_branch_logs_its_entry(self):
        """The branch must announce itself so a scan log proves it ran."""
        src = inspect.getsource(runner_mod)
        self.assertIn("CVE watchlist (NVD)", src)
        self.assertNotIn("elif self.map_cves", src)


class TestIndependentIfBlocks(unittest.TestCase):
    def test_cve_block_follows_another_independent_if(self):
        """Sanity: critical_web and map_cves are separate If statements."""
        src = inspect.getsource(runner_mod)
        idx_crit = src.find("if self.critical_web:")
        idx_cve = src.find("if self.map_cves:")
        self.assertNotEqual(idx_crit, -1)
        self.assertNotEqual(idx_cve, -1)
        self.assertGreater(idx_cve, idx_crit)


if __name__ == "__main__":
    unittest.main()
