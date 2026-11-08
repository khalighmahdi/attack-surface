"""Smoke tests for attack-surface core logic (no network).

Run:  python3 -m tests.test_smoke   (or pytest)
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils import sanitize_domain            # noqa: E402
from core.scope import ScopeFilter                # noqa: E402
from modules.risk_scoring import calculate_risk, _risk_level  # noqa: E402


class TestSanitizeDomain(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(sanitize_domain("Example.COM"), "example.com")

    def test_strips_scheme_path(self):
        self.assertEqual(sanitize_domain("https://Example.com/path?q=1#f"), "example.com")
        self.assertEqual(sanitize_domain("http://example.com."), "example.com")

    def test_rejects_garbage(self):
        for bad in ("", None, "not a domain!!", "http://"):
            with self.assertRaises(ValueError):
                sanitize_domain(bad)


class TestScopeFilter(unittest.TestCase):
    def test_primary_domain_allowed(self):
        sf = ScopeFilter(primary="example.com")
        self.assertTrue(sf.check("sub.example.com").allowed)
        self.assertTrue(sf.check("example.com").allowed)

    def test_out_of_scope_blocked(self):
        sf = ScopeFilter(primary="example.com")
        self.assertFalse(sf.check("evil.com").allowed)
        self.assertFalse(sf.check("example.com.evil.com").allowed)

    def test_suffix_trap(self):
        sf = ScopeFilter(primary="example.com")
        d = sf.check("notexample.com")
        self.assertFalse(d.allowed)


class TestRiskScoring(unittest.TestCase):
    def test_level_bands(self):
        self.assertEqual(_risk_level(0), "Low")
        self.assertEqual(_risk_level(20), "Medium")
        self.assertEqual(_risk_level(40), "High")
        self.assertEqual(_risk_level(75), "Critical")

    def test_calculate_risk_empty(self):
        r = calculate_risk([])
        self.assertEqual(r["overall_score"], 0)
        self.assertEqual(r["overall_level"], "Low")


if __name__ == "__main__":
    unittest.main(verbosity=2)
