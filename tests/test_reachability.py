"""Tests for scan reachability reporting.

A scan of an unreachable target produces zero findings — which must never
be mistaken for a clean scan. Reachability is recorded explicitly and
surfaced as a coverage finding.
"""

import unittest

from core.runner import ScannerRunner


class _Ctx:
    def __init__(self, hosts=(), ports=None, http_results=None, domain="t.example"):
        self.domain = domain
        self.alive_hosts = list(hosts)
        self.ports = ports if ports is not None else {}
        self.http_results = http_results or []
        self.findings = {}

    def check(self):
        ScannerRunner._record_reachability(self)
        return self.reachability


class TestReachability(unittest.TestCase):
    def test_http_answer_means_reachable(self):
        ctx = _Ctx(hosts=[{"domain": "t.example", "http_ok": True}])
        state = ctx.check()
        self.assertTrue(state["reachable"])
        self.assertEqual(state["state"], "reachable")
        self.assertEqual(ctx.findings, {})  # no warning when healthy

    def test_httpx_results_alone_mean_reachable(self):
        ctx = _Ctx(http_results=[{"url": "https://t.example", "status": 200}])
        self.assertEqual(ctx.check()["state"], "reachable")

    def test_open_ports_without_http_is_no_web(self):
        ctx = _Ctx(hosts=[{"domain": "t.example"}],
                   ports={"t.example": {"open_ports": [{"port": 21},
                                                       {"port": 22}]}})
        state = ctx.check()
        self.assertEqual(state["state"], "no_web")
        self.assertFalse(state["reachable"])
        self.assertEqual(state["open_ports"], 2)
        self.assertIn("web-phase coverage is incomplete",
                      state["note"])

    def test_nothing_answered_is_unreachable_and_recorded(self):
        ctx = _Ctx()
        state = ctx.check()
        self.assertEqual(state["state"], "unreachable")
        self.assertFalse(state["reachable"])
        rows = ctx.findings["t.example"]
        self.assertEqual(len(rows), 1)
        self.assertIn("UNREACHABLE", rows[0])
        self.assertIn("INCOMPLETE, not clean", rows[0])
        self.assertTrue(rows[0].endswith("(high)"))

    def test_counts_are_reported(self):
        ctx = _Ctx(hosts=[{"domain": "a", "http_ok": True},
                          {"domain": "b"}])
        state = ctx.check()
        self.assertEqual(state["http_hosts"], 1)
        self.assertEqual(state["hosts_checked"], 2)

    def test_malformed_ports_do_not_crash(self):
        ctx = _Ctx(ports={"t.example": "not-a-dict"})
        self.assertEqual(ctx.check()["state"], "unreachable")


if __name__ == "__main__":
    unittest.main()
