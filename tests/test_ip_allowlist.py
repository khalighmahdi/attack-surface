"""Tests for the IP-allowlist checks (header bypass vs network enforcement).

The defect: an application that decides "is this client internal?" by
reading X-Forwarded-For and friends is not access-controlled at all —
anyone who can set a header is in. The same probe must stay silent when
the gate is real (network layer), and the two verdicts must never be
reported for the same host.
"""
import http.server
import threading
import unittest

from modules.web_misconfig import (check_ip_allowlist_bypass,
                                   check_ip_allowlist_enforcing, run_checks)

PAGE = b"<html><title>Admin Area</title><body>secret</body></html>"


class _Vulnerable(http.server.BaseHTTPRequestHandler):
    """403 unless the client claims to be 127.0.0.1 via X-Forwarded-For."""

    def do_GET(self):
        if self.headers.get("X-Forwarded-For", "").strip() == "127.0.0.1":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(PAGE)))
            self.end_headers()
            self.wfile.write(PAGE)
        else:
            self.send_error(403, "Forbidden")

    def log_message(self, *a):
        pass


class _Safe(http.server.BaseHTTPRequestHandler):
    """Network-style gate: nothing the client sends changes the answer."""

    def do_GET(self):
        self.send_error(403, "Forbidden")

    def log_message(self, *a):
        pass


class _Server:
    def __init__(self, handler):
        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class TestAllowlistHeaderBypass(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln = _Server(_Vulnerable)
        cls.safe = _Server(_Safe)

    @classmethod
    def tearDownClass(cls):
        cls.vuln.stop()
        cls.safe.stop()

    def test_forged_header_is_reported_as_a_finding(self):
        out = check_ip_allowlist_bypass(self.vuln.url)
        self.assertEqual(len(out), 1, "expected exactly one bypass finding")
        f = out[0]
        self.assertEqual(f["type"], "IP_ALLOWLIST_HEADER_BYPASS")
        self.assertEqual(f["severity"], "high")
        self.assertIn("X-Forwarded-For", f["evidence"])
        self.assertIn("403", f["evidence"])

    def test_a_real_gate_produces_no_bypass_finding(self):
        self.assertEqual(check_ip_allowlist_bypass(self.safe.url), [])

    def test_a_real_gate_is_reported_as_enforced(self):
        out = check_ip_allowlist_enforcing(self.safe.url)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["type"], "IP_ALLOWLIST_ENFORCED")
        self.assertEqual(out[0]["severity"], "info")

    def test_an_open_host_is_not_mistaken_for_a_gate(self):
        """A plain 200 means there is no allowlist to characterise."""
        class _Open(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(PAGE)))
                self.end_headers()
                self.wfile.write(PAGE)

            def log_message(self, *a):
                pass

        s = _Server(_Open)
        try:
            self.assertEqual(check_ip_allowlist_bypass(s.url), [])
            self.assertEqual(check_ip_allowlist_enforcing(s.url), [])
        finally:
            s.stop()

    def test_the_two_verdicts_never_contradict_each_other(self):
        """The core invariant: a bypassable host must not also read as
        network-enforced, and a solid host must not read as bypassable."""
        for label, srv in (("vulnerable", self.vuln), ("safe", self.safe)):
            findings = run_checks([{"domain": srv.url.split("//")[1],
                                    "protocol": "http"}])
            types = {f["type"] for f in findings}
            self.assertFalse(
                {"IP_ALLOWLIST_HEADER_BYPASS",
                 "IP_ALLOWLIST_ENFORCED"} <= types,
                "%s host reported both bypassable and enforced: %s"
                % (label, types))
            if label == "vulnerable":
                self.assertIn("IP_ALLOWLIST_HEADER_BYPASS", types)
            else:
                self.assertIn("IP_ALLOWLIST_ENFORCED", types)


class TestAllowlistRiskWeight(unittest.TestCase):
    def test_bypass_carries_a_risk_weight(self):
        from modules.risk_scoring import FINDING_WEIGHTS
        self.assertIn("IP_ALLOWLIST_HEADER_BYPASS", FINDING_WEIGHTS)
        self.assertGreater(FINDING_WEIGHTS["IP_ALLOWLIST_HEADER_BYPASS"], 0)


if __name__ == "__main__":
    unittest.main()
