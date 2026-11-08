"""Tests for nuclei/httpx command construction and v3 output parsing.

These guard three bugs that silently zeroed every scan:
  * `-random-agent` does not exist in nuclei v3 → exit 2, no output;
  * strategy flags were appended element-wise, leaking bare values;
  * v3 emits kebab-case keys (`template-id`, `matched-at`) while the
    parsers read snake_case, so every finding lost its template id.
"""

import unittest
from unittest import mock

from modules.waf_evasion import (_flag_pairs, _merge_flag_pairs,
                                 _sanitize_flags, build_httpx_command,
                                 build_nuclei_command, get_evasion_strategy,
                                 normalize_nuclei_finding)

NUCLEI_FLAGS = ["-l", "-severity", "-silent", "-j", "-timeout",
                "-rate-limit", "-retries", "-headless", "-t"]
HTTPX_FLAGS = ["-l", "-silent", "-status-code", "-title", "-tech-detect",
               "-content-length", "-web-server", "-ip", "-cname", "-cdn",
               "-rt", "-json", "-timeout", "-threads", "-random-agent",
               "-http2", "-follow-redirects"]


class TestFlagPairs(unittest.TestCase):
    def test_pairs_keep_values_with_their_flags(self):
        self.assertEqual(
            _flag_pairs(["nuclei", "-severity", "high,critical", "-silent"]),
            [("-severity", ["high,critical"]), ("-silent", [])])

    def test_stray_leading_value_is_dropped(self):
        """Values with no owning flag are discarded; the rest attach."""
        self.assertEqual(_flag_pairs(["5", "-retries", "2", "9"]),
                         [("-retries", ["2", "9"])])


class TestMergeFlagPairs(unittest.TestCase):
    def test_program_name_survives(self):
        """argv[0] must never be eaten as a stray value."""
        merged = _merge_flag_pairs(["nuclei", "-l", "/tmp/t"],
                                   ["-rate-limit", "5"])
        self.assertEqual(merged[0], "nuclei")
        self.assertIn("/tmp/t", merged)

    def test_strategy_value_replaces_default(self):
        merged = _merge_flag_pairs(["nuclei", "-rate-limit", "10"],
                                   ["-rate-limit", "5"])
        self.assertEqual(merged, ["nuclei", "-rate-limit", "5"])

    def test_no_bare_values_leak_out(self):
        merged = _merge_flag_pairs(
            ["nuclei", "-silent"], ["-rate-limit", "5", "-retries", "2"])
        self.assertEqual(merged, ["nuclei", "-silent",
                                  "-rate-limit", "5", "-retries", "2"])


class TestSanitizeFlags(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch(
            "modules.waf_evasion._tool_supported_flags",
            return_value=NUCLEI_FLAGS)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_unsupported_flag_and_its_value_are_dropped(self):
        out = _sanitize_flags(
            ["nuclei", "-random-agent", "-severity", "high"], "nuclei")
        self.assertNotIn("-random-agent", out)
        self.assertEqual(out, ["nuclei", "-severity", "high"])

    def test_supported_flags_survive(self):
        out = _sanitize_flags(["nuclei", "-severity", "high", "-silent"],
                              "nuclei")
        self.assertEqual(out, ["nuclei", "-severity", "high", "-silent"])

    def test_headless_removed_when_no_browser(self):
        with mock.patch("modules.waf_evasion._headless_available",
                        return_value=False):
            out = _sanitize_flags(["nuclei", "-headless", "5", "-silent"],
                                  "nuclei")
        self.assertNotIn("-headless", out)
        self.assertNotIn("5", out)
        self.assertIn("-silent", out)

    def test_headless_kept_when_browser_exists(self):
        with mock.patch("modules.waf_evasion._headless_available",
                        return_value=True):
            out = _sanitize_flags(["nuclei", "-headless", "-silent"],
                                  "nuclei")
        self.assertIn("-headless", out)

    def test_unknown_tool_means_no_filtering(self):
        with mock.patch("modules.waf_evasion._tool_supported_flags",
                        return_value=[]):
            out = _sanitize_flags(["nuclei", "-whatever"], "nuclei")
        self.assertIn("-whatever", out)


class TestBuiltCommands(unittest.TestCase):
    def setUp(self):
        p1 = mock.patch("modules.waf_evasion._tool_supported_flags",
                        return_value=NUCLEI_FLAGS)
        p2 = mock.patch("modules.waf_evasion._headless_available",
                        return_value=False)
        p1.start(); self.addCleanup(p1.stop)
        p2.start(); self.addCleanup(p2.stop)

    def test_nuclei_command_is_executable(self):
        cmd = build_nuclei_command(
            "/tmp/t", get_evasion_strategy([]),
            severity="info,low,medium,high,critical")
        self.assertEqual(cmd[0], "nuclei")
        self.assertNotIn("-random-agent", cmd)
        self.assertNotIn("-headless", cmd)
        # -l's value must still be there
        self.assertEqual(cmd[cmd.index("-l") + 1], "/tmp/t")

    def test_default_strategy_no_longer_forces_a_crawl(self):
        """No detected WAF ⇒ the caller's rate must win (was pinned at 5)."""
        cmd = build_nuclei_command("/tmp/t", get_evasion_strategy([]),
                                   rate_limit=20)
        self.assertEqual(cmd[cmd.index("-rate-limit") + 1], "20")

    def test_waf_strategy_still_overrides_rate(self):
        """A real WAF strategy keeps its deliberate throttling."""
        strat = {"description": "cloudflare", "strategies": [],
                 "httpx_flags": [],
                 "nuclei_flags": ["-rate-limit", "5", "-retries", "2"]}
        cmd = build_nuclei_command("/tmp/t", strat, rate_limit=50)
        self.assertEqual(cmd[cmd.index("-rate-limit") + 1], "5")

    def test_rate_limit_cap_is_not_the_old_10(self):
        cmd = build_nuclei_command("/tmp/t", get_evasion_strategy([]),
                                   rate_limit=500)
        self.assertEqual(cmd[cmd.index("-rate-limit") + 1], "100")

    def test_httpx_command_keeps_binary_and_its_valid_flag(self):
        with mock.patch("modules.waf_evasion._tool_supported_flags",
                        return_value=HTTPX_FLAGS):
            cmd = build_httpx_command("/tmp/t", get_evasion_strategy([]))
        self.assertEqual(cmd[0], "httpx")
        self.assertIn("-random-agent", cmd)  # httpx does support it
        self.assertEqual(cmd[cmd.index("-l") + 1], "/tmp/t")


class TestNormalizeNucleiFinding(unittest.TestCase):
    def test_v3_kebab_keys_are_mapped(self):
        d = {"template-id": "git-config",
             "matched-at": "https://x/.git/config",
             "url": "https://x",
             "type": "http",
             "info": {"name": "Git Configuration - Detect",
                      "severity": "Medium",
                      "classification": {"cve-id": "CVE-2021-44228"}}}
        out = normalize_nuclei_finding(d)
        self.assertEqual(out["template_id"], "git-config")
        self.assertEqual(out["matched_at"], "https://x/.git/config")
        self.assertEqual(out["url"], "https://x/.git/config")
        self.assertEqual(out["severity"], "medium")
        self.assertEqual(out["cve"], "CVE-2021-44228")

    def test_legacy_snake_keys_still_work(self):
        d = {"template_id": "old", "matched_at": "https://y/a",
             "info": {"name": "n", "severity": "low"}}
        out = normalize_nuclei_finding(d)
        self.assertEqual(out["template_id"], "old")
        self.assertEqual(out["matched_at"], "https://y/a")
        self.assertEqual(out["severity"], "low")

    def test_missing_fields_default_safely(self):
        out = normalize_nuclei_finding({"info": {}})
        self.assertEqual(out["template_id"], "")
        self.assertEqual(out["severity"], "info")
        self.assertEqual(out["reference"], [])

    def test_advisor_reads_the_normalized_shape(self):
        from modules.attack_advisor import extract_target_properties
        scan = {"domain": "x.example",
                "hosts": [{"host": "x.example", "ip": "", "ports": [],
                           "tech": []}],
                "subdomains": [], "findings": [],
                "sections": {"nuclei": [normalize_nuclei_finding(
                    {"template-id": "cve-2021-44228",
                     "matched-at": "https://x.example/login",
                     "info": {"name": "Log4j", "severity": "critical",
                              "classification": {"cve-id": "CVE-2021-44228"}}})]}}
        props = extract_target_properties(scan)[0]
        self.assertTrue(props["cve_detected"])


class TestStreamingRunner(unittest.TestCase):
    """A timeout must keep the findings already collected, not drop them."""

    def test_completes_within_budget(self):
        from modules.waf_evasion import _run_streaming
        out, rc, timed_out = _run_streaming(
            ["bash", "-c", "echo one; echo two"], timeout=15)
        self.assertFalse(timed_out)
        self.assertEqual(rc, 0)
        self.assertIn("one", out)
        self.assertIn("two", out)

    def test_timeout_keeps_partial_output(self):
        from modules.waf_evasion import _run_streaming
        out, _rc, timed_out = _run_streaming(
            ["bash", "-c", "echo first-finding; sleep 60"], timeout=3)
        self.assertTrue(timed_out)
        self.assertIn("first-finding", out)

    def test_timeout_kills_the_process(self):
        from modules.waf_evasion import _run_streaming
        _out, rc, timed_out = _run_streaming(["sleep", "60"], timeout=2)
        self.assertTrue(timed_out)
        self.assertEqual(rc, -9)  # SIGKILL — no orphaned worker left


if __name__ == "__main__":
    unittest.main()
