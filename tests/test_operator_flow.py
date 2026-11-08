import os
import sys
import unittest

os.environ.setdefault("ATTACK_SURFACE_NO_AUTOTERM", "1")  # never pop windows in tests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestVersionSingleSource(unittest.TestCase):
    def test_version_module(self):
        from core.version import __version__
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+$")

    def test_context_uses_version_module(self):
        from core.context import ScanContext
        from core.version import __version__
        ctx = ScanContext(domain="example.com")
        self.assertEqual(ctx.version, "v" + __version__)

    def test_deb_control_matches(self):
        from core.version import __version__
        ctrl = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "packaging/debian/DEBIAN/control")
        with open(ctrl) as f:
            for line in f:
                if line.startswith("Version:"):
                    self.assertEqual(line.split(":", 1)[1].strip(), __version__)
                    return
        self.fail("Version: line not found in control")

    def test_cli_banner_uses_version_module(self):
        import attack_surface
        src = open(attack_surface.__file__).read()
        self.assertIn("v{__version__}", src)
        self.assertNotIn('v0.21.0"', src)
        self.assertNotIn('"0.17.0"', src)


class TestDBPathExpansion(unittest.TestCase):
    def test_expanduser(self):
        import db_store
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            fake_home = os.path.join(td, "home")
            os.makedirs(fake_home, exist_ok=True)
            old = os.environ.get("HOME")
            os.environ["HOME"] = fake_home
            try:
                con, path = db_store._connect("~/.attack_surface/t.db")
                con.close()
                self.assertTrue(path.startswith(fake_home))
                self.assertTrue(os.path.isfile(path))
            finally:
                if old is not None:
                    os.environ["HOME"] = old

    def test_relative_path_no_dirname(self):
        import db_store
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            cwd = os.getcwd()
            os.chdir(td)
            try:
                con, path = db_store._connect("plain.db")
                con.close()
                self.assertEqual(path, "plain.db")
                self.assertTrue(os.path.isfile("plain.db"))
            finally:
                os.chdir(cwd)


class TestTerminalFlow(unittest.TestCase):
    """The core operator flow: finding → attack option → terminal prefilled."""

    def test_rejects_unknown_tool(self):
        from modules import action_center
        r = action_center.open_terminal("not-a-tool", "whatever", "h")
        self.assertFalse(r["ok"])

    def test_rejects_empty_and_multiline(self):
        from modules import action_center
        self.assertFalse(action_center.open_terminal("nmap", "", "h")["ok"])
        self.assertFalse(
            action_center.open_terminal("nmap", "nmap -sV a\nrm -rf /", "h")["ok"])

    def test_whitelist_rejects_raw_shell(self):
        from modules import action_center
        # tool not in whitelist → propose returns None
        self.assertIsNone(action_center.propose("bash", "rm -rf /", "h"))

    def test_local_terminal_prefills_without_exec(self):
        import shutil
        if not (shutil.which("tmux") and shutil.which("nmap")):
            self.skipTest("tmux/nmap not available locally")
        from modules import action_center
        r = action_center.open_terminal(
            "nmap", "nmap -sV -sC --top-ports 100 scanme.example", "scanme.example")
        self.assertTrue(r["ok"], r)
        self.assertIn("tmux attach", r["attach_cmd"])
        self.assertEqual(r["cmd"], "nmap -sV -sC --top-ports 100 scanme.example")
        # command must sit at the prompt, NOT executed
        import subprocess
        cap = subprocess.run(["tmux", "capture-pane", "-p", "-t", r["session"]],
                             capture_output=True, text=True, timeout=10)
        self.assertIn("nmap -sV", cap.stdout)
        subprocess.run(["tmux", "kill-session", "-t", r["session"]],
                       capture_output=True, timeout=10)

    def test_container_tool_detection(self):
        import subprocess
        r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", "kali-as"],
                           capture_output=True, text=True, timeout=15)
        if r.returncode != 0 or r.stdout.strip() != "true":
            self.skipTest("kali-as container not running")
        from modules import action_center
        # hydra + sqlmap + tmux were installed in kali-as for this flow
        self.assertTrue(action_center.tool_available("hydra"))
        self.assertTrue(action_center.tool_available("sqlmap"))


class TestAttackChainDashboard(unittest.TestCase):
    def test_default_chain_shape(self):
        from modules.redteam.attack_chain import SmartAttackChain
        chain = SmartAttackChain().default_chain()
        self.assertGreaterEqual(len(chain), 3)
        for item in chain:
            for k in ("category", "tool", "cmd", "target", "finding", "risk_level"):
                self.assertIn(k, item)

    def test_chain_for_scan_maps_findings(self):
        import db_store
        import tempfile
        from modules.redteam.attack_chain import SmartAttackChain
        with tempfile.TemporaryDirectory() as td:
            dbp = os.path.join(td, "t.db")
            sid = db_store.save_scan({
                "risk": {"overall_score": 55.0, "overall_level": "High"},
                "findings": {
                    "victim.example": [
                        "The host presents a HIGH risk score",
                        "**Public Exposure**: SSH (OpenSSH) is open on port 22",
                        "Weak password login page found on admin panel",
                    ]
                },
                "hosts": [], "subdomains": [],
            }, "victim.example", "0.21.0", db_path=dbp)
            out = SmartAttackChain().chain_for_scan(sid, dbp)
            self.assertIsInstance(out, list)
            tools = [i["tool"] for i in out]
            # SSH open port → enumeration (nmap), credential finding → hydra
            self.assertIn("nmap", tools, out)
            self.assertIn("hydra", tools, out)
            # port must be extracted from the finding text, no <UNSET> left
            for i in out:
                self.assertNotIn("<UNSET", i["cmd"], i)

    def test_keyword_mapping_bruteforce(self):
        from modules.redteam.attack_chain import SmartAttackChain
        chain = SmartAttackChain()
        opts = chain.get_attack_options(
            {"title": "Weak password login page found", "host": "t.example"})
        self.assertTrue(any(o.tool == "hydra" for o in opts), opts)

    def test_risk_trend_series(self):
        import db_store
        import tempfile
        from modules.redteam.risk_trend import RiskTrend
        with tempfile.TemporaryDirectory() as td:
            dbp = os.path.join(td, "t.db")
            db_store.save_scan({"risk": {"overall_score": 10.0, "overall_level": "Low"},
                                "findings": {}, "hosts": [], "subdomains": []},
                               "a.example", "0.21.0", db_path=dbp)
            db_store.save_scan({"risk": {"overall_score": 70.0, "overall_level": "High"},
                                "findings": {}, "hosts": [], "subdomains": []},
                               "a.example", "0.21.0", db_path=dbp)
            s = RiskTrend(db_path=dbp).series("a.example")
            self.assertEqual(s["scores"], [10.0, 70.0])
            self.assertEqual(s["deltas"], [None, 60.0])


class TestRedteamFindingMapping(unittest.TestCase):
    def test_string_finding_maps_to_hydra(self):
        from modules.redteam import create_redteam_orchestrator
        rt = create_redteam_orchestrator()
        acts = rt.map_finding_to_actions(
            {"title": "**Public Exposure**: SSH (OpenSSH) is open on port 22",
             "host": "victim.example"})
        self.assertTrue(any(a.tool == "hydra" for a in acts), acts)
        for a in acts:
            if a.tool == "hydra":
                self.assertIn("unix_users.txt", " ".join(a.cmd))
                self.assertIn("rockyou.txt", " ".join(a.cmd))

    def test_db_port_finding_maps_to_nmap(self):
        from modules.redteam import create_redteam_orchestrator
        rt = create_redteam_orchestrator()
        acts = rt.map_finding_to_actions(
            {"title": "MySQL (3306) exposed to the internet", "host": "db.example"})
        self.assertTrue(any(a.tool == "nmap" for a in acts), acts)


class TestEntrypoint(unittest.TestCase):
    def test_passthrough_and_security_defaults(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        src = open(os.path.join(root, "entrypoint.sh")).read()
        # CLI passthrough exists (dashboard/watch/scan containers work)
        self.assertIn("exec python3 attack_surface.py", src)
        self.assertIn('if [ "$#" -gt 0 ]', src)
        # security: no fixed password, no 0.0.0.0 default, SSL on
        self.assertNotIn("-P attack", src)
        self.assertIn('msfrpcd -U "$MSF_USER" -P "$MSF_RPC_PASS" -p "$MSF_PORT" -a "$MSF_BIND" -n &', src)
        # the actual msfrpcd invocation must not disable SSL (-S)
        invoke = [ln for ln in src.splitlines() if ln.strip().startswith("msfrpcd ")][0]
        self.assertNotIn(" -S", invoke)
        self.assertIn("MSF_BIND:-127.0.0.1", src)
        self.assertIn("SLIVER_BIND:-127.0.0.1", src)
        self.assertIn("msfrpcd.env", src)


class TestDashboardWiring(unittest.TestCase):
    def test_html_has_terminal_and_redteam_nodes(self):
        from modules.dashboard import _HTML
        self.assertIn('id="tab-r2"', _HTML)
        self.assertIn('id="redteam-content"', _HTML)
        self.assertIn("termAction", _HTML)
        self.assertIn("/api/action/terminal", _HTML)
        self.assertIn("attack-chain", _HTML)

    def test_state_payload_exposes_redteam_actions(self):
        from modules.dashboard import _state_payload
        p = _state_payload()
        self.assertIn("scans", p)
        latest = p.get("latest")
        if latest is not None:
            self.assertIn("redteam_actions", latest)


if __name__ == "__main__":
    unittest.main()
