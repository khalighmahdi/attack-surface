"""Tests for continuous ASM wiring and the ready-to-run arsenal."""

import os
import tempfile
import unittest
from pathlib import Path

import db_store
from core.runner import ScannerRunner
from core.scope import ScopeFilter
from modules import ops_arsenal


class _Ctx:
    """Minimal stand-in for ScanContext."""

    def __init__(self, domain="t.example", subs=None, findings=None):
        self.domain = domain
        self.scan_id = 0
        self.subdomains = subs or [domain, "www." + domain]
        self.alive_hosts = [{"domain": domain, "ip": "10.0.0.5"}]
        self.ports = {domain: {"open_ports": [{"port": 22, "service": "ssh"}]}}
        self.technologies = {domain: ["nginx"]}
        self.findings = findings or {domain: ["**Public Exposure**: SSH open"]}
        self.events = []
        self.asm_changes = None


class TestAsmWiring(unittest.TestCase):
    def setUp(self):
        self.db = tempfile.mktemp(suffix=".asm.db")
        self.runner = ScannerRunner(enable_asm=True,
                                    scope=ScopeFilter(primary="t.example"))
        self.runner.asm_db_path = self.db

    def tearDown(self):
        for s in ("", "-wal", "-shm"):
            try:
                os.unlink(self.db + s)
            except OSError:
                pass

    def test_first_scan_records_a_baseline(self):
        ctx = _Ctx()
        self.runner._run_asm(ctx)
        self.assertIsNotNone(ctx.asm_changes)
        self.assertTrue(ctx.asm_changes)
        self.assertTrue(all(c.get("type") == "baseline"
                            for c in ctx.asm_changes),
                        ctx.asm_changes)

    def test_a_new_subdomain_is_reported(self):
        ctx = _Ctx()
        self.runner._run_asm(ctx)                      # baseline
        ctx.subdomains = ctx.subdomains + ["new.t.example"]
        self.runner._run_asm(ctx)
        added = [c for c in ctx.asm_changes if c.get("type") == "added"]
        self.assertTrue(added, f"expected an added subdomain, got {ctx.asm_changes}")
        self.assertTrue(any("new.t.example" in str(c.get("value"))
                            for c in added))

    def test_a_new_port_is_reported(self):
        ctx = _Ctx()
        self.runner._run_asm(ctx)
        ctx.ports["t.example"]["open_ports"].append(
            {"port": 3306, "service": "mysql"})
        self.runner._run_asm(ctx)
        self.assertTrue(any("3306" in str(c.get("value"))
                            for c in ctx.asm_changes), ctx.asm_changes)

    def test_disabled_asm_writes_nothing(self):
        runner = ScannerRunner(enable_asm=False,
                               scope=ScopeFilter(primary="t.example"))
        runner.asm_db_path = self.db
        ctx = _Ctx()
        runner._run_asm(ctx)
        self.assertIsNone(ctx.asm_changes)

    def test_asm_failure_never_raises(self):
        self.runner.asm_db_path = "/nonexistent-dir/x.db"
        ctx = _Ctx()
        self.runner._run_asm(ctx)   # must not raise
        self.assertIsNotNone(ctx.asm_changes)


class TestReadyActions(unittest.TestCase):
    def setUp(self):
        fd, self._db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db_store.save_scan({
            "risk": {"overall_score": 55.0, "overall_level": "High"},
            "hosts": [{"host": "t.example", "ip": "10.0.0.5",
                       "ports": [{"port": 21}, {"port": 22}], "tech": []}],
            "subdomains": ["t.example"],
            "findings": {
                "t.example": [
                    "**Public Exposure**: FTP is open on port 21",
                    "**Missing Security Headers**: HSTS absent",
                    "WordPress CMS detected",
                ]},
            "sections": {"cves": {"t.example": [{
                "tech": "Apache", "match": "cpe_exact",
                "cves": [{"id": "CVE-2021-41773", "cvss": 7.5, "kev": True,
                          "metasploit": [{"path": "exploit/multi/http/apache_traversal"}],
                          "exploitdb": 50512,
                          "summary": "path traversal"}]}]}},
        }, "t.example", "test", db_path=self._db)

    def tearDown(self):
        for s in ("", "-wal", "-shm"):
            try:
                os.unlink(self._db + s)
            except OSError:
                pass

    def test_findings_map_to_commands(self):
        out = ops_arsenal.ready_actions(db_path=self._db)
        self.assertEqual(out["target"], "t.example")
        tools = {a["tool"] for f in out["findings"] for a in f["actions"]}
        self.assertIn("nmap", tools)          # public exposure -> port scan
        self.assertIn("curl", tools)          # missing headers
        self.assertIn("wpscan", tools)        # wordpress
        # every command is a real string an operator can paste
        for f in out["findings"]:
            for a in f["actions"]:
                self.assertTrue(a["cmd"], a)
                self.assertNotIn("<your", a["cmd"].replace("<your-ip>", ""))

    def test_cve_carries_its_metasploit_module(self):
        out = ops_arsenal.ready_actions(db_path=self._db)
        self.assertEqual(len(out["cves"]), 1)
        cve = out["cves"][0]
        self.assertEqual(cve["cve"], "CVE-2021-41773")
        self.assertEqual(cve["match"], "cpe_exact")
        self.assertTrue(cve["kev"])
        cmds = " ".join(c["cmd"] for c in cve["commands"])
        self.assertIn("msfconsole", cmds)
        self.assertIn("exploit/multi/http/apache_traversal", cmds)
        self.assertIn("searchsploit CVE-2021-41773", cmds)
        self.assertIn("RHOSTS t.example", cmds)

    def test_every_cve_gets_a_searchsploit_fallback(self):
        out = ops_arsenal.ready_actions(db_path=self._db)
        self.assertTrue(any("searchsploit" in c["cmd"]
                            for c in out["cves"][0]["commands"]))

    def test_totals_match(self):
        out = ops_arsenal.ready_actions(db_path=self._db)
        t = out["totals"]
        self.assertEqual(t["findings"], len(out["findings"]))
        self.assertEqual(t["cves"], len(out["cves"]))

    def test_empty_db_is_safe(self):
        fd, db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            out = ops_arsenal.ready_actions(db_path=db)
            self.assertIsNone(out["target"])
            self.assertEqual(out["totals"]["prepared"], 0)
        finally:
            for s in ("", "-wal", "-shm"):
                try:
                    os.unlink(db + s)
                except OSError:
                    pass


if __name__ == "__main__":
    unittest.main()
