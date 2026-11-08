"""Tests for Knull's LLM reasoning layer and kill-chain advancement."""

import unittest
from unittest import mock

from modules import knull_brain
from modules.knull import Knull


def _resp(payload, status: int = 200) -> mock.Mock:
    import json as _json
    r = mock.Mock()
    r.status_code = status
    r.json.return_value = {
        "choices": [{"message": {"content": payload if isinstance(payload, str)
                                 else _json.dumps(payload)}}]
    }
    r.text = str(payload)[:200]
    return r


VALID_BRIEF = {
    "domain": "target.example",
    "hosts": [{"host": "target.example", "ports": [22, 80]}],
    "findings": [],
    "kill_chain": {"initial_access": "pending"},
    "memory": {},
    "tried": [],
    "chains": [],
    "techniques": ["sqli", "ssh_brute", "ftp_anonymous"],
}


class TestBrainParsing(unittest.TestCase):
    def test_extracts_raw_json(self):
        self.assertEqual(
            knull_brain._extract_json('{"a": 1}'), {"a": 1})

    def test_extracts_fenced_json(self):
        text = 'Sure.\n```json\n{"a": 1, "b": [2]}\n```\nthanks'
        self.assertEqual(knull_brain._extract_json(text), {"a": 1, "b": [2]})

    def test_extracts_json_surrounded_by_prose(self):
        text = 'Here you go: {"next": {"technique": "sqli"}} hope that helps'
        obj = knull_brain._extract_json(text)
        self.assertIsNotNone(obj)
        assert obj is not None
        self.assertEqual(obj["next"]["technique"], "sqli")

    def test_rejects_non_json(self):
        self.assertIsNone(knull_brain._extract_json("I cannot do that."))
        self.assertIsNone(knull_brain._extract_json(""))
        self.assertIsNone(knull_brain._extract_json("{broken"))


class TestBrainValidation(unittest.TestCase):
    def test_valid_plan_accepted(self):
        plan = {"hypothesis": "SQLi yields db creds",
                "next": {"technique": "sqli", "target": "target.example"},
                "skip": ["xss"], "confidence": 0.7}
        with mock.patch("requests.post",
                        return_value=_resp(plan)) as post:
            out = knull_brain.hypothesize(VALID_BRIEF)
        self.assertIsNotNone(out)
        assert out is not None
        self.assertEqual(out["technique"], "sqli")
        self.assertEqual(out["target"], "target.example")
        self.assertAlmostEqual(out["confidence"], 0.7)
        # the model receives an explicit technique whitelist, so it can
        # only ever name a move we already know how to run
        body = post.call_args.kwargs["json"]
        self.assertIn("ssh_brute", str(body))
        self.assertNotIn("rm -rf", str(body))

    def test_unknown_technique_rejected(self):
        plan = {"hypothesis": "x", "next": {"technique": "make_me_root",
                                            "target": "target.example"},
                "confidence": 0.9}
        with mock.patch("requests.post", return_value=_resp(plan)):
            self.assertIsNone(knull_brain.hypothesize(VALID_BRIEF))

    def test_unknown_target_rejected(self):
        plan = {"hypothesis": "x", "next": {"technique": "sqli",
                                            "target": "not-in-scope.example"},
                "confidence": 0.9}
        with mock.patch("requests.post", return_value=_resp(plan)):
            self.assertIsNone(knull_brain.hypothesize(VALID_BRIEF))

    def test_http_error_returns_none(self):
        with mock.patch("requests.post", return_value=_resp("{}", 500)):
            self.assertIsNone(knull_brain.hypothesize(VALID_BRIEF))

    def test_network_failure_returns_none(self):
        with mock.patch("requests.post",
                        side_effect=RuntimeError("boom")):
            self.assertIsNone(knull_brain.hypothesize(VALID_BRIEF))

    def test_unparseable_reply_returns_none(self):
        with mock.patch("requests.post",
                        return_value=_resp("I refuse to answer")):
            self.assertIsNone(knull_brain.hypothesize(VALID_BRIEF))

    def test_missing_api_key_short_circuits(self):
        with mock.patch.dict("os.environ",
                             {"ATTACK_SURFACE_LLM_API_KEY": "",
                              "KNOLL_LLM_API_KEY": ""}):
            with mock.patch("requests.post") as post:
                self.assertIsNone(knull_brain.hypothesize(VALID_BRIEF))
            post.assert_not_called()

    def test_prompt_carries_scope_and_evidence(self):
        prompt = knull_brain._build_prompt(VALID_BRIEF)
        self.assertIn("target.example", prompt)
        self.assertIn("ssh_brute", prompt)
        self.assertIn("CREDENTIALS ALREADY HELD", prompt)
        self.assertIn("JSON ONLY", prompt)


class TestKillChainPhases(unittest.TestCase):
    def test_brute_force_is_credential_access(self):
        self.assertEqual(Knull._TECHNIQUE_PHASE["ssh_brute"],
                         "credential_access")
        self.assertEqual(Knull._TECHNIQUE_PHASE["rdp_brute"],
                         "credential_access")

    def test_foothold_techniques_are_initial_access(self):
        for key in ("sqli", "ftp_anonymous", "cve_exploit"):
            self.assertEqual(Knull._TECHNIQUE_PHASE[key], "initial_access")

    def test_every_known_technique_has_a_phase(self):
        from modules.attack_advisor import ATTACK_TECHNIQUES
        missing = set(ATTACK_TECHNIQUES) - set(Knull._TECHNIQUE_PHASE)
        self.assertEqual(missing, set(),
                         "techniques without a kill-chain phase: %s" % missing)


class TestCredentialHarvest(unittest.TestCase):
    def setUp(self):
        import os
        import tempfile
        # Tests must never write into the production memory table.
        fd, self._db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.k = Knull(db_path=self._db)

    def tearDown(self):
        import os
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(self._db + suffix)
            except OSError:
                pass

    def test_extracts_explicit_credentials(self):
        out = self.k._harvest_credentials(
            "Found: username=admin password=Sup3rS3cret!")
        self.assertEqual(out, [{"username": "admin",
                                "password": "Sup3rS3cret!"}])

    def test_ignores_noise(self):
        for text in ("hydra: tried 1000 passwords, all failed",
                     "ERROR: connection refused",
                     "password policy requires 12 characters"):
            self.assertEqual(self.k._harvest_credentials(text), [], text)

    def test_deduplicates(self):
        text = "user=a pass=1\nuser=a pass=1"
        self.assertEqual(len(self.k._harvest_credentials(text)), 1)

    def test_success_marks_phase_and_harvests(self):
        target = {"technique": "SQL Injection", "technique_key": "sqli",
                  "target": "target.example", "score": 8.5}
        result = {"executed": True, "exit_code": 0,
                  "output": "username=sa password=P@ssw0rd"}
        self.k._on_success(target, result)
        self.assertEqual(self.k.kill_chain["initial_access"].status, "success")
        self.assertEqual(self.k.kill_chain["credential_access"].status,
                         "success")
        self.assertEqual(len(self.k.credentials_found), 1)

    def test_shell_output_marks_execution(self):
        target = {"technique": "CVE Exploitation", "technique_key": "cve_exploit",
                  "target": "target.example", "score": 20}
        result = {"executed": True, "exit_code": 0,
                  "output": "meterpreter > sysinfo\nuid=33(www-data)"}
        self.k._on_success(target, result)
        self.assertEqual(self.k.kill_chain["execution"].status, "success")

    def test_dry_run_changes_nothing(self):
        target = {"technique": "SQL Injection", "technique_key": "sqli",
                  "target": "target.example", "score": 8.5}
        result = {"executed": False, "output": ""}
        self.assertIsNone(self.k._verify(result))
        self.assertEqual(self.k.kill_chain["initial_access"].status, "pending")


if __name__ == "__main__":
    unittest.main()
