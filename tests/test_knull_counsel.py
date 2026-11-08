"""Tests for the operator <-> Knull chat (KnullCounsel).

Two things must hold: the reply can only be grounded in context we built
ourselves, and anything the model proposes as an action must survive
whitelisting before the UI is allowed to offer it as a button.
"""

import os
import tempfile
import unittest
from unittest import mock

import db_store
from modules import knull_counsel as kc

SCAN = {"risk": {"overall_score": 61.0, "overall_level": "High"},
        "findings": {"h.example": ["**Public Exposure**: FTP is open on port 21"]},
        "hosts": [], "subdomains": ["h.example"],
        "sections": {"reachability": {"state": "unreachable",
                                      "note": "target did not answer"}}}


def _db_with_scan():
    fd, db = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db_store.save_scan(SCAN, "h.example", "test", db_path=db)
    return db


class TestBuildContext(unittest.TestCase):
    def setUp(self):
        self.db = _db_with_scan()

    def tearDown(self):
        for s in ("", "-wal", "-shm"):
            try:
                os.unlink(self.db + s)
            except OSError:
                pass

    def test_contains_the_real_scan_numbers(self):
        ctx = kc.build_context(db_path=self.db)
        self.assertIn("domain=h.example", ctx)
        self.assertIn("risk=61.0 (High)", ctx)
        self.assertIn("reachability=unreachable", ctx)
        self.assertIn("[LEARNING SCOREBOARD]", ctx)
        self.assertIn("[CHAINS]", ctx)
        self.assertIn("[SCOPE]", ctx)
        self.assertIn("h.example", ctx.split("[SCOPE]")[-1])

    def test_findings_are_included(self):
        ctx = kc.build_context(db_path=self.db)
        self.assertIn("FTP is open on port 21", ctx)

    def test_survives_no_scan_and_no_agent(self):
        fd, db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            ctx = kc.build_context(db_path=db, agent=None)
            self.assertIn("(no scan)", ctx)
            self.assertIn("(no agent running)", ctx)
        finally:
            for s in ("", "-wal", "-shm"):
                try:
                    os.unlink(db + s)
                except OSError:
                    pass

    def test_includes_agent_queue_and_scope_when_present(self):
        from modules.knull import Knull
        agent = Knull(db_path=self.db, target_domain="h.example",
                      use_brain=False)
        agent._emit("execute", "command_prepared", "cmd",
                    data={"command": "ftp -n h.example",
                          "technique": "FTP Anonymous Login",
                          "target": "h.example",
                          "target_key": "h.example:FTP Anonymous Login"})
        ctx = kc.build_context(db_path=self.db, agent=agent)
        self.assertIn("PREPARED", ctx)
        self.assertIn("h.example:FTP Anonymous Login", ctx)
        self.assertIn("roots: h.example", ctx)


class TestValidateActions(unittest.TestCase):
    def test_unknown_op_rejected(self):
        self.assertEqual(kc.validate_actions([{"op": "rm_rf"}]), [])

    def test_missing_required_field_rejected(self):
        self.assertEqual(kc.validate_actions([{"op": "fire"}]), [])
        self.assertEqual(kc.validate_actions([{"op": "start_scan"}]), [])

    def test_valid_fire_passes(self):
        out = kc.validate_actions(
            [{"op": "fire", "target_key": "h.example:X"}])
        self.assertEqual(out, [{"op": "fire", "target_key": "h.example:X"}])

    def test_record_requires_a_known_outcome(self):
        self.assertEqual(
            kc.validate_actions([{"op": "record", "technique": "sqli",
                                  "target": "h.example", "outcome": "maybe"}]),
            [])
        ok = kc.validate_actions([{"op": "record", "technique": "sqli",
                                   "target": "h.example", "outcome": "failure"}])
        self.assertEqual(ok[0]["outcome"], "failure")

    def test_actions_are_capped(self):
        many = [{"op": "fire", "target_key": f"h:X{i}"} for i in range(10)]
        self.assertEqual(len(kc.validate_actions(many)), kc.MAX_ACTIONS)

    def test_junk_and_non_dicts_are_skipped(self):
        self.assertEqual(kc.validate_actions(["fire", None, 42]), [])
        self.assertEqual(kc.validate_actions({"op": "fire"}), [])


class TestChat(unittest.TestCase):
    def test_empty_message_is_an_error(self):
        self.assertFalse(kc.chat("   ")["ok"])

    def test_missing_key_short_circuits(self):
        with mock.patch.dict(os.environ,
                             {"ATTACK_SURFACE_LLM_API_KEY": "",
                              "KNOLL_LLM_API_KEY": ""}):
            out = kc.chat("hi", context="ctx")
        self.assertFalse(out["ok"])
        self.assertIn("endpoint", out["error"])

    def test_reply_and_actions_are_parsed(self):
        payload = {"reply": "Risk is 61 — one FTP port open, nothing decided yet",
                   "actions": [{"op": "fire", "target_key": "h:X"},
                               {"op": "bogus"}]}
        with mock.patch("requests.post") as post:
            post.return_value = mock.Mock(
                status_code=200,
                json=lambda: {"choices": [{"message": {
                    "content": __import__("json").dumps(payload)}}]})
            out = kc.chat("status?", context="ctx")
        self.assertTrue(out["ok"])
        self.assertEqual(out["reply"],
                         "Risk is 61 — one FTP port open, nothing decided yet")
        self.assertEqual(out["actions"], [{"op": "fire",
                                           "target_key": "h:X"}])

    def test_non_json_reply_is_passed_through(self):
        with mock.patch("requests.post") as post:
            post.return_value = mock.Mock(
                status_code=200,
                json=lambda: {"choices": [{"message": {
                    "content": "I can only answer from the context."}}]})
            out = kc.chat("hi", context="ctx")
        self.assertTrue(out["ok"])
        self.assertIn("I can only answer", out["reply"])
        self.assertEqual(out["actions"], [])

    def test_http_error_is_reported(self):
        with mock.patch("requests.post") as post:
            post.return_value = mock.Mock(status_code=500, text="boom")
            out = kc.chat("hi", context="ctx")
        self.assertFalse(out["ok"])
        self.assertIn("500", out["error"])

    def test_system_prompt_does_not_crash_on_json_braces(self):
        """Regression: str.format() choked on the prompt's own JSON."""
        s = kc._SYSTEM.replace("{ops}", ", ".join(sorted(kc.ALLOWED_OPS)))
        self.assertNotIn("{ops}", s)
        self.assertIn('"reply"', s)
        self.assertIn("fire", s)
        # no leftover single-brace placeholders
        import re
        leftovers = re.findall(r"(?<!\{)\{[a-z_]+\}(?!\})", s)
        self.assertEqual(leftovers, [])

    def test_system_prompt_is_english_and_conversational(self):
        s = kc._SYSTEM.replace("{ops}", ", ".join(sorted(kc.ALLOWED_OPS)))
        self.assertIn("Always reply in English", s)
        self.assertNotIn("language the operator used", s)
        self.assertIn("colleague on shift", s)
        self.assertIn("no corporate filler", s)

    def test_prompt_has_no_persian_or_other_non_latin_scripts(self):
        """English only — em-dashes are fine, Persian/Arabic/CJK are not."""
        non_latin = sorted({c for c in kc._SYSTEM
                            if c.isalpha()
                            and not ("a" <= c.lower() <= "z")})
        self.assertEqual(non_latin, [])

    def test_dashboard_ui_has_no_persian(self):
        """The served UI must be English: no Arabic-block characters."""
        import re as _re
        from modules import dashboard
        found = _re.findall(r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF]",
                            dashboard._HTML)
        self.assertEqual(found, [], "Persian text left in the dashboard UI")

    def test_history_is_bounded_and_typed(self):
        history = [{"role": "user", "content": f"m{i}"}
                   for i in range(50)]
        with mock.patch("requests.post") as post:
            post.return_value = mock.Mock(
                status_code=200,
                json=lambda: {"choices": [{"message": {"content": "ok"}}]})
            kc.chat("hi", history=history, context="c")
        msgs = post.call_args.kwargs["json"]["messages"]
        roles = [m["role"] for m in msgs]
        self.assertEqual(roles[0], "system")
        self.assertEqual(roles[-1], "user")
        self.assertLessEqual(len(roles), kc.MAX_HISTORY + 2)
        self.assertEqual(roles.count("user"), 13)  # 12 history + current


if __name__ == "__main__":
    unittest.main()
