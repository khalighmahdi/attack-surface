"""Tests for CVE-driven risk and the blue-team re-score.

Before this, Phase 4 scored risk BEFORE blue-team ran, so email spoofing,
takeover and the whole CVE watchlist were invisible — a scan with 10 CVEs
(including CVSS 10.0) scored 23 while one with none scored 66.
"""

import unittest

from modules.risk_scoring import CVE_SCORE_CAP, calculate_risk


def _cve(cid, cvss=7.5, kev=False, exact=True, host="h.example",
         severity=None):
    return {"type": "CVE_WATCHLIST", "domain": host, "cve": cid,
            "cvss": cvss, "kev": kev, "exact": exact,
            "severity": severity or ("critical" if cvss >= 9 else
                                     "high" if cvss >= 7 else
                                     "medium" if cvss >= 4 else "low")}


class TestCveRisk(unittest.TestCase):
    def test_cve_now_contributes_to_risk(self):
        r = calculate_risk([_cve("CVE-2021-41773")])
        d = r["per_domain"]["h.example"]
        self.assertGreater(d["score"], 0)
        self.assertIn("known_vulnerability", d["attack_types"])
        self.assertIn("CVE-2021-41773 (CVSS 7.5, exact)", d["reasons"])

    def test_kev_and_exact_score_higher_than_keyword(self):
        exact = calculate_risk([_cve("CVE-1", exact=True)])
        keyword = calculate_risk([_cve("CVE-1", exact=False)])
        self.assertGreater(exact["per_domain"]["h.example"]["score"],
                           keyword["per_domain"]["h.example"]["score"])

    def test_same_cve_counted_once(self):
        r = calculate_risk([_cve("CVE-1"), _cve("CVE-1"), _cve("CVE-1")])
        one = calculate_risk([_cve("CVE-1")])
        self.assertEqual(r["per_domain"]["h.example"]["score"],
                         one["per_domain"]["h.example"]["score"])

    def test_contribution_is_capped(self):
        events = [_cve(f"CVE-{i}", cvss=10.0, exact=False, severity="critical")
                  for i in range(12)]
        d = calculate_risk(events)["per_domain"]["h.example"]
        self.assertEqual(d["cve_score"], CVE_SCORE_CAP)
        self.assertLessEqual(d["score"], CVE_SCORE_CAP)

    def test_cvss_zero_is_soft(self):
        low = calculate_risk([_cve("CVE-low", cvss=0.0, exact=False,
                                   severity="low")])
        high = calculate_risk([_cve("CVE-high", cvss=10.0, exact=True,
                                    severity="critical")])
        self.assertLess(low["per_domain"]["h.example"]["score"],
                        high["per_domain"]["h.example"]["score"])

    def test_missing_domain_or_cid_is_ignored(self):
        # no domain at all → nothing scored
        self.assertEqual(calculate_risk([{"type": "CVE_WATCHLIST",
                                          "domain": ""}]), {
            "per_domain": {}, "overall_score": 0, "overall_level": "Low"})
        # a domain with an empty cid contributes no CVE evidence: it only
        # gets the same baseline any unknown event type would
        d = calculate_risk([{"type": "CVE_WATCHLIST",
                             "domain": "x", "cve": ""}])["per_domain"]["x"]
        self.assertEqual(d["score"], 5)
        self.assertEqual(d["reasons"], ["Baseline risk applied"])


class TestBlueTeamRescore(unittest.TestCase):
    def test_emits_events_for_every_watchlist_row(self):
        from core.runner import ScannerRunner

        class Ctx:
            cve_watchlist = {
                "h.example": [
                    {"tech": "Apache", "match": "cpe_exact",
                     "cves": [{"id": "CVE-2021-41773", "cvss": 7.5},
                              {"id": "CVE-2019-0211", "cvss": 8.8}]},
                    {"tech": "GA", "match": "keyword",
                     "cves": [{"cve": "CVE-2024-1203", "cvss": 8.8}]},
                ],
                "bad": "not-a-list",
            }
            events = []

            def add_event(self, e):
                self.events.append(e)

        ctx = Ctx()
        ScannerRunner._emit_cve_events(ctx)
        self.assertEqual(len(ctx.events), 3)
        evs = {e["cve"]: e for e in ctx.events}
        self.assertTrue(evs["CVE-2021-41773"]["exact"])
        self.assertFalse(evs["CVE-2024-1203"]["exact"])
        self.assertEqual(evs["CVE-2024-1203"]["domain"], "h.example")
        self.assertEqual(evs["CVE-2019-0211"]["severity"], "high")

    def test_rescore_uses_blue_team_evidence(self):
        from core.runner import ScannerRunner

        class Ctx:
            events = [{"type": "EMAIL_SPOOFING_POSSIBLE",
                       "domain": "h.example", "severity": "high"}]
            risk_scores = {"h.example": {"score": 5, "level": "Low",
                                         "reasons": ["Baseline risk applied"]}}

        ctx = Ctx()
        ScannerRunner()._rescore_after_blue_team(ctx)
        # 25 (weight) x 1.2 (high) = 30 → Medium (High needs >= 40)
        self.assertGreater(ctx.risk_scores["h.example"]["score"], 5)
        self.assertEqual(ctx.risk_scores["h.example"]["score"], 30)
        self.assertEqual(ctx.risk_scores["h.example"]["level"], "Medium")
        self.assertTrue(any("EMAIL_SPOOFING" in r for r in
                            ctx.risk_scores["h.example"]["reasons"]))

    def test_rescore_keeps_phase4_scores_when_it_fails(self):
        from core.runner import ScannerRunner

        class Ctx:
            events = "not-a-list"          # calculate_risk will no-op
            risk_scores = {"keep.me": {"score": 42, "level": "High"}}

        ctx = Ctx()
        ScannerRunner()._rescore_after_blue_team(ctx)
        # per_domain will be empty → the old scores must survive
        self.assertEqual(ctx.risk_scores["keep.me"]["score"], 42)


if __name__ == "__main__":
    unittest.main()
