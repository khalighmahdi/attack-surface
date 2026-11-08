"""Tests for attack-chain construction and the advisor intelligence fixes."""

import unittest

from modules.attack_advisor import (extract_target_properties,
                                    ports_from_findings, recommend_attacks,
                                    score_attack)
from modules.attack_graph import find_chains


def _scan(host="target.example", ports=(21, 22, 80)):
    """Minimal scan dict with real open ports on one host."""
    return {
        "domain": host,
        "hosts": [{"host": host, "ip": "10.0.0.5",
                   "ports": [{"port": p, "service": "unknown"} for p in ports],
                   "tech": []}],
        "subdomains": [host],
        "findings": [{"host": host, "title": "Host responds on HTTP",
                      "severity": "Info", "category": "info"}],
        "sections": {},
    }


class TestPortsFromFindings(unittest.TestCase):
    def test_exposure_text_is_parsed(self):
        findings = [
            {"title": "**Public Exposure**: FTP (ftp?) is open on port 21",
             "detail": ""},
            {"title": "**Public Exposure**: SSH (ssh?) is open on port 22",
             "detail": ""},
        ]
        self.assertEqual(sorted(ports_from_findings(findings)), [21, 22])

    def test_plain_port_mention(self):
        self.assertEqual(ports_from_findings([{"title": "open port 8080"}]),
                         [8080])

    def test_no_ports_no_false_positives(self):
        self.assertEqual(ports_from_findings([{"title": "Missing HTTPOnly"}]),
                         [])


class TestAdvisorIntelligence(unittest.TestCase):
    def test_credential_techniques_survive_the_cutoff(self):
        """SSH brute force (score 4.4) used to be dropped by the >5 cut."""
        order = recommend_attacks(_scan()).get("execution_order", [])
        keys = {p["technique_key"] for p in order}
        self.assertIn("ssh_brute", keys)
        self.assertIn("ftp_anonymous", keys)

    def test_unmet_prerequisites_still_excluded(self):
        """A host with only HTTP must not offer SSH brute force."""
        scan = _scan(ports=(80, 443))
        order = recommend_attacks(scan).get("execution_order", [])
        keys = {p["technique_key"] for p in order}
        self.assertNotIn("ssh_brute", keys)

    def test_execution_order_is_diverse(self):
        """Nine sibling hosts must not spend nine slots on one technique."""
        scan = {
            "domain": "a.example",
            "hosts": [{"host": f"n{i}.a.example", "ip": "10.0.0.1",
                       "ports": [{"port": 21, "service": "ftp"},
                                 {"port": 22, "service": "ssh"}],
                       "tech": []} for i in range(9)],
            "subdomains": [], "findings": [], "sections": {},
        }
        order = recommend_attacks(scan).get("execution_order", [])
        keys = [p["technique_key"] for p in order]
        self.assertEqual(len(keys), len(set(keys)),
                         "each technique must appear at most once: %s" % keys)
        self.assertIn("ftp_anonymous", keys)
        self.assertIn("ssh_brute", keys)

    def test_ports_recovered_from_findings_text(self):
        scan = {
            "domain": "b.example",
            "hosts": [{"host": "b.example", "ip": "10.0.0.9",
                       "ports": "[]", "tech": "[]"}],
            "subdomains": [], "sections": {},
            "findings": [{"host": "b.example",
                          "title": "**Public Exposure**: SSH (ssh?) is open "
                                   "on port 22"}],
        }
        targets = extract_target_properties(scan)
        self.assertTrue(targets[0]["port_22"])
        self.assertTrue(targets[0]["ssh_service"])
        order = recommend_attacks(scan).get("execution_order", [])
        self.assertIn("ssh_brute", {p["technique_key"] for p in order})

    def test_score_zero_when_prerequisite_missing(self):
        props = {"host": "x", "http_service": True, "port_80": True}
        self.assertEqual(score_attack("ssh_brute", props)["overall_score"], 0.0)
        props["port_22"] = True
        props["ssh_service"] = True
        self.assertGreater(score_attack("ssh_brute", props)["overall_score"], 0)


class TestProofGatedTechniques(unittest.TestCase):
    """Phases 3-7 score only when Knull holds evidence of a foothold/creds."""

    # Everything a host could show EXCEPT the two engagement-state flags.
    _HOST = {"host": "t.example", "port_22": True, "ssh_service": True,
             "port_3306": True, "mysql_service": True,
             "version_known": True, "no_fail2ban": True,
             "default_creds_known": True, "anonymous_login": True,
             "msf_module_present": True, "module_matches_service": True,
             "same_credential_scope": True}

    def test_no_foothold_scores_exactly_zero(self):
        """Success factors must not resurrect an unproven post-ex move."""
        for key in ("sudo_check", "ssh_persist"):
            score = score_attack(key, dict(self._HOST))
            self.assertEqual(score["overall_score"], 0.0,
                             "%s planned without a foothold: %s"
                             % (key, score["overall_score"]))

    def test_no_creds_scores_exactly_zero(self):
        self.assertEqual(
            score_attack("cred_reuse", dict(self._HOST))["overall_score"], 0.0)

    def test_proven_foothold_scores_positive(self):
        props = dict(self._HOST, foothold_verified=True)
        for key in ("sudo_check", "ssh_persist"):
            self.assertGreater(score_attack(key, props)["overall_score"], 0.0,
                               "%s scored 0 despite a verified foothold" % key)

    def test_held_creds_score_positive(self):
        self.assertGreater(
            score_attack("cred_reuse", dict(self._HOST, creds_held=True))
            ["overall_score"], 0.0)

    def test_all_techniques_have_a_kill_chain_phase(self):
        from modules.attack_advisor import ATTACK_TECHNIQUES
        from modules.knull import Knull
        missing = set(ATTACK_TECHNIQUES) - set(Knull._TECHNIQUE_PHASE)
        self.assertEqual(missing, set())
        self.assertEqual(
            Knull._TECHNIQUE_PHASE["sudo_check"], "privilege_escalation")
        self.assertEqual(Knull._TECHNIQUE_PHASE["ssh_persist"], "persistence")
        self.assertEqual(Knull._TECHNIQUE_PHASE["cred_reuse"],
                         "lateral_movement")


class TestReconInjectsEngagement(unittest.TestCase):
    """_recon must hand the advisor this run's proof, not scan assumptions."""

    def setUp(self):
        import os
        import tempfile
        import db_store
        fd, self._db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db_store.save_scan({
            "risk": {"overall_score": 50.0, "overall_level": "High"},
            "hosts": [{"host": "t.example", "ip": "10.0.0.7",
                       "ports": [{"port": 22, "service": "ssh"}], "tech": []}],
            "subdomains": ["t.example"], "findings": [], "sections": {},
        }, "t.example", "test", db_path=self._db)
        from modules.knull import Knull
        self.k = Knull(scan_id=1, target_domain="t.example",
                       db_path=self._db)

    def tearDown(self):
        import os
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(self._db + suffix)
            except OSError:
                pass

    def test_no_proof_means_no_engagement(self):
        data = self.k._recon()
        eng = data.get("_engagement") or {}
        self.assertFalse(eng.get("foothold"))
        self.assertEqual(int(eng.get("creds") or 0), 0)
        # and the post-exploitation techniques stay out of the plan
        from modules.attack_advisor import recommend_attacks
        order = recommend_attacks(data).get("execution_order", [])
        self.assertNotIn("sudo_check", {p["technique_key"] for p in order})

    def test_harvested_creds_are_reported_to_the_advisor(self):
        self.k.credentials_found.append(
            {"username": "root", "password": "toor", "source": "ftp"})
        self.assertEqual(self.k._recon()["_engagement"]["creds"], 1)

    def test_proved_foothold_unlocks_post_exploitation(self):
        phase = self.k.kill_chain["execution"]
        phase.status = "success"
        data = self.k._recon()
        self.assertTrue(data["_engagement"]["foothold"])
        from modules.attack_advisor import recommend_attacks
        order = recommend_attacks(data).get("execution_order", [])
        self.assertIn("sudo_check", {p["technique_key"] for p in order})


class TestCveToMsfPipeline(unittest.TestCase):
    """An MSF step must name a real module, never the placeholder."""

    def _scan(self):
        return {
            "domain": "t.example",
            "hosts": [{"host": "t.example", "ip": "10.0.0.5",
                       "ports": [{"port": 3306, "service": "mysql"}],
                       "tech": []}],
            "subdomains": ["t.example"], "findings": [],
            "sections": {"msf_suggestions": [
                {"host": "t.example", "module": "exploit/linux/mysql/x",
                 "stage": "exploit"}]},
        }

    def test_module_path_reaches_the_plan(self):
        from modules.attack_advisor import (extract_target_properties,
                                           recommend_attacks)
        props = extract_target_properties(self._scan())
        self.assertEqual(props[0].get("msf_module"),
                         "exploit/linux/mysql/x")
        order = recommend_attacks(self._scan()).get("execution_order", [])
        msf = [p for p in order if p["technique_key"] == "msf_exploit"]
        self.assertEqual(len(msf), 1, "exactly one MSF step per host")
        self.assertIn("exploit/linux/mysql/x", msf[0]["command"])
        self.assertNotIn("<module-from-msf-tab>", msf[0]["command"])

    def test_no_suggestion_means_no_msf_step(self):
        scan = self._scan()
        scan["sections"] = {}
        order = recommend_attacks(scan).get("execution_order", [])
        self.assertNotIn("msf_exploit", {p["technique_key"] for p in order})


class TestCampaignMode(unittest.TestCase):
    """A campaign works the whole estate: legs advance, proof carries over."""

    def setUp(self):
        import os
        import tempfile
        import db_store
        fd, self._db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        for dom, port in (("a.example", 22), ("b.example", 21)):
            db_store.save_scan({
                "risk": {"overall_score": 40.0, "overall_level": "High"},
                "hosts": [{"host": dom, "ip": "10.0.0.7",
                           "ports": [{"port": port,
                                      "service": "ssh" if port == 22 else "ftp"}],
                           "tech": []}],
                "subdomains": [dom], "findings": [], "sections": {},
            }, dom, "test", db_path=self._db)
        from modules.knull import Knull
        self.k = Knull(scan_id=1, target_domain="a.example", db_path=self._db,
                       campaign=True, extra_scope=["b.example"],
                       use_brain=False)

    def tearDown(self):
        import os
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(self._db + suffix)
            except OSError:
                pass

    def test_legs_follow_the_scope(self):
        self.assertEqual(self.k.campaign_legs(), ["a.example", "b.example"])

    def test_leg_order_follows_scope_not_the_alphabet(self):
        """z.example declared first must still be leg 1."""
        from modules.knull import Knull
        k = Knull(db_path=self._db, target_domain="z.example",
                  extra_scope=["a.example"], campaign=True, use_brain=False)
        self.assertEqual(k.campaign_legs(), ["z.example", "a.example"])

    def test_each_leg_loads_its_own_newest_scan(self):
        import db_store
        db_store.save_scan({
            "risk": {"overall_score": 10.0, "overall_level": "Low"},
            "hosts": [], "subdomains": ["a.example"], "findings": [],
            "sections": {},
        }, "a.example", "test", db_path=self._db)   # newer scan for leg 1
        self.k._campaign_begin()
        newest = max(s["id"] for s in db_store.list_scans(self._db)
                     if s["domain"] == "a.example")
        self.assertEqual(self.k.scan_id, newest,
                         "a leg must read its own newest scan, not the oldest")

    def test_advance_moves_the_leg_and_closes_the_last(self):
        self.assertTrue(self.k._campaign_begin())
        self.assertEqual(self.k.campaign_state()["current_leg"], "a.example")
        self.assertTrue(self.k._campaign_advance())
        st = self.k.campaign_state()
        self.assertEqual(st["current_leg"], "b.example")
        self.assertTrue(st["leg_state"]["a.example"]["closed"])

    def test_last_leg_returns_false_so_the_loop_stops(self):
        self.k._campaign_begin()
        self.k._campaign_advance()
        self.assertFalse(self.k._campaign_advance(),
                         "the final leg must end the campaign, not loop")

    def test_credentials_carry_into_the_next_leg(self):
        self.k._campaign_begin()
        self.k.credentials_found.append({"username": "r", "password": "t"})
        self.k._campaign_advance()
        # proof from leg 1 is still held, so leg 2 can open with reuse
        self.assertEqual(len(self.k.credentials_found), 1)
        self.assertEqual(
            self.k.campaign_state()["leg_state"]["a.example"]["creds"], 1)

    def test_campaign_off_is_inert(self):
        from modules.knull import Knull
        k = Knull(db_path=self._db, campaign=False, use_brain=False)
        self.assertFalse(k._campaign_advance())
        self.assertFalse(k.campaign_state()["campaign"])

    def test_config_exposes_and_types_the_switch(self):
        self.assertIn("campaign", self.k.config())
        res = self.k.configure({"campaign": "yes"})
        self.assertIn("campaign must be true/false", res["errors"])

    def test_a_drained_leg_is_detectable_by_the_loop(self):
        """The loop's advance condition: no decide candidate -> advance leg.

        The loop closes a leg on 'no_target', so prove the primitive it
        relies on: with every path already attempted, _decide returns None
        while a next leg exists to advance to.
        """
        self.k._campaign_begin()
        self.assertEqual(self.k.campaign_legs(), ["a.example", "b.example"])
        analysis = self.k._analyze(self.k._recon()) or {}
        paths = analysis.get("execution_order") or []
        self.assertTrue(paths, "the advisor must score paths for a.example")
        # Every move already attempted this run: the dedup key is
        # target:display-name (the canonical key every emitter writes).
        for p in paths:
            self.k._emit("decide", "target_selected", "seed",
                         data={"target_key": f"{p['target']}:{p['technique']}"})
        self.assertIsNone(self.k._decide(analysis),
                          "all moves attempted => no target, leg is drained")
        self.assertTrue(self.k._campaign_advance(),
                        "a drained leg must advance, not spin")


class TestFindChains(unittest.TestCase):
    def test_two_hop_chain_links_on_confirmed_port(self):
        chains = find_chains(_scan())
        self.assertTrue(chains, "expected at least one chain")
        best = chains[0]
        self.assertEqual(best["hops"], 2)
        self.assertIn(best["confidence"], {"strong", "plausible"})
        self.assertIn("port", best["reason"])

    def test_chained_probability_is_the_product(self):
        chains = find_chains(_scan())
        probs = [s["probability"] for s in chains[0]["steps"]]
        self.assertAlmostEqual(chains[0]["probability"],
                               probs[0] * probs[1], places=4)

    def test_same_service_chain_is_rejected(self):
        """FTP anonymous login -> FTP brute force is one service, not a pivot."""
        for c in find_chains(_scan(ports=(21,))):
            if c["hops"] != 2:
                continue
            step1 = c["steps"][0]["technique_key"]
            step2 = c["steps"][1]["technique_key"]
            self.assertFalse(step1 == "ftp_anonymous" and step2 == "ftp_brute")

    def test_xss_cannot_start_a_chain(self):
        """A browser-side bug grants no server foothold for a brute force."""
        scan = _scan(ports=(21, 80))
        scan["findings"].append({"host": scan["domain"],
                                 "title": "Reflected XSS in q parameter"})
        for c in find_chains(scan):
            if c["hops"] == 2:
                self.assertNotEqual(c["steps"][0]["technique_key"], "xss")

    def test_empty_scan_returns_no_chains(self):
        self.assertEqual(find_chains({"domain": "z.example", "hosts": [],
                                      "subdomains": [], "findings": []}), [])


if __name__ == "__main__":
    unittest.main()
