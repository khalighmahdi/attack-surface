"""Tests for CVE nodes in the attack graph and their advisor gating.

The CVE watchlist (--cves / --cves-deep) must reach the graph as real
vulnerability nodes, while the advisor only recommends *exploiting* a CVE
when the version is actually known (cpe_exact) — a keyword match is a
candidate to verify, not a target to fire at.
"""

import unittest

from modules.attack_advisor import (extract_target_properties,
                                    recommend_attacks, score_attack)
from modules.attack_graph import build_graph, find_chains

CVE_ROW = {
    "tech": "Apache 2.4.49",
    "cpe": "cpe:2.3:a:apache:http_server:2.4.49",
    "match": "cpe_exact",
    "cves": [{"id": "CVE-2021-41773", "cvss": 7.5, "kev": True,
              "epss": 0.9, "contextual_risk": 92,
              "summary": "path traversal in Apache HTTP Server"}],
}
KEYWORD_ROW = {
    "tech": "Google Analytics",
    "cpe": None,
    "match": "keyword",
    "cves": [{"id": "CVE-2024-1203", "cvss": 8.8}],
}


def _scan(cves=None, ports=(21, 80)):
    return {
        "domain": "target.example",
        "hosts": [{"host": "target.example", "ip": "10.0.0.5",
                   "ports": [{"port": p, "service": "x"} for p in ports],
                   "tech": []}],
        "subdomains": ["target.example"],
        "findings": [],
        "sections": {"cves": cves or {}},
    }


class TestGraphCveNodes(unittest.TestCase):
    def test_cve_nodes_are_rendered_with_their_severity(self):
        scan = _scan({"target.example": [CVE_ROW]})
        g = build_graph(scan)
        cves = [n for n in g["nodes"] if n["type"] == "CVE"]
        self.assertEqual(len(cves), 1)
        node = cves[0]
        self.assertEqual(node["label"], "CVE-2021-41773 ⚑KEV")
        self.assertEqual(node["cve"], "CVE-2021-41773")
        self.assertEqual(node["cvss"], 7.5)
        self.assertTrue(node["kev"])
        self.assertEqual(node["match"], "cpe_exact")
        self.assertEqual(node["risk"], 92)  # contextual_risk wins

    def test_kev_forces_a_high_risk_floor(self):
        row = dict(CVE_ROW, cves=[{"id": "CVE-X", "cvss": 4.0, "kev": True}])
        g = build_graph(_scan({"target.example": [row]}))
        node = next(n for n in g["nodes"] if n["type"] == "CVE")
        self.assertGreaterEqual(node["risk"], 90)

    def test_edge_is_labelled_with_how_it_was_matched(self):
        scan = _scan({"target.example": [CVE_ROW, KEYWORD_ROW]})
        g = build_graph(scan)
        edges = [e for e in g["edges"] if str(e["target"]).startswith("cve:")]
        self.assertEqual(len(edges), 2)
        self.assertEqual({e["label"] for e in edges}, {"exact", "keyword"})
        for e in edges:
            self.assertEqual(e["type"], "vulnerable_to")
            self.assertEqual(e["source"], "target.example")

    def test_host_node_is_created_when_missing(self):
        scan = _scan({"orphan.example": [CVE_ROW]})
        g = build_graph(scan)
        ids = {n["id"] for n in g["nodes"]}
        self.assertIn("orphan.example", ids)

    def test_cve_nodes_counted_in_stats(self):
        g = build_graph(_scan({"target.example": [CVE_ROW, KEYWORD_ROW]}))
        self.assertEqual(g["stats"]["by_type"].get("CVE"), 2)


class TestAdvisorGatesCveExploit(unittest.TestCase):
    def test_watchlist_marks_cve_detected(self):
        targets = extract_target_properties(
            _scan({"target.example": [KEYWORD_ROW]}))
        self.assertTrue(targets[0]["cve_detected"])

    def test_only_exact_match_marks_version_known(self):
        exact = extract_target_properties(
            _scan({"target.example": [CVE_ROW]}))
        self.assertTrue(exact[0]["version_known"])
        keyword = extract_target_properties(
            _scan({"target.example": [KEYWORD_ROW]}))
        self.assertFalse(keyword[0]["version_known"])

    def test_keyword_match_does_not_unlock_exploitation(self):
        """A keyword hit is a candidate — the technique must stay at 0."""
        props = extract_target_properties(
            _scan({"target.example": [KEYWORD_ROW]}))[0]
        self.assertEqual(score_attack("cve_exploit", props)["overall_score"],
                         0.0)

    def test_exact_match_unlocks_cve_exploit(self):
        props = extract_target_properties(
            _scan({"target.example": [CVE_ROW]}))[0]
        self.assertGreater(
            score_attack("cve_exploit", props)["overall_score"], 0.0)
        order = recommend_attacks(
            _scan({"target.example": [CVE_ROW]})).get("execution_order", [])
        self.assertIn("cve_exploit", {p["technique_key"] for p in order})

    def test_chain_can_start_from_a_confirmed_cve(self):
        """cve_exploit is an access step; FTP on 21 is a linkable follow-up."""
        chains = find_chains(_scan({"target.example": [CVE_ROW]}))
        two_hop = [c for c in chains if c["hops"] == 2]
        self.assertTrue(two_hop, "expected a CVE -> credential chain")
        self.assertEqual(two_hop[0]["steps"][0]["technique_key"], "cve_exploit")
        self.assertEqual(two_hop[0]["steps"][1]["technique_key"], "ftp_brute")
        self.assertEqual(two_hop[0]["confidence"], "strong")
        self.assertIn("port 21 confirmed open", two_hop[0]["reason"])


if __name__ == "__main__":
    unittest.main()
