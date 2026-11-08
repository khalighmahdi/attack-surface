"""risk_trend.py — risk-score time series for the dashboard Risk Trend chart.

Reads scan history from the central SQLite store and returns
{labels, scores, levels} for charting. Stdlib-only.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


class RiskTrend:
    """Risk score history across stored scans."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

    def series(self, domain: Optional[str] = None) -> Dict[str, Any]:
        """Return chronological risk series, optionally filtered by domain."""
        import db_store

        scans = db_store.list_scans(self.db_path)
        if domain:
            scans = [s for s in scans if s.get("domain") == domain]
        # list_scans returns newest-first; chart wants oldest-first
        scans = list(reversed(scans))

        labels: List[str] = []
        scores: List[float] = []
        levels: List[str] = []
        domains: List[str] = []
        for s in scans:
            labels.append(str(s.get("ts") or ""))
            score = s.get("risk_score")
            scores.append(float(score) if score is not None else 0.0)
            levels.append(str(s.get("risk_level") or ""))
            domains.append(str(s.get("domain") or ""))

        # Simple delta series: change vs previous scan per domain
        deltas: List[Optional[float]] = []
        prev_by_domain: Dict[str, Optional[float]] = {}
        for dom, sc in zip(domains, scores):
            prev = prev_by_domain.get(dom)
            deltas.append(None if prev is None else round(sc - prev, 1))
            prev_by_domain[dom] = sc

        return {
            "domain": domain or "all",
            "labels": labels,
            "scores": scores,
            "levels": levels,
            "domains": domains,
            "deltas": deltas,
            "count": len(labels),
        }
