"""
modules/graph_builder.py
==========================
Builds a graph model of the attack surface.

Uses NetworkX if available; otherwise exports a JSON representation
suitable for D3.js / Cytoscape / external renderers.
"""

from __future__ import annotations

import json
import logging
import os

logger = logging.getLogger("AttackSurface")


def _get(obj, key, default=None):
    """Dict-or-dataclass accessor."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def build_attack_surface_graph(data):
    """
    Build & export a graph representation of the scan.

    Accepts a dict (legacy) or a ScanContext (v0.7).
    """
    alive_hosts = _get(data, "alive_hosts", default=[]) or []
    ports_map = _get(data, "ports", default={}) or {}
    attack_paths = _get(data, "attack_paths", default=[]) or []
    risk_scores = _get(data, "risk_scores", default={}) or {}

    # Try NetworkX for a richer export; fall back to plain JSON.
    nx_graph = None
    try:
        import networkx as nx  # type: ignore
        G = nx.Graph()
        for host in alive_hosts:
            domain = host.get("domain") if isinstance(host, dict) else str(host)
            score = (risk_scores.get(domain, {}) or {}).get("score", 0) if isinstance(risk_scores, dict) else 0
            G.add_node(domain, type="Host", risk=score)

        for host, info in (ports_map.items() if isinstance(ports_map, dict) else []):
            if not isinstance(info, dict):
                continue
            for p in info.get("open_ports", []) or []:
                if not isinstance(p, dict):
                    continue
                port_node = f"Service:{p.get('service', 'unknown')}:{p.get('port')}"
                G.add_node(port_node, type="Service", protocol=p.get("protocol", "tcp"))
                G.add_edge(host, port_node, relationship="Exposed_Port")

        for path in attack_paths:
            if not isinstance(path, dict):
                continue
            source = path.get("source_host")
            target_service = path.get("target_service")
            if source and target_service:
                G.add_edge(source, target_service, relationship=path.get("path_type", "Unknown"))
        nx_graph = G
    except ImportError:
        logger.info("networkx not available; exporting JSON-only graph")

    # JSON export (always)
    nodes = []
    for host in alive_hosts:
        domain = host.get("domain") if isinstance(host, dict) else str(host)
        score = (risk_scores.get(domain, {}) or {}).get("score", 0) if isinstance(risk_scores, dict) else 0
        nodes.append({"id": domain, "type": "Host", "risk": score})

    for host, info in (ports_map.items() if isinstance(ports_map, dict) else []):
        if not isinstance(info, dict):
            continue
        for p in info.get("open_ports", []) or []:
            if not isinstance(p, dict):
                continue
            nodes.append({
                "id": f"Service:{p.get('service', 'unknown')}:{p.get('port')}",
                "type": "Service",
                "protocol": p.get("protocol", "tcp"),
            })

    edges = []
    for host, info in (ports_map.items() if isinstance(ports_map, dict) else []):
        if not isinstance(info, dict):
            continue
        for p in info.get("open_ports", []) or []:
            if not isinstance(p, dict):
                continue
            edges.append({
                "source": host,
                "target": f"Service:{p.get('service', 'unknown')}:{p.get('port')}",
                "relationship": "Exposed_Port",
            })

    for path in attack_paths:
        if not isinstance(path, dict):
            continue
        edges.append({
            "source": path.get("source_host"),
            "target": path.get("target_service", "External"),
            "relationship": path.get("path_type", "Unknown"),
            "risk_score": path.get("risk_score"),
        })

    graph_data = {"nodes": nodes, "edges": edges}

    try:
        os.makedirs("reports", exist_ok=True)
        with open("reports/graph_data.json", "w", encoding="utf-8") as f:
            json.dump(graph_data, f, indent=2, ensure_ascii=False)
        logger.info("Attack Surface Graph data exported to reports/graph_data.json "
                    "(%d nodes, %d edges)", len(nodes), len(edges))
    except Exception as e:
        logger.error("Failed to export graph data: %s", e)
