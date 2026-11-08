"""
Network Topology Analysis Module for Red Team Operations.

Provides graph-based network modelling, Dijkstra shortest-path routing,
BFS/DFS traversal, attack-path discovery, segment detection, and D3.js
visualisation export.  All graph algorithms are implemented from scratch
(stdlib only — no external graph libraries).

Typical usage:
    topo = NetworkTopology()
    topo.add_host(TopologyNode(ip="10.0.0.1", hostname="dc01", ...))
    topo.add_connection(TopologyEdge(src="10.0.0.1", dst="10.0.0.2", ...))
    paths = topo.identify_attack_paths("10.0.0.1", "10.0.0.5")
    print(topo.generate_graph_json())
"""

from __future__ import annotations

import heapq
import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class TopologyNode:
    """Represents a single host on the network."""

    ip: str
    hostname: str = ""
    ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    os: str = "unknown"
    risk_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.ip)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TopologyNode):
            return NotImplemented
        return self.ip == other.ip


@dataclass
class TopologyEdge:
    """Directed or bidirectional link between two nodes."""

    src: str
    dst: str
    protocol: str = "tcp"
    port: int = 0
    bidirectional: bool = True
    weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPath:
    """Describes a potential attack chain through the network."""

    steps: List[str]
    tools: List[str]
    risk: float
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "steps": list(self.steps),
            "tools": list(self.tools),
            "risk": self.risk,
            "description": self.description,
        }


@dataclass
class NetworkSegment:
    """Logical grouping of hosts (e.g. VLAN / subnet)."""

    name: str
    hosts: List[str] = field(default_factory=list)
    gateway: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "hosts": list(self.hosts),
            "gateway": self.gateway,
        }


# ---------------------------------------------------------------------------
# Heuristic tool mappings per service / port
# ---------------------------------------------------------------------------

_SERVICE_TOOL_MAP: Dict[str, List[str]] = {
    "ssh": ["hydra", "medusa", "ssh-audit"],
    "http": ["nikto", "gobuster", "nuclei", "sqlmap"],
    "https": ["nikto", "gobuster", "nuclei", "sslscan"],
    "smb": ["smbclient", "enum4linux", "crackmapexec"],
    "rdp": ["hydra", "ncrack", "crowbar"],
    "ftp": ["hydra", "nmap", "ftpcrack"],
    "mysql": ["hydra", "nmap"],
    "mssql": ["hydra", "nmap"],
    "winrm": ["evil-winrm", "crackmapexec"],
    "ldap": ["ldapsearch", "bloodhound"],
    "dns": ["dig", "dnsrecon", "dnsenum"],
}


def _tools_for_services(services: Dict[int, str]) -> List[str]:
    """Return an aggregated tool list for a set of services."""
    tools: List[str] = []
    for svc in services.values():
        for tool in _SERVICE_TOOL_MAP.get(svc.lower(), []):
            if tool not in tools:
                tools.append(tool)
    return tools


# ---------------------------------------------------------------------------
# Main topology class
# ---------------------------------------------------------------------------

class NetworkTopology:
    """In-memory graph of a network with analysis methods."""

    def __init__(self) -> None:
        self._nodes: Dict[str, TopologyNode] = {}
        self._edges: Dict[str, List[TopologyEdge]] = defaultdict(list)
        self._reverse_edges: Dict[str, List[TopologyEdge]] = defaultdict(list)

    # -- mutations ----------------------------------------------------------

    def add_host(self, node: TopologyNode) -> None:
        """Register a host (node) in the topology."""
        self._nodes[node.ip] = node

    def add_connection(self, edge: TopologyEdge) -> None:
        """Register a link between two hosts."""
        self._edges[edge.src].append(edge)
        if edge.bidirectional:
            mirror = TopologyEdge(
                src=edge.dst,
                dst=edge.src,
                protocol=edge.protocol,
                port=edge.port,
                bidirectional=True,
                weight=edge.weight,
                metadata=edge.metadata,
            )
            self._edges[edge.dst].append(mirror)

    def build_topology(
        self,
        hosts: List[TopologyNode],
        connections: List[TopologyEdge],
    ) -> None:
        """Bulk-load the graph from explicit lists."""
        for h in hosts:
            self.add_host(h)
        for c in connections:
            self.add_connection(c)

    # -- helpers ------------------------------------------------------------

    def get_node(self, ip: str) -> Optional[TopologyNode]:
        return self._nodes.get(ip)

    @property
    def nodes(self) -> List[TopologyNode]:
        return list(self._nodes.values())

    @property
    def edges(self) -> List[TopologyEdge]:
        seen: Set[Tuple[str, str]] = set()
        result: List[TopologyEdge] = []
        for elist in self._edges.values():
            for e in elist:
                key = (e.src, e.dst)
                if key not in seen:
                    seen.add(key)
                    result.append(e)
        return result

    def neighbors(self, ip: str) -> List[str]:
        return [e.dst for e in self._edges.get(ip, [])]

    # -- graph algorithms (stdlib only) -------------------------------------

    def _bfs(self, start: str) -> List[str]:
        """Breadth-first traversal returning visited order."""
        visited: List[str] = []
        seen: Set[str] = {start}
        queue: deque[str] = deque([start])
        while queue:
            current = queue.popleft()
            visited.append(current)
            for nb in self.neighbors(current):
                if nb not in seen:
                    seen.add(nb)
                    queue.append(nb)
        return visited

    def _dfs(self, start: str, _visited: Optional[List[str]] = None) -> List[str]:
        """Depth-first traversal returning visited order."""
        if _visited is None:
            _visited = []
        _visited.append(start)
        for nb in self.neighbors(start):
            if nb not in _visited:
                self._dfs(nb, _visited)
        return _visited

    def find_shortest_path(self, src: str, dst: str) -> Optional[List[str]]:
        """Dijkstra shortest path (weight-based).  Returns IP list or None."""
        if src not in self._nodes or dst not in self._nodes:
            return None
        distances: Dict[str, float] = {n: float("inf") for n in self._nodes}
        distances[src] = 0.0
        predecessors: Dict[str, Optional[str]] = {n: None for n in self._nodes}
        heap: List[Tuple[float, str]] = [(0.0, src)]

        while heap:
            dist, current = heapq.heappop(heap)
            if dist > distances[current]:
                continue
            if current == dst:
                break
            for edge in self._edges.get(current, []):
                new_dist = dist + edge.weight
                if new_dist < distances.get(edge.dst, float("inf")):
                    distances[edge.dst] = new_dist
                    predecessors[edge.dst] = current
                    heapq.heappush(heap, (new_dist, edge.dst))

        if distances[dst] == float("inf"):
            return None

        path: List[str] = []
        node: Optional[str] = dst
        while node is not None:
            path.append(node)
            node = predecessors[node]
        path.reverse()
        return path

    def all_pairs_shortest(self) -> Dict[Tuple[str, str], Optional[List[str]]]:
        """Compute shortest paths between every pair of nodes."""
        pairs: Dict[Tuple[str, str], Optional[List[str]]] = {}
        for src in self._nodes:
            for dst in self._nodes:
                if src == dst:
                    pairs[(src, dst)] = [src]
                else:
                    pairs[(src, dst)] = self.find_shortest_path(src, dst)
        return pairs

    # -- attack path analysis -----------------------------------------------

    def identify_attack_paths(
        self,
        source_ip: str,
        target_ip: str,
        max_depth: int = 10,
    ) -> List[AttackPath]:
        """Enumerate attack paths from source to target using BFS on depth.

        For each candidate path, a risk score and suggested tool list are
        computed from the services exposed on intermediate hops.
        """
        if source_ip not in self._nodes or target_ip not in self._nodes:
            return []

        results: List[AttackPath] = []
        queue: deque[List[str]] = deque([[source_ip]])
        seen_paths: Set[Tuple[str, ...]] = set()

        while queue:
            path = queue.popleft()
            if len(path) > max_depth:
                continue
            current = path[-1]
            if current == target_ip and len(path) > 1:
                results.append(self._build_attack_path(path))
                continue
            for nb in self.neighbors(current):
                if nb not in path:
                    new_path = path + [nb]
                    key = tuple(new_path)
                    if key not in seen_paths:
                        seen_paths.add(key)
                        queue.append(new_path)

        results.sort(key=lambda p: p.risk, reverse=True)
        return results

    def _build_attack_path(self, path: List[str]) -> AttackPath:
        """Construct an AttackPath from an IP sequence."""
        all_tools: List[str] = []
        total_risk = 0.0
        for ip in path:
            node = self._nodes.get(ip)
            if node is None:
                continue
            total_risk += node.risk_score
            for t in _tools_for_services(node.services):
                if t not in all_tools:
                    all_tools.append(t)
        avg_risk = total_risk / len(path) if path else 0.0
        description = (
            f"Path through {len(path)} hop(s): "
            + " -> ".join(path)
        )
        return AttackPath(
            steps=list(path),
            tools=all_tools,
            risk=round(avg_risk, 2),
            description=description,
        )

    # -- segment detection --------------------------------------------------

    def detect_network_segments(self) -> List[NetworkSegment]:
        """Detect network segments using connected-component analysis (BFS).

        Nodes that share edges are grouped into the same segment.
        A gateway is chosen as the node with the highest degree in each
        component.
        """
        visited: Set[str] = set()
        segments: List[NetworkSegment] = []

        for ip in self._nodes:
            if ip in visited:
                continue
            component = self._bfs(ip)
            visited.update(component)
            # gateway = highest-degree node
            gateway = max(
                component,
                key=lambda n: len(self._edges.get(n, [])),
            )
            segment = NetworkSegment(
                name=f"segment-{len(segments) + 1}",
                hosts=sorted(component),
                gateway=gateway,
            )
            segments.append(segment)
        return segments

    # -- critical node analysis ---------------------------------------------

    def find_critical_nodes(self) -> List[Dict[str, Any]]:
        """Identify critical nodes based on betweenness-centrality heuristic.

        A node is critical if it appears on many shortest paths.  We
        approximate betweenness by counting how often each node sits on the
        shortest path between every (s, t) pair.
        """
        all_pairs = self.all_pairs_shortest()
        betweenness: Dict[str, int] = {n: 0 for n in self._nodes}

        for (_s, _t), path in all_pairs.items():
            if path is None or len(path) <= 2:
                continue
            for intermediate in path[1:-1]:
                betweenness[intermediate] = betweenness.get(intermediate, 0) + 1

        ranked = sorted(
            betweenness.items(), key=lambda kv: kv[1], reverse=True
        )
        result: List[Dict[str, Any]] = []
        for ip, count in ranked:
            node = self._nodes[ip]
            result.append({
                "ip": ip,
                "hostname": node.hostname,
                "betweenness": count,
                "risk_score": node.risk_score,
                "services": list(node.services.values()),
                "degree": len(self._edges.get(ip, [])),
            })
        return result

    # -- D3.js JSON export --------------------------------------------------

    def generate_graph_json(self) -> str:
        """Produce a D3.js-compatible JSON string with ``nodes`` and ``links``.

        Output format::

            {
                "nodes": [{"id": "10.0.0.1", "label": "dc01", ...}],
                "links": [{"source": "10.0.0.1", "target": "10.0.0.2", ...}]
            }
        """
        nodes_out: List[Dict[str, Any]] = []
        for ip, node in self._nodes.items():
            nodes_out.append({
                "id": ip,
                "label": node.hostname or ip,
                "ports": node.ports,
                "services": node.services,
                "os": node.os,
                "risk": node.risk_score,
            })

        seen: Set[Tuple[str, str]] = set()
        links_out: List[Dict[str, Any]] = []
        for elist in self._edges.values():
            for e in elist:
                pair = (e.src, e.dst)
                if pair in seen:
                    continue
                seen.add(pair)
                links_out.append({
                    "source": e.src,
                    "target": e.dst,
                    "protocol": e.protocol,
                    "port": e.port,
                    "weight": e.weight,
                })

        payload = {"nodes": nodes_out, "links": links_out}
        return json.dumps(payload, indent=2)

    # -- summary ------------------------------------------------------------

    def summary(self) -> Dict[str, Any]:
        """Return a high-level summary dict of the topology."""
        segments = self.detect_network_segments()
        critical = self.find_critical_nodes()
        return {
            "total_hosts": len(self._nodes),
            "total_edges": len(self.edges),
            "segments": len(segments),
            "critical_nodes": [c["ip"] for c in critical[:5]],
            "avg_risk": round(
                sum(n.risk_score for n in self._nodes.values())
                / max(len(self._nodes), 1),
                2,
            ),
        }


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def build_sample_topology() -> NetworkTopology:
    """Create a small sample topology for testing / demonstration."""
    topo = NetworkTopology()

    hosts = [
        TopologyNode(ip="10.0.0.1", hostname="firewall", os="Linux",
                     ports=[22, 80], services={22: "ssh", 80: "http"},
                     risk_score=0.3),
        TopologyNode(ip="10.0.0.2", hostname="web01", os="Linux",
                     ports=[22, 80, 443], services={22: "ssh", 80: "http",
                                                     443: "https"},
                     risk_score=0.5),
        TopologyNode(ip="10.0.0.3", hostname="db01", os="Linux",
                     ports=[22, 3306], services={22: "ssh", 3306: "mysql"},
                     risk_score=0.7),
        TopologyNode(ip="10.0.0.4", hostname="dc01", os="Windows",
                     ports=[389, 445, 3389], services={389: "ldap",
                                                        445: "smb",
                                                        3389: "rdp"},
                     risk_score=0.9),
        TopologyNode(ip="10.0.0.5", hostname="wkst01", os="Windows",
                     ports=[445, 3389], services={445: "smb", 3389: "rdp"},
                     risk_score=0.4),
    ]
    connections = [
        TopologyEdge(src="10.0.0.1", dst="10.0.0.2", protocol="tcp", port=80),
        TopologyEdge(src="10.0.0.2", dst="10.0.0.3", protocol="tcp", port=3306),
        TopologyEdge(src="10.0.0.2", dst="10.0.0.4", protocol="tcp", port=445),
        TopologyEdge(src="10.0.0.4", dst="10.0.0.5", protocol="tcp", port=445),
    ]

    topo.build_topology(hosts, connections)
    return topo
