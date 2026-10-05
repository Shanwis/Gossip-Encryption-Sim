"""NetworkX topology -> deterministic per-edge link plan (one veth pair + /31 per edge).

Link ``n`` uses ``10.200.0.0/16`` offset ``2n`` (RFC 3021 /31). The lexicographically
smaller node ID of the edge owns interface ``vlk{n}a`` and the even (``.0``-style)
address; the other node owns ``vlk{n}b`` and the odd address.
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import asdict, dataclass

import networkx as nx

from crypto.encoding import EncodingError, validate_id

LINK_BASE = ipaddress.IPv4Network("10.200.0.0/16")
MAX_LINKS = LINK_BASE.num_addresses // 2
TOPOLOGIES = ("linear", "ring", "star", "full", "random", "custom")


@dataclass
class LinkSpec:
    index: int
    u: str
    v: str
    iface_u: str
    iface_v: str
    addr_u: str
    addr_v: str
    subnet: str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "LinkSpec":
        return cls(**{k: data[k] for k in cls.__dataclass_fields__})

    def end(self, node: str) -> tuple[str, str, str, str]:
        """(iface, local_addr, peer, remote_addr) as seen from ``node``."""
        if node == self.u:
            return self.iface_u, self.addr_u, self.v, self.addr_v
        if node == self.v:
            return self.iface_v, self.addr_v, self.u, self.addr_u
        raise KeyError(f"{node} is not an endpoint of link {self.index}")

    @property
    def key(self) -> tuple[str, str]:
        return (self.u, self.v)


def parse_nodes(spec: str) -> list[str]:
    """``"5"`` -> node-1..node-5; otherwise a comma-separated list of IDs."""
    spec = spec.strip()
    if spec.isdigit():
        count = int(spec)
        if count < 1:
            raise ValueError("need at least one node")
        return [f"node-{i}" for i in range(1, count + 1)]
    names = [n.strip() for n in spec.split(",") if n.strip()]
    if not names:
        raise ValueError("no node names given")
    for name in names:
        try:
            validate_id(name, "node_id")
        except EncodingError as exc:
            raise ValueError(str(exc)) from exc
    if len(set(names)) != len(names):
        raise ValueError("duplicate node names")
    return names


def parse_edges(spec: str) -> list[tuple[str, str]]:
    """``"a:b,b:c"`` (``:`` cannot appear in IDs, unlike ``-``)."""
    edges = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        if item.count(":") != 1:
            raise ValueError(f"edge {item!r} must look like a:b")
        u, v = item.split(":")
        edges.append((u.strip(), v.strip()))
    return edges


def build_graph(
    nodes: list[str],
    topology: str = "linear",
    seed: int = 0,
    p: float | None = None,
    edges: list[tuple[str, str]] | None = None,
) -> nx.Graph:
    g = nx.Graph()
    g.add_nodes_from(nodes)
    n = len(nodes)
    if topology == "linear":
        g.add_edges_from(zip(nodes, nodes[1:]))
    elif topology == "ring":
        g.add_edges_from(zip(nodes, nodes[1:]))
        if n > 2:
            g.add_edge(nodes[-1], nodes[0])
    elif topology == "star":
        g.add_edges_from((nodes[0], other) for other in nodes[1:])
    elif topology == "full":
        g.add_edges_from((a, b) for i, a in enumerate(nodes) for b in nodes[i + 1 :])
    elif topology == "random":
        prob = p if p is not None else min(1.0, 2.0 * math.log(max(n, 2)) / max(n, 2))
        for attempt in range(1000):
            candidate = nx.gnp_random_graph(n, prob, seed=seed + attempt)
            if n <= 1 or nx.is_connected(candidate):
                g.add_edges_from((nodes[a], nodes[b]) for a, b in candidate.edges())
                break
        else:
            raise ValueError(f"could not draw a connected G({n}, {prob}) graph")
    elif topology == "custom":
        for u, v in edges or []:
            if u not in g or v not in g:
                raise ValueError(f"edge {u}-{v} references an unknown node")
            if u == v:
                raise ValueError("self loops are not allowed")
            g.add_edge(u, v)
    else:
        raise ValueError(f"unknown topology {topology!r} (choose from {', '.join(TOPOLOGIES)})")
    return g


def link_addresses(index: int) -> tuple[str, str, str]:
    if not 0 <= index < MAX_LINKS:
        raise ValueError(f"link index {index} outside the /31 pool")
    base = int(LINK_BASE.network_address) + 2 * index
    a, b = ipaddress.IPv4Address(base), ipaddress.IPv4Address(base + 1)
    return str(a), str(b), f"{a}/31"


def make_link(index: int, u: str, v: str) -> LinkSpec:
    lo, hi = sorted((u, v))
    addr_lo, addr_hi, subnet = link_addresses(index)
    return LinkSpec(index, lo, hi, f"vlk{index}a", f"vlk{index}b", addr_lo, addr_hi, subnet)


def compile_link_plan(graph: nx.Graph) -> list[LinkSpec]:
    """Deterministic: sorted (lo, hi) node-ID pairs get indices 0..E-1."""
    pairs = sorted(tuple(sorted(edge)) for edge in graph.edges())
    return [make_link(i, u, v) for i, (u, v) in enumerate(pairs)]


def allocate_index(used: set[int]) -> int:
    """Lowest free link index (runtime ``link add``)."""
    index = 0
    while index in used:
        index += 1
    if index >= MAX_LINKS:
        raise ValueError("link pool exhausted")
    return index


def node_links(links: list[LinkSpec], node: str) -> list[dict]:
    """Per-node link config consumed by the daemon (peer table)."""
    out = []
    for link in links:
        if node in (link.u, link.v):
            iface, local, peer, remote = link.end(node)
            out.append({"peer": peer, "iface": iface, "local_addr": local, "remote_addr": remote, "link_index": link.index})
    return sorted(out, key=lambda item: item["peer"])


def edge_cut(links: list[LinkSpec], group_a: set[str], group_b: set[str]) -> list[LinkSpec]:
    """Links with one endpoint in A and the other in B."""
    if group_a & group_b:
        raise ValueError("partition sides overlap")
    return [l for l in links if (l.u in group_a and l.v in group_b) or (l.u in group_b and l.v in group_a)]


def graph_from_links(nodes: list[str], links: list[LinkSpec]) -> nx.Graph:
    g = nx.Graph()
    g.add_nodes_from(nodes)
    g.add_edges_from(link.key for link in links)
    return g
