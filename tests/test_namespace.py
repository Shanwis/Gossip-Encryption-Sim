"""Integration: netns + per-edge links, isolation by construction, crash-safe teardown (root)."""

from __future__ import annotations

import shutil
import tempfile

import pytest

from conftest import requires_root
from node.control_server import RPCError
from simulator.namespace import CommandError, CommandRunner, NamespaceManager
from simulator.network_impairer import NetemSpec, NetemUnavailable, NetworkImpairer, parse_ms
from simulator.orchestrator import Orchestrator, SimulatorError
from simulator.topology import build_graph, compile_link_plan, edge_cut, make_link, parse_edges, parse_nodes

PREFIX = "gst-"


def root_test(fn):
    return pytest.mark.root(requires_root(fn))


# ---------------------------------------------------------------- zero privilege ----


def test_link_plan_is_deterministic_and_ifnamsiz_safe():
    nodes = ["dave", "alice", "charlie", "bob"]
    plan = compile_link_plan(build_graph(nodes, "ring"))
    assert [(l.u, l.v) for l in plan] == [("alice", "charlie"), ("alice", "dave"), ("bob", "charlie"), ("bob", "dave")]
    assert all(len(l.iface_u) <= 15 for l in plan)
    assert plan[3].addr_u == "10.200.0.6" and plan[3].addr_v == "10.200.0.7" and plan[3].subnet == "10.200.0.6/31"
    assert make_link(32767, "a", "b").addr_v == "10.200.255.255"
    with pytest.raises(ValueError):
        make_link(32768, "a", "b")


def test_topologies_and_parsers():
    assert parse_nodes("3") == ["node-1", "node-2", "node-3"]
    with pytest.raises(ValueError):
        parse_nodes("a,a")
    with pytest.raises(ValueError):
        parse_nodes("a|b")
    assert parse_edges("node-1:node-2, node-2:node-3") == [("node-1", "node-2"), ("node-2", "node-3")]
    nodes = [f"n{i}" for i in range(10)]
    g1, g2 = build_graph(nodes, "random", seed=5), build_graph(nodes, "random", seed=5)
    assert sorted(g1.edges()) == sorted(g2.edges())  # seeded and reproducible
    import networkx as nx

    assert nx.is_connected(g1)
    assert build_graph(nodes, "star").degree("n0") == 9
    assert build_graph(nodes, "full").number_of_edges() == 45
    plan = compile_link_plan(build_graph(["a", "b", "c", "d"], "ring"))
    assert {(l.u, l.v) for l in edge_cut(plan, {"a", "b"}, {"c", "d"})} == {("b", "c"), ("a", "d")}


class FakeRunner(CommandRunner):
    def __init__(self, netem: bool):
        super().__init__()
        self.netem = netem

    def run(self, args, check=True, input=None):
        args = [str(a) for a in args]
        self.history.append(args)
        if "netem" in args and not self.netem:
            raise CommandError(args, 2, "Error: Specified qdisc kind is unknown.")
        import subprocess

        return subprocess.CompletedProcess(args, 0, "", "")


def test_impairer_uses_netem_inside_the_namespace():
    runner = FakeRunner(netem=True)
    imp = NetworkImpairer(NamespaceManager(runner, prefix="netns-"))
    link = make_link(0, "alice", "bob")
    spec = NetemSpec(loss=10, delay_ms=100, jitter_ms=20, reorder=25, duplicate=2)
    assert imp.apply_link(link, spec) == {"alice": "netem", "bob": "netem"}
    cmd = [c for c in runner.history if "replace" in c][0]
    assert cmd[:8] == ["tc", "-n", "netns-alice", "qdisc", "replace", "dev", "vlk0a", "root"]
    assert cmd[8:] == ["netem", "delay", "100ms", "20ms", "distribution", "normal", "loss", "10%", "reorder", "25%", "50%", "duplicate", "2%"]


def test_impairer_falls_back_to_receiver_side_drops_without_netem():
    runner = FakeRunner(netem=False)
    imp = NetworkImpairer(NamespaceManager(runner, prefix="netns-"))
    link = make_link(0, "alice", "bob")
    assert imp.apply_end(link, "alice", NetemSpec(loss=10)) == "iptables"
    rule = runner.history[-1]
    # alice's egress loss is emulated on bob's INPUT for bob's end of the link.
    assert rule[:4] == ["ip", "netns", "exec", "netns-bob"] and "INPUT" in rule and rule[rule.index("-i") + 1] == "vlk0b"
    assert "0.100000" in rule
    with pytest.raises(NetemUnavailable):
        imp.apply_end(link, "alice", NetemSpec(delay_ms=50))


def test_netem_spec_validation_and_units():
    with pytest.raises(ValueError):
        NetemSpec(reorder=10)  # reorder needs delay
    with pytest.raises(ValueError):
        NetemSpec(loss=150)
    assert NetemSpec(loss=5).merged(delay_ms=20, jitter_ms=None).to_dict()["delay_ms"] == 20
    assert parse_ms("100ms") == 100 and parse_ms("0.2s") == 200 and parse_ms(7) == 7


# ------------------------------------------------------------------- root only ----


def _connect(orch: Orchestrator, src: str, addr: str, port: int = 9000) -> str:
    code = (
        "import socket,sys\n"
        "s=socket.socket(); s.settimeout(2)\n"
        f"try:\n    s.connect(({addr!r},{port})); print('OK')\n"
        "except OSError as e:\n    print('ERR', e.errno)\n"
    )
    return orch.ns.run_in(src, ["python3", "-c", code]).stdout.strip()


@pytest.fixture
def orch():
    home = tempfile.mkdtemp(prefix="gst", dir="/tmp")
    o = Orchestrator(home, ns_prefix=PREFIX)
    yield o
    o.destroy(purge_logs=True)
    shutil.rmtree(home, ignore_errors=True)


@root_test
def test_links_addresses_and_isolation_by_construction(orch):
    orch.init(["a", "b", "c"], "linear")
    assert {orch.ns.ns_name(n) for n in "abc"} <= orch.ns.list_namespaces()
    links = orch.links()
    assert [(l.index, l.u, l.v, l.iface_u, l.addr_u, l.addr_v) for l in links] == [
        (0, "a", "b", "vlk0a", "10.200.0.0", "10.200.0.1"),
        (1, "b", "c", "vlk1a", "10.200.0.2", "10.200.0.3"),
    ]
    out = orch.runner.run(["ip", "-n", PREFIX + "b", "-o", "addr", "show"]).stdout
    assert "10.200.0.1/31" in out and "10.200.0.2/31" in out
    orch.start(anti_entropy_interval=0.5)
    # Adjacent pairs reach each other's data port; non-adjacent nodes have no route.
    assert _connect(orch, "a", "10.200.0.1") == "OK"
    assert _connect(orch, "c", "10.200.0.2") == "OK"
    assert _connect(orch, "a", "10.200.0.3") == "ERR 101"  # ENETUNREACH
    assert _connect(orch, "c", "10.200.0.0") == "ERR 101"
    assert orch.rpc("a", "node.send_direct", {"to": "b", "message": "hi"})["status"] == "SENT"
    with pytest.raises(RPCError) as exc:
        orch.rpc("a", "node.send_direct", {"to": "c", "message": "no"})
    assert exc.value.code == "ERR_PEER_UNREACHABLE"


@root_test
def test_runtime_link_add_remove(orch):
    orch.init(["a", "b", "c"], "linear")
    orch.start(anti_entropy_interval=0.5)
    link = orch.link_add("a", "c")
    assert link.index == 2 and link.iface_u == "vlk2a"
    assert _connect(orch, "a", link.addr_v) == "OK"
    assert orch.rpc("a", "node.send_direct", {"to": "c", "message": "direct now"})["status"] == "SENT"
    assert "c" in [p["node_id"] for p in orch.inspect("a")["peers"]]
    orch.link_remove("a", "c")
    assert _connect(orch, "a", link.addr_v) == "ERR 101"
    assert "c" not in [p["node_id"] for p in orch.inspect("a")["peers"]]
    with pytest.raises(SimulatorError):
        orch.link_remove("a", "c")


@root_test
def test_partition_cuts_and_heal_restores(orch):
    orch.init(["a", "b", "c", "d"], "linear")
    orch.start(anti_entropy_interval=0.5)
    cut = orch.partition(["a", "b"], ["c", "d"])
    assert [(l.u, l.v) for l in cut] == [("b", "c")]
    assert not orch.ns.link_is_up(cut[0])
    assert _connect(orch, "b", "10.200.0.3") == "ERR 101"
    # The control plane still reaches a partitioned node (UDS bypasses the netns).
    assert orch.inspect("d")["status"] == "ONLINE"
    orch.heal()
    assert orch.ns.link_is_up(cut[0])
    assert _connect(orch, "b", "10.200.0.3") == "OK"


@root_test
def test_impairment_is_recorded_and_cleared(orch):
    orch.init(["a", "b"], "linear")
    applied = orch.impair(link=("a", "b"), loss=20.0)
    assert {a["backend"] for a in applied} <= {"netem", "iptables"} and len(applied) == 2
    assert orch.ledger["links"]["0"]["impair"]["a"]["spec"]["loss"] == 20.0
    try:
        orch.impair(node="a", delay_ms=50.0, jitter_ms=5.0)
        assert orch.ledger["links"]["0"]["impair"]["a"]["spec"]["delay_ms"] == 50.0
    except NetemUnavailable:
        pass  # kernel without sch_netem: loss-only fallback is documented
    orch.clear_impairments()
    assert orch.ledger["links"]["0"]["impair"] == {}


class FailingRunner(CommandRunner):
    """Fails the second veth creation to simulate a crash mid-init."""

    def __init__(self):
        super().__init__()
        self.veths = 0

    def run(self, args, check=True, input=None):
        args = [str(a) for a in args]
        if args[:3] == ["ip", "link", "add"]:
            self.veths += 1
            if self.veths == 2:
                raise CommandError(args, 2, "induced failure")
        return super().run(args, check=check, input=input)


@root_test
def test_failed_init_rolls_back_everything():
    home = tempfile.mkdtemp(prefix="gst", dir="/tmp")
    try:
        orch = Orchestrator(home, runner=FailingRunner(), ns_prefix=PREFIX)
        with pytest.raises(CommandError):
            orch.init(["a", "b", "c"], "linear")
        assert not any(ns.startswith(PREFIX) for ns in orch.ns.list_namespaces())
        assert not orch.initialized
    finally:
        shutil.rmtree(home, ignore_errors=True)


@root_test
def test_destroy_from_ledger_after_crash():
    home = tempfile.mkdtemp(prefix="gst", dir="/tmp")
    try:
        first = Orchestrator(home, ns_prefix=PREFIX)
        first.init(["a", "b", "c"], "ring")
        first.start()
        pids = [info["pid"] for info in first.ledger["daemons"].values()]
        first.impair(link=("a", "b"), loss=5.0)
        # Simulate the CLI process dying: a fresh orchestrator only has the ledger.
        second = Orchestrator(home)
        assert second.ns.prefix == PREFIX
        removed = second.destroy()
        assert removed["namespaces"] == 3 and removed["daemons"] == 3
        assert not any(ns.startswith(PREFIX) for ns in second.ns.list_namespaces())
        for pid in pids:
            first._reap(next(n for n, p in first._procs.items() if p.pid == pid), block=True)
        assert second.destroy() == {"daemons": 0, "namespaces": 0, "links": 0}  # idempotent
    finally:
        shutil.rmtree(home, ignore_errors=True)
