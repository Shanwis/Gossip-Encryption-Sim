"""Seen cache, update log, fanout, framing, HELLO and real TCP/UDS daemons on localhost."""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import struct
import tempfile
import time

import pytest

from crypto.certificate import fingerprint
from crypto.encoding import b64e
from crypto.identity import IdentityKeypair
from crypto.key_agreement import KeyAgreementKeypair
from node.control_server import RPCError, rpc_call
from node.daemon import NodeDaemon
from node.logger import EventLogger, read_events
from node.messaging import (
    MAX_FRAME,
    FrameError,
    ProtocolError,
    encode_frame,
    make_hello,
    read_frame,
    validate_frame,
    verify_hello,
)
from node.state import NodeState, SeenCache, StatePaths, UpdateLog, atomic_write_json, write_identity


def test_seen_cache_is_bounded_lru():
    cache = SeenCache(capacity=3)
    for item in "abc":
        cache.add(item)
    assert "a" in cache  # touch -> most recently used
    cache.add("d")
    assert "b" not in cache and all(x in cache for x in "acd")
    assert len(cache) == 3


def test_seen_set_persists_across_restart(make_net):
    net = make_net(["a", "b"])
    update = net.nodes["a"].gossip.create_group("g")
    net.run()
    b = net.restart("b")
    assert update["update_id"] in b.state.seen_updates
    assert b.gossip.handle_group_update(update, "a") == "DUPLICATE"
    assert b.epoch("g") == 1  # resumed at its last epoch, not 0


def test_update_log_ring_buffer():
    log = UpdateLog(capacity=256)
    for e in range(1, 301):
        log.append({"new_epoch": e, "update_id": f"{e:064x}"})
    assert len(log) == 256 and log.oldest_epoch() == 45 and log.latest()["new_epoch"] == 300
    picked = log.since(100, limit=64)
    assert [u["new_epoch"] for u in picked] == list(range(101, 165))
    assert log.since(100, limit=2, exclude={f"{101:064x}"})[0]["new_epoch"] == 102


def test_fanout_selects_k_distinct_peers_excluding_sender(make_net):
    names = ["hub", "p1", "p2", "p3", "p4", "p5"]
    net = make_net(names, edges=[("hub", p) for p in names[1:]], fanout=2)
    hub = net.nodes["hub"]
    for trial in range(20):
        picks = hub.gossip._forward({"update_id": "x", "group_id": "g"}, exclude="p1")
        assert len(picks) == 2 and len(set(picks)) == 2 and "p1" not in picks
    hub.gossip.fanout = 10
    assert sorted(hub.gossip._forward({"update_id": "x", "group_id": "g"}, exclude="p3")) == ["p1", "p2", "p4", "p5"]
    net.queue.clear()


def test_fanout_sampling_is_seeded(make_net):
    names = ["hub", "p1", "p2", "p3", "p4", "p5"]
    runs = []
    for _ in range(2):
        net = make_net(names, edges=[("hub", p) for p in names[1:]], fanout=2, seed=7)
        runs.append([tuple(net.nodes["hub"].gossip._forward({"update_id": "x", "group_id": "g"}, None)) for _ in range(5)])
        net.queue.clear()
    assert runs[0] == runs[1]


@pytest.mark.parametrize("topology", ["linear", "ring"])
def test_epidemic_convergence_over_mock_sockets(make_net, topology):
    names = [f"n{i}" for i in range(8)]
    edges = list(zip(names, names[1:])) + ([(names[-1], names[0])] if topology == "ring" else [])
    net = make_net(names, edges=edges)
    admin = net.nodes["n0"]
    admin.gossip.create_group("g")
    for name in names[1:]:
        admin.gossip.add_member("g", name)
    net.run()
    assert set(net.epochs("g").values()) == {8}
    assert all(net.nodes[n].group("g").keys.get(8) == admin.group("g").keys[8] for n in names)
    if topology == "ring":  # two paths -> duplicates are dropped, not re-applied
        assert sum(net.nodes[n].state.stats["duplicates_dropped"] for n in names) > 0


def test_frame_ceiling_and_malformed_payloads():
    with pytest.raises(FrameError):
        encode_frame({"blob": "x" * (MAX_FRAME + 1)})

    async def feed(data: bytes):
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        return await read_frame(reader)

    with pytest.raises(FrameError):
        asyncio.run(feed(struct.pack(">I", MAX_FRAME + 1)))
    with pytest.raises(FrameError):
        asyncio.run(feed(struct.pack(">I", 3) + b"{x}"))
    with pytest.raises(FrameError):
        asyncio.run(feed(struct.pack(">I", 2) + b"[]"))
    assert asyncio.run(feed(encode_frame({"a": 1}))) == {"a": 1}


@pytest.mark.parametrize(
    "frame",
    [
        {"version": 2, "type": "HELLO"},
        {"version": 1, "type": "NOPE"},
        {"version": 1, "type": "DIRECT_MSG", "msg_id": "d_1", "sender_id": "a|b", "recipient_id": "b", "timestamp": 1, "payload": ""},
        {"version": 1, "type": "GROUP_MSG", "msg_id": "m", "group_id": "g", "epoch": 1, "sender_id": "a", "counter": 0, "nonce": "", "ciphertext": ""},
        {"version": 1, "type": "STATE_REQUEST", "req_id": "r", "sender_id": "a", "group_id": "g", "from_epoch": -1},
    ],
)
def test_validate_frame_rejects(frame):
    with pytest.raises(ProtocolError):
        validate_frame(frame)


def test_hello_is_checked_against_pinned_roster(make_net):
    net = make_net(["a", "b"])
    a, b = net.nodes["a"].state, net.nodes["b"].state
    assert verify_hello(b, make_hello(a)) == "a"
    spoofed = dict(make_hello(a), ed25519_pubkey=b64e(IdentityKeypair().public_bytes()))
    with pytest.raises(ProtocolError) as exc:
        verify_hello(b, spoofed)
    assert exc.value.code == "ERR_IDENTITY_UNKNOWN"
    with pytest.raises(ProtocolError):
        verify_hello(b, dict(make_hello(a), node_id="mallory"))


def test_sender_must_match_hello_identity(make_net):
    net = make_net(["a", "b", "c"], edges=[("a", "b"), ("b", "c")])
    b = net.nodes["b"]
    digest = net.nodes["a"].gossip.make_digest()
    assert b.router.handle_frame(digest, "c") == "ERR_IDENTITY_UNKNOWN"


# ---------------------------------------------------------------------------
# Real asyncio TCP + UDS daemons on localhost (zero privilege)
# ---------------------------------------------------------------------------
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def localhost_cluster():
    home = tempfile.mkdtemp(prefix="gsd", dir="/tmp")  # short: UDS paths are limited to 107 bytes
    names = ["a", "b", "c"]
    edges = [("a", "b"), ("b", "c")]
    ports = {n: _free_port() for n in names}
    keys = {n: (IdentityKeypair(), KeyAgreementKeypair()) for n in names}
    roster = {
        "version": 1,
        "nodes": {
            n: {
                "ed25519_pubkey": b64e(i.public_bytes()),
                "x25519_pubkey": b64e(x.public_bytes()),
                "fingerprint": fingerprint(i.public_bytes(), x.public_bytes()),
            }
            for n, (i, x) in keys.items()
        },
    }
    paths = StatePaths(home)
    for n, (ident, kex) in keys.items():
        state_dir = paths.state_dir(n)
        write_identity(state_dir, n, ident, kex)
        atomic_write_json(os.path.join(state_dir, "roster.json"), roster)
        links = [
            {"peer": p, "iface": "lo", "local_addr": "127.0.0.1", "remote_addr": "127.0.0.1", "port": ports[p]}
            for u, v in edges
            for (me, p) in ((u, v), (v, u))
            if me == n
        ]
        atomic_write_json(os.path.join(state_dir, "config.json"), {"node_id": n, "port": ports[n], "links": links})
    yield home, names, ports
    shutil.rmtree(home, ignore_errors=True)


async def _wait(predicate, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if await predicate():
            return True
        await asyncio.sleep(0.05)
    return False


async def test_daemons_over_real_tcp_and_uds(localhost_cluster):
    home, names, ports = localhost_cluster
    paths = StatePaths(home)
    daemons = {}
    for n in names:
        state = NodeState.from_state_dir(paths.state_dir(n))
        daemons[n] = NodeDaemon(
            state, StatePaths(home, n), EventLogger(n, paths.log(n)), host="127.0.0.1", anti_entropy_interval=0.3, seed=1
        )
        await daemons[n].start()

    async def rpc(node, method, **params):
        return await asyncio.to_thread(rpc_call, paths.socket(node), method, params)

    try:
        assert (await rpc("a", "node.send_direct", to="b", message="hi"))["status"] == "SENT"
        with pytest.raises(RPCError) as exc:
            await rpc("a", "node.send_direct", to="c", message="no path")
        assert exc.value.code == "ERR_PEER_UNREACHABLE"

        await rpc("a", "node.group_create", group_id="team")
        await rpc("a", "node.group_join", group_id="team", member="b")
        await rpc("a", "node.group_join", group_id="team", member="c")

        async def converged():
            data = await rpc("c", "node.inspect")
            return data["groups"].get("team", {}).get("epoch") == 3

        assert await _wait(converged)
        await rpc("a", "node.group_send", group_id="team", message="over tcp")

        async def delivered():
            return any(m["message"] == "over tcp" for m in (await rpc("c", "node.inspect"))["inbox"])

        assert await _wait(delivered)
        info = await rpc("b", "node.inspect")
        assert info["direct_inbox"][-1]["message"] == "hi"
        assert {p["node_id"] for p in info["peers"]} == {"a", "c"}
        assert info["groups"]["team"]["role"] == "MEMBER" and info["groups"]["team"]["key_fingerprint"]

        # Secret export is daemon-gated.
        with pytest.raises(RPCError) as exc:
            await rpc("b", "node.secrets")
        assert exc.value.code == "ERR_UNSAFE_DISABLED"

        # A spoofed HELLO is rejected and logged.
        reader, writer = await asyncio.open_connection("127.0.0.1", ports["b"])
        forged = dict(make_hello(daemons["a"].state), ed25519_pubkey=b64e(IdentityKeypair().public_bytes()))
        writer.write(encode_frame(forged))
        await writer.drain()
        await reader.read()  # server closes the connection
        writer.close()
        assert any(e["event"] == "HELLO_REJECTED" for e in read_events(paths.log("b")))

        # Restart c: it reloads persisted state and resyncs a missed rekey.
        await daemons["c"].stop()
        await rpc("a", "node.group_rekey", group_id="team")
        state = NodeState.from_state_dir(paths.state_dir("c"))
        assert state.groups["team"].epoch == 3
        daemons["c"] = NodeDaemon(state, StatePaths(home, "c"), EventLogger("c", paths.log("c")), host="127.0.0.1", anti_entropy_interval=0.3, seed=1)
        await daemons["c"].start()

        async def caught_up():
            return (await rpc("c", "node.inspect"))["groups"]["team"]["epoch"] == 4

        assert await _wait(caught_up)
    finally:
        for d in daemons.values():
            await d.stop()


def test_rpc_unknown_method_and_bad_params(localhost_cluster):
    home, names, _ = localhost_cluster
    paths = StatePaths(home)

    async def scenario():
        state = NodeState.from_state_dir(paths.state_dir("a"))
        daemon = NodeDaemon(state, StatePaths(home, "a"), EventLogger("a"), host="127.0.0.1")
        await daemon.start()
        try:
            with pytest.raises(RPCError):
                await asyncio.to_thread(rpc_call, paths.socket("a"), "node.nope", {})
            with pytest.raises(RPCError) as exc:
                await asyncio.to_thread(rpc_call, paths.socket("a"), "node.group_join", {"group_id": "zz"})
            assert exc.value.code == "ERR_INVALID_PARAMS"
            assert oct(os.stat(paths.socket("a")).st_mode & 0o777) == "0o660"
        finally:
            await daemon.stop()

    asyncio.run(scenario())
