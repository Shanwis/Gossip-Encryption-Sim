"""Shared fixtures: an in-memory, zero-privilege network of node cores.

``SimNet`` wires real NodeState/GossipEngine/MessageRouter instances together
through a FIFO "mock socket" transport. Every frame is round-tripped through the
real wire encoder/decoder, and per-node state is persisted to a temp directory
so restart scenarios use the actual persistence code.
"""

from __future__ import annotations

import os
import random
import shutil
import subprocess
from collections import deque
from typing import Callable

import pytest

from crypto.certificate import fingerprint
from crypto.encoding import b64e
from crypto.identity import IdentityKeypair
from crypto.key_agreement import KeyAgreementKeypair
from node.gossip import GossipEngine
from node.logger import EventLogger
from node.messaging import MessageRouter, Outbox, decode_payload, encode_frame
from node.state import NodeState, Roster, atomic_write_json, write_identity


class ListLogger(EventLogger):
    def __init__(self, node_id: str):
        super().__init__(node_id)
        self.events: list[dict] = []

    def log(self, event: str, **fields):
        record = super().log(event, **fields)
        self.events.append(record)
        return record

    def named(self, event: str) -> list[dict]:
        return [e for e in self.events if e["event"] == event]


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class SimTransport:
    def __init__(self, net: "SimNet", node_id: str):
        self.net = net
        self.node_id = node_id

    def neighbors(self) -> list[str]:
        return sorted(self.net.adj[self.node_id])

    def send(self, peer: str, frame: dict) -> bool:
        if peer not in self.net.adj[self.node_id]:
            return False
        self.net.sent += 1
        if not self.net.link_up(self.node_id, peer) or peer not in self.net.nodes:
            self.net.dropped += 1
            return True
        if self.net.drop_filter and self.net.drop_filter(self.node_id, peer, frame):
            self.net.dropped += 1
            return True
        self.net.queue.append((self.node_id, peer, encode_frame(frame)))
        return True


class SimNode:
    def __init__(self, net: "SimNet", node_id: str, state: NodeState, fanout: int, seed: int):
        self.node_id = node_id
        self.state = state
        self.logger = ListLogger(node_id)
        self.transport = SimTransport(net, node_id)
        self.outbox = Outbox(state, self.transport, self.logger)
        self.gossip = GossipEngine(
            state, self.outbox, self.logger, fanout=fanout, rng=random.Random(f"{seed}:{node_id}"), clock=net.clock
        )
        self.router = MessageRouter(state, self.gossip, self.outbox, self.logger)

    def group(self, gid: str):
        return self.state.groups.get(gid)

    def epoch(self, gid: str) -> int:
        g = self.group(gid)
        return g.epoch if g else 0


class SimNet:
    def __init__(self, root: str, node_ids: list[str], edges: list[tuple[str, str]], fanout: int = 3, seed: int = 0):
        self.root = root
        self.fanout = fanout
        self.seed = seed
        self.clock = FakeClock()
        self.adj: dict[str, set[str]] = {n: set() for n in node_ids}
        for u, v in edges:
            self.adj[u].add(v)
            self.adj[v].add(u)
        self.down: set[frozenset] = set()
        self.queue: deque = deque()
        self.drop_filter: Callable[[str, str, dict], bool] | None = None
        self.sent = 0
        self.dropped = 0
        self.keys = {n: (IdentityKeypair(), KeyAgreementKeypair()) for n in node_ids}
        self.roster = Roster.from_dict(
            {
                "nodes": {
                    n: {
                        "ed25519_pubkey": b64e(i.public_bytes()),
                        "x25519_pubkey": b64e(x.public_bytes()),
                        "fingerprint": fingerprint(i.public_bytes(), x.public_bytes()),
                    }
                    for n, (i, x) in self.keys.items()
                }
            }
        )
        for n, (ident, kex) in self.keys.items():
            state_dir = os.path.join(root, n)
            write_identity(state_dir, n, ident, kex)
            atomic_write_json(os.path.join(state_dir, "roster.json"), self.roster.to_dict())
            self._write_config(n)
        self.nodes: dict[str, SimNode] = {}
        for n in node_ids:
            self.start(n)

    def _write_config(self, n: str) -> None:
        links = [{"peer": p, "iface": f"sim-{n}-{p}", "local_addr": n, "remote_addr": p, "port": 9000} for p in sorted(self.adj[n])]
        atomic_write_json(os.path.join(self.root, n, "config.json"), {"node_id": n, "port": 9000, "links": links})

    def start(self, n: str) -> SimNode:
        state = NodeState.from_state_dir(os.path.join(self.root, n))
        node = SimNode(self, n, state, self.fanout, self.seed)
        self.nodes[n] = node
        return node

    def stop(self, n: str) -> None:
        node = self.nodes.pop(n)
        node.state.save()

    def restart(self, n: str) -> SimNode:
        self.stop(n)
        return self.start(n)

    def link_up(self, u: str, v: str) -> bool:
        return frozenset((u, v)) not in self.down

    def cut(self, u: str, v: str) -> None:
        self.down.add(frozenset((u, v)))

    def heal(self) -> None:
        self.down.clear()

    def run(self, max_steps: int = 200_000) -> int:
        steps = 0
        while self.queue and steps < max_steps:
            src, dst, data = self.queue.popleft()
            steps += 1
            node = self.nodes.get(dst)
            if node is None:
                continue
            node.router.handle_frame(decode_payload(data[4:]), src)
        assert not self.queue, "network did not quiesce"
        return steps

    def anti_entropy(self, rounds: int = 1) -> None:
        for _ in range(rounds):
            for n in sorted(self.nodes):
                self.nodes[n].gossip.anti_entropy_round()
            self.run()
            self.clock.advance(2.0)

    def epochs(self, gid: str) -> dict[str, int]:
        return {n: node.epoch(gid) for n, node in sorted(self.nodes.items())}


def linear(names: list[str]) -> list[tuple[str, str]]:
    return list(zip(names, names[1:]))


@pytest.fixture
def make_net(tmp_path):
    def factory(names, edges=None, **kwargs) -> SimNet:
        return SimNet(str(tmp_path / "nodes"), names, edges if edges is not None else linear(names), **kwargs)

    return factory


def root_available() -> bool:
    if os.geteuid() != 0 or shutil.which("ip") is None:
        return False
    probe = "gsprobe-ns"
    ok = subprocess.run(["ip", "netns", "add", probe], capture_output=True).returncode == 0
    if ok:
        subprocess.run(["ip", "netns", "del", probe], capture_output=True)
    return ok


ROOT_OK = root_available()
requires_root = pytest.mark.skipif(not ROOT_OK, reason="requires root, iproute2 and network namespace support")
