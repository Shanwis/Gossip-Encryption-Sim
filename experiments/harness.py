"""Shared experiment harness: seeded clusters, convergence measurement, statistics.

Metric definition (PLAN.md Resolved Decision 6): convergence time is measured from
the Admin's ``UPDATE_COMMITTED`` timestamp to the ``EPOCH_INSTALLED`` timestamps of
the *receivers* (members of e+1 other than the Admin), all taken from JSONL logs on
the shared host clock; t90 = time until >= 90 % of receivers installed e+1, t100 =
time until all did.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import statistics
import time
from typing import Any, Callable

from node.logger import read_events
from simulator.orchestrator import Orchestrator, teardown_on_signal
from simulator.topology import parse_nodes

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
EXP_HOME = "/tmp/gossip-exp"
EXP_NS_PREFIX = "gx-"


def mean_std(values: list[float]) -> dict:
    vals = [v for v in values if v is not None]
    return {
        "mean": statistics.fmean(vals) if vals else None,
        "stdev": statistics.stdev(vals) if len(vals) > 1 else 0.0 if vals else None,
        "n": len(vals),
        "missing": len(values) - len(vals),
    }


def write_results(path: str, data: dict) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    return path


def metadata(args: argparse.Namespace, backend: str | None) -> dict:
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "kernel": platform.release(),
        "impairment_backend": backend,
        "args": {k: v for k, v in vars(args).items() if k != "func"},
    }


def common_args(parser: argparse.ArgumentParser, reps: int = 5, nodes: str = "8") -> None:
    parser.add_argument("--nodes", default=nodes, help="node count or comma list")
    parser.add_argument("--reps", type=int, default=reps, help="repetitions per data point (N >= 5 for reports)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--anti-entropy-interval", type=float, default=2.0)
    parser.add_argument("--timeout", type=float, default=30.0, help="per-transition convergence timeout (s)")
    parser.add_argument("--quick", action="store_true", help="small smoke-test configuration")


def parse_args(parser: argparse.ArgumentParser, argv: list[str] | None, quick: dict) -> argparse.Namespace:
    """``--quick`` swaps in small defaults; explicitly passed flags still win."""
    known, _ = parser.parse_known_args(argv)
    if known.quick:
        parser.set_defaults(**quick)
    return parser.parse_args(argv)


class Cluster:
    """A seeded simulation in its own home + namespace prefix, torn down on exit/signal."""

    def __init__(
        self,
        name: str,
        nodes: list[str] | str,
        topology: str,
        seed: int = 42,
        fanout: int = 3,
        anti_entropy_interval: float = 2.0,
        p: float | None = None,
        unsafe_nodes: set[str] | None = None,
    ):
        self.name = name
        self.nodes = parse_nodes(nodes) if isinstance(nodes, str) else list(nodes)
        self.topology = topology
        self.seed = seed
        self.fanout = fanout
        self.ae = anti_entropy_interval
        self.p = p
        self.unsafe_nodes = unsafe_nodes or set()
        self.orch = Orchestrator(os.path.join(EXP_HOME, name), ns_prefix=EXP_NS_PREFIX)
        self._guard = None

    def __enter__(self) -> "Cluster":
        self.orch.destroy(purge_logs=True)
        self._guard = teardown_on_signal(self.orch)
        self._guard.__enter__()
        self.orch.init(self.nodes, self.topology, seed=self.seed, p=self.p)
        self.orch.start(fanout=self.fanout, anti_entropy_interval=self.ae, seed=self.seed, unsafe_nodes=self.unsafe_nodes)
        return self

    def __exit__(self, *exc) -> None:
        self._guard.__exit__(*exc)

    # --- control -------------------------------------------------------------
    def rpc(self, node: str, method: str, **params) -> Any:
        return self.orch.rpc(node, method, params)

    def inspect(self, node: str) -> dict:
        return self.orch.inspect(node)

    def epoch(self, node: str, group: str) -> int:
        return self.inspect(node)["groups"].get(group, {}).get("epoch", 0)

    def wait(self, predicate: Callable[[], bool], timeout: float, interval: float = 0.05) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return True
            time.sleep(interval)
        return False

    def wait_epoch(self, nodes: list[str], group: str, epoch: int, timeout: float) -> bool:
        return self.wait(lambda: all(self.epoch(n, group) >= epoch for n in nodes), timeout)

    def form_group(self, admin: str, group: str, members: list[str], timeout: float = 60.0) -> int:
        self.rpc(admin, "node.group_create", group_id=group)
        epoch = 1
        for member in members:
            if member != admin:
                epoch = self.rpc(admin, "node.group_join", group_id=group, member=member)["epoch"]
        if not self.wait_epoch(self.nodes, group, epoch, timeout):
            raise RuntimeError(f"group {group} did not converge to epoch {epoch}")
        return epoch

    def set_loss(self, pct: float) -> str | None:
        if pct <= 0:
            self.orch.clear_impairments()
            return None
        backends = set()
        for link in self.orch.links():
            for item in self.orch.impair(link=link.key, loss=pct):
                backends.add(item["backend"])
        return ",".join(sorted(backends))

    def stats_sum(self, key: str) -> int:
        return sum(self.inspect(n)["stats"].get(key, 0) for n in self.nodes)

    # --- logs ------------------------------------------------------------------
    def events(self, node: str, event: str | None = None, since: float = 0.0) -> list[dict]:
        return [
            e for e in read_events(self.orch.paths.log(node)) if e["ts"] >= since and (event is None or e["event"] == event)
        ]

    def commit_ts(self, admin: str, update_id: str) -> float:
        for e in self.events(admin, "UPDATE_COMMITTED"):
            if e.get("update_id") == update_id:
                return e["ts"]
        raise RuntimeError(f"no UPDATE_COMMITTED for {update_id}")

    def install_ts(self, nodes: list[str], group: str, update_id: str) -> dict[str, float]:
        out = {}
        for node in nodes:
            for e in self.events(node, "EPOCH_INSTALLED"):
                if e.get("group_id") == group and e.get("update_id") == update_id:
                    out[node] = e["ts"]
                    break
        return out

    def measure_transition(self, admin: str, group: str, commit: Callable[[], dict], timeout: float) -> dict:
        """Run one admin commit and measure t90/t100 over its receivers."""
        dup_before = self.stats_sum("duplicates_dropped")
        prop_before = self.stats_sum("gossip_propagated")
        result = commit()
        receivers = [m for m in result["members"] if m != admin]
        converged = self.wait_epoch(receivers, group, result["epoch"], timeout)
        time.sleep(0.2)  # let in-flight duplicates land before counting them
        t0 = self.commit_ts(admin, result["update_id"])
        installs = self.install_ts(receivers, group, result["update_id"])
        delays = sorted(ts - t0 for ts in installs.values())
        need90 = math.ceil(0.9 * len(receivers))
        return {
            "epoch": result["epoch"],
            "action": result["action"],
            "receivers": len(receivers),
            "installed": len(installs),
            "converged": converged,
            "t90": delays[need90 - 1] if receivers and len(delays) >= need90 else None,
            "t100": delays[-1] if receivers and len(delays) == len(receivers) else None,
            "duplicates": self.stats_sum("duplicates_dropped") - dup_before,
            "propagated": self.stats_sum("gossip_propagated") - prop_before,
        }
