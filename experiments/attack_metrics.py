"""Benchmark: detection rate and time-to-detect for replay, tampering, forgery, double-sign.

    sudo python3 -m experiments.attack_metrics [--quick]

Linear topology, admin = first node, attacker = second node, target = third node.
Time-to-detect = injection timestamp (attacker log, or the triggering send for
in-transit tampering) -> matching detection event in the target's JSONL log.
Double-sign detection rate is the fraction of non-admin nodes that log
``ADMIN_DOUBLE_SIGN``.
"""

from __future__ import annotations

import argparse
import os
import time

from experiments.harness import DATA_DIR, Cluster, common_args, mean_std, metadata, parse_args, write_results
from simulator.attack_engine import AttackEngine

GROUP = "bench"


def run(args: argparse.Namespace) -> dict:
    results: dict[str, dict] = {}
    with Cluster("attacks", args.nodes, "linear", seed=args.seed, anti_entropy_interval=args.anti_entropy_interval) as c:
        engine = AttackEngine(c.orch)
        admin, attacker, target = c.nodes[0], c.nodes[1], c.nodes[2]
        c.form_group(admin, GROUP, c.nodes)

        def detect(node: str, expect: tuple, ref: float, extra: dict | None = None) -> float | None:
            """Seconds from ``ref`` (injection / triggering send) to the detection event."""
            record = engine.wait_for_event(
                node, expect[0], ref - 0.01, {**expect[1], **(extra or {})}, timeout=args.detect_timeout
            )
            return max(0.0, record["ts"] - ref) if record else None

        def send(text: str) -> float:
            t0 = time.time()
            c.rpc(admin, "node.group_send", group_id=GROUP, message=text)
            return t0

        scenarios = {
            "replay_msg": [],
            "replay_update": [],
            "tamper_msg": [],
            "tamper_update": [],
            "forge": [],
            "forge_unauthorized": [],
            "double_sign": [],
        }
        for rep in range(args.reps):
            t0 = send(f"capture-{rep}")
            c.wait(lambda: any(m["message"] == f"capture-{rep}" for m in c.inspect(target)["inbox"]), 5.0)
            res = engine.replay(target, via=attacker, kind="msg")
            scenarios["replay_msg"].append(detect(target, res["expect"], res["ts"], {"msg_id": res["msg_id"]}))

            res = engine.replay(target, via=attacker, kind="update")
            scenarios["replay_update"].append(detect(target, res["expect"], res["ts"], {"update_id": res["update_id"]}))

            res = engine.tamper(attacker, target, kind="msg")
            t0 = send(f"tamper-{rep}")
            scenarios["tamper_msg"].append(detect(target, res["expect"], t0))

            res = engine.tamper(attacker, target, kind="update")
            t0 = time.time()
            commit = c.rpc(admin, "node.group_rekey", group_id=GROUP)
            scenarios["tamper_update"].append(detect(target, res["expect"], t0))
            c.wait_epoch(c.nodes, GROUP, commit["epoch"], args.timeout)  # anti-entropy heals the victim

            res = engine.forge(admin, target, via=attacker)
            scenarios["forge"].append(detect(target, res["expect"], res["ts"], {"update_id": res["update_id"]}))
            res = engine.forge(attacker, target, via=attacker)
            scenarios["forge_unauthorized"].append(detect(target, res["expect"], res["ts"], {"update_id": res["update_id"]}))

            res = engine.double_sign(admin, GROUP)
            t0 = res["ts"]
            observers = [n for n in c.nodes if n != admin]
            per_node = [detect(n, res["expect"], t0, {"conflicting_update_id": res["update_ids"][1]}) for n in observers]
            scenarios["double_sign"].append(per_node)
            c.wait_epoch(c.nodes, GROUP, res["epoch"], args.timeout)
            print(f"[attacks] rep={rep} done", flush=True)

        for name, samples in scenarios.items():
            if name == "double_sign":
                flat = [x for per in samples for x in per]
                rate = sum(1 for x in flat if x is not None) / len(flat) if flat else 0.0
            else:
                flat = samples
                rate = sum(1 for x in flat if x is not None) / len(flat) if flat else 0.0
            results[name] = {"detection_rate": rate, "time_to_detect": mean_std(flat), "samples": samples}
            print(f"[attacks] {name:<18} rate={rate:.2f} ttd={results[name]['time_to_detect']['mean']}", flush=True)
        results["telemetry"] = {n: c.inspect(n)["stats"] for n in c.nodes}
    return {"attacks": results, "meta": metadata(args, None)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    common_args(parser, nodes="5")
    parser.add_argument("--detect-timeout", type=float, default=10.0)
    parser.add_argument("--out", default=os.path.join(DATA_DIR, "attack_results.json"))
    args = parse_args(parser, argv, {"nodes": "4", "reps": 2})
    path = write_results(args.out, run(args))
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
