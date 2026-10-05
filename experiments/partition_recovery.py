"""Benchmark: re-convergence after healing a partition, and anti-entropy-only recovery.

    sudo python3 -m experiments.partition_recovery [--quick]

Scenario ``partition_heal``: ring topology, cut (A | B) with the admin in A, the
admin commits a rekey that only A can see, then the cut heals; the metric is
heal timestamp -> last member of B installing the new epoch.
Scenario ``suppression``: linear topology, the relay right after the admin
silently drops GROUP_UPDATE rumors; nodes beyond it can only recover through
anti-entropy (commit -> 100 % installed). ``baseline`` is the same transition
without suppression.
"""

from __future__ import annotations

import argparse
import os
import time

from experiments.harness import DATA_DIR, Cluster, common_args, mean_std, metadata, parse_args, write_results

GROUP = "bench"


def partition_heal(args: argparse.Namespace) -> list[dict]:
    """Short cuts heal via TCP retransmission of the pending rumor; cuts longer than
    TCP_USER_TIMEOUT (5 s) abort the connection and recovery falls to anti-entropy."""
    samples = []
    with Cluster("part-ring", args.nodes, "ring", seed=args.seed, anti_entropy_interval=args.anti_entropy_interval) as c:
        admin = c.nodes[0]
        c.form_group(admin, GROUP, c.nodes)
        half = len(c.nodes) // 2
        side_a, side_b = c.nodes[:half], c.nodes[half:]
        for hold in args.holds:
            for rep in range(args.reps):
                c.orch.partition(side_a, side_b)
                result = c.rpc(admin, "node.group_rekey", group_id=GROUP)
                c.wait_epoch(side_a, GROUP, result["epoch"], args.timeout)
                time.sleep(hold)  # partition persists for a while
                stale_b = sum(1 for n in side_b if c.epoch(n, GROUP) < result["epoch"])
                heal_ts = time.time()
                c.orch.heal()
                converged = c.wait_epoch(side_b, GROUP, result["epoch"], args.timeout)
                installs = c.install_ts(side_b, GROUP, result["update_id"])
                delays = [ts - heal_ts for ts in installs.values()]
                via = sorted({e.get("via") for n in side_b for e in c.events(n, "EPOCH_INSTALLED", since=heal_ts - 0.01) if e.get("update_id") == result["update_id"]})
                samples.append(
                    {
                        "hold": hold,
                        "rep": rep,
                        "isolated_members": stale_b,
                        "converged": converged,
                        "recovery": max(delays) if converged and delays else None,
                        "first_recovery": min(delays) if delays else None,
                        "installed_via": via,
                    }
                )
                print(f"[partition] hold={hold}s rep={rep} recovery={samples[-1]['recovery']} via={via}", flush=True)
    return samples


def suppression(args: argparse.Namespace) -> tuple[list[dict], list[dict]]:
    baseline, suppressed = [], []
    with Cluster("part-supp", args.nodes, "linear", seed=args.seed, anti_entropy_interval=args.anti_entropy_interval) as c:
        admin, relay = c.nodes[0], c.nodes[1]
        c.form_group(admin, GROUP, c.nodes)
        rekey = lambda: c.rpc(admin, "node.group_rekey", group_id=GROUP)  # noqa: E731
        for rep in range(args.reps):
            baseline.append(c.measure_transition(admin, GROUP, rekey, args.timeout))
        c.rpc(relay, "node.inject_attack", attack="suppress", enabled=True)
        for rep in range(args.reps):
            suppressed.append(c.measure_transition(admin, GROUP, rekey, args.timeout))
            print(f"[suppression] rep={rep} t100={suppressed[-1]['t100']}", flush=True)
        c.rpc(relay, "node.inject_attack", attack="suppress", enabled=False)
    return baseline, suppressed


def run(args: argparse.Namespace) -> dict:
    heal = partition_heal(args)
    baseline, suppressed = suppression(args)
    results = {
        "partition_heal": [
            {"hold": hold, "recovery": mean_std([s["recovery"] for s in heal if s["hold"] == hold])} for hold in args.holds
        ],
        "partition_samples": heal,
        "baseline": {"t100": mean_std([s["t100"] for s in baseline]), "samples": baseline},
        "suppression": {"t100": mean_std([s["t100"] for s in suppressed]), "samples": suppressed},
        "meta": metadata(args, None),
    }
    results["meta"]["anti_entropy_interval"] = args.anti_entropy_interval
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    common_args(parser)
    parser.add_argument("--holds", default="1,8", help="seconds the partition persists after the commit")
    parser.add_argument("--out", default=os.path.join(DATA_DIR, "partition_results.json"))
    args = parse_args(parser, argv, {"nodes": "6", "reps": 2, "holds": "0.5,6"})
    args.holds = [float(x) for x in args.holds.split(",") if x]
    path = write_results(args.out, run(args))
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
