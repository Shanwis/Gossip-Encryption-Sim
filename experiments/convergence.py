"""Benchmark: gossip convergence time vs per-link packet loss, and duplicate overhead vs fanout.

    sudo python3 -m experiments.convergence [--quick]

Loss sweep: for each topology (fixed seed), one cluster; for each loss level the
same per-link loss is applied to every link (both directions) and ``--reps``
membership transitions (alternating REMOVE/ADD of a rotating member) are measured.
Fanout sweep: a denser seeded random graph per fanout k, ``--reps`` REKEYs at 0 % loss.
"""

from __future__ import annotations

import argparse
import os

from experiments.harness import DATA_DIR, Cluster, common_args, mean_std, metadata, parse_args, write_results

GROUP = "bench"


def membership_transitions(cluster: Cluster, admin: str, reps: int, timeout: float) -> list[dict]:
    members = [n for n in cluster.nodes if n != admin]
    samples = []
    for rep in range(reps):
        target = members[(rep // 2) % len(members)]
        if rep % 2 == 0:
            commit = lambda t=target: cluster.rpc(admin, "node.group_leave", group_id=GROUP, member=t)  # noqa: E731
        else:
            commit = lambda t=target: cluster.rpc(admin, "node.group_join", group_id=GROUP, member=t)  # noqa: E731
        samples.append(cluster.measure_transition(admin, GROUP, commit, timeout))
    # Leave the group complete for the next data point.
    current = set(cluster.inspect(admin)["groups"][GROUP]["members"])
    for node in cluster.nodes:
        if node not in current:
            cluster.measure_transition(
                admin, GROUP, lambda n=node: cluster.rpc(admin, "node.group_join", group_id=GROUP, member=n), timeout
            )
    return samples


def summarise(samples: list[dict]) -> dict:
    return {
        "t90": mean_std([s["t90"] for s in samples]),
        "t100": mean_std([s["t100"] for s in samples]),
        "duplicates": mean_std([s["duplicates"] for s in samples]),
        "propagated": mean_std([s["propagated"] for s in samples]),
        "timeouts": sum(1 for s in samples if not s["converged"]),
        "samples": samples,
    }


def run(args: argparse.Namespace) -> dict:
    results = {"loss_sweep": [], "fanout_sweep": []}
    backend = None
    for topology in args.topologies:
        with Cluster(f"conv-{topology}", args.nodes, topology, seed=args.seed, anti_entropy_interval=args.anti_entropy_interval) as cluster:
            admin = cluster.nodes[0]
            cluster.form_group(admin, GROUP, cluster.nodes)
            for loss in args.losses:
                backend = cluster.set_loss(loss) or backend
                samples = membership_transitions(cluster, admin, args.reps, args.timeout)
                row = {"topology": topology, "loss_pct": loss, "nodes": len(cluster.nodes), **summarise(samples)}
                results["loss_sweep"].append(row)
                print(
                    f"[convergence] {topology:<7} loss={loss:>4}%  t90={row['t90']['mean']}  t100={row['t100']['mean']}"
                    f"  timeouts={row['timeouts']}",
                    flush=True,
                )
            cluster.set_loss(0)
    for k in args.fanouts:
        with Cluster(f"fan-{k}", args.nodes, "random", seed=args.seed, fanout=k, p=args.fanout_p,
                     anti_entropy_interval=args.anti_entropy_interval) as cluster:  # fmt: skip
            admin = cluster.nodes[0]
            cluster.form_group(admin, GROUP, cluster.nodes)
            samples = [
                cluster.measure_transition(admin, GROUP, lambda: cluster.rpc(admin, "node.group_rekey", group_id=GROUP), args.timeout)
                for _ in range(args.reps)
            ]
            degree = 2 * len(cluster.orch.links()) / len(cluster.nodes)
            row = {"fanout": k, "nodes": len(cluster.nodes), "mean_degree": degree, **summarise(samples)}
            results["fanout_sweep"].append(row)
            print(f"[fanout] k={k} dup/transition={row['duplicates']['mean']} t100={row['t100']['mean']}", flush=True)
    results["meta"] = metadata(args, backend)
    results["meta"]["metric"] = "commit -> EPOCH_INSTALLED at >=90% / 100% of receivers (members of e+1 except admin)"
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    # 12 nodes: with <= 10 receivers, ceil(0.9 * n) == n and t90 would equal t100.
    common_args(parser, reps=10, nodes="12")
    parser.add_argument("--topologies", default="linear,ring,random")
    parser.add_argument("--losses", default="0,5,10,20", help="per-link loss percentages")
    parser.add_argument("--fanouts", default="1,2,3,4")
    parser.add_argument("--fanout-p", type=float, default=0.5, help="edge probability for the fanout sweep graph")
    parser.add_argument("--out", default=os.path.join(DATA_DIR, "convergence_results.json"))
    args = parse_args(parser, argv, {"nodes": "5", "reps": 2, "losses": "0,10", "fanouts": "1,3", "topologies": "linear,ring"})
    args.topologies = [t for t in args.topologies.split(",") if t]
    args.losses = [float(x) for x in args.losses.split(",") if x]
    args.fanouts = [int(x) for x in args.fanouts.split(",") if x]
    path = write_results(args.out, run(args))
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
