"""Benchmark: group-message throughput and epoch-transition latency under join/leave churn.

    sudo python3 -m experiments.churn_resilience [--quick]

For each churn interval, the admin streams group messages at ``--rate`` msg/s for
``--duration`` seconds while alternately removing and re-adding a rotating member
every interval. From the JSONL logs: delivery ratio = deliveries / expected
(expected = members of the sending epoch minus the sender), throughput =
deliveries per second, and commit -> 100 % install latency per transition.
"""

from __future__ import annotations

import argparse
import os
import time

from experiments.harness import DATA_DIR, Cluster, common_args, mean_std, metadata, parse_args, write_results

GROUP = "bench"


def one_run(c: Cluster, admin: str, interval: float, args: argparse.Namespace) -> dict:
    members = [n for n in c.nodes if n != admin]
    start = time.time()
    next_send, next_churn = start, start + interval
    removed: str | None = None
    churn_idx = 0
    commits = []
    while time.time() - start < args.duration:
        now = time.time()
        if now >= next_churn:
            if removed is None:
                removed = members[churn_idx % len(members)]
                churn_idx += 1
                commits.append(c.rpc(admin, "node.group_leave", group_id=GROUP, member=removed))
            else:
                commits.append(c.rpc(admin, "node.group_join", group_id=GROUP, member=removed))
                removed = None
            next_churn += interval
        if now >= next_send:
            c.rpc(admin, "node.group_send", group_id=GROUP, message=f"m{int(now * 1000)}")
            next_send += 1.0 / args.rate
        time.sleep(max(0.0, min(next_send, next_churn) - time.time()))
    end = time.time()
    if removed is not None:  # restore the full group
        commits.append(c.rpc(admin, "node.group_join", group_id=GROUP, member=removed))
    final_epoch = commits[-1]["epoch"] if commits else c.epoch(admin, GROUP)
    c.wait_epoch(c.nodes, GROUP, final_epoch, args.timeout)
    time.sleep(args.settle)

    sent = [e for e in c.events(admin, "GROUP_MSG_SENT", since=start) if e["ts"] <= end]
    expected = sum(e["recipients"] for e in sent)
    keys = {(e["epoch"], e["counter"]) for e in sent}
    delivered = 0
    for node in members:
        delivered += sum(
            1
            for e in c.events(node, "GROUP_MSG_DELIVERED", since=start)
            if e["sender_id"] == admin and (e["epoch"], e["counter"]) in keys
        )
    latencies = []
    for commit in commits:
        receivers = [m for m in commit["members"] if m != admin]
        installs = c.install_ts(receivers, GROUP, commit["update_id"])
        if len(installs) == len(receivers) and receivers:
            latencies.append(max(installs.values()) - c.commit_ts(admin, commit["update_id"]))
    return {
        "interval": interval,
        "messages_sent": len(sent),
        "expected_deliveries": expected,
        "delivered": delivered,
        "delivery_ratio": delivered / expected if expected else None,
        "throughput": delivered / (end - start),
        "transitions": len(commits),
        "transition_latency": mean_std(latencies),
    }


def run(args: argparse.Namespace) -> dict:
    rows = []
    with Cluster("churn", args.nodes, args.topology, seed=args.seed, anti_entropy_interval=args.anti_entropy_interval) as c:
        admin = c.nodes[0]
        c.form_group(admin, GROUP, c.nodes)
        for interval in args.intervals:
            runs = [one_run(c, admin, interval, args) for _ in range(args.reps)]
            row = {
                "interval": interval,
                "churn_rate_per_s": 1.0 / interval,
                "delivery_ratio": mean_std([r["delivery_ratio"] for r in runs]),
                "throughput": mean_std([r["throughput"] for r in runs]),
                "transition_latency": mean_std([r["transition_latency"]["mean"] for r in runs]),
                "runs": runs,
            }
            rows.append(row)
            print(
                f"[churn] interval={interval}s delivery={row['delivery_ratio']['mean']:.3f} "
                f"throughput={row['throughput']['mean']:.1f}/s latency={row['transition_latency']['mean']}",
                flush=True,
            )
    return {"churn": rows, "meta": metadata(args, None)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    common_args(parser)
    parser.add_argument("--topology", default="ring")
    parser.add_argument("--intervals", default="2.0,1.0,0.5,0.25", help="seconds between membership changes")
    parser.add_argument("--rate", type=float, default=20.0, help="group messages per second")
    parser.add_argument("--duration", type=float, default=6.0)
    parser.add_argument("--settle", type=float, default=1.0)
    parser.add_argument("--out", default=os.path.join(DATA_DIR, "churn_results.json"))
    args = parse_args(parser, argv, {"nodes": "5", "reps": 2, "intervals": "1.0,0.25", "duration": 3.0})
    args.intervals = [float(x) for x in args.intervals.split(",") if x]
    path = write_results(args.out, run(args))
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
