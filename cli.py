#!/usr/bin/env python3
"""gossip-sim: command-line orchestrator for the gossip secure-messaging simulator.

Network setup/teardown commands need root (sudo); node commands talk to daemons
over their Unix sockets and must run as the socket owner (the sudo-invoking user).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

from node.control_server import RPCError
from node.state import default_home
from simulator.attack_engine import AttackEngine
from simulator.namespace import CommandError
from simulator.network_impairer import NetemUnavailable, parse_ms
from simulator.orchestrator import Orchestrator, SimulatorError
from simulator.topology import TOPOLOGIES, parse_edges, parse_nodes


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _pair(value: str) -> tuple[str, str]:
    items = _csv(value)
    if len(items) != 2:
        raise argparse.ArgumentTypeError("expected two comma-separated node IDs, e.g. alice,bob")
    return items[0], items[1]


def _dump(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True, default=str))


# ---------------------------------------------------------------------------
# Simulator management
# ---------------------------------------------------------------------------
def cmd_init(orch: Orchestrator, args) -> None:
    nodes = parse_nodes(args.nodes)
    edges = parse_edges(args.edges) if args.edges else None
    topology = "custom" if edges else args.topology
    summary = orch.init(nodes, topology, seed=args.seed, port=args.port, p=args.p, edges=edges, force=args.force)
    print(f"initialised {len(nodes)} nodes ({topology}) in {summary['home']}")
    for link in summary["links"]:
        print(f"  link {link['index']}: {link['u']}[{link['ifaces'][0]} {link['addrs'][0]}] <-> {link['v']}[{link['ifaces'][1]} {link['addrs'][1]}]")


def cmd_start(orch: Orchestrator, args) -> None:
    unsafe = set(orch.nodes) if args.unsafe_allow_secret_export else set(_csv(args.unsafe_nodes or ""))
    started = orch.start(
        nodes=_csv(args.nodes) if args.nodes else None,
        fanout=args.fanout,
        anti_entropy_interval=args.anti_entropy_interval,
        seed=args.seed,
        unsafe_nodes=unsafe,
    )
    print(f"started {len(started)} daemon(s): {', '.join(started) or '-'}")


def cmd_stop(orch: Orchestrator, args) -> None:
    stopped = orch.stop(_csv(args.nodes) if args.nodes else None)
    print(f"stopped {len(stopped)} daemon(s): {', '.join(stopped) or '-'}")


def cmd_status(orch: Orchestrator, args) -> None:
    if not orch.initialized:
        print(f"no simulation in {orch.home}")
        return
    status = orch.status()
    if args.json:
        _dump(status)
        return
    print(f"home: {status['home']}   topology: {status['topology']}")
    for node, info in status["daemons"].items():
        state = "running" if info["running"] else "stopped"
        groups = ", ".join(f"{g}@{e}" for g, e in info.get("groups", {}).items()) or "-"
        print(f"  {node:<12} {state:<8} pid={info['pid'] or '-':<8} groups: {groups}")
    _print_links(status["links"], status.get("partition"))


def _print_links(links: list[dict], partition) -> None:
    print("links:")
    for link in links:
        impair = "; ".join(
            f"{node}:{_fmt_spec(entry['spec'])} ({entry['backend']})" for node, entry in sorted(link["impair"].items())
        )
        print(
            f"  [{link['index']}] {link['u']}<->{link['v']}  {link['ifaces'][0]}/{link['ifaces'][1]}  "
            f"{link['addrs'][0]}/{link['addrs'][1]}  {'UP' if link['up'] else 'DOWN (cut)'}"
            + (f"  impair: {impair}" if impair else "")
        )
    if partition:
        print(f"partition: {','.join(partition['a'])} | {','.join(partition['b'])}")


def _fmt_spec(spec: dict) -> str:
    parts = []
    if spec.get("loss"):
        parts.append(f"loss {spec['loss']:g}%")
    if spec.get("delay_ms"):
        parts.append(f"delay {spec['delay_ms']:g}ms" + (f"±{spec['jitter_ms']:g}ms" if spec.get("jitter_ms") else ""))
    if spec.get("reorder"):
        parts.append(f"reorder {spec['reorder']:g}%")
    if spec.get("duplicate"):
        parts.append(f"dup {spec['duplicate']:g}%")
    return ", ".join(parts) or "none"


def cmd_destroy(orch: Orchestrator, args) -> None:
    removed = orch.destroy(purge_logs=args.purge_logs)
    print(
        f"destroyed: {removed['daemons']} daemon(s), {removed['links']} link(s), {removed['namespaces']} namespace(s)"
    )


# ---------------------------------------------------------------------------
# Topology / messaging / groups
# ---------------------------------------------------------------------------
def cmd_link(orch: Orchestrator, args) -> None:
    if args.link_cmd == "add":
        link = orch.link_add(args.u, args.v)
        print(f"added link {link.index}: {link.u}[{link.iface_u} {link.addr_u}] <-> {link.v}[{link.iface_v} {link.addr_v}]")
    else:
        link = orch.link_remove(args.u, args.v)
        print(f"removed link {link.index}: {link.u} <-> {link.v}")


def cmd_send(orch: Orchestrator, args) -> None:
    result = orch.rpc(args.sender, "node.send_direct", {"to": args.recipient, "message": args.message})
    print(f"{args.sender} -> {args.recipient}: {result['status']} ({result['msg_id']})")


def cmd_group(orch: Orchestrator, args) -> None:
    if args.group_cmd == "create":
        res = orch.rpc(args.admin, "node.group_create", {"group_id": args.group_id})
    elif args.group_cmd == "join":
        res = orch.rpc(args.admin, "node.group_join", {"group_id": args.group_id, "member": args.node})
    elif args.group_cmd == "leave":
        res = orch.rpc(args.admin, "node.group_leave", {"group_id": args.group_id, "member": args.node})
    else:
        res = orch.rpc(args.sender, "node.group_send", {"group_id": args.group_id, "message": args.message})
        print(f"sent to {res['group_id']} epoch {res['epoch']} counter {res['counter']} ({res['msg_id']})")
        return
    print(
        f"{res['action']} committed: {res['group_id']} -> epoch {res['epoch']}  members={','.join(res['members'])}  "
        f"update_id={res['update_id'][:16]}…"
    )


# ---------------------------------------------------------------------------
# Node inspection
# ---------------------------------------------------------------------------
def cmd_node(orch: Orchestrator, args) -> None:
    if args.node_cmd == "list":
        rows = []
        for node in orch.nodes:
            try:
                data = orch.rpc(node, "node.inspect", timeout=2.0)
                rows.append({"node_id": node, "status": data["status"], "peers": [p["node_id"] for p in data["peers"]],
                             "groups": {g: v["epoch"] for g, v in data["groups"].items()}})  # fmt: skip
            except (OSError, RPCError):
                rows.append({"node_id": node, "status": "OFFLINE", "peers": [], "groups": {}})
        if args.json:
            _dump(rows)
            return
        for row in rows:
            groups = ", ".join(f"{g}@{e}" for g, e in row["groups"].items()) or "-"
            print(f"{row['node_id']:<12} {row['status']:<8} peers: {','.join(row['peers']) or '-':<24} groups: {groups}")
    elif args.node_cmd == "show":
        data = orch.rpc(args.node_id, "node.inspect")
        if args.json:
            _dump(data)
        else:
            _print_inspect(data)
    elif args.node_cmd == "secrets":
        if not args.unsafe:
            raise SimulatorError("refusing to export secrets without --unsafe")
        _dump(orch.rpc(args.node_id, "node.secrets"))


def _print_inspect(d: dict) -> None:
    ident = d["identity"]
    print(f"node {d['node_id']}  [{d['status']}]  pid {d['pid']}  namespace {d['namespace']}  up {d['uptime_seconds']}s")
    print(f"  ed25519   {ident['ed25519_pubkey']}")
    print(f"  x25519    {ident['x25519_pubkey']}")
    print(f"  fingerprint {ident['fingerprint']}  (self-signed, issuer {ident['issuer']})")
    print(f"  pinned roster: {', '.join(f'{n}={fp[:12]}' for n, fp in d['roster'].items())}")
    print("  links:")
    for link in d["links"]:
        print(f"    {link['iface']:<8} {link['local_addr']} -> {link['peer']} {link['remote_addr']}:{link['port']}")
    print("  peers:")
    for peer in d["peers"]:
        uptime = f" up {peer['connection_uptime']}s" if peer["connection_uptime"] else ""
        print(f"    {peer['node_id']:<12} {peer['address']:<20} {peer['status']}{uptime}")
    print("  groups:")
    for gid, g in d["groups"].items() or {}:
        members = ", ".join(f"{m}:{p}" for m, p in g["members"].items())
        print(f"    {gid}: role={g['role']} epoch={g['epoch']} admin={g['admin_id']} key={g['key_fingerprint'] or '-'}")
        print(f"      members {members}")
    if not d["groups"]:
        print("    -")
    nonzero = {k: v for k, v in d["stats"].items() if v}
    print("  stats: " + (", ".join(f"{k}={v}" for k, v in sorted(nonzero.items())) or "all zero"))
    sec = d["security"]
    print(f"  security: compromised={sec['compromised']} modes={sec['attack_modes']}")
    for ev in sec["recent_events"][-5:]:
        extra = ev.get("code") or ev.get("attack") or ""
        print(f"    {time.strftime('%H:%M:%S', time.localtime(ev['ts']))} {ev['event']} {extra}")
    if d["inbox"]:
        print("  recent group messages:")
        for m in d["inbox"][-5:]:
            print(f"    [{m['group_id']}@{m['epoch']}] {m['sender_id']}: {m['message']}")
    if d["direct_inbox"]:
        print("  recent direct messages:")
        for m in d["direct_inbox"][-5:]:
            print(f"    {m['from']}: {m['message']}")


# ---------------------------------------------------------------------------
# Network impairment
# ---------------------------------------------------------------------------
def cmd_network(orch: Orchestrator, args) -> None:
    if args.net_cmd == "loss":
        applied = orch.impair(link=args.link, node=args.node, loss=args.rate)
        _print_applied(applied)
    elif args.net_cmd == "latency":
        applied = orch.impair(
            link=args.link,
            node=args.node,
            delay_ms=parse_ms(args.delay),
            jitter_ms=parse_ms(args.jitter) if args.jitter else 0.0,
            reorder=args.reorder,
            duplicate=args.duplicate,
        )
        _print_applied(applied)
    elif args.net_cmd == "partition":
        cut = orch.partition(_csv(args.group_a), _csv(args.group_b))
        print(f"partitioned: {len(cut)} link(s) cut: " + ", ".join(f"{l.u}-{l.v}" for l in cut))
    elif args.net_cmd == "heal":
        restored = orch.heal()
        print(f"healed: {len(restored)} link(s) restored: " + ", ".join(f"{l.u}-{l.v}" for l in restored))
    elif args.net_cmd == "clear":
        count = orch.clear_impairments(link=args.link, node=args.node)
        print(f"cleared impairment on {count} link end(s)")
    else:
        summary = orch.summary()
        _print_links(summary["links"], summary.get("partition"))


def _print_applied(applied: list[dict]) -> None:
    for item in applied:
        print(f"  link {item['link']} {item['node']}:{item['iface']} -> {_fmt_spec(item['spec'])} via {item['backend']}")


# ---------------------------------------------------------------------------
# Attacks
# ---------------------------------------------------------------------------
def cmd_attack(orch: Orchestrator, args) -> None:
    engine = AttackEngine(orch)
    if args.attack_cmd == "replay":
        result = engine.replay(args.target, via=args.via, kind=args.kind)
    elif args.attack_cmd == "tamper":
        result = engine.tamper(args.src, args.dst, kind=args.kind, count=args.count)
    elif args.attack_cmd == "forge":
        result = engine.forge(args.as_node, args.dst, via=args.via, group=args.group)
    elif args.attack_cmd == "double-sign":
        result = engine.double_sign(args.admin, args.group)
    elif args.attack_cmd == "suppress":
        result = engine.suppress(args.node_id, enabled=not args.off)
    else:
        result = engine.compromise(args.node_id)
    _dump(result)
    expect = result.get("expect")
    if not expect or args.attack_cmd == "tamper":
        return  # tamper is armed; detection happens when traffic next crosses the link
    since = result.get("ts", time.time()) - 0.01
    targets = [n for n in orch.nodes if n != args.admin] if args.attack_cmd == "double-sign" else [result["target"]]
    for target in targets:
        record = engine.wait_for_event(target, expect[0], since, expect[1], timeout=5.0)
        print(f"detection at {target}: " + (f"{record['event']} {record.get('code', '')}" if record else "not observed within 5s"))


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gossip-sim", description=__doc__.splitlines()[0])
    p.add_argument("--home", default=default_home(), help="simulator home (default: $GOSSIP_SIM_HOME or /tmp/gossip-sim)")
    p.add_argument("-v", "--verbose", action="store_true", help="echo executed ip/tc commands")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", help="create namespaces, per-edge links, keys and roster (root)")
    s.add_argument("--nodes", required=True, help="comma list (alice,bob,...) or a count (5 -> node-1..node-5)")
    s.add_argument("--topology", default="linear", choices=TOPOLOGIES)
    s.add_argument("--edges", help="custom edges a:b,b:c (implies --topology custom)")
    s.add_argument("--seed", type=int, default=0, help="RNG seed (random topology, daemon fanout)")
    s.add_argument("--p", type=float, default=None, help="edge probability for --topology random")
    s.add_argument("--port", type=int, default=9000)
    s.add_argument("--force", action="store_true", help="destroy an existing simulation first")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("start", help="launch node daemons inside their namespaces (root)")
    s.add_argument("--nodes", help="subset of nodes to start")
    s.add_argument("--fanout", type=int, default=3)
    s.add_argument("--anti-entropy-interval", type=float, default=2.0)
    s.add_argument("--seed", type=int, default=None)
    s.add_argument("--unsafe-allow-secret-export", action="store_true", help="enable node.secrets on all daemons")
    s.add_argument("--unsafe-nodes", help="enable node.secrets on these daemons only")
    s.set_defaults(func=cmd_start)

    s = sub.add_parser("stop", help="stop node daemons (state persists)")
    s.add_argument("--nodes")
    s.set_defaults(func=cmd_stop)

    s = sub.add_parser("status", help="simulation overview")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("destroy", help="idempotent teardown from the resource ledger (root)")
    s.add_argument("--purge-logs", action="store_true")
    s.set_defaults(func=cmd_destroy)

    s = sub.add_parser("link", help="runtime topology changes (root)")
    lsub = s.add_subparsers(dest="link_cmd", required=True)
    for name in ("add", "remove"):
        ls = lsub.add_parser(name)
        ls.add_argument("u")
        ls.add_argument("v")
    s.set_defaults(func=cmd_link)

    s = sub.add_parser("send", help="direct node-to-node message (adjacent nodes only)")
    s.add_argument("sender")
    s.add_argument("recipient")
    s.add_argument("message")
    s.set_defaults(func=cmd_send)

    s = sub.add_parser("group", help="group management and messaging")
    gsub = s.add_subparsers(dest="group_cmd", required=True)
    gs = gsub.add_parser("create")
    gs.add_argument("admin")
    gs.add_argument("group_id")
    for name in ("join", "leave"):
        gs = gsub.add_parser(name)
        gs.add_argument("admin")
        gs.add_argument("group_id")
        gs.add_argument("node")
    gs = gsub.add_parser("send")
    gs.add_argument("sender")
    gs.add_argument("group_id")
    gs.add_argument("message")
    s.set_defaults(func=cmd_group)

    s = sub.add_parser("node", help="node inspection")
    nsub = s.add_subparsers(dest="node_cmd", required=True)
    ns = nsub.add_parser("list")
    ns.add_argument("--json", action="store_true")
    ns = nsub.add_parser("show")
    ns.add_argument("node_id")
    ns.add_argument("--json", action="store_true")
    ns = nsub.add_parser("secrets")
    ns.add_argument("node_id")
    ns.add_argument("--unsafe", action="store_true", help="acknowledge raw key export")
    s.set_defaults(func=cmd_node)

    s = sub.add_parser("network", help="per-link impairment and partitions (root)")
    wsub = s.add_subparsers(dest="net_cmd", required=True)
    for name in ("loss", "latency", "clear"):
        ws = wsub.add_parser(name)
        target = ws.add_mutually_exclusive_group(required=name != "clear")
        target.add_argument("--link", type=_pair, help="u,v")
        target.add_argument("--node", help="apply to every link end of this node")
        if name == "loss":
            ws.add_argument("--rate", type=float, required=True, help="loss percentage (0 clears)")
        elif name == "latency":
            ws.add_argument("--delay", required=True, help="e.g. 100ms")
            ws.add_argument("--jitter", help="e.g. 20ms")
            ws.add_argument("--reorder", type=float, default=None, help="reorder percentage")
            ws.add_argument("--duplicate", type=float, default=None, help="duplicate percentage")
    ws = wsub.add_parser("partition")
    ws.add_argument("--group-a", required=True)
    ws.add_argument("--group-b", required=True)
    wsub.add_parser("heal")
    wsub.add_parser("show")
    s.set_defaults(func=cmd_network)

    s = sub.add_parser("attack", help="attack injection")
    asub = s.add_subparsers(dest="attack_cmd", required=True)
    a = asub.add_parser("replay")
    a.add_argument("--target", required=True)
    a.add_argument("--via", help="adjacent attacker node (default: first neighbour with captures)")
    a.add_argument("--kind", choices=("msg", "update"), default="msg")
    a = asub.add_parser("tamper")
    a.add_argument("--from", dest="src", required=True)
    a.add_argument("--to", dest="dst", required=True)
    a.add_argument("--kind", choices=("msg", "update", "any"), default="msg")
    a.add_argument("--count", type=int, default=1)
    a = asub.add_parser("forge")
    a.add_argument("--as", dest="as_node", required=True)
    a.add_argument("--to", dest="dst", required=True)
    a.add_argument("--via")
    a.add_argument("--group")
    a = asub.add_parser("double-sign")
    a.add_argument("--admin", required=True)
    a.add_argument("--group", required=True)
    a = asub.add_parser("compromise")
    a.add_argument("node_id")
    a = asub.add_parser("suppress")
    a.add_argument("node_id")
    a.add_argument("--off", action="store_true")
    s.set_defaults(func=cmd_attack)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    from simulator.namespace import CommandRunner

    orch = Orchestrator(args.home, runner=CommandRunner(verbose=args.verbose))
    try:
        args.func(orch, args)
        return 0
    except RPCError as exc:
        print(f"error: {exc.code}: {exc.message}", file=sys.stderr)
    except (ConnectionRefusedError, FileNotFoundError) as exc:
        if exc.errno:  # control socket missing/refused
            print("error: node daemon not reachable (is it started? `gossip-sim start`)", file=sys.stderr)
        else:
            print(f"error: {exc}", file=sys.stderr)
    except PermissionError as exc:
        hint = "" if "root" in str(exc) else " (node commands must run as the control-socket owner)"
        print(f"error: {exc}{hint}", file=sys.stderr)
    except (SimulatorError, CommandError, NetemUnavailable, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
