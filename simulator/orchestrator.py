"""Simulator lifecycle: init / start / stop / destroy with a crash-safe resource ledger.

Every kernel resource (namespace, link, impairment, cut) is recorded in
``<home>/ledger.json`` immediately after it is created, so ``destroy`` can tear
everything down idempotently even after a crash or a failed ``init``.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from typing import Any, Iterator

from crypto.certificate import fingerprint
from crypto.encoding import b64e
from crypto.identity import IdentityKeypair
from crypto.key_agreement import KeyAgreementKeypair
from node.control_server import RPCError, rpc_call
from node.state import StatePaths, atomic_write_json, default_home, read_json, write_identity
from simulator.namespace import DEFAULT_NS_PREFIX, CommandRunner, NamespaceManager
from simulator.network_impairer import NetemSpec, NetworkImpairer
from simulator.topology import (
    LinkSpec,
    allocate_index,
    build_graph,
    compile_link_plan,
    edge_cut,
    make_link,
    node_links,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PORT = 9000


class SimulatorError(RuntimeError):
    pass


def invoking_owner() -> tuple[int, int]:
    """The user that should own sockets/state: ``SUDO_UID`` under sudo, else ourselves."""
    if os.geteuid() == 0 and os.environ.get("SUDO_UID"):
        return int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", os.environ["SUDO_UID"]))
    return os.getuid(), os.getgid()


def _pid_alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as fh:
            state = fh.read().rsplit(")", 1)[1].split()[0]
        return state not in ("Z", "X")
    except (FileNotFoundError, IndexError, PermissionError):
        return False


def _pid_is_daemon(pid: int, node_id: str) -> bool:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            argv = fh.read().split(b"\0")
    except (FileNotFoundError, PermissionError):
        return False
    return b"node.daemon" in argv and node_id.encode() in argv


class Orchestrator:
    def __init__(self, home: str | None = None, runner: CommandRunner | None = None, ns_prefix: str | None = None):
        self.paths = StatePaths(home or default_home())
        self.runner = runner or CommandRunner()
        self.ledger: dict[str, Any] = read_json(self.paths.ledger, None) or {}
        prefix = ns_prefix or self.ledger.get("ns_prefix") or DEFAULT_NS_PREFIX
        self.ns = NamespaceManager(self.runner, prefix=prefix)
        self.impairer = NetworkImpairer(self.ns)
        self._procs: dict[str, subprocess.Popen] = {}

    # ------------------------------------------------------------------
    # Ledger
    # ------------------------------------------------------------------
    @property
    def home(self) -> str:
        return self.paths.home

    @property
    def initialized(self) -> bool:
        return bool(self.ledger)

    @property
    def nodes(self) -> list[str]:
        return list(self.ledger.get("nodes", []))

    def _save_ledger(self) -> None:
        os.makedirs(self.home, exist_ok=True)
        atomic_write_json(self.paths.ledger, self.ledger, mode=0o640)
        self._chown(self.paths.ledger)

    def links(self) -> list[LinkSpec]:
        return [LinkSpec.from_dict(item) for _, item in sorted(self.ledger.get("links", {}).items(), key=lambda kv: int(kv[0]))]

    def find_link(self, u: str, v: str) -> LinkSpec:
        key = tuple(sorted((u, v)))
        for link in self.links():
            if link.key == key:
                return link
        raise SimulatorError(f"no link between {u} and {v}")

    def _owner(self) -> tuple[int, int]:
        owner = self.ledger.get("owner")
        return (owner["uid"], owner["gid"]) if owner else invoking_owner()

    def _chown(self, path: str, recursive: bool = False) -> None:
        uid, gid = self._owner()
        if os.geteuid() != 0 or uid == 0 or not os.path.exists(path):
            return
        os.chown(path, uid, gid)
        if recursive and os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for name in dirs + files:
                    os.chown(os.path.join(root, name), uid, gid)

    def _require_init(self) -> None:
        if not self.initialized:
            raise SimulatorError(f"no simulation initialised in {self.home} (run `gossip-sim init` first)")

    # ------------------------------------------------------------------
    # init / destroy
    # ------------------------------------------------------------------
    def init(
        self,
        nodes: list[str],
        topology: str = "linear",
        seed: int = 0,
        port: int = DEFAULT_PORT,
        p: float | None = None,
        edges: list[tuple[str, str]] | None = None,
        force: bool = False,
    ) -> dict:
        NamespaceManager.check_privileges()
        if self.initialized:
            if not force:
                raise SimulatorError(f"simulation already initialised in {self.home}; run `destroy` or pass --force")
            self.destroy()
        graph = build_graph(nodes, topology, seed=seed, p=p, edges=edges)
        plan = compile_link_plan(graph)
        clashes = sorted(self.ns.ns_name(n) for n in nodes if self.ns.exists(n))
        if clashes:
            raise SimulatorError(f"namespaces already exist: {', '.join(clashes)} (stale run? try `destroy`)")
        uid, gid = invoking_owner()
        self.ledger = {
            "version": 1,
            "created_at": time.time(),
            "home": self.home,
            "ns_prefix": self.ns.prefix,
            "port": port,
            "seed": seed,
            "topology": topology,
            "nodes": list(nodes),
            "owner": {"uid": uid, "gid": gid},
            "namespaces": {},
            "links": {},
            "cut_links": [],
            "partition": None,
            "daemons": {},
            "daemon_options": {},
        }
        for directory, mode in ((self.home, 0o755), (self.paths.sockets_dir, 0o750), (self.paths.logs_dir, 0o750), (self.paths.state_root, 0o750)):
            os.makedirs(directory, exist_ok=True)
            os.chmod(directory, mode)
        self._save_ledger()
        try:
            self._write_identities(nodes, plan, port)
            for node in nodes:
                self.ns.create_namespace(node)
                self.ledger["namespaces"][node] = self.ns.ns_name(node)
                self._save_ledger()
            for link in plan:
                self.ns.create_link(link)
                self.ledger["links"][str(link.index)] = {**link.to_dict(), "impair": {}}
                self._save_ledger()
        except BaseException:
            self.destroy()
            raise
        self._chown(self.home, recursive=True)
        return self.summary()

    def _write_identities(self, nodes: list[str], plan: list[LinkSpec], port: int) -> None:
        roster = {"version": 1, "nodes": {}}
        keys = {}
        for node in nodes:
            ident, kex = IdentityKeypair(), KeyAgreementKeypair()
            keys[node] = (ident, kex)
            roster["nodes"][node] = {
                "ed25519_pubkey": b64e(ident.public_bytes()),
                "x25519_pubkey": b64e(kex.public_bytes()),
                "fingerprint": fingerprint(ident.public_bytes(), kex.public_bytes()),
            }
        atomic_write_json(self.paths.roster, roster, mode=0o644)
        for node, (ident, kex) in keys.items():
            state_dir = self.paths.state_dir(node)
            write_identity(state_dir, node, ident, kex)
            atomic_write_json(os.path.join(state_dir, "roster.json"), roster)  # pinned copy, 0600
            self._write_config(node, plan, port)

    def _write_config(self, node: str, links: list[LinkSpec], port: int | None = None) -> None:
        port = port or self.ledger.get("port", DEFAULT_PORT)
        cfg_links = [{**item, "port": port} for item in node_links(links, node)]
        path = os.path.join(self.paths.state_dir(node), "config.json")
        atomic_write_json(path, {"node_id": node, "port": port, "links": cfg_links})
        self._chown(path)

    def destroy(self, purge_logs: bool = False) -> dict:
        """Idempotent teardown of daemons, links, namespaces, sockets and state."""
        removed = {"daemons": 0, "namespaces": 0, "links": 0}
        if not self.ledger:
            if purge_logs and os.path.isdir(self.paths.logs_dir):
                shutil.rmtree(self.paths.logs_dir, ignore_errors=True)
            return removed
        NamespaceManager.check_privileges()
        removed["daemons"] = len(self.stop())
        existing = self.ns.list_namespaces()
        namespaces = set(self.ledger.get("namespaces", {}).values())
        namespaces |= {self.ns.ns_name(n) for n in self.nodes if self.ns.ns_name(n) in existing}
        for link in self.links():
            if self.ns.ns_name(link.u) in existing and self.ns.ns_name(link.v) in existing:
                removed["links"] += int(self.ns.delete_link(link))
        for ns in sorted(namespaces):
            removed["namespaces"] += int(self.ns.delete_namespace(ns))
        for node in self.nodes:
            sock = self.paths.socket(node)
            if os.path.exists(sock):
                os.unlink(sock)
        shutil.rmtree(self.paths.state_root, ignore_errors=True)
        shutil.rmtree(os.path.join(self.home, "attacks"), ignore_errors=True)  # exported secrets
        for path in (self.paths.roster, self.paths.ledger):
            if os.path.exists(path):
                os.unlink(path)
        if purge_logs:
            shutil.rmtree(self.paths.logs_dir, ignore_errors=True)
        self.ledger = {}
        return removed

    # ------------------------------------------------------------------
    # Daemons
    # ------------------------------------------------------------------
    def daemon_running(self, node: str) -> bool:
        info = self.ledger.get("daemons", {}).get(node)
        return bool(info) and _pid_alive(info["pid"]) and _pid_is_daemon(info["pid"], node)

    def start(
        self,
        nodes: list[str] | None = None,
        fanout: int = 3,
        anti_entropy_interval: float = 2.0,
        seed: int | None = None,
        unsafe_nodes: set[str] | None = None,
        wait: bool = True,
        timeout: float = 20.0,
    ) -> list[str]:
        self._require_init()
        NamespaceManager.check_privileges()
        unsafe_nodes = unsafe_nodes or set()
        seed = self.ledger.get("seed", 0) if seed is None else seed
        self.ledger["daemon_options"] = {
            "fanout": fanout,
            "anti_entropy_interval": anti_entropy_interval,
            "seed": seed,
            "unsafe_nodes": sorted(unsafe_nodes),
        }
        uid, gid = self._owner()
        started = []
        for node in nodes or self.nodes:
            if node not in self.nodes:
                raise SimulatorError(f"unknown node {node}")
            if self.daemon_running(node):
                continue
            args = [
                sys.executable, "-m", "node.daemon",
                "--id", node,
                "--home", self.home,
                "--fanout", str(fanout),
                "--anti-entropy-interval", str(anti_entropy_interval),
                "--seed", str(seed),
                "--namespace", self.ns.ns_name(node),
            ]  # fmt: skip
            if node in unsafe_nodes:
                args.append("--unsafe-allow-secret-export")
            if uid != 0:
                args += ["--uid", str(uid), "--gid", str(gid)]
            env = dict(os.environ, PYTHONPATH=REPO_ROOT, PYTHONUNBUFFERED="1")
            log = open(self.paths.stdout_log(node), "ab")
            proc = subprocess.Popen(
                self.ns.exec_args(node, args),
                cwd=REPO_ROOT,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                env=env,
                start_new_session=True,
            )
            log.close()
            self._procs[node] = proc
            self.ledger["daemons"][node] = {"pid": proc.pid, "started_at": time.time(), "unsafe": node in unsafe_nodes}
            self._save_ledger()
            started.append(node)
        if wait:
            for node in started:
                self.wait_ready(node, timeout)
        return started

    def wait_ready(self, node: str, timeout: float = 20.0) -> dict:
        deadline = time.time() + timeout
        last_error: Exception | None = None
        while time.time() < deadline:
            proc = self._procs.get(node)
            if proc is not None and proc.poll() is not None:
                raise SimulatorError(f"daemon {node} exited with {proc.returncode}:\n{self.tail_stdout(node)}")
            try:
                return self.rpc(node, "node.inspect", timeout=2.0)
            except (OSError, RPCError) as exc:
                last_error = exc
                time.sleep(0.1)
        raise SimulatorError(f"daemon {node} not ready after {timeout}s ({last_error}):\n{self.tail_stdout(node)}")

    def tail_stdout(self, node: str, lines: int = 20) -> str:
        path = self.paths.stdout_log(node)
        if not os.path.exists(path):
            return ""
        with open(path, encoding="utf-8", errors="replace") as fh:
            return "".join(fh.readlines()[-lines:])

    def stop(self, nodes: list[str] | None = None, timeout: float = 5.0) -> list[str]:
        stopped = []
        daemons = self.ledger.get("daemons", {})
        for node in nodes or list(daemons):
            info = daemons.get(node)
            if not info:
                continue
            pid = info["pid"]
            if _pid_alive(pid) and _pid_is_daemon(pid, node):
                os.kill(pid, signal.SIGTERM)
                deadline = time.time() + timeout
                while time.time() < deadline and _pid_alive(pid):
                    self._reap(node)
                    time.sleep(0.05)
                if _pid_alive(pid):
                    os.kill(pid, signal.SIGKILL)
                stopped.append(node)
            self._reap(node, block=True)
            daemons.pop(node, None)
            sock = self.paths.socket(node)
            if os.path.exists(sock) and not _pid_alive(pid):
                try:
                    os.unlink(sock)
                except OSError:
                    pass
        if self.ledger:
            self._save_ledger()
        return stopped

    def _reap(self, node: str, block: bool = False) -> None:
        proc = self._procs.get(node)
        if proc is None:
            return
        try:
            proc.wait(timeout=2.0 if block else 0.001)
            self._procs.pop(node, None)
        except subprocess.TimeoutExpired:
            pass

    # ------------------------------------------------------------------
    # Control plane
    # ------------------------------------------------------------------
    def rpc(self, node: str, method: str, params: dict | None = None, timeout: float = 10.0) -> Any:
        return rpc_call(self.paths.socket(node), method, params or {}, timeout=timeout)

    def inspect(self, node: str) -> dict:
        return self.rpc(node, "node.inspect")

    # ------------------------------------------------------------------
    # Runtime topology
    # ------------------------------------------------------------------
    def link_add(self, u: str, v: str) -> LinkSpec:
        self._require_init()
        NamespaceManager.check_privileges()
        for node in (u, v):
            if node not in self.nodes:
                raise SimulatorError(f"unknown node {node}")
        if u == v:
            raise SimulatorError("self links are not allowed")
        key = tuple(sorted((u, v)))
        if any(link.key == key for link in self.links()):
            raise SimulatorError(f"link {u}-{v} already exists")
        link = make_link(allocate_index({link.index for link in self.links()}), u, v)
        self.ns.create_link(link)
        self.ledger["links"][str(link.index)] = {**link.to_dict(), "impair": {}}
        self._save_ledger()
        self._sync_peers(link, add=True)
        return link

    def link_remove(self, u: str, v: str) -> LinkSpec:
        self._require_init()
        NamespaceManager.check_privileges()
        link = self.find_link(u, v)
        self.ns.delete_link(link)
        self.ledger["links"].pop(str(link.index), None)
        self.ledger["cut_links"] = [i for i in self.ledger.get("cut_links", []) if i != link.index]
        self._save_ledger()
        self._sync_peers(link, add=False)
        return link

    def _sync_peers(self, link: LinkSpec, add: bool) -> None:
        """Rewrite both endpoints' config and nudge running daemons over UDS."""
        links = self.links()
        for node in (link.u, link.v):
            self._write_config(node, links)
            if not self.daemon_running(node):
                continue
            iface, local, peer, remote = link.end(node)
            if add:
                params = {"peer": peer, "iface": iface, "local_addr": local, "remote_addr": remote,
                          "port": self.ledger.get("port", DEFAULT_PORT), "link_index": link.index}  # fmt: skip
                self.rpc(node, "node.peer_add", params)
            else:
                self.rpc(node, "node.peer_remove", {"peer": peer})

    # ------------------------------------------------------------------
    # Impairment / partitions
    # ------------------------------------------------------------------
    def _record_impair(self, link: LinkSpec, node: str, spec: NetemSpec, backend: str) -> None:
        entry = self.ledger["links"][str(link.index)].setdefault("impair", {})
        if spec.is_empty():
            entry.pop(node, None)
        else:
            entry[node] = {"spec": spec.to_dict(), "backend": backend}

    def _current_spec(self, link: LinkSpec, node: str) -> NetemSpec:
        entry = self.ledger["links"][str(link.index)].get("impair", {}).get(node)
        return NetemSpec.from_dict(entry["spec"]) if entry else NetemSpec()

    def impair(self, link: tuple[str, str] | None = None, node: str | None = None, **changes) -> list[dict]:
        """Merge ``changes`` (loss, delay_ms, jitter_ms, reorder, duplicate) into the
        impairment of one link (both ends) or of every link end of one node."""
        self._require_init()
        NamespaceManager.check_privileges()
        targets = self._targets(link, node)
        applied = []
        for target_link, end in targets:
            spec = self._current_spec(target_link, end).merged(**changes)
            backend = self.impairer.apply_end(target_link, end, spec)
            self._record_impair(target_link, end, spec, backend)
            applied.append({"link": target_link.index, "node": end, "iface": target_link.end(end)[0], "backend": backend, "spec": spec.to_dict()})
        self._save_ledger()
        return applied

    def clear_impairments(self, link: tuple[str, str] | None = None, node: str | None = None) -> int:
        self._require_init()
        NamespaceManager.check_privileges()
        targets = self._targets(link, node) if (link or node) else [(l, end) for l in self.links() for end in (l.u, l.v)]
        for target_link, end in targets:
            self.impairer.clear_end(target_link, end)
            self._record_impair(target_link, end, NetemSpec(), "none")
        self._save_ledger()
        return len(targets)

    def _targets(self, link: tuple[str, str] | None, node: str | None) -> list[tuple[LinkSpec, str]]:
        if link is not None:
            spec = self.find_link(*link)
            return [(spec, spec.u), (spec, spec.v)]
        if node is not None:
            if node not in self.nodes:
                raise SimulatorError(f"unknown node {node}")
            return [(l, node) for l in self.links() if node in (l.u, l.v)]
        raise SimulatorError("specify --link u,v or --node n")

    def partition(self, group_a: list[str], group_b: list[str]) -> list[LinkSpec]:
        self._require_init()
        NamespaceManager.check_privileges()
        unknown = set(group_a + group_b) - set(self.nodes)
        if unknown:
            raise SimulatorError(f"unknown nodes: {', '.join(sorted(unknown))}")
        cut = edge_cut(self.links(), set(group_a), set(group_b))
        self.impairer.cut(cut)
        self.ledger["cut_links"] = sorted(set(self.ledger.get("cut_links", [])) | {l.index for l in cut})
        self.ledger["partition"] = {"a": group_a, "b": group_b, "at": time.time()}
        self._save_ledger()
        return cut

    def heal(self) -> list[LinkSpec]:
        self._require_init()
        NamespaceManager.check_privileges()
        cut = [l for l in self.links() if l.index in set(self.ledger.get("cut_links", []))]
        self.impairer.restore(cut)
        self.ledger["cut_links"] = []
        self.ledger["partition"] = None
        self._save_ledger()
        return cut

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def summary(self) -> dict:
        return {
            "home": self.home,
            "topology": self.ledger.get("topology"),
            "nodes": self.nodes,
            "links": [
                {
                    "index": l.index,
                    "u": l.u,
                    "v": l.v,
                    "ifaces": [l.iface_u, l.iface_v],
                    "addrs": [l.addr_u, l.addr_v],
                    "up": l.index not in set(self.ledger.get("cut_links", [])),
                    "impair": self.ledger["links"][str(l.index)].get("impair", {}),
                }
                for l in self.links()
            ],
            "partition": self.ledger.get("partition"),
        }

    def status(self) -> dict:
        info = self.summary()
        info["daemons"] = {}
        for node in self.nodes:
            entry = {"running": self.daemon_running(node), "pid": self.ledger.get("daemons", {}).get(node, {}).get("pid")}
            if entry["running"]:
                try:
                    data = self.rpc(node, "node.inspect", timeout=2.0)
                    entry["groups"] = {gid: g["epoch"] for gid, g in data["groups"].items()}
                    entry["status"] = data["status"]
                except (OSError, RPCError) as exc:
                    entry["status"] = f"UNRESPONSIVE ({exc})"
            info["daemons"][node] = entry
        return info


@contextmanager
def teardown_on_signal(orch: Orchestrator) -> Iterator[Orchestrator]:
    """Destroy the simulation on SIGINT/SIGTERM or exceptions (experiments/tests)."""

    def handler(signum, frame):
        raise KeyboardInterrupt(f"signal {signum}")

    previous = {sig: signal.signal(sig, handler) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield orch
    finally:
        try:
            orch.destroy()
        finally:
            for sig, old in previous.items():
                signal.signal(sig, old)
