"""Linux network namespaces + per-edge veth pairs (topology by construction).

All interface/link commands address the owning namespace explicitly
(``ip -n <ns> ...``): once a veth end lives inside a namespace it is invisible
from the host, so host-level ``ip link set vlk0a ...`` would fail. Pairs are
created directly inside their namespaces, so no transient names exist in the
root namespace.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Sequence

from simulator.topology import LinkSpec

DEFAULT_NS_PREFIX = "netns-"


class CommandError(RuntimeError):
    def __init__(self, args: Sequence[str], returncode: int, stderr: str):
        super().__init__(f"command failed ({returncode}): {' '.join(args)}\n{stderr.strip()}")
        self.args_list = list(args)
        self.returncode = returncode
        self.stderr = stderr


class CommandRunner:
    """Thin subprocess wrapper (mockable in tests)."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.history: list[list[str]] = []

    def run(self, args: Sequence[str], check: bool = True, input: str | None = None) -> subprocess.CompletedProcess:
        args = [str(a) for a in args]
        self.history.append(args)
        if self.verbose:
            print("+", " ".join(args))
        proc = subprocess.run(args, capture_output=True, text=True, input=input)
        if check and proc.returncode != 0:
            raise CommandError(args, proc.returncode, proc.stderr or proc.stdout)
        return proc


def _missing(err: CommandError) -> bool:
    text = err.stderr.lower()
    return any(s in text for s in ("cannot find device", "does not exist", "no such file", "not found", "cannot open network namespace"))


class NamespaceManager:
    def __init__(self, runner: CommandRunner | None = None, prefix: str = DEFAULT_NS_PREFIX):
        self.runner = runner or CommandRunner()
        self.prefix = prefix

    @staticmethod
    def check_privileges() -> None:
        if os.geteuid() != 0:
            raise PermissionError("network setup requires root / CAP_NET_ADMIN (re-run with sudo)")
        if shutil.which("ip") is None:
            raise FileNotFoundError("iproute2 'ip' command not found")

    def ns_name(self, node_id: str) -> str:
        return f"{self.prefix}{node_id}"

    def list_namespaces(self) -> set[str]:
        proc = self.runner.run(["ip", "netns", "list"], check=False)
        return {line.split()[0] for line in proc.stdout.splitlines() if line.strip()}

    def exists(self, node_id: str) -> bool:
        return self.ns_name(node_id) in self.list_namespaces()

    def create_namespace(self, node_id: str) -> str:
        ns = self.ns_name(node_id)
        self.runner.run(["ip", "netns", "add", ns])
        self.runner.run(["ip", "-n", ns, "link", "set", "lo", "up"])
        return ns

    def delete_namespace(self, ns: str) -> bool:
        """Idempotent; deleting a namespace also destroys the veth ends inside it."""
        try:
            self.runner.run(["ip", "netns", "del", ns])
            return True
        except CommandError as err:
            if _missing(err):
                return False
            raise

    def create_link(self, link: LinkSpec) -> None:
        ns_u, ns_v = self.ns_name(link.u), self.ns_name(link.v)
        self.runner.run(
            ["ip", "link", "add", link.iface_u, "netns", ns_u, "type", "veth", "peer", "name", link.iface_v, "netns", ns_v]
        )
        try:
            self.runner.run(["ip", "-n", ns_u, "addr", "add", f"{link.addr_u}/31", "dev", link.iface_u])
            self.runner.run(["ip", "-n", ns_v, "addr", "add", f"{link.addr_v}/31", "dev", link.iface_v])
            self.set_link_state(link, up=True)
        except CommandError:
            self.delete_link(link)
            raise

    def delete_link(self, link: LinkSpec) -> bool:
        """Deleting one end removes the pair; idempotent."""
        for node, iface in ((link.u, link.iface_u), (link.v, link.iface_v)):
            try:
                self.runner.run(["ip", "-n", self.ns_name(node), "link", "del", iface])
                return True
            except CommandError as err:
                if not _missing(err):
                    raise
        return False

    def set_link_state(self, link: LinkSpec, up: bool) -> None:
        """Both ends, so neither side keeps a route over a cut link."""
        state = "up" if up else "down"
        self.runner.run(["ip", "-n", self.ns_name(link.u), "link", "set", link.iface_u, state])
        self.runner.run(["ip", "-n", self.ns_name(link.v), "link", "set", link.iface_v, state])

    def link_is_up(self, link: LinkSpec) -> bool:
        proc = self.runner.run(["ip", "-n", self.ns_name(link.u), "-o", "link", "show", link.iface_u], check=False)
        if proc.returncode != 0 or "<" not in proc.stdout:
            return False
        flags = proc.stdout.split("<", 1)[1].split(">", 1)[0].split(",")
        return "UP" in flags

    def exec_args(self, node_id: str, command: Sequence[str]) -> list[str]:
        return ["ip", "netns", "exec", self.ns_name(node_id), *command]

    def run_in(self, node_id: str, command: Sequence[str], check: bool = True) -> subprocess.CompletedProcess:
        return self.runner.run(self.exec_args(node_id, command), check=check)
