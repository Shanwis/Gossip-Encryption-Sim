"""Per-link impairment: ``tc netem`` on veth ends, link-state cuts for partitions.

Commands run inside the owning namespace (``tc -n <ns> ...``). If the kernel lacks
``sch_netem`` (some minimal/VM kernels), *loss-only* impairments fall back to a
random drop rule (``iptables -m statistic --mode random``) on the **receiving**
peer's INPUT chain for that link: the packet leaves the sender and silently
vanishes, exactly like egress netem loss (an OUTPUT-chain drop would instead be
reported to the sending socket as EPERM). delay/jitter/reorder/duplicate have no
fallback and raise :class:`NetemUnavailable`.
"""

from __future__ import annotations

import shlex
from dataclasses import asdict, dataclass, replace

from simulator.namespace import CommandError, NamespaceManager
from simulator.topology import LinkSpec

NETEM_MISSING_MARKERS = ("specified qdisc kind is unknown", "unknown qdisc", "qdisc kind is unknown")


class NetemUnavailable(RuntimeError):
    pass


@dataclass
class NetemSpec:
    loss: float = 0.0  # percent
    delay_ms: float = 0.0
    jitter_ms: float = 0.0
    reorder: float = 0.0  # percent (requires delay)
    reorder_corr: float = 50.0
    duplicate: float = 0.0  # percent

    def __post_init__(self) -> None:
        for name in ("loss", "reorder", "duplicate", "reorder_corr"):
            value = getattr(self, name)
            if not 0.0 <= value <= 100.0:
                raise ValueError(f"{name} must be within [0, 100] percent")
        if self.delay_ms < 0 or self.jitter_ms < 0:
            raise ValueError("delay/jitter must be non-negative")
        if self.jitter_ms and not self.delay_ms:
            raise ValueError("jitter requires a delay")
        if self.reorder and not self.delay_ms:
            raise ValueError("netem reordering requires a delay")

    def merged(self, **changes) -> "NetemSpec":
        return replace(self, **{k: v for k, v in changes.items() if v is not None})

    def is_empty(self) -> bool:
        return not (self.loss or self.delay_ms or self.jitter_ms or self.reorder or self.duplicate)

    def loss_only(self) -> bool:
        return bool(self.loss) and not (self.delay_ms or self.jitter_ms or self.reorder or self.duplicate)

    def netem_args(self) -> list[str]:
        args = ["netem"]
        if self.delay_ms:
            args += ["delay", f"{self.delay_ms:g}ms"]
            if self.jitter_ms:
                args += [f"{self.jitter_ms:g}ms", "distribution", "normal"]
        if self.loss:
            args += ["loss", f"{self.loss:g}%"]
        if self.reorder:
            args += ["reorder", f"{self.reorder:g}%", f"{self.reorder_corr:g}%"]
        if self.duplicate:
            args += ["duplicate", f"{self.duplicate:g}%"]
        return args

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict | None) -> "NetemSpec":
        data = data or {}
        return cls(**{k: data[k] for k in cls.__dataclass_fields__ if k in data})


def parse_ms(value: str | float | None) -> float | None:
    """``"100ms"`` / ``"0.1s"`` / ``100`` -> milliseconds."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = value.strip().lower()
    if text.endswith("ms"):
        return float(text[:-2])
    if text.endswith("us"):
        return float(text[:-2]) / 1000.0
    if text.endswith("s"):
        return float(text[:-1]) * 1000.0
    return float(text)


class NetworkImpairer:
    def __init__(self, namespaces: NamespaceManager, backend: str = "auto"):
        if backend not in ("auto", "netem", "iptables"):
            raise ValueError("backend must be auto|netem|iptables")
        self.ns = namespaces
        self.runner = namespaces.runner
        self.backend = backend
        self.netem_supported: bool | None = None if backend == "auto" else backend == "netem"

    # --- per link end (egress of ``node`` on ``link``) ----------------------
    def apply_end(self, link: LinkSpec, node: str, spec: NetemSpec) -> str:
        """Replace the impairment on ``node``'s end of ``link``; returns the backend used."""
        iface = link.end(node)[0]
        self.clear_end(link, node)
        if spec.is_empty():
            return "none"
        if self.netem_supported is not False:
            try:
                self.runner.run(["tc", "-n", self.ns.ns_name(node), "qdisc", "replace", "dev", iface, "root", *spec.netem_args()])
                self.netem_supported = True
                return "netem"
            except CommandError as err:
                if not any(m in err.stderr.lower() for m in NETEM_MISSING_MARKERS):
                    raise
                self.netem_supported = False
        if not spec.loss_only():
            raise NetemUnavailable(
                "this kernel has no sch_netem support: delay/jitter/reorder/duplicate cannot be emulated "
                "(packet loss alone falls back to iptables statistic drops)"
            )
        peer, peer_iface = self._peer_end(link, node)
        self._iptables(peer, ["-A", "INPUT", *self._loss_rule(peer_iface, spec.loss)])
        return "iptables"

    def clear_end(self, link: LinkSpec, node: str) -> None:
        if self.netem_supported is not False:
            self.runner.run(["tc", "-n", self.ns.ns_name(node), "qdisc", "del", "dev", link.end(node)[0], "root"], check=False)
        peer, peer_iface = self._peer_end(link, node)
        self._clear_loss_rules(peer, peer_iface)

    @staticmethod
    def _peer_end(link: LinkSpec, node: str) -> tuple[str, str]:
        peer = link.end(node)[2]
        return peer, link.end(peer)[0]

    @staticmethod
    def _comment(iface: str) -> str:
        return f"gsim-loss:{iface}"

    def _loss_rule(self, in_iface: str, loss_pct: float) -> list[str]:
        return [
            "-i", in_iface,
            "-m", "statistic", "--mode", "random", "--probability", f"{loss_pct / 100.0:.6f}",
            "-m", "comment", "--comment", self._comment(in_iface),
            "-j", "DROP",
        ]  # fmt: skip

    def _iptables(self, node: str, args: list[str], check: bool = True):
        return self.ns.run_in(node, ["iptables", "-w", *args], check=check)

    def _clear_loss_rules(self, node: str, iface: str) -> None:
        proc = self._iptables(node, ["-S", "INPUT"], check=False)
        if proc.returncode != 0:
            return
        for line in proc.stdout.splitlines():
            if self._comment(iface) in line and line.startswith("-A INPUT"):
                self._iptables(node, ["-D", *shlex.split(line)[1:]], check=False)

    # --- per-link -----------------------------------------------------------
    def apply_link(self, link: LinkSpec, spec: NetemSpec, nodes: tuple[str, ...] | None = None) -> dict[str, str]:
        """Impair the chosen ends of ``link`` (both by default = both directions)."""
        return {node: self.apply_end(link, node, spec) for node in nodes or (link.u, link.v)}

    def clear_link(self, link: LinkSpec, nodes: tuple[str, ...] | None = None) -> None:
        for node in nodes or (link.u, link.v):
            self.clear_end(link, node)

    def cut(self, links: list[LinkSpec]) -> None:
        for link in links:
            self.ns.set_link_state(link, up=False)

    def restore(self, links: list[LinkSpec]) -> None:
        for link in links:
            self.ns.set_link_state(link, up=True)
