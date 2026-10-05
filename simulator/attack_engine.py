"""Attack orchestration (protocol threat model, IDEA.md §9).

Network-level attacks drive ``tc netem`` / link cuts through the orchestrator and
:mod:`simulator.network_impairer`. Protocol-level attacks are executed by a node
adjacent to the victim (the "attacker" holds captured frames and a data-plane
link) via ``node.inject_attack`` over the out-of-band control socket.
"""

from __future__ import annotations

import os
import time
from typing import Any

from node.control_server import RPCError
from node.logger import read_events
from node.state import atomic_write_json
from simulator.orchestrator import Orchestrator, SimulatorError

DETECTION_EVENTS = {
    "replay_msg": ("REPLAY_DETECTED", {}),
    "replay_update": ("UPDATE_DUPLICATE", {}),
    "tamper_msg": ("DECRYPT_FAIL", {}),
    "tamper_update": ("UPDATE_REJECTED", {"code": "ERR_SIG_INVALID"}),
    "forge": ("UPDATE_REJECTED", {"code": "ERR_SIG_INVALID"}),
    "forge_unauthorized": ("UPDATE_REJECTED", {"code": "ERR_UNAUTHORIZED"}),
    "double_sign": ("ADMIN_DOUBLE_SIGN", {}),
}


class AttackEngine:
    def __init__(self, orchestrator: Orchestrator):
        self.orch = orchestrator

    # --- helpers --------------------------------------------------------------
    def neighbors(self, node: str) -> list[str]:
        out = []
        for link in self.orch.links():
            if node in (link.u, link.v):
                out.append(link.end(node)[2])
        return sorted(out)

    def _inject(self, attacker: str, params: dict) -> dict:
        return self.orch.rpc(attacker, "node.inject_attack", params)

    def _attacker_for(self, target: str, via: str | None, avoid: set[str] | None = None) -> str:
        nbrs = self.neighbors(target)
        if via is not None:
            if via not in nbrs:
                raise SimulatorError(f"{via} is not adjacent to {target}: attacks need a data-plane link")
            return via
        candidates = [n for n in nbrs if n not in (avoid or set())] or nbrs
        if not candidates:
            raise SimulatorError(f"{target} has no neighbours to attack from")
        return candidates[0]

    # --- protocol attacks ----------------------------------------------------------
    def replay(self, target: str, via: str | None = None, kind: str = "msg") -> dict:
        """Re-inject a captured GROUP_MSG/GROUP_UPDATE into ``target``."""
        attackers = [via] if via else self.neighbors(target)
        last_error: Exception | None = None
        for attacker in attackers:
            try:
                result = self._inject(attacker, {"attack": "replay", "target": target, "kind": kind})
                result["attacker"] = attacker
                result["expect"] = DETECTION_EVENTS["replay_msg" if kind == "msg" else "replay_update"]
                return result
            except RPCError as exc:
                last_error = exc
        raise SimulatorError(f"replay failed: {last_error}")

    def tamper(self, src: str, dst: str, kind: str = "msg", count: int = 1) -> dict:
        """Arm in-transit bit flipping on the next ``count`` frames ``src`` sends to ``dst``."""
        result = self._inject(src, {"attack": "tamper", "target": dst, "kind": kind, "count": count})
        result["attacker"] = src
        result["expect"] = DETECTION_EVENTS["tamper_msg" if kind == "msg" else "tamper_update"]
        return result

    def forge(self, as_node: str, target: str, via: str | None = None, group: str | None = None) -> dict:
        """Inject a GROUP_UPDATE claiming ``as_node`` as admin, signed with the attacker's key."""
        attacker = self._attacker_for(target, via, avoid={as_node})
        params = {"attack": "forge", "target": target, "as": as_node}
        if group:
            params["group_id"] = group
        result = self._inject(attacker, params)
        result["attacker"] = attacker
        result["expect"] = DETECTION_EVENTS["forge_unauthorized" if attacker == as_node else "forge"]
        return result

    def double_sign(self, admin: str, group: str) -> dict:
        result = self._inject(admin, {"attack": "double_sign", "group_id": group})
        result["attacker"] = admin
        result["expect"] = DETECTION_EVENTS["double_sign"]
        return result

    def suppress(self, node: str, enabled: bool = True) -> dict:
        return self._inject(node, {"attack": "suppress", "enabled": enabled})

    def clear(self, node: str) -> dict:
        return self._inject(node, {"attack": "clear"})

    def compromise(self, node: str, save: bool = True) -> dict:
        """Exfiltrate keys (daemon must run with --unsafe-allow-secret-export)."""
        secrets = self.orch.rpc(node, "node.secrets")
        radius = {gid: sorted(int(e) for e in keys) for gid, keys in secrets["group_keys"].items() if keys}
        report: dict[str, Any] = {
            "node": node,
            "exported_at": secrets["exported_at"],
            "impact_radius": radius,
            "identity_keys_exposed": True,
            "mitigation": [f"gossip-sim group leave <admin> {gid} {node}  (removal + fresh-key rekey)" for gid in radius],
        }
        if save:
            directory = os.path.join(self.orch.home, "attacks")
            os.makedirs(directory, mode=0o700, exist_ok=True)
            path = os.path.join(directory, f"compromise-{node}.json")
            atomic_write_json(path, {"report": report, "secrets": secrets})
            report["saved_to"] = path
        return report

    # --- network attacks (Component 6.1) --------------------------------------------
    def network(self, link: tuple[str, str] | None = None, node: str | None = None, **changes) -> list[dict]:
        return self.orch.impair(link=link, node=node, **changes)

    def partition(self, group_a: list[str], group_b: list[str]):
        return self.orch.partition(group_a, group_b)

    # --- detection -----------------------------------------------------------------
    def wait_for_event(
        self, node: str, event: str, since: float, match: dict | None = None, timeout: float = 10.0
    ) -> dict | None:
        """Poll ``node``'s JSONL log for ``event`` (fields matching ``match``) after ``since``."""
        match = match or {}
        deadline = time.time() + timeout
        path = self.orch.paths.log(node)
        while True:
            for record in read_events(path):
                if record["event"] == event and record["ts"] >= since and all(record.get(k) == v for k, v in match.items()):
                    return record
            if time.time() >= deadline:
                return None
            time.sleep(0.05)
