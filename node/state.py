"""Node state: pinned roster, group epochs, keystore, replay windows, seen-set.

Durable state lives in ``<home>/state/<node_id>/`` (directory ``0700``, files
``0600``) and is reloaded before the daemon starts networking (protocol §6.3).
Key erasure is best-effort only: CPython cannot guarantee zeroisation.
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, Iterable

from crypto.certificate import fingerprint
from crypto.encoding import b64d, b64e, validate_id
from crypto.identity import IdentityKeypair
from crypto.key_agreement import KeyAgreementKeypair

DEFAULT_HOME = "/tmp/gossip-sim"
SEEN_CAPACITY = 10_000
UPDATE_LOG_CAPACITY = 256
REPLAY_WINDOW = 64
INSTALLED_HISTORY = 256

ADMIN = "ADMIN"
MEMBER = "MEMBER"
REMOVED = "REMOVED"
OBSERVER = "OBSERVER"  # relays/tracks group metadata, never held a key


def default_home() -> str:
    return os.environ.get("GOSSIP_SIM_HOME", DEFAULT_HOME)


class StatePaths:
    """Filesystem layout shared by the orchestrator, daemons and CLI."""

    def __init__(self, home: str, node_id: str | None = None):
        self.home = os.path.abspath(home)
        self.node_id = node_id

    @property
    def sockets_dir(self) -> str:
        return os.path.join(self.home, "sockets")

    @property
    def logs_dir(self) -> str:
        return os.path.join(self.home, "logs")

    @property
    def state_root(self) -> str:
        return os.path.join(self.home, "state")

    @property
    def roster(self) -> str:
        return os.path.join(self.home, "roster.json")

    @property
    def ledger(self) -> str:
        return os.path.join(self.home, "ledger.json")

    def _node(self, node_id: str | None) -> str:
        node_id = node_id or self.node_id
        if node_id is None:
            raise ValueError("node_id required")
        return validate_id(node_id, "node_id")

    def state_dir(self, node_id: str | None = None) -> str:
        return os.path.join(self.state_root, self._node(node_id))

    def socket(self, node_id: str | None = None) -> str:
        return os.path.join(self.sockets_dir, f"{self._node(node_id)}.sock")

    def log(self, node_id: str | None = None) -> str:
        return os.path.join(self.logs_dir, f"{self._node(node_id)}.jsonl")

    def stdout_log(self, node_id: str | None = None) -> str:
        return os.path.join(self.logs_dir, f"{self._node(node_id)}.out")

    def node_file(self, name: str, node_id: str | None = None) -> str:
        return os.path.join(self.state_dir(node_id), name)


def atomic_write_json(path: str, data: Any, mode: int = 0o600) -> None:
    tmp = f"{path}.tmp.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, sort_keys=True, indent=1)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def read_json(path: str, default: Any = None) -> Any:
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Pinned roster (trust anchor, protocol §10)
# ---------------------------------------------------------------------------
@dataclass
class RosterEntry:
    node_id: str
    ed25519_pubkey: bytes
    x25519_pubkey: bytes
    fingerprint: str


class Roster:
    def __init__(self, entries: dict[str, RosterEntry]):
        self.entries = entries

    @classmethod
    def from_dict(cls, data: dict) -> "Roster":
        entries = {}
        for node_id, item in data.get("nodes", {}).items():
            validate_id(node_id, "node_id")
            ed = b64d(item["ed25519_pubkey"], "ed25519_pubkey")
            xk = b64d(item["x25519_pubkey"], "x25519_pubkey")
            fp = fingerprint(ed, xk)
            if item.get("fingerprint") != fp:
                raise ValueError(f"roster fingerprint mismatch for {node_id}")
            entries[node_id] = RosterEntry(node_id, ed, xk, fp)
        return cls(entries)

    @classmethod
    def load(cls, path: str) -> "Roster":
        return cls.from_dict(read_json(path, {}))

    def to_dict(self) -> dict:
        return {
            "version": 1,
            "nodes": {
                nid: {
                    "ed25519_pubkey": b64e(e.ed25519_pubkey),
                    "x25519_pubkey": b64e(e.x25519_pubkey),
                    "fingerprint": e.fingerprint,
                }
                for nid, e in sorted(self.entries.items())
            },
        }

    def __contains__(self, node_id: str) -> bool:
        return node_id in self.entries

    def ed25519(self, node_id: str) -> bytes:
        return self.entries[node_id].ed25519_pubkey

    def x25519(self, node_id: str) -> bytes:
        return self.entries[node_id].x25519_pubkey

    def node_ids(self) -> list[str]:
        return sorted(self.entries)


# ---------------------------------------------------------------------------
# Replay window, seen cache, update log
# ---------------------------------------------------------------------------
class ReplayWindow:
    """64-bit sliding window per (group, epoch, sender) (protocol §7.2). Bit 0 = max_counter."""

    MASK = (1 << REPLAY_WINDOW) - 1

    def __init__(self, max_counter: int = 0, bitmap: int = 0):
        self.max_counter = max_counter
        self.bitmap = bitmap

    def check(self, counter: int) -> bool:
        if counter <= 0:
            return False
        if counter > self.max_counter:
            return True
        offset = self.max_counter - counter
        if offset >= REPLAY_WINDOW:
            return False
        return not (self.bitmap >> offset) & 1

    def update(self, counter: int) -> None:
        if counter > self.max_counter:
            shift = counter - self.max_counter
            self.bitmap = ((self.bitmap << shift) | 1) & self.MASK if shift < REPLAY_WINDOW else 1
            self.max_counter = counter
        else:
            self.bitmap |= 1 << (self.max_counter - counter)

    def to_list(self) -> list[int]:
        return [self.max_counter, self.bitmap]

    @classmethod
    def from_list(cls, data: list[int]) -> "ReplayWindow":
        return cls(int(data[0]), int(data[1]))


class SeenCache:
    """Bounded LRU set of IDs."""

    def __init__(self, capacity: int = SEEN_CAPACITY, items: Iterable[str] = ()):
        self.capacity = capacity
        self._items: OrderedDict[str, None] = OrderedDict()
        for item in items:
            self.add(item)

    def add(self, item: str) -> None:
        self._items[item] = None
        self._items.move_to_end(item)
        while len(self._items) > self.capacity:
            self._items.popitem(last=False)

    def __contains__(self, item: str) -> bool:
        if item in self._items:
            self._items.move_to_end(item)
            return True
        return False

    def __len__(self) -> int:
        return len(self._items)

    def to_list(self) -> list[str]:
        return list(self._items)


class UpdateLog:
    """Ring buffer of the last N valid GROUP_UPDATEs of one group (serves resync)."""

    def __init__(self, capacity: int = UPDATE_LOG_CAPACITY, items: Iterable[dict] = ()):
        self._items: deque[dict] = deque(items, maxlen=capacity)

    def append(self, update: dict) -> None:
        self._items.append(update)

    def since(self, from_epoch: int, limit: int = 64, exclude: set[str] | None = None) -> list[dict]:
        exclude = exclude or set()
        picked = [u for u in self._items if u["new_epoch"] > from_epoch and u["update_id"] not in exclude]
        picked.sort(key=lambda u: u["new_epoch"])
        return picked[:limit]

    def latest(self) -> dict | None:
        return max(self._items, key=lambda u: u["new_epoch"], default=None)

    def oldest_epoch(self) -> int | None:
        return min((u["new_epoch"] for u in self._items), default=None)

    def by_epoch(self, epoch: int) -> list[dict]:
        return [u for u in self._items if u["new_epoch"] == epoch]

    def __len__(self) -> int:
        return len(self._items)

    def to_list(self) -> list[dict]:
        return list(self._items)


# ---------------------------------------------------------------------------
# Group state
# ---------------------------------------------------------------------------
@dataclass
class GroupState:
    group_id: str
    admin_id: str
    epoch: int = 0
    members: dict[str, str] = field(default_factory=dict)
    membership_hash: str = ""
    prev_members: dict[str, str] = field(default_factory=dict)
    status: str = OBSERVER
    keys: dict[int, bytes] = field(default_factory=dict)  # at most {e, e-1}
    stale_key: tuple[int, bytes] | None = None  # removed-member view of its last key
    send_counter: int = 0  # last counter used in the current epoch (write-ahead persisted)
    windows: dict[str, ReplayWindow] = field(default_factory=dict)
    installed: dict[int, str] = field(default_factory=dict)  # epoch -> update_id
    latest_update_id: str = ""

    @property
    def is_member(self) -> bool:
        return self.status in (ADMIN, MEMBER)

    def window(self, epoch: int, sender_id: str) -> ReplayWindow:
        return self.windows.setdefault(f"{epoch}|{sender_id}", ReplayWindow())

    def install_epoch(
        self,
        new_epoch: int,
        members: dict[str, str],
        membership_hash: str,
        update_id: str,
        admin_id: str,
        key: bytes | None,
        self_id: str,
        snapshot: bool = False,
    ) -> None:
        """Install epoch ``new_epoch``; keeps exactly K_e and K_{e-1} (grace)."""
        old_epoch, old_keys, was_member = self.epoch, self.keys, self.is_member
        contiguous = new_epoch == old_epoch + 1 and not snapshot
        self.prev_members = dict(self.members) if contiguous else {}
        self.epoch = new_epoch
        self.members = dict(members)
        self.membership_hash = membership_hash
        self.latest_update_id = update_id
        self.admin_id = admin_id
        self.installed[new_epoch] = update_id
        for stale in sorted(self.installed)[:-INSTALLED_HISTORY]:
            del self.installed[stale]

        new_keys: dict[int, bytes] = {}
        if self_id in members:
            if key is not None:
                new_keys[new_epoch] = key
            if contiguous and old_epoch in old_keys:
                new_keys[old_epoch] = old_keys[old_epoch]
            self.status = ADMIN if self_id == admin_id else MEMBER
            self.stale_key = None
        else:
            if was_member and old_epoch in old_keys:
                self.stale_key = (old_epoch, old_keys[old_epoch])
            self.status = REMOVED if (was_member or self.status == REMOVED) else OBSERVER
        # K_{e-2} (and everything older) is dropped here: best-effort erasure.
        self.keys = new_keys
        self.send_counter = 0
        keep = {new_epoch, new_epoch - 1}
        self.windows = {k: w for k, w in self.windows.items() if int(k.split("|", 1)[0]) in keep}

    def to_dict(self) -> dict:
        return {
            "group_id": self.group_id,
            "admin_id": self.admin_id,
            "epoch": self.epoch,
            "members": self.members,
            "membership_hash": self.membership_hash,
            "prev_members": self.prev_members,
            "status": self.status,
            "keys": {str(e): b64e(k) for e, k in self.keys.items()},
            "stale_key": [self.stale_key[0], b64e(self.stale_key[1])] if self.stale_key else None,
            "send_counter": self.send_counter,
            "windows": {k: w.to_list() for k, w in self.windows.items()},
            "installed": {str(e): u for e, u in self.installed.items()},
            "latest_update_id": self.latest_update_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "GroupState":
        stale = data.get("stale_key")
        return cls(
            group_id=data["group_id"],
            admin_id=data["admin_id"],
            epoch=int(data["epoch"]),
            members=dict(data.get("members", {})),
            membership_hash=data.get("membership_hash", ""),
            prev_members=dict(data.get("prev_members", {})),
            status=data.get("status", OBSERVER),
            keys={int(e): b64d(k) for e, k in data.get("keys", {}).items()},
            stale_key=(int(stale[0]), b64d(stale[1])) if stale else None,
            send_counter=int(data.get("send_counter", 0)),
            windows={k: ReplayWindow.from_list(v) for k, v in data.get("windows", {}).items()},
            installed={int(e): u for e, u in data.get("installed", {}).items()},
            latest_update_id=data.get("latest_update_id", ""),
        )


# ---------------------------------------------------------------------------
# Node state
# ---------------------------------------------------------------------------
class NodeState:
    GROUPS_FILE = "groups.json"
    GOSSIP_FILE = "gossip.json"

    def __init__(
        self,
        node_id: str,
        identity: IdentityKeypair,
        kex: KeyAgreementKeypair,
        roster: Roster,
        state_dir: str | None = None,
        links: list[dict] | None = None,
        port: int = 9000,
    ):
        self.node_id = validate_id(node_id, "node_id")
        self.identity = identity
        self.kex = kex
        self.roster = roster
        self.state_dir = state_dir
        self.port = port
        self.links: dict[str, dict] = {link["peer"]: dict(link) for link in (links or [])}
        self.groups: dict[str, GroupState] = {}
        self.seen_updates = SeenCache()
        self.update_logs: dict[str, UpdateLog] = {}
        self.seen_msgs = SeenCache()
        self.stats: Counter[str] = Counter()
        self.inbox: deque[dict] = deque(maxlen=100)
        self.direct_inbox: deque[dict] = deque(maxlen=100)
        self.captured: dict[str, deque[dict]] = {"GROUP_MSG": deque(maxlen=32), "GROUP_UPDATE": deque(maxlen=32)}
        self.attack_modes: dict[str, Any] = {"tamper": {}, "suppress": False}
        self.compromised = False
        self.started_at = time.time()
        if roster.entries and node_id in roster:
            if roster.ed25519(node_id) != identity.public_bytes() or roster.x25519(node_id) != kex.public_bytes():
                raise ValueError("local identity does not match the pinned roster")

    # --- helpers ------------------------------------------------------------
    def update_log(self, group_id: str) -> UpdateLog:
        return self.update_logs.setdefault(group_id, UpdateLog())

    def neighbors(self) -> list[str]:
        return sorted(self.links)

    # --- persistence --------------------------------------------------------
    def _path(self, name: str) -> str | None:
        return os.path.join(self.state_dir, name) if self.state_dir else None

    def save_groups(self) -> None:
        path = self._path(self.GROUPS_FILE)
        if path:
            atomic_write_json(path, {gid: g.to_dict() for gid, g in self.groups.items()})

    def save_gossip(self) -> None:
        path = self._path(self.GOSSIP_FILE)
        if path:
            atomic_write_json(
                path,
                {
                    "seen_update_ids": self.seen_updates.to_list(),
                    "update_logs": {gid: log.to_list() for gid, log in self.update_logs.items()},
                },
            )

    def save(self) -> None:
        self.save_groups()
        self.save_gossip()

    def load_persistent(self) -> bool:
        """Reload durable group/gossip state. Returns True if anything was restored."""
        restored = False
        groups = read_json(self._path(self.GROUPS_FILE), None) if self.state_dir else None
        if groups:
            self.groups = {gid: GroupState.from_dict(g) for gid, g in groups.items()}
            restored = True
        gossip = read_json(self._path(self.GOSSIP_FILE), None) if self.state_dir else None
        if gossip:
            self.seen_updates = SeenCache(items=gossip.get("seen_update_ids", []))
            self.update_logs = {gid: UpdateLog(items=items) for gid, items in gossip.get("update_logs", {}).items()}
            restored = True
        return restored

    @classmethod
    def from_state_dir(cls, state_dir: str) -> "NodeState":
        """Load identity, pinned roster and link config written by the orchestrator."""
        ident = read_json(os.path.join(state_dir, "identity.json"))
        if ident is None:
            raise FileNotFoundError(f"no identity.json in {state_dir}")
        roster = Roster.load(os.path.join(state_dir, "roster.json"))
        config = read_json(os.path.join(state_dir, "config.json"), {})
        state = cls(
            ident["node_id"],
            IdentityKeypair.from_private_bytes(b64d(ident["ed25519_private"])),
            KeyAgreementKeypair.from_private_bytes(b64d(ident["x25519_private"])),
            roster,
            state_dir=state_dir,
            links=config.get("links", []),
            port=int(config.get("port", 9000)),
        )
        state.load_persistent()
        return state

    def save_config(self) -> None:
        path = self._path("config.json")
        if path:
            atomic_write_json(path, {"node_id": self.node_id, "port": self.port, "links": list(self.links.values())})


def write_identity(state_dir: str, node_id: str, identity: IdentityKeypair, kex: KeyAgreementKeypair) -> None:
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    os.chmod(state_dir, 0o700)
    atomic_write_json(
        os.path.join(state_dir, "identity.json"),
        {
            "node_id": node_id,
            "ed25519_private": b64e(identity.private_bytes()),
            "x25519_private": b64e(kex.private_bytes()),
        },
    )
