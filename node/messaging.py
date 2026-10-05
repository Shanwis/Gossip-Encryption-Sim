"""Data-plane framing, frame validation, direct messages and the GROUP_MSG pipeline.

Wire format (protocol §3): 4-byte big-endian length || UTF-8 JSON, 1 MiB ceiling.
GROUP_MSG frames are relayed hop-by-hop (flooded to every neighbour except the
one it arrived from, de-duplicated by ``msg_id``) because non-adjacent nodes have
no L3 path; members validate per §7.3 before delivering.
"""

from __future__ import annotations

import asyncio
import copy
import json
import os
import re
import struct
import time
from typing import Any, Callable, Protocol

from cryptography.exceptions import InvalidTag

from crypto.encoding import EncodingError, b64d, b64e, update_id as compute_update_id, validate_id, wire_json
from crypto.engine import CryptoEngine, get_engine
from crypto.symmetric import MAX_COUNTER
from node.logger import EventLogger
from node.state import OBSERVER, REMOVED, NodeState

PROTOCOL_VERSION = 1
MAX_FRAME = 1 << 20  # 1 MiB payload ceiling

# Error codes (protocol §9)
ERR_SIG_INVALID = "ERR_SIG_INVALID"
ERR_EPOCH_STALE = "ERR_EPOCH_STALE"
ERR_EPOCH_GAP = "ERR_EPOCH_GAP"
ERR_UNAUTHORIZED = "ERR_UNAUTHORIZED"
ERR_IDENTITY_UNKNOWN = "ERR_IDENTITY_UNKNOWN"
ERR_PREFIX_MISMATCH = "ERR_PREFIX_MISMATCH"
ERR_SENDER_NOT_MEMBER = "ERR_SENDER_NOT_MEMBER"
ERR_REPLAY = "ERR_REPLAY"
ERR_DECRYPT_FAIL = "ERR_DECRYPT_FAIL"
ERR_KEY_UNWRAP = "ERR_KEY_UNWRAP"
ERR_PEER_UNREACHABLE = "ERR_PEER_UNREACHABLE"
EV_ADMIN_DOUBLE_SIGN = "EV_ADMIN_DOUBLE_SIGN"
ERR_MALFORMED = "ERR_MALFORMED"
# Local (control-plane) operation errors
ERR_NOT_MEMBER = "ERR_NOT_MEMBER"
ERR_UNKNOWN_GROUP = "ERR_UNKNOWN_GROUP"
ERR_GROUP_EXISTS = "ERR_GROUP_EXISTS"
ERR_INVALID_PARAMS = "ERR_INVALID_PARAMS"
ERR_COUNTER_EXHAUSTED = "ERR_COUNTER_EXHAUSTED"
ERR_UNSAFE_DISABLED = "ERR_UNSAFE_DISABLED"

ACTIONS = ("CREATE_GROUP", "ADD_MEMBER", "REMOVE_MEMBER", "REKEY")
FRAME_TYPES = ("HELLO", "DIRECT_MSG", "GROUP_MSG", "GROUP_UPDATE", "STATE_DIGEST", "STATE_REQUEST", "STATE_BUNDLE")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PREFIX_HEX = re.compile(r"^[0-9a-f]{8}$")
MSG_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
MAX_PENDING_MSGS = 256


class ProtocolError(Exception):
    def __init__(self, code: str, message: str = ""):
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.message = message or code


class FrameError(Exception):
    """Framing-level violation; the connection is dropped."""


class Transport(Protocol):
    def neighbors(self) -> list[str]: ...

    def send(self, peer_id: str, frame: dict) -> bool: ...


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------
def encode_frame(obj: dict) -> bytes:
    payload = wire_json(obj)
    if len(payload) > MAX_FRAME:
        raise FrameError(f"frame of {len(payload)} bytes exceeds {MAX_FRAME}")
    return struct.pack(">I", len(payload)) + payload


def decode_payload(payload: bytes) -> dict:
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FrameError("payload is not UTF-8 JSON") from exc
    if not isinstance(obj, dict):
        raise FrameError("payload must be a JSON object")
    return obj


async def read_frame(reader: asyncio.StreamReader) -> dict:
    header = await reader.readexactly(4)
    (length,) = struct.unpack(">I", header)
    if length > MAX_FRAME:
        raise FrameError(f"announced frame length {length} exceeds {MAX_FRAME}")
    return decode_payload(await reader.readexactly(length))


# ---------------------------------------------------------------------------
# Frame schema validation (trust boundary)
# ---------------------------------------------------------------------------
def _int(value: Any, field: str, minimum: int = 0, maximum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ProtocolError(ERR_MALFORMED, f"{field} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise ProtocolError(ERR_MALFORMED, f"{field} out of range")
    return value


def _str(value: Any, field: str, pattern: re.Pattern | None = None, max_len: int = MAX_FRAME) -> str:
    if not isinstance(value, str) or len(value) > max_len or (pattern is not None and not pattern.fullmatch(value)):
        raise ProtocolError(ERR_MALFORMED, f"invalid {field}")
    return value


def _id(value: Any, field: str) -> str:
    try:
        return validate_id(value, field)
    except EncodingError as exc:
        raise ProtocolError(ERR_MALFORMED, str(exc)) from exc


def _number(value: Any, field: str) -> None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ProtocolError(ERR_MALFORMED, f"{field} must be a number")


def validate_update_fields(u: dict) -> None:
    _str(u.get("update_id"), "update_id", HEX64)
    _id(u.get("group_id"), "group_id")
    prev = _int(u.get("prev_epoch"), "prev_epoch", 0)
    new = _int(u.get("new_epoch"), "new_epoch", 1)
    if new != prev + 1:
        raise ProtocolError(ERR_MALFORMED, "new_epoch must equal prev_epoch + 1")
    if u.get("action") not in ACTIONS:
        raise ProtocolError(ERR_MALFORMED, "unknown action")
    if u.get("target_member") is not None:
        _id(u["target_member"], "target_member")
    members = u.get("members")
    if not isinstance(members, dict) or not members:
        raise ProtocolError(ERR_MALFORMED, "members must be a non-empty object")
    for node_id, prefix in members.items():
        _id(node_id, "member id")
        _str(prefix, "sender prefix", PREFIX_HEX)
    _str(u.get("membership_hash"), "membership_hash", HEX64)
    _id(u.get("admin_id"), "admin_id")
    _str(u.get("ephemeral_pubkey"), "ephemeral_pubkey", max_len=128)
    keys = u.get("encrypted_keys")
    if not isinstance(keys, dict):
        raise ProtocolError(ERR_MALFORMED, "encrypted_keys must be an object")
    for node_id, blob in keys.items():
        _id(node_id, "encrypted_keys id")
        _str(blob, "wrapped key", max_len=256)
    _str(u.get("signature"), "signature", max_len=256)


def validate_frame(frame: Any) -> str:
    """Validate envelope + per-type schema; returns the frame type."""
    if not isinstance(frame, dict):
        raise ProtocolError(ERR_MALFORMED, "frame must be an object")
    if frame.get("version") != PROTOCOL_VERSION:
        raise ProtocolError(ERR_MALFORMED, "unsupported protocol version")
    ftype = frame.get("type")
    if ftype not in FRAME_TYPES:
        raise ProtocolError(ERR_MALFORMED, f"unknown frame type {ftype!r}")
    if ftype == "HELLO":
        _id(frame.get("node_id"), "node_id")
        _str(frame.get("ed25519_pubkey"), "ed25519_pubkey", max_len=128)
        _number(frame.get("timestamp"), "timestamp")
    elif ftype == "DIRECT_MSG":
        _str(frame.get("msg_id"), "msg_id", MSG_ID)
        _id(frame.get("sender_id"), "sender_id")
        _id(frame.get("recipient_id"), "recipient_id")
        _number(frame.get("timestamp"), "timestamp")
        _str(frame.get("payload"), "payload")
    elif ftype == "GROUP_MSG":
        _str(frame.get("msg_id"), "msg_id", MSG_ID)
        _id(frame.get("group_id"), "group_id")
        _int(frame.get("epoch"), "epoch", 1)
        _id(frame.get("sender_id"), "sender_id")
        _int(frame.get("counter"), "counter", 1, MAX_COUNTER)
        _str(frame.get("nonce"), "nonce", max_len=64)
        _str(frame.get("ciphertext"), "ciphertext")
    elif ftype == "GROUP_UPDATE":
        validate_update_fields(frame)
    elif ftype == "STATE_DIGEST":
        _id(frame.get("sender_id"), "sender_id")
        groups = frame.get("groups")
        if not isinstance(groups, dict):
            raise ProtocolError(ERR_MALFORMED, "groups must be an object")
        for gid, info in groups.items():
            _id(gid, "group_id")
            if not isinstance(info, dict):
                raise ProtocolError(ERR_MALFORMED, "digest entry must be an object")
            _int(info.get("epoch"), "epoch", 0)
            _str(info.get("membership_hash", ""), "membership_hash", max_len=64)
            _str(info.get("latest_update_id", ""), "latest_update_id", max_len=64)
    elif ftype == "STATE_REQUEST":
        _str(frame.get("req_id"), "req_id", MSG_ID)
        _id(frame.get("sender_id"), "sender_id")
        _id(frame.get("group_id"), "group_id")
        _int(frame.get("from_epoch"), "from_epoch", 0)
        known = frame.get("known_update_ids", [])
        if not isinstance(known, list) or len(known) > 256:
            raise ProtocolError(ERR_MALFORMED, "known_update_ids must be a list")
        for item in known:
            _str(item, "known update id", HEX64)
    elif ftype == "STATE_BUNDLE":
        _str(frame.get("req_id"), "req_id", MSG_ID)
        _id(frame.get("sender_id"), "sender_id")
        _id(frame.get("group_id"), "group_id")
        _int(frame.get("from_epoch"), "from_epoch", 0)
        if not isinstance(frame.get("truncated", False), bool):
            raise ProtocolError(ERR_MALFORMED, "truncated must be boolean")
        updates = frame.get("updates")
        if not isinstance(updates, list) or len(updates) > 256:
            raise ProtocolError(ERR_MALFORMED, "updates must be a list")
    return ftype


def make_hello(state: NodeState) -> dict:
    return {
        "version": PROTOCOL_VERSION,
        "type": "HELLO",
        "node_id": state.node_id,
        "ed25519_pubkey": b64e(state.identity.public_bytes()),
        "timestamp": time.time(),
    }


def verify_hello(state: NodeState, frame: dict) -> str:
    """Check the HELLO identity claim against the pinned roster (§10.3)."""
    if validate_frame(frame) != "HELLO":
        raise ProtocolError(ERR_MALFORMED, "first frame must be HELLO")
    node_id = frame["node_id"]
    if node_id not in state.roster:
        raise ProtocolError(ERR_IDENTITY_UNKNOWN, f"{node_id} not in roster")
    try:
        claimed = b64d(frame["ed25519_pubkey"])
    except EncodingError as exc:
        raise ProtocolError(ERR_MALFORMED, "bad HELLO key encoding") from exc
    if claimed != state.roster.ed25519(node_id):
        raise ProtocolError(ERR_IDENTITY_UNKNOWN, f"HELLO key for {node_id} does not match roster")
    return node_id


def new_id(prefix: str) -> str:
    return f"{prefix}_{os.urandom(8).hex()}"


# ---------------------------------------------------------------------------
# Outbox: every outgoing data-plane frame passes through here (attack hooks)
# ---------------------------------------------------------------------------
class Outbox:
    def __init__(self, state: NodeState, transport: Transport, logger: EventLogger):
        self.state = state
        self.transport = transport
        self.logger = logger

    def neighbors(self) -> list[str]:
        return self.transport.neighbors()

    def send(self, peer_id: str, frame: dict) -> bool:
        return self.transport.send(peer_id, self._maybe_tamper(peer_id, frame))

    def _maybe_tamper(self, peer_id: str, frame: dict) -> dict:
        """In-transit bit-flip attack armed via ``node.inject_attack`` (tamper)."""
        mode = self.state.attack_modes["tamper"].get(peer_id)
        ftype = frame.get("type")
        if not mode or ftype not in ("GROUP_MSG", "GROUP_UPDATE"):
            return frame
        if mode["kind"] == "msg" and ftype != "GROUP_MSG" or mode["kind"] == "update" and ftype != "GROUP_UPDATE":
            return frame
        tampered = copy.deepcopy(frame)
        if ftype == "GROUP_MSG":
            raw = bytearray(b64d(tampered["ciphertext"]))
            raw[0] ^= 0x01
            tampered["ciphertext"] = b64e(bytes(raw))
            detail = {"msg_id": frame["msg_id"], "field": "ciphertext"}
        else:
            raw = bytearray(b64d(tampered["signature"]))
            raw[0] ^= 0x01
            tampered["signature"] = b64e(bytes(raw))
            # A real attacker can recompute the public update_id derivation.
            tampered["update_id"] = compute_update_id(
                tampered["admin_id"], tampered["group_id"], tampered["new_epoch"], bytes(raw)
            )
            detail = {"update_id": frame["update_id"], "field": "signature"}
        mode["remaining"] -= 1
        if mode["remaining"] <= 0:
            del self.state.attack_modes["tamper"][peer_id]
        self.state.stats["attacks_injected"] += 1
        self.logger.log("ATTACK_INJECTED", attack="tamper", target=peer_id, frame_type=ftype, **detail)
        return tampered


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
class MessageRouter:
    def __init__(
        self,
        state: NodeState,
        gossip: Any,
        outbox: Outbox,
        logger: EventLogger,
        engine: CryptoEngine | None = None,
    ):
        self.state = state
        self.gossip = gossip
        self.outbox = outbox
        self.logger = logger
        self.engine = engine or get_engine()
        self.pending_msgs: dict[str, list[tuple[dict, str | None]]] = {}
        gossip.listeners.append(self.on_epoch_installed)
        self.delivery_hooks: list[Callable[[dict], None]] = []

    # --- dispatch -----------------------------------------------------------
    def handle_frame(self, frame: dict, from_peer: str | None) -> str:
        try:
            ftype = validate_frame(frame)
            if ftype in ("DIRECT_MSG", "STATE_DIGEST", "STATE_REQUEST", "STATE_BUNDLE") and from_peer is not None:
                if frame["sender_id"] != from_peer:
                    raise ProtocolError(ERR_IDENTITY_UNKNOWN, "sender_id does not match HELLO identity")
        except ProtocolError as exc:
            self.state.stats["malformed_frames"] += 1
            self.logger.log("FRAME_REJECTED", code=exc.code, reason=exc.message, from_peer=from_peer)
            return exc.code
        if ftype == "HELLO":
            return "IGNORED"
        if ftype == "DIRECT_MSG":
            return self.handle_direct(frame, from_peer)
        if ftype == "GROUP_MSG":
            return self.handle_group_msg(frame, from_peer)
        if ftype == "GROUP_UPDATE":
            self._capture(frame)
            return self.gossip.handle_group_update(frame, from_peer)
        if ftype == "STATE_DIGEST":
            return self.gossip.handle_digest(frame, from_peer)
        if ftype == "STATE_REQUEST":
            return self.gossip.handle_state_request(frame, from_peer)
        return self.gossip.handle_state_bundle(frame, from_peer)

    def _capture(self, frame: dict) -> None:
        self.state.captured[frame["type"]].append(copy.deepcopy(frame))

    # --- direct messages (unsigned test channel, outside the security model) --
    def make_direct(self, recipient: str, text: str) -> dict:
        return {
            "version": PROTOCOL_VERSION,
            "type": "DIRECT_MSG",
            "msg_id": new_id("dmsg"),
            "sender_id": self.state.node_id,
            "recipient_id": recipient,
            "timestamp": time.time(),
            "payload": text,
        }

    def handle_direct(self, frame: dict, from_peer: str | None) -> str:
        if frame["recipient_id"] != self.state.node_id:
            self.logger.log("DIRECT_MSG_DROPPED", reason="not addressed to this node", msg_id=frame["msg_id"])
            return "DROPPED"
        self.state.stats["direct_received"] += 1
        entry = {"ts": time.time(), "from": frame["sender_id"], "msg_id": frame["msg_id"], "message": frame["payload"]}
        self.state.direct_inbox.append(entry)
        self.logger.log("DIRECT_MSG_RECEIVED", sender_id=frame["sender_id"], msg_id=frame["msg_id"])
        return "DELIVERED"

    # --- group messages -----------------------------------------------------
    def send_group(self, group_id: str, text: str) -> dict:
        g = self.state.groups.get(group_id)
        if g is None:
            raise ProtocolError(ERR_UNKNOWN_GROUP, group_id)
        if not g.is_member or g.epoch not in g.keys or self.state.node_id not in g.members:
            raise ProtocolError(ERR_NOT_MEMBER, f"{self.state.node_id} holds no key for {group_id}@{g.epoch}")
        counter = g.send_counter + 1
        if counter > MAX_COUNTER:
            raise ProtocolError(ERR_COUNTER_EXHAUSTED, "counter exhausted: rekey required")
        g.send_counter = counter
        self.state.save_groups()  # write-ahead: a restart can never reuse this nonce
        prefix = bytes.fromhex(g.members[self.state.node_id])
        nonce, ciphertext = self.engine.encrypt_group(
            g.keys[g.epoch], text.encode("utf-8"), prefix, group_id, g.epoch, self.state.node_id, counter
        )
        frame = {
            "version": PROTOCOL_VERSION,
            "type": "GROUP_MSG",
            "msg_id": new_id("gmsg"),
            "group_id": group_id,
            "epoch": g.epoch,
            "sender_id": self.state.node_id,
            "counter": counter,
            "nonce": b64e(nonce),
            "ciphertext": b64e(ciphertext),
        }
        self.state.seen_msgs.add(frame["msg_id"])
        self._capture(frame)
        self.state.stats["group_sent"] += 1
        self.logger.log(
            "GROUP_MSG_SENT",
            group_id=group_id,
            epoch=g.epoch,
            counter=counter,
            msg_id=frame["msg_id"],
            recipients=len(g.members) - 1,
        )
        self._flood(frame, exclude=None)
        return frame

    def _flood(self, frame: dict, exclude: str | None) -> int:
        sent = 0
        for peer in self.outbox.neighbors():
            if peer != exclude and self.outbox.send(peer, frame):
                sent += 1
        return sent

    def handle_group_msg(self, frame: dict, from_peer: str | None) -> str:
        if frame["msg_id"] in self.state.seen_msgs:
            self.state.stats["group_duplicates"] += 1
            return "DUPLICATE"
        self.state.seen_msgs.add(frame["msg_id"])
        self._capture(frame)
        code, forward = self._process_group_msg(frame, from_peer)
        if forward:
            if self._flood(frame, exclude=from_peer):
                self.state.stats["group_relayed"] += 1
        return code

    def _reject(self, event: str, code: str, stat: str, frame: dict, **extra: Any) -> None:
        self.state.stats[stat] += 1
        self.logger.log(
            event,
            code=code,
            group_id=frame["group_id"],
            epoch=frame["epoch"],
            sender_id=frame["sender_id"],
            counter=frame["counter"],
            msg_id=frame["msg_id"],
            **extra,
        )

    def _process_group_msg(self, frame: dict, from_peer: str | None, replayed: bool = False) -> tuple[str, bool]:
        """§7.3 validation pipeline. Returns (result code, forward?)."""
        gid, epoch, sender, counter = frame["group_id"], frame["epoch"], frame["sender_id"], frame["counter"]
        g = self.state.groups.get(gid)
        if g is None or g.status == OBSERVER:
            return "RELAYED", True
        if g.status == REMOVED:
            return self._removed_member_attempt(frame, g), True

        # (1) epoch / grace window
        if epoch == g.epoch:
            members = g.members
        elif epoch == g.epoch - 1 and epoch in g.keys:
            members = g.prev_members
        elif epoch > g.epoch:
            queue = self.pending_msgs.setdefault(gid, [])
            if len(queue) < MAX_PENDING_MSGS:
                queue.append((frame, from_peer))
            self.logger.log("MSG_PENDING", group_id=gid, epoch=epoch, local_epoch=g.epoch, msg_id=frame["msg_id"])
            self.gossip.request_resync(gid, from_peer)
            return "PENDING", True
        else:
            self._reject("MSG_REJECTED", ERR_EPOCH_STALE, "stale_messages", frame, local_epoch=g.epoch)
            return ERR_EPOCH_STALE, False
        key = g.keys.get(epoch)
        if key is None:
            self._reject("DECRYPT_FAIL", ERR_DECRYPT_FAIL, "decryption_failures", frame, reason="no key for epoch")
            return ERR_DECRYPT_FAIL, True
        # (2) sender membership in that epoch's pinned member map; a grace-epoch
        # sender must also survive the transition (removed members are cut off).
        if sender not in members or (epoch != g.epoch and sender not in g.members):
            self._reject("MSG_REJECTED", ERR_SENDER_NOT_MEMBER, "non_member_rejections", frame)
            return ERR_SENDER_NOT_MEMBER, False
        # (3) pinned sender prefix
        try:
            nonce = b64d(frame["nonce"], "nonce")
            ciphertext = b64d(frame["ciphertext"], "ciphertext")
        except EncodingError:
            self._reject("MSG_REJECTED", ERR_MALFORMED, "malformed_frames", frame)
            return ERR_MALFORMED, False
        if nonce[:4] != bytes.fromhex(members[sender]):
            self._reject("MSG_REJECTED", ERR_PREFIX_MISMATCH, "prefix_mismatches", frame)
            return ERR_PREFIX_MISMATCH, False
        # (4) sliding replay window (own messages coming back are reflections)
        window = g.window(epoch, sender)
        if sender == self.state.node_id or not window.check(counter):
            self._reject("REPLAY_DETECTED", ERR_REPLAY, "replays_detected", frame)
            return ERR_REPLAY, False
        # (5) AEAD
        try:
            plaintext = self.engine.decrypt_group(
                key, nonce, ciphertext, bytes.fromhex(members[sender]), gid, epoch, sender, counter
            )
        except (InvalidTag, ValueError):
            self._reject("DECRYPT_FAIL", ERR_DECRYPT_FAIL, "decryption_failures", frame, reason="AEAD failure")
            return ERR_DECRYPT_FAIL, False
        window.update(counter)
        self.state.save_groups()
        self.state.stats["group_received"] += 1
        text = plaintext.decode("utf-8", errors="replace")
        entry = {"ts": time.time(), "group_id": gid, "epoch": epoch, "sender_id": sender, "counter": counter, "message": text}
        self.state.inbox.append(entry)
        self.logger.log(
            "GROUP_MSG_DELIVERED", group_id=gid, epoch=epoch, sender_id=sender, counter=counter, msg_id=frame["msg_id"]
        )
        for hook in self.delivery_hooks:
            hook(entry)
        return "DELIVERED", True

    def _removed_member_attempt(self, frame: dict, g) -> str:
        """A removed member tries its last (stale) key on new traffic: must fail (§9)."""
        if not g.stale_key:
            return "RELAYED"
        stale_epoch, stale_key = g.stale_key
        try:
            nonce = b64d(frame["nonce"])
            self.engine.decrypt_group(
                stale_key,
                nonce,
                b64d(frame["ciphertext"]),
                nonce[:4],
                frame["group_id"],
                frame["epoch"],
                frame["sender_id"],
                frame["counter"],
            )
        except (InvalidTag, ValueError, EncodingError):
            self._reject(
                "DECRYPT_FAIL",
                ERR_DECRYPT_FAIL,
                "decryption_failures",
                frame,
                reason="removed member: stale key",
                stale_epoch=stale_epoch,
            )
            return ERR_DECRYPT_FAIL
        self.logger.log("STALE_KEY_DECRYPTED", group_id=frame["group_id"], epoch=frame["epoch"], msg_id=frame["msg_id"])
        return "STALE_DECRYPTED"

    def on_epoch_installed(self, group_id: str, epoch: int) -> None:
        queue = self.pending_msgs.get(group_id)
        if not queue:
            return
        ready = [item for item in queue if item[0]["epoch"] <= epoch]
        self.pending_msgs[group_id] = [item for item in queue if item[0]["epoch"] > epoch]
        for frame, from_peer in ready:
            self._process_group_msg(frame, from_peer)

    # --- attack primitives (node side of simulator/attack_engine.py) ----------
    def attack_replay(self, target: str, kind: str = "msg") -> dict:
        if target not in self.outbox.neighbors():
            raise ProtocolError(ERR_PEER_UNREACHABLE, f"{target} is not adjacent to {self.state.node_id}")
        ftype = "GROUP_MSG" if kind == "msg" else "GROUP_UPDATE"
        captured = self.state.captured[ftype]
        if not captured:
            raise ProtocolError(ERR_INVALID_PARAMS, f"no captured {ftype} to replay")
        original = captured[-1]
        frame = copy.deepcopy(original)
        info: dict[str, Any] = {"attack": "replay", "kind": kind, "target": target}
        if ftype == "GROUP_MSG":
            # Fresh msg_id: msg_id is unauthenticated relay metadata, so the best
            # replay bypasses relay de-dup and must be stopped by the window.
            frame["msg_id"] = new_id("gmsg")
            info.update(
                msg_id=frame["msg_id"],
                original_msg_id=original["msg_id"],
                group_id=frame["group_id"],
                epoch=frame["epoch"],
                sender_id=frame["sender_id"],
                counter=frame["counter"],
            )
        else:
            info.update(update_id=frame["update_id"], group_id=frame["group_id"], epoch=frame["new_epoch"])
        self.transport_send_raw(target, frame)
        self.state.stats["attacks_injected"] += 1
        record = self.logger.log("ATTACK_INJECTED", **info)
        info["ts"] = record["ts"]
        return info

    def arm_tamper(self, target: str, kind: str = "msg", count: int = 1) -> dict:
        if target not in self.outbox.neighbors():
            raise ProtocolError(ERR_PEER_UNREACHABLE, f"{target} is not adjacent to {self.state.node_id}")
        if kind not in ("msg", "update", "any") or count < 1:
            raise ProtocolError(ERR_INVALID_PARAMS, "kind must be msg|update|any and count >= 1")
        self.state.attack_modes["tamper"][target] = {"kind": kind, "remaining": int(count)}
        self.logger.log("ATTACK_ARMED", attack="tamper", target=target, kind=kind, count=count)
        return {"attack": "tamper", "target": target, "kind": kind, "count": count, "armed": True}

    def transport_send_raw(self, peer: str, frame: dict) -> bool:
        """Bypass the tamper hook (attacker-crafted frames are sent as-is)."""
        return self.outbox.transport.send(peer, frame)
