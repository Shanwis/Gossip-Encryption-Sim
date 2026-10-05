"""Epidemic gossip: admin commits, GROUP_UPDATE verification pipeline, rumor
mongering with a seen-LRU + update log, and push-pull anti-entropy (protocol §6).

Every node tracks every group it hears about (relays track metadata only), so
updates can cross non-member relays and anti-entropy works across them.
"""

from __future__ import annotations

import random
import time
from typing import Any, Callable

from crypto.encoding import EncodingError, b64d, b64e, membership_hash, update_id as compute_update_id, validate_id
from crypto.engine import CryptoEngine, get_engine
from crypto.key_agreement import KeyUnwrapError
from crypto.symmetric import assign_sender_prefix
from node.logger import EventLogger
from node.messaging import (
    ERR_EPOCH_GAP,
    ERR_EPOCH_STALE,
    ERR_GROUP_EXISTS,
    ERR_IDENTITY_UNKNOWN,
    ERR_INVALID_PARAMS,
    ERR_MALFORMED,
    ERR_SIG_INVALID,
    ERR_UNAUTHORIZED,
    ERR_UNKNOWN_GROUP,
    EV_ADMIN_DOUBLE_SIGN,
    PROTOCOL_VERSION,
    Outbox,
    ProtocolError,
    new_id,
    validate_frame,
)
from node.state import ADMIN, REMOVED, GroupState, NodeState

DEFAULT_FANOUT = 3
BUNDLE_LIMIT = 64
MAX_PENDING_UPDATES = 128
REQUEST_RATE_LIMIT = 0.5  # seconds between gap-triggered STATE_REQUESTs per (group, peer)

REJECTION_STATS = {
    ERR_SIG_INVALID: "signature_failures",
    ERR_UNAUTHORIZED: "unauthorized_updates",
    ERR_IDENTITY_UNKNOWN: "unknown_identity",
    ERR_MALFORMED: "malformed_updates",
}


class GossipEngine:
    def __init__(
        self,
        state: NodeState,
        outbox: Outbox,
        logger: EventLogger,
        fanout: int = DEFAULT_FANOUT,
        rng: random.Random | None = None,
        engine: CryptoEngine | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.state = state
        self.outbox = outbox
        self.logger = logger
        self.fanout = fanout
        self.rng = rng or random.Random()
        self.engine = engine or get_engine()
        self.clock = clock
        self.pending: dict[str, dict[int, tuple[dict, str | None]]] = {}
        self.listeners: list[Callable[[str, int], None]] = []
        self._last_request: dict[tuple[str, str], float] = {}

    @property
    def me(self) -> str:
        return self.state.node_id

    # ------------------------------------------------------------------
    # Building signed updates
    # ------------------------------------------------------------------
    def build_update(
        self,
        group_id: str,
        new_epoch: int,
        action: str,
        target: str | None,
        members: dict[str, str],
        admin_id: str | None = None,
        signer=None,
        group_key: bytes | None = None,
    ) -> tuple[dict, bytes]:
        admin_id = admin_id or self.me
        signer = signer or self.state.identity
        group_key = group_key or self.engine.new_group_key()
        members = dict(sorted(members.items()))
        recipients = {m: self.state.roster.x25519(m) for m in members if m != admin_id}
        eph_pub, wrapped = self.engine.wrap_group_key(group_key, recipients, group_id, new_epoch)
        body = {
            "version": PROTOCOL_VERSION,
            "type": "GROUP_UPDATE",
            "group_id": group_id,
            "prev_epoch": new_epoch - 1,
            "new_epoch": new_epoch,
            "action": action,
            "target_member": target,
            "members": members,
            "membership_hash": membership_hash(members),
            "admin_id": admin_id,
            "ephemeral_pubkey": b64e(eph_pub),
            "encrypted_keys": {m: b64e(w) for m, w in sorted(wrapped.items())},
        }
        signature = self.engine.sign_group_update(signer, body)
        body["signature"] = b64e(signature)
        body["update_id"] = compute_update_id(admin_id, group_id, new_epoch, signature)
        return body, group_key

    # ------------------------------------------------------------------
    # Admin (single committer) operations
    # ------------------------------------------------------------------
    def _admin_group(self, group_id: str) -> GroupState:
        g = self.state.groups.get(group_id)
        if g is None:
            raise ProtocolError(ERR_UNKNOWN_GROUP, group_id)
        if g.admin_id != self.me or g.status != ADMIN:
            raise ProtocolError(ERR_UNAUTHORIZED, f"{self.me} is not the admin of {group_id}")
        return g

    def create_group(self, group_id: str) -> dict:
        try:
            validate_id(group_id, "group_id")
        except EncodingError as exc:
            raise ProtocolError(ERR_INVALID_PARAMS, str(exc)) from exc
        if group_id in self.state.groups:
            raise ProtocolError(ERR_GROUP_EXISTS, f"group {group_id} already exists")
        members = {self.me: assign_sender_prefix(group_id, self.me, set()).hex()}
        return self._commit(group_id, 1, "CREATE_GROUP", self.me, members)

    def add_member(self, group_id: str, member: str) -> dict:
        g = self._admin_group(group_id)
        if member not in self.state.roster:
            raise ProtocolError(ERR_IDENTITY_UNKNOWN, f"{member} is not in the roster")
        if member in g.members:
            raise ProtocolError(ERR_INVALID_PARAMS, f"{member} is already a member of {group_id}")
        taken = {bytes.fromhex(p) for p in g.members.values()}
        members = dict(g.members)
        members[member] = assign_sender_prefix(group_id, member, taken).hex()
        return self._commit(group_id, g.epoch + 1, "ADD_MEMBER", member, members)

    def remove_member(self, group_id: str, member: str) -> dict:
        g = self._admin_group(group_id)
        if member == self.me:
            raise ProtocolError(ERR_INVALID_PARAMS, "the admin cannot remove itself (admin handover is future work)")
        if member not in g.members:
            raise ProtocolError(ERR_INVALID_PARAMS, f"{member} is not a member of {group_id}")
        members = {m: p for m, p in g.members.items() if m != member}
        return self._commit(group_id, g.epoch + 1, "REMOVE_MEMBER", member, members)

    def rekey(self, group_id: str) -> dict:
        g = self._admin_group(group_id)
        return self._commit(group_id, g.epoch + 1, "REKEY", None, dict(g.members))

    def _commit(self, group_id: str, new_epoch: int, action: str, target: str | None, members: dict) -> dict:
        update, key = self.build_update(group_id, new_epoch, action, target, members)
        g = self.state.groups.get(group_id)
        if g is None:
            g = self.state.groups[group_id] = GroupState(group_id, admin_id=self.me)
        g.install_epoch(new_epoch, update["members"], update["membership_hash"], update["update_id"], self.me, key, self.me)
        self.state.seen_updates.add(update["update_id"])
        self.state.update_log(group_id).append(update)
        self.state.save()
        self.state.captured["GROUP_UPDATE"].append(update)
        self.logger.log(
            "UPDATE_COMMITTED",
            group_id=group_id,
            epoch=new_epoch,
            update_id=update["update_id"],
            action=action,
            target=target,
            members=sorted(members),
        )
        self.logger.log(
            "EPOCH_INSTALLED", group_id=group_id, epoch=new_epoch, update_id=update["update_id"], role=ADMIN, via="commit"
        )
        self._notify(group_id, new_epoch)
        self._forward(update, exclude=None, origin=True)
        return update

    # ------------------------------------------------------------------
    # Receive pipeline (§6.1)
    # ------------------------------------------------------------------
    def handle_group_update(
        self, update: dict, from_peer: str | None = None, via: str = "gossip", allow_snapshot: bool = False
    ) -> str:
        try:
            if validate_frame(update) != "GROUP_UPDATE":
                raise ProtocolError(ERR_MALFORMED, "not a GROUP_UPDATE")
            uid = compute_update_id(update["admin_id"], update["group_id"], update["new_epoch"], b64d(update["signature"]))
        except (ProtocolError, EncodingError) as exc:
            return self._rejected(update, getattr(exc, "code", ERR_MALFORMED), str(exc), from_peer)
        if uid != update["update_id"]:
            return self._rejected(update, ERR_MALFORMED, "update_id does not match its derivation", from_peer)

        # 1. de-duplication (identical update_id => identical signed content)
        if uid in self.state.seen_updates:
            self.state.stats["duplicates_dropped"] += 1
            self.logger.log("UPDATE_DUPLICATE", code="ERR_REPLAY", update_id=uid, group_id=update["group_id"], from_peer=from_peer, via=via)
            return "DUPLICATE"

        # 2. authenticate against the pinned roster / pinned group admin
        error = self._authenticate(update)
        if error:
            return self._rejected(update, error[0], error[1], from_peer)

        gid, new_epoch = update["group_id"], update["new_epoch"]
        g = self.state.groups.get(gid)
        local = g.epoch if g else 0

        # 3. stale epoch (and fork evidence: a *different* valid update for an installed epoch)
        if new_epoch <= local:
            installed = g.installed.get(new_epoch)
            self.state.seen_updates.add(uid)
            if installed is not None and installed != uid:
                self._double_sign(gid, new_epoch, installed, update, from_peer)
                self.state.save_gossip()
                self._forward(update, exclude=from_peer)
                return "DOUBLE_SIGN"
            self.state.stats["stale_updates"] += 1
            self.logger.log("UPDATE_REJECTED", code=ERR_EPOCH_STALE, update_id=uid, group_id=gid, epoch=new_epoch, local_epoch=local, from_peer=from_peer)
            return ERR_EPOCH_STALE

        # 4. future epoch: buffer + STATE_REQUEST (or snapshot from a truncated bundle)
        if new_epoch > local + 1 and not allow_snapshot:
            buffered = self.pending.setdefault(gid, {})
            existing = buffered.get(new_epoch)
            if existing and existing[0]["update_id"] != uid:
                self._double_sign(gid, new_epoch, existing[0]["update_id"], update, from_peer, first=existing[0])
                self.state.seen_updates.add(uid)
                return "DOUBLE_SIGN"
            if existing is None and len(buffered) < MAX_PENDING_UPDATES:
                buffered[new_epoch] = (update, from_peer)
            self.state.stats["epoch_gaps"] += 1
            self.logger.log("UPDATE_BUFFERED", code=ERR_EPOCH_GAP, update_id=uid, group_id=gid, epoch=new_epoch, local_epoch=local, from_peer=from_peer)
            self.request_resync(gid, from_peer, from_epoch=local)
            return "BUFFERED"

        # 5/6. apply (install key, rotate grace window, persist), 7. forward
        self._apply(update, via=via, snapshot=new_epoch > local + 1)
        self._forward(update, exclude=from_peer)
        self._drain_pending(gid)
        return "APPLIED"

    def _rejected(self, update: Any, code: str, reason: str, from_peer: str | None) -> str:
        self.state.stats[REJECTION_STATS.get(code, "malformed_updates")] += 1
        info = update if isinstance(update, dict) else {}
        self.logger.log(
            "UPDATE_REJECTED",
            code=code,
            reason=reason,
            update_id=info.get("update_id"),
            group_id=info.get("group_id"),
            admin_id=info.get("admin_id"),
            epoch=info.get("new_epoch"),
            from_peer=from_peer,
        )
        return code

    def _authenticate(self, u: dict) -> tuple[str, str] | None:
        admin, gid = u["admin_id"], u["group_id"]
        if admin not in self.state.roster:
            return ERR_IDENTITY_UNKNOWN, f"admin {admin} not in roster"
        g = self.state.groups.get(gid)
        if g is not None and g.admin_id != admin:
            return ERR_UNAUTHORIZED, f"{admin} is not the pinned admin ({g.admin_id}) of {gid}"
        if not self.engine.verify_group_update(self.state.roster.ed25519(admin), b64d(u["signature"]), u):
            return ERR_SIG_INVALID, f"signature does not verify under {admin}'s pinned key"
        # Semantic checks on authenticated content (an admin bug must not break nonce uniqueness).
        members = u["members"]
        if admin not in members:
            return ERR_MALFORMED, "admin missing from member map"
        if any(m not in self.state.roster for m in members):
            return ERR_MALFORMED, "member not in roster"
        if len(set(members.values())) != len(members):
            return ERR_MALFORMED, "duplicate sender prefixes"
        if membership_hash(members) != u["membership_hash"]:
            return ERR_MALFORMED, "membership_hash mismatch"
        if set(u["encrypted_keys"]) != set(members) - {admin}:
            return ERR_MALFORMED, "encrypted_keys must cover exactly the non-admin members"
        if u["action"] == "CREATE_GROUP" and u["new_epoch"] != 1:
            return ERR_MALFORMED, "CREATE_GROUP must start at epoch 1"
        return None

    def _apply(self, update: dict, via: str, snapshot: bool = False) -> None:
        gid, new_epoch, admin = update["group_id"], update["new_epoch"], update["admin_id"]
        g = self.state.groups.get(gid)
        if g is None:
            g = self.state.groups[gid] = GroupState(gid, admin_id=admin)
        key = None
        if self.me in update["members"] and self.me != admin:
            try:
                key = self.engine.unwrap_group_key(
                    self.state.kex,
                    b64d(update["ephemeral_pubkey"]),
                    b64d(update["encrypted_keys"][self.me]),
                    gid,
                    new_epoch,
                )
            except (KeyUnwrapError, EncodingError) as exc:
                self.state.stats["key_unwrap_failures"] += 1
                self.logger.log("KEY_UNWRAP_FAIL", code="ERR_KEY_UNWRAP", group_id=gid, epoch=new_epoch, reason=str(exc))
        was_member = g.is_member
        g.install_epoch(
            new_epoch, update["members"], update["membership_hash"], update["update_id"], admin, key, self.me, snapshot
        )
        self.state.seen_updates.add(update["update_id"])
        self.state.update_log(gid).append(update)
        self.state.save()
        self.logger.log(
            "EPOCH_INSTALLED",
            group_id=gid,
            epoch=new_epoch,
            update_id=update["update_id"],
            action=update["action"],
            target=update["target_member"],
            role=g.status,
            via=via,
            snapshot=snapshot,
            has_key=key is not None,
        )
        if was_member and g.status == REMOVED:
            self.logger.log("MEMBER_REMOVED", group_id=gid, epoch=new_epoch)
        self._notify(gid, new_epoch)

    def _drain_pending(self, gid: str) -> None:
        buffered = self.pending.get(gid)
        if not buffered:
            return
        g = self.state.groups[gid]
        for epoch in [e for e in buffered if e <= g.epoch]:
            del buffered[epoch]
        nxt = buffered.pop(g.epoch + 1, None)
        if nxt is not None:
            self.handle_group_update(nxt[0], nxt[1], via="buffer")

    def _notify(self, gid: str, epoch: int) -> None:
        for listener in self.listeners:
            listener(gid, epoch)

    def _double_sign(self, gid: str, epoch: int, kept_id: str, conflicting: dict, from_peer, first: dict | None = None) -> None:
        if first is None:
            first = next((u for u in self.state.update_log(gid).by_epoch(epoch) if u["update_id"] == kept_id), None)
        self.state.stats["double_sign_detected"] += 1
        self.logger.log(
            "ADMIN_DOUBLE_SIGN",
            code=EV_ADMIN_DOUBLE_SIGN,
            group_id=gid,
            epoch=epoch,
            admin_id=conflicting["admin_id"],
            kept_update_id=kept_id,
            conflicting_update_id=conflicting["update_id"],
            from_peer=from_peer,
            evidence={"first": first, "second": conflicting},
        )

    def _forward(self, update: dict, exclude: str | None, origin: bool = False) -> list[str]:
        if not origin and self.state.attack_modes.get("suppress"):
            self.state.stats["gossip_suppressed"] += 1
            self.logger.log("GOSSIP_SUPPRESSED", update_id=update["update_id"], group_id=update["group_id"])
            return []
        candidates = sorted(p for p in self.outbox.neighbors() if p != exclude)
        picks = self.rng.sample(candidates, min(self.fanout, len(candidates)))
        for peer in picks:
            if self.outbox.send(peer, update):
                self.state.stats["gossip_propagated"] += 1
        return picks

    # ------------------------------------------------------------------
    # Anti-entropy (§6.2): push-pull digest exchange
    # ------------------------------------------------------------------
    def make_digest(self) -> dict:
        return {
            "version": PROTOCOL_VERSION,
            "type": "STATE_DIGEST",
            "sender_id": self.me,
            "groups": {
                gid: {"epoch": g.epoch, "membership_hash": g.membership_hash, "latest_update_id": g.latest_update_id}
                for gid, g in sorted(self.state.groups.items())
            },
        }

    def anti_entropy_round(self) -> list[str]:
        """One T_a round: send our (small) digest to *every* neighbour.

        A single random neighbour per round (classic anti-entropy) only heals a
        given edge with probability ~1-(1-1/d)^2 per round; exercising every edge
        each round makes "a suppressed/missed update heals within one T_a per hop"
        a guarantee rather than an expectation, at O(degree) tiny frames per T_a.
        """
        neighbors = sorted(self.outbox.neighbors())
        if not neighbors:
            return []
        digest = self.make_digest()
        for peer in neighbors:
            self.outbox.send(peer, digest)
        self.state.stats["resync_rounds"] += 1
        return neighbors

    def handle_digest(self, frame: dict, from_peer: str | None) -> str:
        peer = from_peer or frame["sender_id"]
        theirs = frame["groups"]
        actions = 0
        for gid in sorted(set(theirs) | set(self.state.groups)):
            t = theirs.get(gid)
            g = self.state.groups.get(gid)
            t_epoch = t["epoch"] if t else 0
            mine = g.epoch if g else 0
            if t_epoch > mine:  # we are behind: pull
                self.request_resync(gid, peer, from_epoch=mine, force=True)
                actions += 1
            elif t_epoch < mine:  # they are behind: push
                actions += self._send_bundle(gid, peer, from_epoch=t_epoch)
            elif g is not None and t is not None and t.get("latest_update_id") != g.latest_update_id:
                # Same epoch, different update: exchange both versions (fork evidence, §6.3).
                self.request_resync(gid, peer, from_epoch=mine - 1, force=True)
                actions += 1 + self._send_bundle(gid, peer, from_epoch=mine - 1)
        return "DIGEST_HANDLED" if actions else "IN_SYNC"

    def request_resync(self, gid: str, peer: str | None, from_epoch: int | None = None, force: bool = False) -> bool:
        neighbors = sorted(self.outbox.neighbors())
        if peer is None or peer not in neighbors:
            if not neighbors:
                return False
            peer = self.rng.choice(neighbors)
        now = self.clock()
        if not force and now - self._last_request.get((gid, peer), float("-inf")) < REQUEST_RATE_LIMIT:
            return False
        self._last_request[(gid, peer)] = now
        g = self.state.groups.get(gid)
        if from_epoch is None:
            from_epoch = g.epoch if g else 0
        known = [g.installed[e] for e in sorted(g.installed)[-16:]] if g else []
        frame = {
            "version": PROTOCOL_VERSION,
            "type": "STATE_REQUEST",
            "req_id": new_id("req"),
            "sender_id": self.me,
            "group_id": gid,
            "from_epoch": max(0, from_epoch),
            "known_update_ids": known,
        }
        self.state.stats["resync_requests"] += 1
        return self.outbox.send(peer, frame)

    def handle_state_request(self, frame: dict, from_peer: str | None) -> str:
        peer = from_peer or frame["sender_id"]
        sent = self._send_bundle(
            frame["group_id"], peer, frame["from_epoch"], exclude=set(frame.get("known_update_ids", [])), req_id=frame["req_id"]
        )
        return "BUNDLE_SENT" if sent else "NOTHING_TO_SEND"

    def _send_bundle(self, gid: str, peer: str, from_epoch: int, exclude: set[str] | None = None, req_id: str | None = None) -> int:
        log = self.state.update_logs.get(gid)
        if not log:
            return 0
        updates = log.since(from_epoch, BUNDLE_LIMIT, exclude)
        g = self.state.groups.get(gid)
        latest = log.latest()
        if g is not None and g.status == ADMIN and latest is not None and latest["new_epoch"] > from_epoch:
            if all(u["update_id"] != latest["update_id"] for u in updates):
                updates.append(latest)  # Admin republishes its current update (§6.2)
        if not updates:
            return 0
        oldest = log.oldest_epoch()
        frame = {
            "version": PROTOCOL_VERSION,
            "type": "STATE_BUNDLE",
            "req_id": req_id or new_id("push"),
            "sender_id": self.me,
            "group_id": gid,
            "from_epoch": max(0, from_epoch),
            "truncated": oldest is not None and oldest > from_epoch + 1,
            "updates": updates,
        }
        self.state.stats["resync_bundles_sent"] += 1
        return 1 if self.outbox.send(peer, frame) else 0

    def handle_state_bundle(self, frame: dict, from_peer: str | None) -> str:
        gid = frame["group_id"]
        updates = sorted(
            (u for u in frame["updates"] if isinstance(u, dict) and u.get("group_id") == gid and isinstance(u.get("new_epoch"), int)),
            key=lambda u: u["new_epoch"],
        )
        if not updates:
            return "EMPTY"
        applied = 0
        g = self.state.groups.get(gid)
        local = g.epoch if g else 0
        start = 0
        if frame.get("truncated") and updates[0]["new_epoch"] > local + 1:
            # Responder's log no longer reaches our epoch: every GROUP_UPDATE is a
            # self-contained snapshot (full member map + wraps), so fast-forward
            # instead of wedging at ERR_EPOCH_GAP forever.
            if self.handle_group_update(updates[0], from_peer, via="snapshot", allow_snapshot=True) == "APPLIED":
                applied += 1
            start = 1
        for update in updates[start:]:
            if self.handle_group_update(update, from_peer, via="resync") == "APPLIED":
                applied += 1
        self.state.stats["resync_updates_applied"] += applied
        self.logger.log("RESYNC_BUNDLE", group_id=gid, received=len(updates), applied=applied, from_peer=from_peer)
        return f"APPLIED_{applied}"

    # ------------------------------------------------------------------
    # Attack primitives (node side of simulator/attack_engine.py)
    # ------------------------------------------------------------------
    def forge_update(self, group_id: str, as_admin: str) -> dict:
        """Craft a GROUP_UPDATE claiming ``as_admin`` but signed with *our* key."""
        if as_admin not in self.state.roster:
            raise ProtocolError(ERR_IDENTITY_UNKNOWN, as_admin)
        g = self.state.groups.get(group_id)
        epoch = (g.epoch if g else 0) + 1
        members = dict(g.members) if g and g.members else {}
        members.setdefault(as_admin, assign_sender_prefix(group_id, as_admin, {bytes.fromhex(p) for p in members.values()}).hex())
        members.setdefault(self.me, assign_sender_prefix(group_id, self.me, {bytes.fromhex(p) for p in members.values()}).hex())
        update, _ = self.build_update(group_id, epoch, "REKEY" if epoch > 1 else "CREATE_GROUP", None, members, admin_id=as_admin)
        return update

    def double_sign(self, group_id: str) -> tuple[dict, dict, float]:
        """Hostile admin: two conflicting valid updates for the same next epoch."""
        g = self._admin_group(group_id)
        epoch = g.epoch + 1
        first, key = self.build_update(group_id, epoch, "REKEY", None, dict(g.members))
        second, _ = self.build_update(group_id, epoch, "REKEY", None, dict(g.members))
        g.install_epoch(epoch, first["members"], first["membership_hash"], first["update_id"], self.me, key, self.me)
        for u in (first, second):
            self.state.seen_updates.add(u["update_id"])
        self.state.update_log(group_id).append(first)
        self.state.save()
        self.logger.log("UPDATE_COMMITTED", group_id=group_id, epoch=epoch, update_id=first["update_id"], action="REKEY", target=None, members=sorted(g.members))
        self.logger.log("EPOCH_INSTALLED", group_id=group_id, epoch=epoch, update_id=first["update_id"], role=ADMIN, via="commit")
        self._notify(group_id, epoch)
        self.state.stats["attacks_injected"] += 1
        record = self.logger.log(
            "ATTACK_INJECTED", attack="double_sign", group_id=group_id, epoch=epoch, update_ids=[first["update_id"], second["update_id"]]
        )
        for peer in sorted(self.outbox.neighbors()):
            self.outbox.send(peer, first)
            self.outbox.send(peer, second)
        return first, second, record["ts"]
