"""Membership state machine, GROUP_MSG validation pipeline, grace keys, double-sign."""

from __future__ import annotations

import copy

import pytest

from crypto.encoding import b64d, b64e
from crypto.identity import IdentityKeypair
from crypto.symmetric import SymmetricGroupCipher
from node.messaging import ProtocolError
from node.state import ADMIN, MEMBER, OBSERVER, REMOVED, ReplayWindow

NAMES = ["alice", "bob", "charlie", "dave"]


@pytest.fixture
def net(make_net):
    net = make_net(NAMES)
    alice = net.nodes["alice"]
    alice.gossip.create_group("g")
    alice.gossip.add_member("g", "bob")
    alice.gossip.add_member("g", "charlie")
    net.run()
    return net


def test_epoch_advancement_and_roles(net):
    assert net.epochs("g") == {"alice": 3, "bob": 3, "charlie": 3, "dave": 3}
    statuses = {n: net.nodes[n].group("g").status for n in NAMES}
    assert statuses == {"alice": ADMIN, "bob": MEMBER, "charlie": MEMBER, "dave": OBSERVER}
    members = net.nodes["bob"].group("g").members
    assert set(members) == {"alice", "bob", "charlie"}
    assert len(set(members.values())) == 3  # admin-assigned prefixes are unique
    # Everybody agrees on the same key fingerprint; the observer holds no key.
    keys = {n: net.nodes[n].group("g").keys.get(3) for n in ("alice", "bob", "charlie")}
    assert len(set(keys.values())) == 1 and None not in keys.values()
    assert net.nodes["dave"].group("g").keys == {}


def test_grace_window_holds_exactly_current_and_previous(net):
    bob = net.nodes["bob"].group("g")
    assert sorted(bob.keys) == [2, 3]
    k3 = bob.keys[3]
    net.nodes["alice"].gossip.rekey("g")
    net.run()
    assert sorted(bob.keys) == [3, 4] and bob.keys[3] == k3
    net.nodes["alice"].gossip.rekey("g")
    net.run()
    assert sorted(bob.keys) == [4, 5]  # K_{e-2} dropped at install time
    assert bob.keys[5] != bob.keys[4]


def test_grace_epoch_message_still_delivered(make_net):
    net = make_net(NAMES)
    alice, bob = net.nodes["alice"], net.nodes["bob"]
    alice.gossip.create_group("g")
    alice.gossip.add_member("g", "bob")
    alice.gossip.add_member("g", "charlie")
    net.run()
    # charlie sends at epoch 3 but the frame is held back while the rekey lands.
    held = []
    net.drop_filter = lambda s, d, f: f.get("type") == "GROUP_MSG" and held.append((s, d, f)) is None
    net.nodes["charlie"].router.send_group("g", "in flight")
    net.drop_filter = None
    alice.gossip.rekey("g")
    net.run()
    assert bob.epoch("g") == 4
    for src, dst, frame in held:
        if dst == "bob":
            assert bob.router.handle_frame(frame, src) == "DELIVERED"
    assert bob.state.inbox[-1]["message"] == "in flight" and bob.state.inbox[-1]["epoch"] == 3


def test_stale_and_gap_updates(make_net):
    net = make_net(NAMES)
    alice, bob = net.nodes["alice"], net.nodes["bob"]
    alice.gossip.create_group("g")
    u2 = alice.gossip.add_member("g", "bob")
    net.run()
    # Stale: an old valid update whose id was evicted from the seen cache.
    bob.state.seen_updates = type(bob.state.seen_updates)()
    alice.gossip.rekey("g")
    net.run()
    assert bob.gossip.handle_group_update(copy.deepcopy(u2), "alice") == "ERR_EPOCH_STALE"
    # Gap: epoch e+2 arrives first -> buffered + STATE_REQUEST, then backfilled in order.
    net.drop_filter = lambda s, d, f: d == "bob" and f.get("type") == "GROUP_UPDATE"
    u4 = alice.gossip.rekey("g")
    u5 = alice.gossip.rekey("g")
    net.run()
    net.drop_filter = None
    assert bob.epoch("g") == 3
    assert bob.gossip.handle_group_update(copy.deepcopy(u5), "alice") == "BUFFERED"
    assert any(e["code"] == "ERR_EPOCH_GAP" for e in bob.logger.named("UPDATE_BUFFERED"))
    net.run()  # STATE_REQUEST -> STATE_BUNDLE -> u4 applied, buffered u5 drained
    assert bob.epoch("g") == 5
    assert bob.group("g").installed[4] == u4["update_id"] and bob.group("g").installed[5] == u5["update_id"]


def _forged_update(net, signer_name, claim_admin, mutate=None):
    """Rebuild alice's next update but sign it with ``signer_name``'s key."""
    signer = net.keys[signer_name][0]
    gossip = net.nodes[signer_name].gossip
    g = net.nodes["bob"].group("g")
    update, _ = gossip.build_update("g", g.epoch + 1, "REKEY", None, dict(g.members), admin_id=claim_admin, signer=signer)
    if mutate:
        mutate(update)
    return update


def test_authentication_failures(net):
    bob = net.nodes["bob"]
    # Forged under the admin's identity without the admin's key.
    assert bob.gossip.handle_group_update(_forged_update(net, "dave", "alice"), "charlie") == "ERR_SIG_INVALID"
    # Validly signed, but by a node that is not the pinned group admin.
    assert bob.gossip.handle_group_update(_forged_update(net, "charlie", "charlie"), "charlie") == "ERR_UNAUTHORIZED"
    # Unknown admin identity.
    bad = _forged_update(net, "alice", "alice")
    bad["admin_id"] = "mallory"
    assert bob.gossip.handle_group_update(bad, "alice") in ("ERR_MALFORMED", "ERR_IDENTITY_UNKNOWN")
    # Admin-signed but internally inconsistent (duplicate prefixes) -> malformed.
    alice = net.nodes["alice"]
    g = alice.group("g")
    members = dict(g.members)
    members["charlie"] = members["bob"]
    dup, _ = alice.gossip.build_update("g", g.epoch + 1, "REKEY", None, members)
    assert bob.gossip.handle_group_update(dup, "alice") == "ERR_MALFORMED"
    # envelope update_id not matching its derivation -> malformed
    honest = _forged_update(net, "alice", "alice")
    honest["update_id"] = "0" * 64
    assert bob.gossip.handle_group_update(honest, "alice") == "ERR_MALFORMED"
    assert bob.epoch("g") == 3
    assert bob.state.stats["signature_failures"] == 1 and bob.state.stats["unauthorized_updates"] == 1


def test_invalid_update_does_not_poison_seen_cache(net):
    """A tampered copy shares the update_id of the honest one only if the signature
    is intact; rejected updates must never enter the seen set (DoS vector)."""
    alice, bob = net.nodes["alice"], net.nodes["bob"]
    honest, _ = alice.gossip.build_update("g", 4, "REKEY", None, dict(alice.group("g").members))
    tampered = copy.deepcopy(honest)
    tampered["ephemeral_pubkey"] = b64e(bytes(32))
    assert bob.gossip.handle_group_update(tampered, "alice") == "ERR_SIG_INVALID"
    assert bob.gossip.handle_group_update(honest, "alice") == "APPLIED"


def _encrypt(net, node, gid, text, counter=None, prefix=None, sender=None, epoch=None, msg_id="gmsg_custom"):
    g = net.nodes[node].group(gid)
    epoch = epoch or g.epoch
    sender = sender or node
    counter = counter or g.send_counter + 1
    prefix = prefix or bytes.fromhex(g.members[node])
    nonce, ct = SymmetricGroupCipher.encrypt(g.keys[epoch], text.encode(), prefix, gid, epoch, sender, counter)
    return {
        "version": 1, "type": "GROUP_MSG", "msg_id": msg_id, "group_id": gid, "epoch": epoch,
        "sender_id": sender, "counter": counter, "nonce": b64e(nonce), "ciphertext": b64e(ct),
    }  # fmt: skip


def test_group_msg_pipeline_rejections(net):
    bob, charlie = net.nodes["bob"], net.nodes["charlie"]
    # Non-member sender (dave encrypting with a stolen key, claiming his own id).
    frame = _encrypt(net, "alice", "g", "x", sender="dave", msg_id="gmsg_1")
    assert bob.router.handle_frame(frame, "alice") == "ERR_SENDER_NOT_MEMBER"
    # Prefix spoofing: charlie uses bob's prefix.
    bob_prefix = bytes.fromhex(bob.group("g").members["bob"])
    frame = _encrypt(net, "charlie", "g", "x", prefix=bob_prefix, msg_id="gmsg_2")
    assert bob.router.handle_frame(frame, "charlie") == "ERR_PREFIX_MISMATCH"
    # Valid message delivered, then replayed under a fresh msg_id -> sliding window.
    frame = charlie.router.send_group("g", "hello")
    net.run()
    assert bob.state.inbox[-1]["message"] == "hello"
    replay = dict(frame, msg_id="gmsg_replay")
    assert bob.router.handle_frame(replay, "charlie") == "ERR_REPLAY"
    assert bob.state.stats["replays_detected"] == 1
    # Same msg_id is just a relay duplicate (not counted as a replay).
    assert bob.router.handle_frame(dict(frame), "charlie") == "DUPLICATE"
    # Tampered ciphertext -> AEAD failure; envelope counter tamper -> AEAD/nonce failure.
    good = _encrypt(net, "charlie", "g", "t", counter=50, msg_id="gmsg_3")
    raw = bytearray(b64d(good["ciphertext"]))
    raw[0] ^= 1
    assert bob.router.handle_frame(dict(good, ciphertext=b64e(bytes(raw))), "charlie") == "ERR_DECRYPT_FAIL"
    assert bob.router.handle_frame(dict(good, msg_id="gmsg_4", counter=51), "charlie") == "ERR_DECRYPT_FAIL"
    # The untampered original is still accepted (window only advances on success).
    assert bob.router.handle_frame(dict(good, msg_id="gmsg_5"), "charlie") == "DELIVERED"
    # Stale epoch (outside the grace window).
    net.nodes["alice"].gossip.rekey("g")
    net.nodes["alice"].gossip.rekey("g")
    net.run()
    stale = dict(frame, msg_id="gmsg_6")
    assert bob.router.handle_frame(stale, "charlie") == "ERR_EPOCH_STALE"


def test_replay_window_semantics():
    w = ReplayWindow()
    assert not w.check(0)
    for c in (1, 3, 2, 70):
        assert w.check(c)
        w.update(c)
    assert not w.check(70) and not w.check(3)
    assert w.check(10)  # within [70-63, 70] and unseen
    assert not w.check(6)  # 70 - 6 = 64 -> outside the window
    w.update(10)
    assert not w.check(10)
    w.update(500)  # large jump resets the bitmap
    assert w.bitmap == 1 and w.check(499) and not w.check(436)


def test_removed_member_cannot_decrypt_new_epoch(net):
    alice, charlie = net.nodes["alice"], net.nodes["charlie"]
    alice.gossip.remove_member("g", "charlie")
    net.run()
    g = charlie.group("g")
    assert g.status == REMOVED and g.keys == {} and g.epoch == 4
    alice.router.send_group("g", "charlie must not read this")
    net.run()
    assert charlie.state.stats["decryption_failures"] == 1
    assert all(m["message"] != "charlie must not read this" for m in charlie.state.inbox)
    assert net.nodes["bob"].state.inbox[-1]["message"] == "charlie must not read this"
    # A message from the removed member under its stale key is dropped.
    stale = _encrypt(net, "bob", "g", "x", sender="charlie", epoch=3, prefix=bytes.fromhex(alice.group("g").prev_members["charlie"]), msg_id="gmsg_s")
    assert net.nodes["bob"].router.handle_frame(stale, "charlie") == "ERR_SENDER_NOT_MEMBER"


def test_new_member_cannot_read_history(net):
    alice, dave = net.nodes["alice"], net.nodes["dave"]
    old = alice.router.send_group("g", "before dave")
    net.run()
    alice.gossip.add_member("g", "dave")
    net.run()
    assert dave.group("g").status == MEMBER and sorted(dave.group("g").keys) == [4]
    # Captured epoch-3 traffic is undecryptable for dave (no epoch-3 key was ever wrapped for him).
    assert dave.router.handle_frame(dict(old, msg_id="gmsg_hist"), "charlie") in ("ERR_EPOCH_STALE", "ERR_DECRYPT_FAIL")
    assert all(m["message"] != "before dave" for m in dave.state.inbox)


def test_admin_double_sign_detected_first_installed_kept(net):
    alice = net.nodes["alice"]
    first, second, _ = alice.gossip.double_sign("g")
    net.run()
    for name in ("bob", "charlie", "dave"):
        node = net.nodes[name]
        assert node.group("g").installed[4] == first["update_id"], name
        assert node.state.stats["double_sign_detected"] == 1, name
        (event,) = node.logger.named("ADMIN_DOUBLE_SIGN")
        assert event["code"] == "EV_ADMIN_DOUBLE_SIGN"
        assert {event["evidence"]["first"]["update_id"], event["evidence"]["second"]["update_id"]} == {
            first["update_id"],
            second["update_id"],
        }
    # No flapping: replaying the conflicting update again is a plain duplicate.
    assert net.nodes["bob"].gossip.handle_group_update(copy.deepcopy(second), "alice") == "DUPLICATE"


def test_send_counter_is_write_ahead_persisted(net):
    bob = net.nodes["bob"]
    frames = [bob.router.send_group("g", f"m{i}") for i in range(3)]
    net.run()
    bob = net.restart("bob")
    nxt = bob.router.send_group("g", "after restart")
    assert nxt["counter"] == frames[-1]["counter"] + 1  # no nonce reuse across restarts
    assert len({f["nonce"] for f in frames + [nxt]}) == 4


def test_admin_operation_errors(net):
    with pytest.raises(ProtocolError) as exc:
        net.nodes["bob"].gossip.add_member("g", "dave")
    assert exc.value.code == "ERR_UNAUTHORIZED"
    with pytest.raises(ProtocolError) as exc:
        net.nodes["alice"].gossip.remove_member("g", "alice")
    assert exc.value.code == "ERR_INVALID_PARAMS"
    with pytest.raises(ProtocolError) as exc:
        net.nodes["alice"].gossip.create_group("g")
    assert exc.value.code == "ERR_GROUP_EXISTS"
    with pytest.raises(ProtocolError) as exc:
        net.nodes["dave"].router.send_group("g", "x")
    assert exc.value.code == "ERR_NOT_MEMBER"


def test_rejoin_after_removal_restores_membership(net):
    alice, charlie = net.nodes["alice"], net.nodes["charlie"]
    alice.gossip.remove_member("g", "charlie")
    alice.gossip.add_member("g", "charlie")
    net.run()
    assert charlie.group("g").status == MEMBER and charlie.group("g").stale_key is None
    charlie.router.send_group("g", "back")
    net.run()
    assert alice.state.inbox[-1]["message"] == "back"


def test_identity_mismatch_with_roster_is_refused(net):
    state = net.nodes["bob"].state
    with pytest.raises(ValueError):
        type(state)("bob", IdentityKeypair(), state.kex, state.roster)
