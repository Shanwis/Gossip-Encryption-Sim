"""Anti-entropy: restart, late join, epoch-gap backfill, suppression and partition healing."""

from __future__ import annotations

import json

from node.state import MEMBER, UpdateLog

NAMES = ["n0", "n1", "n2", "n3", "n4"]


def _group(net, members=NAMES):
    admin = net.nodes["n0"]
    admin.gossip.create_group("g")
    for name in members[1:]:
        admin.gossip.add_member("g", name)
    net.run()
    return admin


def test_restart_recovery_resumes_and_backfills(make_net):
    net = make_net(NAMES)
    admin = _group(net)
    net.stop("n3")
    admin.gossip.rekey("g")
    admin.gossip.rekey("g")
    net.run()
    n3 = net.start("n3")
    assert n3.epoch("g") == 5  # resumes from persisted state, never epoch 0
    assert sorted(n3.group("g").keys) == [4, 5]
    net.anti_entropy(rounds=1)
    assert n3.epoch("g") == 7 and n3.group("g").keys[7] == admin.group("g").keys[7]
    n3.router.send_group("g", "back online")
    net.run()
    assert admin.state.inbox[-1]["message"] == "back online"


def test_late_join_node_converges_via_anti_entropy(make_net):
    net = make_net(NAMES)
    net.stop("n4")  # offline for the whole group formation
    admin = net.nodes["n0"]
    admin.gossip.create_group("g")
    for name in ("n1", "n2", "n3"):
        admin.gossip.add_member("g", name)
    admin.gossip.add_member("g", "n4")  # admitted while offline
    net.run()
    n4 = net.start("n4")
    assert n4.epoch("g") == 0
    net.anti_entropy(rounds=2)
    assert n4.epoch("g") == 5 and n4.group("g").status == MEMBER
    assert sorted(n4.group("g").keys) == [5]  # backward secrecy: no history keys


def test_epoch_gap_backfill_via_state_request(make_net):
    net = make_net(NAMES)
    admin = _group(net)
    n4 = net.nodes["n4"]
    # n4 misses two rumors, then receives the third directly.
    net.drop_filter = lambda s, d, f: d == "n4" and f.get("type") == "GROUP_UPDATE"
    admin.gossip.rekey("g")
    admin.gossip.rekey("g")
    last = admin.gossip.rekey("g")
    net.run()
    net.drop_filter = None
    assert n4.epoch("g") == 5
    assert n4.gossip.handle_group_update(last, "n3") == "BUFFERED"
    net.run()
    assert n4.epoch("g") == 8
    assert [n4.group("g").installed[e] for e in (6, 7, 8)] == [u["update_id"] for u in admin.state.update_log("g").since(5)]
    assert n4.state.stats["resync_updates_applied"] >= 2


def test_gossip_suppression_heals_within_one_round(make_net):
    net = make_net(NAMES)  # linear: n2 is the only path to n3/n4
    admin = _group(net)
    net.nodes["n2"].state.attack_modes["suppress"] = True
    admin.gossip.rekey("g")
    net.run()
    assert net.epochs("g") == {"n0": 6, "n1": 6, "n2": 6, "n3": 5, "n4": 5}
    assert net.nodes["n2"].state.stats["gossip_suppressed"] == 1
    net.anti_entropy(rounds=1)  # one T_a round: every node runs one digest exchange
    assert set(net.epochs("g").values()) == {6}


def test_partition_heal_reconverges(make_net):
    ring = NAMES + []
    edges = list(zip(ring, ring[1:])) + [(ring[-1], ring[0])]
    net = make_net(NAMES, edges=edges)
    admin = _group(net)
    net.cut("n1", "n2")
    net.cut("n3", "n4")  # cut {n0,n1,n4} | {n2,n3}
    for _ in range(3):
        admin.gossip.rekey("g")
    net.run()
    net.anti_entropy(rounds=2)
    assert net.epochs("g")["n2"] == 5 and net.epochs("g")["n3"] == 5
    net.heal()
    net.anti_entropy(rounds=2)
    assert set(net.epochs("g").values()) == {8}


def test_admin_republishes_latest_beyond_bundle_limit(make_net):
    net = make_net(["n0", "n1"])
    admin = _group(net, ["n0", "n1"])
    n1 = net.nodes["n1"]
    net.drop_filter = lambda s, d, f: d == "n1"
    for _ in range(70):  # n1 falls 70 epochs behind (> the 64-update bundle limit)
        admin.gossip.rekey("g")
    net.run()
    net.drop_filter = None
    assert admin.gossip._send_bundle("g", "n1", from_epoch=n1.epoch("g")) == 1
    _, _, data = net.queue[-1]
    epochs = [u["new_epoch"] for u in json.loads(data[4:])["updates"]]
    assert len(epochs) == 65 and epochs[-1] == 72  # oldest 64 + the admin's current update
    net.run()
    assert n1.epoch("g") in range(66, 73)
    net.anti_entropy(rounds=1)
    assert n1.epoch("g") == 72 and n1.group("g").keys[72] == admin.group("g").keys[72]


def test_truncated_log_fast_forwards_instead_of_wedging(make_net):
    net = make_net(["n0", "n1"])
    admin = _group(net, ["n0", "n1"])
    n1 = net.nodes["n1"]
    net.drop_filter = lambda s, d, f: d == "n1"
    for _ in range(6):
        admin.gossip.rekey("g")
    net.run()
    net.drop_filter = None
    # Admin's log only retains the last 2 updates: n1 (epoch 2) cannot be backfilled.
    admin.state.update_logs["g"] = UpdateLog(capacity=2, items=admin.state.update_log("g").to_list())
    assert n1.epoch("g") == 2
    net.anti_entropy(rounds=1)
    assert n1.epoch("g") == 8
    assert n1.group("g").keys.get(8) == admin.group("g").keys[8]
    assert any(e.get("via") == "snapshot" for e in n1.logger.named("EPOCH_INSTALLED"))


def test_fork_detected_by_digest_mismatch(make_net):
    net = make_net(["n0", "n1", "n2"], edges=[("n0", "n1"), ("n0", "n2")])
    admin = _group(net, ["n0", "n1", "n2"])
    g = admin.group("g")
    first, key = admin.gossip.build_update("g", 4, "REKEY", None, dict(g.members))
    second, _ = admin.gossip.build_update("g", 4, "REKEY", None, dict(g.members))
    # Malicious admin shows each side a different epoch-4 update (split brain).
    assert net.nodes["n1"].gossip.handle_group_update(first, None) == "APPLIED"
    assert net.nodes["n2"].gossip.handle_group_update(second, None) == "APPLIED"
    net.queue.clear()
    net.adj["n1"].add("n2")
    net.adj["n2"].add("n1")
    net.nodes["n1"].outbox.send("n2", net.nodes["n1"].gossip.make_digest())
    net.run()
    for name in ("n1", "n2"):
        assert net.nodes[name].state.stats["double_sign_detected"] == 1
    # Each keeps its first-installed state (no flapping).
    assert net.nodes["n1"].group("g").latest_update_id == first["update_id"]
    assert net.nodes["n2"].group("g").latest_update_id == second["update_id"]
