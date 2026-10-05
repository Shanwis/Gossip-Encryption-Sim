"""Replay, tampering, forgery, double-sign and key-exclusion defenses on real daemons (root)."""

from __future__ import annotations

import shutil
import tempfile
import time

import pytest

from conftest import requires_root
from node.control_server import RPCError
from simulator.attack_engine import AttackEngine
from simulator.orchestrator import Orchestrator

pytestmark = [pytest.mark.root, requires_root]
NODES = ["a", "b", "c", "d"]


def wait_until(predicate, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


@pytest.fixture(scope="module")
def cluster():
    home = tempfile.mkdtemp(prefix="gsa", dir="/tmp")
    orch = Orchestrator(home, ns_prefix="gsa-")
    try:
        orch.init(NODES, "linear")
        orch.start(anti_entropy_interval=0.5, unsafe_nodes={"c"})
        orch.rpc("a", "node.group_create", {"group_id": "g"})
        for member in ("b", "c"):
            orch.rpc("a", "node.group_join", {"group_id": "g", "member": member})
        assert wait_until(lambda: all(orch.inspect(n)["groups"].get("g", {}).get("epoch") == 3 for n in NODES))
        yield orch, AttackEngine(orch)
    finally:
        orch.destroy(purge_logs=True)
        shutil.rmtree(home, ignore_errors=True)


def epoch(orch, node):
    return orch.inspect(node)["groups"]["g"]["epoch"]


def stat(orch, node, key):
    return orch.inspect(node)["stats"][key]


def send_and_wait(orch, text, sender="a", receiver="c"):
    orch.rpc(sender, "node.group_send", {"group_id": "g", "message": text})
    assert wait_until(lambda: any(m["message"] == text for m in orch.inspect(receiver)["inbox"]))


def test_replay_of_group_message_detected(cluster):
    orch, engine = cluster
    send_and_wait(orch, "original")
    received = stat(orch, "c", "group_received")
    result = engine.replay("c", via="b", kind="msg")
    record = engine.wait_for_event("c", "REPLAY_DETECTED", result["ts"] - 0.01, {"msg_id": result["msg_id"]})
    assert record is not None and record["code"] == "ERR_REPLAY"
    assert stat(orch, "c", "group_received") == received  # not re-delivered


def test_replay_of_group_update_rejected(cluster):
    orch, engine = cluster
    before = epoch(orch, "c")
    result = engine.replay("c", via="b", kind="update")
    record = engine.wait_for_event("c", "UPDATE_DUPLICATE", result["ts"] - 0.01, {"update_id": result["update_id"]})
    assert record is not None and record["code"] == "ERR_REPLAY"
    assert epoch(orch, "c") == before


def test_tampered_ciphertext_fails_authentication(cluster):
    orch, engine = cluster
    engine.tamper("b", "c", kind="msg")
    t0 = time.time()
    orch.rpc("a", "node.group_send", {"group_id": "g", "message": "flipped in transit"})
    record = engine.wait_for_event("c", "DECRYPT_FAIL", t0)
    assert record is not None and record["code"] == "ERR_DECRYPT_FAIL"
    assert all(m["message"] != "flipped in transit" for m in orch.inspect("c")["inbox"])
    assert any(m["message"] == "flipped in transit" for m in orch.inspect("b")["inbox"])


def test_tampered_update_signature_rejected_then_healed(cluster):
    orch, engine = cluster
    engine.tamper("b", "c", kind="update")
    t0 = time.time()
    res = orch.rpc("a", "node.group_rekey", {"group_id": "g"})
    record = engine.wait_for_event("c", "UPDATE_REJECTED", t0, {"code": "ERR_SIG_INVALID"})
    assert record is not None
    # Anti-entropy delivers the authentic update afterwards.
    assert wait_until(lambda: epoch(orch, "c") == res["epoch"])


def test_forgery_and_unauthorized_updates(cluster):
    orch, engine = cluster
    before = epoch(orch, "c")
    result = engine.forge("a", "c", via="b")  # b impersonates the admin
    assert engine.wait_for_event("c", "UPDATE_REJECTED", result["ts"] - 0.01, {"code": "ERR_SIG_INVALID"})
    result = engine.forge("b", "c", via="b")  # b signs as itself but is not the admin
    assert engine.wait_for_event("c", "UPDATE_REJECTED", result["ts"] - 0.01, {"code": "ERR_UNAUTHORIZED"})
    assert epoch(orch, "c") == before


def test_compromise_gate_and_removed_member_exclusion(cluster):
    orch, engine = cluster
    with pytest.raises(RPCError) as exc:
        orch.rpc("b", "node.secrets")
    assert exc.value.code == "ERR_UNSAFE_DISABLED"
    report = engine.compromise("c")
    assert "g" in report["impact_radius"]
    # Mitigation: admin removes c + rekeys; c's stolen/stale key cannot read new traffic.
    res = orch.rpc("a", "node.group_leave", {"group_id": "g", "member": "c"})
    assert wait_until(lambda: orch.inspect("c")["groups"]["g"]["epoch"] == res["epoch"])
    assert orch.inspect("c")["groups"]["g"]["role"] == "REMOVED"
    failures = stat(orch, "c", "decryption_failures")
    send_and_wait(orch, "after removal", receiver="b")
    assert wait_until(lambda: stat(orch, "c", "decryption_failures") == failures + 1)
    assert all(m["message"] != "after removal" for m in orch.inspect("c")["inbox"])
    stolen_epochs = report["impact_radius"]["g"]
    assert res["epoch"] not in stolen_epochs


def test_admin_double_sign_detected_everywhere(cluster):
    orch, engine = cluster
    result = engine.double_sign("a", "g")
    for node in ("b", "c", "d"):
        record = engine.wait_for_event(node, "ADMIN_DOUBLE_SIGN", result["ts"] - 0.01)
        assert record is not None, node
        assert record["kept_update_id"] == result["update_ids"][0]
