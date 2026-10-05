"""Crypto primitives, nonce/prefix rules and canonical encoding vectors (zero privilege)."""

from __future__ import annotations

import base64
import hashlib
import struct

import pytest
from cryptography.exceptions import InvalidTag

from crypto import encoding
from crypto.certificate import display_fingerprint, fingerprint, issue_self_signed, verify_certificate
from crypto.engine import CryptoEngine, available_suites
from crypto.identity import GROUP_UPDATE_DOMAIN, IdentityKeypair, group_update_digest
from crypto.key_agreement import KeyAgreementKeypair, KeyUnwrapError, derive_kek, unwrap_group_key, wrap_group_key
from crypto.symmetric import (
    SymmetricGroupCipher,
    assign_sender_prefix,
    derive_sender_prefix,
    generate_group_key,
    key_fingerprint,
)

# ---------------------------------------------------------------- Ed25519 ----


def test_sign_verify_and_reject_altered_payload():
    ident = IdentityKeypair()
    sig = ident.sign(b"payload", GROUP_UPDATE_DOMAIN)
    assert IdentityKeypair.verify(ident.public_bytes(), sig, b"payload", GROUP_UPDATE_DOMAIN)
    assert not IdentityKeypair.verify(ident.public_bytes(), sig, b"payloaD", GROUP_UPDATE_DOMAIN)
    flipped = bytes([sig[0] ^ 1]) + sig[1:]
    assert not IdentityKeypair.verify(ident.public_bytes(), flipped, b"payload", GROUP_UPDATE_DOMAIN)
    other = IdentityKeypair()
    assert not IdentityKeypair.verify(other.public_bytes(), sig, b"payload", GROUP_UPDATE_DOMAIN)


def test_domain_separation_is_enforced():
    ident = IdentityKeypair()
    sig = ident.sign(b"m", "gossip-sim-v1:group-update:v1|")
    assert not IdentityKeypair.verify(ident.public_bytes(), sig, b"m", "gossip-sim-v1:certificate:v1|")
    # The domain is mandatory and must be a well-formed purpose tag.
    for bad in ("", "group-update", "gossip-sim-v1:group-update:v1", "other:x:v1|", None):
        with pytest.raises(ValueError):
            ident.sign(b"m", bad)
    with pytest.raises(TypeError):
        ident.sign(b"m")  # no silent default domain


def test_verify_never_raises_on_garbage_keys():
    assert not IdentityKeypair.verify(b"short", b"\x00" * 64, b"m", GROUP_UPDATE_DOMAIN)
    assert not IdentityKeypair.verify(b"\x00" * 32, b"sig", b"m", GROUP_UPDATE_DOMAIN)


def test_keypair_serialisation_round_trip():
    ident = IdentityKeypair()
    clone = IdentityKeypair.from_private_bytes(ident.private_bytes())
    assert clone.public_bytes() == ident.public_bytes()
    kex = KeyAgreementKeypair()
    assert KeyAgreementKeypair.from_private_bytes(kex.private_bytes()).public_bytes() == kex.public_bytes()


def test_group_update_digest_excludes_signature_and_update_id():
    body = {"group_id": "g", "new_epoch": 2, "members": {"a": "00000001"}}
    with_extras = dict(body, signature="AAAA", update_id="ff" * 32)
    assert group_update_digest(body) == group_update_digest(with_extras)
    assert group_update_digest(body) == hashlib.sha256(encoding.canonical_json(body)).digest()


# --------------------------------------------------------------- AES-GCM ----


def test_nonce_layout_and_counter_rules():
    nonce = SymmetricGroupCipher.build_nonce(b"\x9f\x2c\x11\xa0", 14)
    assert nonce == b"\x9f\x2c\x11\xa0" + struct.pack(">Q", 14)
    assert len(nonce) == 12
    with pytest.raises(ValueError):
        SymmetricGroupCipher.build_nonce(b"\x00" * 4, 0)  # first message carries counter 1
    with pytest.raises(ValueError):
        SymmetricGroupCipher.build_nonce(b"\x00" * 4, 1 << 64)
    with pytest.raises(ValueError):
        SymmetricGroupCipher.build_nonce(b"\x00" * 3, 1)


def test_equal_counters_distinct_nonces_by_assigned_prefix():
    taken: set[bytes] = set()
    prefixes = {}
    for member in ("alice", "bob", "charlie", "dave"):
        prefixes[member] = assign_sender_prefix("quantum-team", member, taken)
        taken.add(prefixes[member])
    nonces = {SymmetricGroupCipher.build_nonce(p, 1) for p in prefixes.values()}
    assert len(nonces) == 4


def test_prefix_collision_retry_uses_salted_derivation():
    first = derive_sender_prefix("g", "bob")
    # Force collisions with the unsalted and first salted candidates.
    taken = {first, derive_sender_prefix("g", "bob", 1)}
    assigned = assign_sender_prefix("g", "bob", taken)
    assert assigned == derive_sender_prefix("g", "bob", 2)
    assert assigned not in taken
    # Unsalted candidate matches the documented preimage (with the "|" delimiter).
    expected = hashlib.sha256(b"gossip-sim-v1:sender-prefix:v1|g|bob").digest()[:4]
    assert first == expected
    assert derive_sender_prefix("g", "bob", 1) == hashlib.sha256(b"gossip-sim-v1:sender-prefix:v1|g|bob|1").digest()[:4]


def test_encrypt_decrypt_and_aad_binding():
    key = generate_group_key()
    prefix = b"\x01\x02\x03\x04"
    nonce, ct = SymmetricGroupCipher.encrypt(key, b"secret", prefix, "grp", 3, "alice", 5)
    assert SymmetricGroupCipher.decrypt(key, nonce, ct, prefix, "grp", 3, "alice", 5) == b"secret"
    for args in (("grp", 4, "alice", 5), ("grp", 3, "bob", 5), ("grx", 3, "alice", 5)):
        with pytest.raises(InvalidTag):
            SymmetricGroupCipher.decrypt(key, nonce, ct, prefix, *args)
    with pytest.raises(ValueError):  # nonce no longer matches prefix||counter
        SymmetricGroupCipher.decrypt(key, nonce, ct, prefix, "grp", 3, "alice", 6)
    tampered = bytes([ct[0] ^ 1]) + ct[1:]
    with pytest.raises(InvalidTag):
        SymmetricGroupCipher.decrypt(key, nonce, tampered, prefix, "grp", 3, "alice", 5)
    with pytest.raises(InvalidTag):
        SymmetricGroupCipher.decrypt(generate_group_key(), nonce, ct, prefix, "grp", 3, "alice", 5)


def test_fresh_keys_are_random_not_chained():
    keys = {generate_group_key() for _ in range(32)}
    assert len(keys) == 32 and all(len(k) == 32 for k in keys)
    assert len(key_fingerprint(next(iter(keys)))) == 8


# ------------------------------------------------------ canonical encodings ----


def test_aad_vector():
    assert SymmetricGroupCipher.build_aad("quantum-team", 7, "alice", 14) == b"v1|quantum-team|7|alice|14"


def test_hkdf_info_vector():
    assert encoding.wrap_info("quantum-team", 8) == b"gossip-sim-v1:gossip-wrap:v1|quantum-team|8"


def test_update_id_vector():
    sig = bytes(range(64))
    expected = hashlib.sha256(
        b"gossip-sim-v1:update-id:v1|alice|quantum-team|7|" + base64.b64encode(sig)
    ).hexdigest()
    assert encoding.update_id("alice", "quantum-team", 7, sig) == expected


def test_membership_hash_vector():
    members = {"dave": "77aa02de", "alice": "9f2c11a0", "bob": "3b7e44c1"}
    expected = hashlib.sha256(b"gossip-sim-v1:membership:v1|alice:9f2c11a0|bob:3b7e44c1|dave:77aa02de").hexdigest()
    assert encoding.membership_hash(members) == expected


def test_fingerprint_vector():
    ed, xk = b"\x11" * 32, b"\x22" * 32
    expected = hashlib.sha256(b"gossip-sim-v1:fingerprint:v1|" + ed + b"|" + xk).hexdigest()
    assert fingerprint(ed, xk) == expected
    assert display_fingerprint(expected).startswith("SHA256:" + expected[:2].upper() + ":")


def test_canonical_json_is_order_and_whitespace_independent():
    a = encoding.canonical_json({"b": 1, "a": {"y": [1, 2], "x": "é"}})
    b = encoding.canonical_json({"a": {"x": "é", "y": [1, 2]}, "b": 1})
    assert a == b == '{"a":{"x":"é","y":[1,2]},"b":1}'.encode("utf-8")
    with pytest.raises(encoding.EncodingError):
        encoding.canonical_json({"t": 1.5})


@pytest.mark.parametrize("bad", ["", "a|b", "a b", "x" * 65, ".", "..", "a:b", None, 7])
def test_identifier_charset_rejects(bad):
    with pytest.raises(encoding.EncodingError):
        encoding.validate_id(bad)


@pytest.mark.parametrize("good", ["alice", "node-1", "a.b_c", "x" * 64])
def test_identifier_charset_accepts(good):
    assert encoding.validate_id(good) == good


def test_preimage_rejects_ambiguous_fields():
    with pytest.raises(encoding.EncodingError):
        encoding.preimage("update-id", "a|b", 1)
    with pytest.raises(encoding.EncodingError):
        encoding.preimage("update-id", -1)


def test_strict_base64():
    assert encoding.b64d(encoding.b64e(b"\x00\xff")) == b"\x00\xff"
    with pytest.raises(encoding.EncodingError):
        encoding.b64d("not base64!!")


# ----------------------------------------------------------------- key wrap ----


def test_wrap_unwrap_round_trip_per_recipient():
    k = generate_group_key()
    bob, dave = KeyAgreementKeypair(), KeyAgreementKeypair()
    eph, wrapped = wrap_group_key(k, {"bob": bob.public_bytes(), "dave": dave.public_bytes()}, "grp", 8)
    assert len(eph) == 32 and set(wrapped) == {"bob", "dave"}
    assert all(len(w) == 40 for w in wrapped.values())  # RFC 3394: n+8 bytes
    assert unwrap_group_key(bob, eph, wrapped["bob"], "grp", 8) == k
    assert unwrap_group_key(dave, eph, wrapped["dave"], "grp", 8) == k
    # A member cannot unwrap a blob addressed to someone else.
    with pytest.raises(KeyUnwrapError):
        unwrap_group_key(bob, eph, wrapped["dave"], "grp", 8)


def test_wrapped_key_tamper_and_context_binding_fail_with_err_key_unwrap():
    k = generate_group_key()
    bob = KeyAgreementKeypair()
    eph, wrapped = wrap_group_key(k, {"bob": bob.public_bytes()}, "grp", 2)
    blob = wrapped["bob"]
    with pytest.raises(KeyUnwrapError) as exc:
        unwrap_group_key(bob, eph, bytes([blob[0] ^ 1]) + blob[1:], "grp", 2)
    assert exc.value.code == "ERR_KEY_UNWRAP"
    with pytest.raises(KeyUnwrapError):
        unwrap_group_key(bob, eph, blob, "grp", 3)  # epoch is bound into the HKDF info
    with pytest.raises(KeyUnwrapError):
        unwrap_group_key(bob, eph, blob, "other", 2)


def test_kek_matches_hkdf_definition():
    ss = b"\x42" * 32
    import hmac

    prk = hmac.new(b"\x00" * 32, ss, hashlib.sha256).digest()  # HKDF-Extract, salt = zeros(HashLen)
    okm = hmac.new(prk, b"gossip-sim-v1:gossip-wrap:v1|g|3" + b"\x01", hashlib.sha256).digest()
    assert derive_kek(ss, "g", 3) == okm


# ---------------------------------------------------------- certificate/engine ----


def test_self_signed_certificate():
    ident, kex = IdentityKeypair(), KeyAgreementKeypair()
    cert = issue_self_signed("alice", ident, kex.public_bytes(), now=1_000_000)
    assert verify_certificate(cert, now=1_000_001)
    assert not verify_certificate(cert, now=999_999)  # before validity window
    cert.node_id = "mallory"
    assert not verify_certificate(cert, now=1_000_001)


def test_engine_facade_registry():
    engine = CryptoEngine()
    assert "gossip-sim-v1" in available_suites()
    assert engine.algorithms["aead"] == "AES-256-GCM"
    with pytest.raises(KeyError):
        CryptoEngine("pqc-unknown")
    ident = IdentityKeypair()
    body = {"version": 1, "group_id": "g", "new_epoch": 1}
    sig = engine.sign_group_update(ident, body)
    assert engine.verify_group_update(ident.public_bytes(), sig, dict(body, update_id="x", signature="y"))
    assert not engine.verify_group_update(ident.public_bytes(), sig, dict(body, new_epoch=2))
