"""X25519 + HKDF-SHA256 + RFC 3394 AES-256-KW ephemeral-static key wrap (protocol §5)."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap, aes_key_wrap

from crypto.encoding import wrap_info


class KeyUnwrapError(Exception):
    """AES-KW integrity failure or unusable wrap input (``ERR_KEY_UNWRAP``)."""

    code = "ERR_KEY_UNWRAP"


class KeyAgreementKeypair:
    """Long-term (or ephemeral) X25519 keypair."""

    def __init__(self, private_key: x25519.X25519PrivateKey | None = None):
        self.private_key = private_key or x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "KeyAgreementKeypair":
        return cls(x25519.X25519PrivateKey.from_private_bytes(raw))

    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def exchange(self, peer_public: bytes) -> bytes:
        return self.private_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))


def derive_kek(shared_secret: bytes, group_id: str, epoch: int) -> bytes:
    """KEK = HKDF-Expand(HKDF-Extract(salt=∅, IKM=SS), info, 32)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=wrap_info(group_id, epoch)).derive(
        shared_secret
    )


def wrap_group_key(
    group_key: bytes, recipients: dict[str, bytes], group_id: str, epoch: int
) -> tuple[bytes, dict[str, bytes]]:
    """Wrap ``group_key`` for every recipient X25519 public key.

    Returns ``(ephemeral_public_key, {node_id: wrapped_key})``. The ephemeral
    private key is generated into a ``bytearray`` that is overwritten after use —
    best-effort erasure only, CPython cannot guarantee zeroisation.
    """
    if len(group_key) != 32:
        raise ValueError("group key must be 32 bytes")
    eph_raw = bytearray(os.urandom(32))
    try:
        eph = KeyAgreementKeypair.from_private_bytes(bytes(eph_raw))
        wrapped = {}
        for node_id, pub in sorted(recipients.items()):
            kek = derive_kek(eph.exchange(pub), group_id, epoch)
            wrapped[node_id] = aes_key_wrap(kek, group_key)
        return eph.public_bytes(), wrapped
    finally:
        for i in range(len(eph_raw)):
            eph_raw[i] = 0
        eph = None  # noqa: F841 - drop the reference (best effort)


def unwrap_group_key(
    recipient: KeyAgreementKeypair, ephemeral_public: bytes, wrapped: bytes, group_id: str, epoch: int
) -> bytes:
    """Recipient side of §5.2; raises :class:`KeyUnwrapError` on any failure."""
    try:
        kek = derive_kek(recipient.exchange(ephemeral_public), group_id, epoch)
        key = aes_key_unwrap(kek, wrapped)
    except (InvalidUnwrap, ValueError) as exc:
        raise KeyUnwrapError(str(exc) or "AES-KW unwrap failed") from exc
    if len(key) != 32:
        raise KeyUnwrapError("unwrapped key has wrong length")
    return key
