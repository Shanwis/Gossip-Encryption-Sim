"""AES-256-GCM group cipher with admin-assigned (sender prefix || counter) nonces (§4.2)."""

from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto.encoding import group_aad, preimage, sha256, sha256_hex, validate_id

MAX_COUNTER = (1 << 64) - 1


def generate_group_key() -> bytes:
    """K_{e+1} <- CSPRNG(256 bits); never derived from K_e (§5.3)."""
    return os.urandom(32)


def key_fingerprint(key: bytes) -> str:
    """Display fingerprint ``SHA256(K)[:8]`` (8 hex characters)."""
    return sha256_hex(key)[:8]


def derive_sender_prefix(group_id: str, sender_id: str, salt: int = 0) -> bytes:
    """Candidate prefix ``SHA256("...sender-prefix:v1|" group "|" sender ["|" salt])[0:4]``."""
    validate_id(group_id, "group_id")
    validate_id(sender_id, "sender_id")
    fields = [group_id, sender_id] + ([salt] if salt else [])
    return sha256(preimage("sender-prefix", *fields))[:4]


def assign_sender_prefix(group_id: str, sender_id: str, taken: set[bytes], max_salt: int = 1 << 16) -> bytes:
    """Admin-side assignment: first salted candidate not used by a current member."""
    for salt in range(max_salt):
        candidate = derive_sender_prefix(group_id, sender_id, salt)
        if candidate not in taken:
            return candidate
    raise RuntimeError("could not assign a unique sender prefix")


class SymmetricGroupCipher:
    @staticmethod
    def build_nonce(sender_prefix: bytes, counter: int) -> bytes:
        if not isinstance(sender_prefix, (bytes, bytearray)) or len(sender_prefix) != 4:
            raise ValueError("sender prefix must be exactly 4 bytes")
        if not isinstance(counter, int) or isinstance(counter, bool) or not 1 <= counter <= MAX_COUNTER:
            raise ValueError("counter must be an integer in [1, 2^64-1]")
        return bytes(sender_prefix) + struct.pack(">Q", counter)

    @staticmethod
    def build_aad(group_id: str, epoch: int, sender_id: str, counter: int) -> bytes:
        return group_aad(group_id, epoch, sender_id, counter)

    @classmethod
    def encrypt(
        cls,
        group_key: bytes,
        plaintext: bytes,
        sender_prefix: bytes,
        group_id: str,
        epoch: int,
        sender_id: str,
        counter: int,
    ) -> tuple[bytes, bytes]:
        nonce = cls.build_nonce(sender_prefix, counter)
        aad = cls.build_aad(group_id, epoch, sender_id, counter)
        return nonce, AESGCM(group_key).encrypt(nonce, plaintext, aad)

    @classmethod
    def decrypt(
        cls,
        group_key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        sender_prefix: bytes,
        group_id: str,
        epoch: int,
        sender_id: str,
        counter: int,
    ) -> bytes:
        """Raises ``ValueError`` on nonce mismatch, ``cryptography.exceptions.InvalidTag`` on AEAD failure."""
        if nonce != cls.build_nonce(sender_prefix, counter):
            raise ValueError("Nonce does not match sender prefix and counter")
        aad = cls.build_aad(group_id, epoch, sender_id, counter)
        return AESGCM(group_key).decrypt(nonce, ciphertext, aad)
