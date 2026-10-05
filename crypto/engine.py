"""Crypto-provider facade.

The gossip and messaging layers only talk to :class:`CryptoEngine`, which resolves
each primitive through a suite registry. A future suite (e.g. ML-KEM wrap plus
ML-DSA signatures) can be registered without touching node code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from crypto import key_agreement, symmetric
from crypto.identity import GROUP_UPDATE_DOMAIN, IdentityKeypair, group_update_digest


@dataclass(frozen=True)
class CryptoSuite:
    name: str
    algorithms: dict[str, str]
    sign: Callable[[IdentityKeypair, bytes, str], bytes]
    verify: Callable[[bytes, bytes, bytes, str], bool]
    new_group_key: Callable[[], bytes]
    wrap: Callable[..., tuple[bytes, dict[str, bytes]]]
    unwrap: Callable[..., bytes]
    encrypt: Callable[..., tuple[bytes, bytes]]
    decrypt: Callable[..., bytes]


CLASSIC_V1 = CryptoSuite(
    name="gossip-sim-v1",
    algorithms={
        "signature": "Ed25519",
        "key_agreement": "X25519",
        "kdf": "HKDF-SHA256",
        "key_wrap": "AES-256-KW",
        "aead": "AES-256-GCM",
        "hash": "SHA-256",
    },
    sign=lambda identity, message, domain: identity.sign(message, domain),
    verify=IdentityKeypair.verify,
    new_group_key=symmetric.generate_group_key,
    wrap=key_agreement.wrap_group_key,
    unwrap=key_agreement.unwrap_group_key,
    encrypt=symmetric.SymmetricGroupCipher.encrypt,
    decrypt=symmetric.SymmetricGroupCipher.decrypt,
)

_REGISTRY: dict[str, CryptoSuite] = {CLASSIC_V1.name: CLASSIC_V1}


def register_suite(suite: CryptoSuite) -> None:
    _REGISTRY[suite.name] = suite


def available_suites() -> list[str]:
    return sorted(_REGISTRY)


class CryptoEngine:
    def __init__(self, suite: str = CLASSIC_V1.name):
        if suite not in _REGISTRY:
            raise KeyError(f"unknown crypto suite {suite!r}")
        self.suite = _REGISTRY[suite]

    @property
    def algorithms(self) -> dict[str, str]:
        return dict(self.suite.algorithms)

    # --- signatures -------------------------------------------------------
    def sign_group_update(self, identity: IdentityKeypair, body: dict) -> bytes:
        return self.suite.sign(identity, group_update_digest(body), GROUP_UPDATE_DOMAIN)

    def verify_group_update(self, public_key: bytes, signature: bytes, body: dict) -> bool:
        return self.suite.verify(public_key, signature, group_update_digest(body), GROUP_UPDATE_DOMAIN)

    # --- group keys -------------------------------------------------------
    def new_group_key(self) -> bytes:
        return self.suite.new_group_key()

    def wrap_group_key(self, group_key: bytes, recipients: dict[str, bytes], group_id: str, epoch: int):
        return self.suite.wrap(group_key, recipients, group_id, epoch)

    def unwrap_group_key(self, recipient, ephemeral_public: bytes, wrapped: bytes, group_id: str, epoch: int):
        return self.suite.unwrap(recipient, ephemeral_public, wrapped, group_id, epoch)

    # --- AEAD ---------------------------------------------------------------
    def encrypt_group(self, key, plaintext, prefix, group_id, epoch, sender_id, counter):
        return self.suite.encrypt(key, plaintext, prefix, group_id, epoch, sender_id, counter)

    def decrypt_group(self, key, nonce, ciphertext, prefix, group_id, epoch, sender_id, counter):
        return self.suite.decrypt(key, nonce, ciphertext, prefix, group_id, epoch, sender_id, counter)


_default: CryptoEngine | None = None


def get_engine() -> CryptoEngine:
    global _default
    if _default is None:
        _default = CryptoEngine()
    return _default
