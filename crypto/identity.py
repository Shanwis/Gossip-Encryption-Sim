"""Ed25519 identities with mandatory domain-separated signatures (protocol §4.3)."""

from __future__ import annotations

import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from crypto.encoding import canonical_json, domain_tag, sha256

DOMAIN_PATTERN = re.compile(r"^gossip-sim-v1:[a-z0-9-]+:v[1-9][0-9]*\|$")

# Registered signing purposes. Callers pass the tag string explicitly.
GROUP_UPDATE_DOMAIN = domain_tag("group-update")
CERTIFICATE_DOMAIN = domain_tag("certificate")


def _check_domain(domain: str) -> bytes:
    if not isinstance(domain, str) or not DOMAIN_PATTERN.fullmatch(domain):
        raise ValueError(f"invalid signature domain tag: {domain!r}")
    return domain.encode("utf-8")


class IdentityKeypair:
    """Long-term Ed25519 identity keypair."""

    def __init__(self, private_key: ed25519.Ed25519PrivateKey | None = None):
        self.private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "IdentityKeypair":
        return cls(ed25519.Ed25519PrivateKey.from_private_bytes(raw))

    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(self, message: bytes, domain: str) -> bytes:
        """Sign ``domain || message``. ``domain`` is mandatory and validated."""
        return self.private_key.sign(_check_domain(domain) + message)

    @staticmethod
    def verify(public_bytes: bytes, signature: bytes, message: bytes, domain: str) -> bool:
        """Verify ``signature`` over ``domain || message``; never raises on bad input."""
        prefix = _check_domain(domain)
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
            pub.verify(signature, prefix + message)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False


def group_update_digest(body: dict) -> bytes:
    """SHA256(CanonicalJSON(update fields except ``signature`` and ``update_id``)).

    ``update_id`` is excluded because it is derived from the signature (§4.3);
    including it would make the signature input depend on its own output.
    """
    unsigned = {k: v for k, v in body.items() if k not in ("signature", "update_id")}
    return sha256(canonical_json(unsigned))
