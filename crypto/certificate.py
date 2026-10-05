"""Self-signed identity metadata and fingerprints (display layer only, protocol §10.4).

The trust anchor is the orchestrator-written ``roster.json``; nothing here is a PKI.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass

from crypto.encoding import b64d, b64e, canonical_json, domain_tag, sha256_hex, validate_id
from crypto.identity import CERTIFICATE_DOMAIN, IdentityKeypair


def fingerprint(ed25519_pub: bytes, x25519_pub: bytes) -> str:
    """``SHA256("gossip-sim-v1:fingerprint:v1|" || ed_pub || "|" || x_pub)`` over raw
    32-byte keys (fixed length, so the delimiter is unambiguous), hex encoded."""
    if len(ed25519_pub) != 32 or len(x25519_pub) != 32:
        raise ValueError("public keys must be 32 bytes")
    return sha256_hex(domain_tag("fingerprint").encode() + ed25519_pub + b"|" + x25519_pub)


def display_fingerprint(fp_hex: str, groups: int = 16) -> str:
    """``SHA256:8D:31:...`` style rendering of the first ``groups`` bytes."""
    pairs = [fp_hex[i : i + 2].upper() for i in range(0, min(len(fp_hex), groups * 2), 2)]
    return "SHA256:" + ":".join(pairs)


@dataclass
class IdentityCertificate:
    node_id: str
    ed25519_pubkey: str
    x25519_pubkey: str
    issuer: str
    not_before: int
    not_after: int
    fingerprint: str
    signature: str = ""

    def body(self) -> dict:
        data = asdict(self)
        data.pop("signature")
        return data

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "IdentityCertificate":
        return cls(**data)


def issue_self_signed(
    node_id: str, identity: IdentityKeypair, x25519_pub: bytes, validity_days: int = 365, now: int | None = None
) -> IdentityCertificate:
    validate_id(node_id, "node_id")
    now = int(time.time()) if now is None else now
    ed_pub = identity.public_bytes()
    cert = IdentityCertificate(
        node_id=node_id,
        ed25519_pubkey=b64e(ed_pub),
        x25519_pubkey=b64e(x25519_pub),
        issuer=node_id,
        not_before=now,
        not_after=now + validity_days * 86400,
        fingerprint=fingerprint(ed_pub, x25519_pub),
    )
    cert.signature = b64e(identity.sign(canonical_json(cert.body()), CERTIFICATE_DOMAIN))
    return cert


def verify_certificate(cert: IdentityCertificate, now: int | None = None) -> bool:
    """Self-signature, fingerprint and validity-window check."""
    now = int(time.time()) if now is None else now
    try:
        ed_pub = b64d(cert.ed25519_pubkey)
        x_pub = b64d(cert.x25519_pubkey)
        if cert.fingerprint != fingerprint(ed_pub, x_pub):
            return False
        if not cert.not_before <= now <= cert.not_after:
            return False
        return IdentityKeypair.verify(ed_pub, b64d(cert.signature), canonical_json(cert.body()), CERTIFICATE_DOMAIN)
    except ValueError:
        return False
