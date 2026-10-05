"""Canonical encodings shared by every hashed, signed or derived value.

Implements docs/protocol.md §3.1: validated identifiers, version-tagged
``|``-delimited preimages and CanonicalJSON (a restricted RFC 8785 profile).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Any

SCHEME = "gossip-sim-v1"
ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class EncodingError(ValueError):
    """Raised when a value violates the canonical encoding rules."""


def validate_id(value: Any, field: str = "identifier") -> str:
    """Validate a node/group/sender identifier against §3.1."""
    if not isinstance(value, str) or not ID_PATTERN.fullmatch(value) or value in (".", ".."):
        raise EncodingError(f"invalid {field}: {value!r} (must match {ID_PATTERN.pattern})")
    return value


def domain_tag(purpose: str, version: int = 1) -> str:
    """Return the version-tagged prefix ``gossip-sim-v1:<purpose>:v<version>|``."""
    return f"{SCHEME}:{purpose}:v{version}|"


def _field(value: Any) -> str:
    if isinstance(value, bool):
        raise EncodingError("booleans are not valid preimage fields")
    if isinstance(value, int):
        if value < 0:
            raise EncodingError("negative integers are not valid preimage fields")
        return str(value)
    if isinstance(value, str):
        if "|" in value:
            raise EncodingError(f"preimage field contains delimiter: {value!r}")
        return value
    raise EncodingError(f"unsupported preimage field type: {type(value).__name__}")


def preimage(purpose: str, *fields: Any, version: int = 1) -> bytes:
    """``"<scheme>:<purpose>:v<n>|" || f1 || "|" || f2 ...`` as UTF-8 bytes."""
    return (domain_tag(purpose, version) + "|".join(_field(f) for f in fields)).encode("utf-8")


def _check_canonical(obj: Any) -> None:
    if isinstance(obj, float):
        raise EncodingError("CanonicalJSON forbids floating point numbers")
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise EncodingError("CanonicalJSON object keys must be strings")
            _check_canonical(value)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _check_canonical(item)
    elif not (obj is None or isinstance(obj, (str, int, bool))):
        raise EncodingError(f"CanonicalJSON cannot encode {type(obj).__name__}")


def canonical_json(obj: Any) -> bytes:
    """CanonicalJSON(X): sorted keys, no whitespace, integers only, minimal escaping.

    Python's code-point key ordering equals UTF-8 byte-lexicographic ordering.
    """
    _check_canonical(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def wire_json(obj: Any) -> bytes:
    """Wire serialisation for data-plane frames: same layout as CanonicalJSON but
    informational floats (e.g. ``timestamp``) are allowed. Signed/hashed content
    always goes through :func:`canonical_json`."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64e(data: bytes) -> str:
    """Standard-alphabet, padded base64 (§3)."""
    return base64.b64encode(data).decode("ascii")


def b64d(text: Any, field: str = "base64 field") -> bytes:
    """Strict base64 decode; raises :class:`EncodingError` on malformed input."""
    if not isinstance(text, str):
        raise EncodingError(f"{field} must be a base64 string")
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise EncodingError(f"{field} is not valid base64") from exc


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def update_id(admin_id: str, group_id: str, new_epoch: int, signature: bytes) -> str:
    """§4.3 ``update_id`` (hex): domain-separated hash over the signature."""
    validate_id(admin_id, "admin_id")
    validate_id(group_id, "group_id")
    return sha256_hex(preimage("update-id", admin_id, group_id, new_epoch, b64e(signature)))


def membership_hash(members: dict[str, str]) -> str:
    """§4.3 ``membership_hash`` over sorted ``node_id:prefix`` entries (hex)."""
    entries = []
    for node_id, prefix in members.items():
        validate_id(node_id, "member id")
        entries.append(f"{node_id}:{prefix}")
    return sha256_hex((domain_tag("membership") + "|".join(sorted(entries))).encode("utf-8"))


def group_aad(group_id: str, epoch: int, sender_id: str, counter: int) -> bytes:
    """§4.2 AAD ``v1|group|epoch|sender|counter``."""
    validate_id(group_id, "group_id")
    validate_id(sender_id, "sender_id")
    return f"v1|{group_id}|{_field(epoch)}|{sender_id}|{_field(counter)}".encode("utf-8")


def wrap_info(group_id: str, epoch: int) -> bytes:
    """§5.1 HKDF ``info`` string for the key-encryption key."""
    validate_id(group_id, "group_id")
    return preimage("gossip-wrap", group_id, epoch)
