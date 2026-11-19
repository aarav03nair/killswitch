"""Hashing helpers: SHA-256 over domain-tagged canonical bytes.

``H(tag, obj) = sha256(tag + b"\\x00" + canonical.dumps(obj))``, rendered as 64 lowercase hex chars.
The tag separates domains, so the hash (or signature) of one contract type can never be
replayed as another. The same ``tag + 0x00 + canonical`` bytes are what signers sign.

Records hold hashes only. Values, tool args, tool results and unparseable raw input live in
the side store (C3 :class:`~ks.contracts.state.SideEntry`), keyed by these hashes.
Caveat (for SEC-03): a plain hash of a low-entropy value (e.g. an IBAN) can be dictionary-reversed.
Records are pseudonymised, not anonymised; production would use keyed commitments (schema bump).
"""

from __future__ import annotations

import hashlib
from typing import Any

from . import canonical

__all__ = [
    "Domain", "GENESIS_HASH", "TOMBSTONE_HASH", "sha256_hex", "tagged_bytes", "tagged_hash",
    "value_hash", "args_hash", "result_hash", "raw_hash",
]


class Domain:
    """Domain tags (ASCII). One per hashed or signed thing; never reuse a tag for another type."""

    ENVELOPE = b"ks/envelope/v1"
    RECORD = b"ks/record/v1"
    WITNESS = b"ks/witness/v1"
    ALERT = b"ks/alert/v1"
    CONTROL = b"ks/control/v1"
    PLAN = b"ks/plan/v1"
    OUTBOX = b"ks/outbox/v1"
    RUN = b"ks/run/v1"
    VALUE = b"ks/value/v1"
    ARGS = b"ks/args/v1"
    RESULT = b"ks/result/v1"
    RAW = b"ks/raw/v1"
    STATE = b"ks/state/v1"
    IDEM = b"ks/idem/v1"
    FRAME = b"ks/frame/v1"
    SIDE = b"ks/side/v1"
    KEYS = b"ks/keys/v1"


GENESIS_HASH = "0" * 64
"""``prev_hash`` of the record with ``seq == 1``."""


def sha256_hex(data: bytes) -> str:
    """Lowercase hex SHA-256 of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def tagged_bytes(tag: bytes, obj: Any) -> bytes:
    """``tag + 0x00 + canonical(obj)``: the exact bytes that are hashed and signed."""
    return tag + b"\x00" + canonical.dumps(obj)


def tagged_hash(tag: bytes, obj: Any) -> str:
    """sha256 hex of :func:`tagged_bytes`."""
    return sha256_hex(tagged_bytes(tag, obj))


def value_hash(value: Any) -> str:
    """Hash of a state value (a row's JSON value). Deletion writes ``None`` -> :data:`TOMBSTONE_HASH`."""
    return tagged_hash(Domain.VALUE, value)


def args_hash(args: dict[str, Any]) -> str:
    """Hash of an envelope's tool args (OTel ``gen_ai.tool.call.arguments`` is never exported raw)."""
    return tagged_hash(Domain.ARGS, args)


def result_hash(result: Any) -> str:
    """Hash of the tool result returned to the agent (OTel ``gen_ai.tool.call.result``)."""
    return tagged_hash(Domain.RESULT, result)


def raw_hash(raw: bytes) -> str:
    """Hash of raw bytes received on a socket that did not parse as an envelope."""
    return sha256_hex(Domain.RAW + b"\x00" + raw)


TOMBSTONE_HASH = value_hash(None)
"""``after.hash`` of a write that deletes an object."""
