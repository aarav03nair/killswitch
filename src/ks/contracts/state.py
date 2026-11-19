"""C3 State: object ids, versions, read/write set entries, outbox items, side store, and the state API.

Object id is ``table:pk``. Every object has a per-object version counter starting at 1; each write
creates version ``before.ver + 1``. Deletion writes the JSON value ``null`` (hash = TOMBSTONE_HASH).
Records carry only (obj, ver, hash); raw values live in the side store, keyed by value hash.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Annotated, Any, Literal, Protocol, runtime_checkable

from pydantic import Field, JsonValue, Strict, StringConstraints, field_validator, model_validator

from ._base import Document, Value
from .canonical import MAX_SAFE_INT
from .hashing import Domain, raw_hash, tagged_hash
from .ids import ActionId, Hash, PrincipalId, Seq, Token

__all__ = [
    "OBJ_ID_RE", "ObjId", "Version", "make_obj_id", "split_obj_id", "ObjVer", "VersionRef", "ReadEntry",
    "WriteEntry", "StateRead", "HistoryEntry", "OutboxStatus", "OutboxItem", "SideDomain", "SideEntry",
    "StateView", "StateWriter", "SideStore", "state_digest", "idempotency_key", "OutboxClass",
]

OBJ_ID_RE = r"^[a-z][a-z0-9_]{0,31}:[A-Za-z0-9_.-]{1,128}$"
ObjId = Annotated[str, StringConstraints(strict=True, pattern=OBJ_ID_RE)]
"""``table:pk``, e.g. ``suppliers:S-17``, ``outbox:ob-000042``, ``tickets:T-3``."""
Version = Annotated[int, Strict(), Field(ge=1, le=MAX_SAFE_INT)]
"""Per-object version; 1 = created. 0 never appears (absent = ``None``)."""

_OBJ = re.compile(OBJ_ID_RE)


def make_obj_id(table: str, pk: str) -> str:
    """Build and validate a ``table:pk`` object id."""
    o = f"{table}:{pk}"
    if not _OBJ.match(o):
        raise ValueError(f"invalid object id {o!r}")
    return o


def split_obj_id(obj: str) -> tuple[str, str]:
    """``"suppliers:S-17"`` -> ``("suppliers", "S-17")``."""
    if not _OBJ.match(obj):
        raise ValueError(f"invalid object id {obj!r}")
    t, _, pk = obj.partition(":")
    return t, pk


class ObjVer(Value):
    """A specific version of an object (taint sets, evidence)."""

    obj: ObjId
    """Object id ``table:pk``."""
    ver: Version
    """Version of that object."""


class VersionRef(Value):
    """A version plus the hash of its value (no raw value)."""

    ver: Version
    """Version number."""
    hash: Hash
    """``value_hash(value)`` of that version; the value itself is in the side store."""


class ReadEntry(Value):
    """One entry of a read set: what an adapter observed, captured by the gateway (OTel ``ks.read_set``)."""

    obj: ObjId
    """Object read."""
    ver: Version
    """Version read."""
    hash: Hash
    """Value hash of the version read."""


class WriteEntry(Value):
    """One entry of a write set (OTel ``ks.write_set``)."""

    obj: ObjId
    """Object written."""
    before: VersionRef | None
    """Version replaced; ``None`` = object did not exist (create)."""
    after: VersionRef
    """Version created; ``after.hash == TOMBSTONE_HASH`` for a delete."""

    @model_validator(mode="after")
    def _monotonic(self) -> WriteEntry:
        want = 1 if self.before is None else self.before.ver + 1
        if self.after.ver != want:
            raise ValueError(f"after.ver must be {want} (before.ver + 1)")
        return self


def _sorted_unique(items: tuple, key, what: str) -> tuple:
    out = tuple(sorted(items, key=key))
    keys = [key(i) for i in out]
    if len(set(keys)) != len(keys):
        raise ValueError(f"duplicate {what}")
    return out


class StateRead(Value):
    """Result of ``StateView.get``: ``(value, ver, author)``. Holds a RAW value: never put it in a record."""

    obj: ObjId
    """Object id."""
    value: JsonValue
    """Raw current value (``None`` = deleted). Gateway-internal only."""
    ver: Version
    """Current version."""
    author: PrincipalId
    """Principal whose recorded action wrote this version."""
    hash: Hash
    """``value_hash(value)``."""


class HistoryEntry(Value):
    """One element of ``StateView.history(obj)``, oldest first."""

    obj: ObjId
    """Object id."""
    ver: Version
    """Version created."""
    hash: Hash
    """Value hash of that version."""
    author: PrincipalId
    """Principal that wrote it."""
    seq: Seq
    """Record seq of the write."""
    action_id: ActionId
    """Action id from the writing envelope."""


class OutboxStatus(StrEnum):
    """Outbox item lifecycle. We hold, never cancel, in containment; only recovery cancels."""

    QUEUED = "queued"        # waiting out the hold window
    HELD = "held"            # lineage hold or sensitive-field hold
    RELEASED = "released"    # cleared to leave; dispatcher will send it
    DISPATCHED = "dispatched"  # left our boundary: irreversible from here
    CANCELLED = "cancelled"  # recovery cancel_outbox; never leaves


OutboxClass = Literal["I1", "I2"]


def idempotency_key(agent_id: str, action_id: str, sink: str, ordinal: int = 0) -> str:
    """Gateway-derived dedupe key for an outbox effect. A re-run of the same (agent, action)
    derives the same key, so the effect is never sent twice. Agents never choose it (a chosen
    key could collide with an honest agent's and suppress its payment)."""
    return tagged_hash(Domain.IDEM, {"agent_id": agent_id, "action_id": action_id, "sink": sink,
                                     "ordinal": ordinal})


class OutboxItem(Document):
    """C3 value of an ``outbox:<id>`` object: an irreversible effect waiting to leave."""

    CONTRACT = "ks.outbox_item/1"
    DOMAIN = Domain.OUTBOX

    contract: Literal["ks.outbox_item/1"] = "ks.outbox_item/1"
    """Contract id."""
    outbox_id: Annotated[str, StringConstraints(strict=True, pattern=r"^ob-[0-9]{6,16}$")]
    """Gateway-assigned id; the object id is ``outbox:<outbox_id>``."""
    author: PrincipalId
    """Principal whose action created the item (``gen_ai.agent.id``)."""
    action_id: ActionId
    """Creating action."""
    created_seq: Seq
    """Record seq that created the item."""
    sink: Token
    """Destination, e.g. ``payments``, ``email``."""
    action_class: OutboxClass
    """``I1`` (containable) or ``I2`` (needs prior approval). Only I-class effects use the outbox."""
    payload_hash: Hash
    """Value hash of the payload; payload in the side store."""
    idempotency_key: Hash
    """Dedupe key from :func:`idempotency_key`; re-runs dedupe on this, never on nonce."""
    lineage: tuple[ReadEntry, ...]
    """Read set of the creating action (from the record, never agent-declared); drives lineage hold."""
    status: OutboxStatus
    """Lifecycle state."""
    release_tick: Annotated[int, Strict(), Field(ge=0, le=MAX_SAFE_INT)]
    """Earliest tick it may be released (created tick + hold window)."""
    dispatched_seq: Seq | None
    """Record seq of the dispatch; set iff status is dispatched."""

    @field_validator("lineage")
    @classmethod
    def _lin(cls, v):
        return _sorted_unique(v, lambda e: e.obj, "lineage obj")

    @model_validator(mode="after")
    def _disp(self) -> OutboxItem:
        if (self.status == OutboxStatus.DISPATCHED) != (self.dispatched_seq is not None):
            raise ValueError("dispatched_seq is set iff status == dispatched")
        return self

    @property
    def obj_id(self) -> str:
        return f"outbox:{self.outbox_id}"


class SideDomain(StrEnum):
    """What a side-store entry holds; selects the hash function."""

    VALUE = "value"
    ARGS = "args"
    RESULT = "result"
    RAW = "raw"


class SideEntry(Document):
    """A side-store entry: the raw value behind a hash in a record. Redactable (erasure keeps the hash)."""

    CONTRACT = "ks.side_entry/1"
    DOMAIN = Domain.SIDE

    contract: Literal["ks.side_entry/1"] = "ks.side_entry/1"
    """Contract id."""
    hash: Hash
    """The hash records refer to."""
    domain: SideDomain
    """Which hash function produced ``hash``."""
    value: JsonValue
    """Raw value (for ``raw``: lowercase hex of the received bytes). ``None`` once redacted."""
    redacted: bool
    """True after erasure; value is then ``None`` and the hash can no longer be checked."""

    @model_validator(mode="after")
    def _check(self) -> SideEntry:
        if self.redacted:
            if self.value is not None:
                raise ValueError("redacted entry must have value None")
            return self
        if self.hash != self.expected_hash():
            raise ValueError("hash does not match value")
        return self

    def expected_hash(self) -> str:
        if self.domain == SideDomain.RAW:
            if not isinstance(self.value, str) or not re.fullmatch(r"(?:[0-9a-f]{2})*", self.value):
                raise ValueError("raw value must be lowercase hex")
            return raw_hash(bytes.fromhex(self.value))
        tag = {SideDomain.VALUE: Domain.VALUE, SideDomain.ARGS: Domain.ARGS,
               SideDomain.RESULT: Domain.RESULT}[self.domain]
        return tagged_hash(tag, self.value)


def state_digest(heads: Mapping[str, VersionRef]) -> str:
    """Digest of a whole state (obj -> head version). Reconciliation compares fold(record) with live."""
    return tagged_hash(Domain.STATE, [[o, heads[o].ver, heads[o].hash] for o in sorted(heads)])


@runtime_checkable
class StateView(Protocol):
    """Read API of the versioned workspace (ks.state, ADR-05). Implemented by the gateway only."""

    def get(self, obj: str) -> StateRead | None:
        """Current ``(value, ver, author)`` or ``None`` if the object never existed."""

    def history(self, obj: str) -> Sequence[HistoryEntry]:
        """Every version of ``obj``, oldest first."""

    def heads(self) -> Mapping[str, VersionRef]:
        """Current version of every object (reconciliation input)."""


@runtime_checkable
class StateWriter(Protocol):
    """Write API, used only inside the gateway's execution transaction (epoch + deny-list checked there)."""

    def put(self, obj: str, value: Any, *, author: str, seq: int, action_id: str) -> WriteEntry:
        """Write a new version and return the write-set entry (``value=None`` deletes)."""


@runtime_checkable
class SideStore(Protocol):
    """Redactable store of raw values keyed by hash (ks.recorder, ADR-02). Layout in C6."""

    def put(self, domain: SideDomain, value: Any) -> str:
        """Store ``value``, return its hash (idempotent)."""

    def get(self, h: str) -> SideEntry | None:
        """Entry for ``h`` or ``None``."""

    def redact(self, h: str) -> None:
        """Erase the value; keep a redacted entry."""
