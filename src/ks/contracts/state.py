"""C3 State: object ids, versions, read/write set entries, outbox items, side store, and the state API.

**Object ids (v1.1, B1/X1).** A row object is ``table:pk``. Each ``RunConfig.sensitive_fields`` entry
``table.field`` is its own versioned **field object** ``table:pk.field`` (:func:`field_obj_id`); the rest
of the row stays ``table:pk``. A pk never contains ``.`` (validator on every ``ObjId``), so
:func:`split_obj_id` -> ``(table, pk, field | None)`` is unambiguous. ``OBJ_ID_RE`` is unchanged; the
"no dot in pk" rule is a Python validator (the JSON schema still shows only the pattern). That a
``.field`` suffix names a sensitive field of that table needs the config: ``RunConfig.check_obj``.

**Versions (M11).** Every object has a per-object counter starting at 1; each write creates
``before.ver + 1``. (a) A delete writes a tombstone (value ``null``, hash TOMBSTONE_HASH); a re-create
continues the counter; ``before is None`` iff the object never existed. (b) A restore writes a *new*
version (author ``ks.recovery``); taint keys on ``(obj, ver)``, never on hash. (c) A version written at
seq *s* is visible only to records with seq > *s* (execution is sequential, M2).

**Field objects in writes and reads (X2).** A row value never carries a sensitive key, so each datum
lives in exactly one object; the row's value hash excludes sensitive fields. Actions write only the
objects that changed: a field-only edit does not bump the row. Row create/delete also writes/tombstones
its field objects; a null field is a tombstone. A read records every object it delivered:

* a **whole-row read** (``<table>.read``, an aggregate, a row in ``TickFrame.view``) lists the row **and
  every existing field object of that row** (``RunConfig.field_objs_of``);
* a projection that omits the field lists only the row (e.g. triage's view lists ``suppliers:S-17``,
  not ``suppliers:S-17.iban``);
* any read that returns a sensitive value lists its field object.

**Aggregates enumerate rows (SEC-03 F7).** There is no coarse (``table:*``) or absence read in v1:
an adapter that scans a table lists every row it read (and, per X2, their field objects).

Records carry only (obj, ver, hash); raw values live in the side store, keyed by value hash.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Annotated, Any, Literal, Protocol, runtime_checkable

from pydantic import AfterValidator, Field, JsonValue, Strict, StringConstraints, field_validator, model_validator

from ._base import Document, Value
from .canonical import MAX_SAFE_INT
from .hashing import Domain, raw_hash, tagged_hash, value_hash
from .ids import ActionId, Hash, PrincipalId, Seq, Token

__all__ = [
    "OBJ_ID_RE", "PK_RE", "FIELD_RE", "ObjId", "Version", "make_obj_id", "field_obj_id", "row_obj_id",
    "split_obj_id", "is_field_obj", "ViewEntry", "ObjVer", "VersionRef", "ReadEntry",
    "WriteEntry", "StateRead", "HistoryEntry", "OutboxStatus", "OutboxItem", "SideDomain", "SideEntry",
    "StateView", "StateWriter", "SideStore", "state_digest", "idempotency_key", "OutboxClass",
]

OBJ_ID_RE = r"^[a-z][a-z0-9_]{0,31}:[A-Za-z0-9_.-]{1,128}$"
"""Unchanged since 1.0 (B1). The id grammar is refined by :func:`split_obj_id` (no ``.`` in a pk)."""
TABLE_RE = r"[a-z][a-z0-9_]{0,31}"
PK_RE = r"[A-Za-z0-9_-]{1,128}"
"""A primary key: no ``.`` (X1), so ``table:pk.field`` can never collide with a row id."""
FIELD_RE = r"[a-z][a-z0-9_]{0,63}"
"""A field name, as in ``RunConfig.sensitive_fields`` entries ``table.field``."""

_OBJ = re.compile(OBJ_ID_RE)
_FORM = re.compile(rf"^({TABLE_RE}):({PK_RE})(?:\.({FIELD_RE}))?$")


def split_obj_id(obj: str) -> tuple[str, str, str | None]:
    """``"suppliers:S-17"`` -> ``("suppliers", "S-17", None)``; ``"suppliers:S-17.iban"`` ->
    ``("suppliers", "S-17", "iban")``. Raises ``ValueError`` for anything else (e.g. a dotted pk)."""
    m = _FORM.fullmatch(obj) if isinstance(obj, str) and _OBJ.fullmatch(obj) else None
    if m is None:
        raise ValueError(f"invalid object id {obj!r} (table:pk or table:pk.field; no '.' in pk)")
    return m.group(1), m.group(2), m.group(3)


def _check_obj(obj: str) -> str:
    split_obj_id(obj)
    return obj


ObjId = Annotated[str, StringConstraints(strict=True, pattern=OBJ_ID_RE), AfterValidator(_check_obj)]
"""``table:pk`` (row) or ``table:pk.field`` (sensitive field object), e.g. ``suppliers:S-17``,
``suppliers:S-17.iban``, ``outbox:ob-000042``, ``tickets:T-3``. A pk never contains ``.``."""
Version = Annotated[int, Strict(), Field(ge=1, le=MAX_SAFE_INT)]
"""Per-object version; 1 = created. 0 never appears (absent = ``None``)."""


def make_obj_id(table: str, pk: str) -> str:
    """Build and validate a row id ``table:pk``. A ``.`` in ``pk`` is rejected (X1)."""
    o = f"{table}:{pk}"
    if split_obj_id(o)[2] is not None:
        raise ValueError(f"'.' not allowed in pk {pk!r}")
    return o


def field_obj_id(table: str, pk: str, field: str) -> str:
    """Build and validate a field object id ``table:pk.field`` (only for ``sensitive_fields`` entries)."""
    o = f"{table}:{pk}.{field}"
    t, p, f = split_obj_id(o)
    if (t, p, f) != (table, pk, field):
        raise ValueError(f"invalid field object {o!r}")
    return o


def row_obj_id(obj: str) -> str:
    """The row object of ``obj``: ``suppliers:S-17.iban`` -> ``suppliers:S-17``; a row id maps to itself."""
    t, pk, _ = split_obj_id(obj)
    return f"{t}:{pk}"


def is_field_obj(obj: str) -> bool:
    return split_obj_id(obj)[2] is not None


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


class ViewEntry(Value):
    """One entry of ``TickFrame.view`` (I1): an object version delivered to an agent with its raw value.
    The gateway adds ``read_entry()`` of every delivered entry to the ``read_set`` of whatever that agent
    submits in the same tick. Raw value: transport only, never in a record."""

    obj: ObjId
    """Object delivered (row or field object, per the scenario's per-agent view scope)."""
    ver: Version
    """Version delivered."""
    hash: Hash
    """``value_hash(value)``; checked."""
    value: JsonValue
    """Raw value of that version (a row value never contains sensitive fields)."""

    @model_validator(mode="after")
    def _h(self) -> ViewEntry:
        if self.hash != value_hash(self.value):
            raise ValueError("view entry hash does not match value")
        return self

    def read_entry(self) -> ReadEntry:
        return ReadEntry(obj=self.obj, ver=self.ver, hash=self.hash)


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
    """Earliest tick it may be released: ``created_tick + H`` (H = ``hold_window_ticks``); with an early
    hold (G3), when the lineage holds a sensitive-field version written at tick v,
    ``max(created_tick + H, v + 2H)``. Off at H = 0."""
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
