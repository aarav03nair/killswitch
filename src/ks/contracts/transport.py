"""Transport: JSON lines over Unix sockets. One canonical frame per line (``canonical.dumps_line``).

Gateway socket (per agent connection)::

    gateway -> agent : TickFrame{tick, epoch, view}  (barrier opens tick n)
    agent -> gateway : SubmitFrame | NoopFrame       (one frame per connection per tick, FIFO)
    gateway -> agent : ReplyFrame                    (after the tick executes in agent_id order)

``TickFrame.epoch`` is the principal's current epoch (``None`` while suspended or revoked), so a released
agent learns its fresh epoch (D3). ``TickFrame.view`` (I1) is the agent's narrow per-agent scope
(<= MAX_VIEW_ENTRIES), snapshotted after the control phase (M2); the delivered entries **join the
read_set** of whatever the agent submits in that tick. A frame for the wrong tick is ``deny/late_frame``.

Signer socket (ADR-01): the signer only signs envelope headers for its own principal, so the agent
process never holds key bytes and cannot get other domains signed::

    agent -> signer  : SignRequest{header}  ->  SignReply{sig}

The signer signs at most MAX_SIGN_PER_TICK headers per tick and refuses (:func:`signer_refusal`, E5):
a header whose ``agent_id`` is not its bound principal, a ``ks.*`` tool, a non-null ``sig``, a stale epoch,
or a suspended/revoked principal. **v1.2 (SKEL-01 finding 3):** a refusal is answered with
``SignRefusal{reason}`` (closed vocabulary :data:`SIGN_REFUSAL_REASONS`: the :func:`signer_refusal` reasons plus
``schema`` for an undecodable request), so the agent no-ops at once instead of waiting out the deadline.
A refusal is not a record (there is no envelope); the console counts refusals::

    agent -> signer  : SignRequest{header}  ->  SignRefusal{reason}

Witness link (v1.2, SKEL-01 finding 2; ADR-00 "Witness cadence", ADR-02 §3): canonical frames on the
path-less gateway<->witness socketpair, decoded with :func:`decode_witness_frame` (a separate union, so a
witness frame is never a valid agent frame and vice versa)::

    gw  -> wit : WitnessInit{key_seed}    null = fresh: the witness generates its own key (E4); repro: derived seed
    wit -> gw  : WitnessPub{pub}
    gw  -> wit : WitnessFiles + SCM_RIGHTS [witness.jsonl O_APPEND fd, witness-heads/ dir fd]
    wit -> gw  : WitnessReady
    gw  -> wit : WitnessHead{seq, head, tick}   once per tick, after the record flush
    wit -> gw  : <WitnessCheckpoint line>       the signed checkpoint (C2) is the ack
    gw  -> wit : WitnessClose

Reading (SEC-03 F8): the gateway reads at most ``MAX_FRAME_BYTES + 1`` bytes per connection per tick and
keeps no read-ahead queue. **Any exception from :func:`decode_frame` is a ``CanonicalError`` and is
recorded as ``deny/schema``**: oversize (then the connection is closed, raw_hash over the prefix),
too deep (``canonical.MAX_DEPTH``), non-canonical, unknown or invalid frames (G7).
"""

from __future__ import annotations

from typing import Annotated, Literal, Union, get_args

from pydantic import Field, JsonValue, TypeAdapter, field_validator

from . import canonical
from ._base import Value
from .envelope import Envelope, EnvelopeHeader
from .hashing import GENESIS_HASH
from .ids import Epoch, Hash, PubKey, RecordId, Seq, Sig, Tick
from .record import Decision, Reason
from .state import ViewEntry, _sorted_unique

__all__ = ["MAX_FRAME_BYTES", "MAX_VIEW_ENTRIES", "MAX_SIGN_PER_TICK", "TickFrame", "SubmitFrame", "NoopFrame",
           "ReplyFrame", "SignRequest", "SignReply", "SignRefusal", "SIGN_REFUSAL_REASONS", "Frame", "encode_frame",
           "decode_frame", "signer_refusal", "WitnessInit", "WitnessPub", "WitnessFiles", "WitnessReady",
           "WitnessHead", "WitnessClose", "WitnessFrame", "decode_witness_frame", "WITNESS_FILES_FDS"]

MAX_FRAME_BYTES = 65536
"""Largest frame accepted, including the LF."""
MAX_VIEW_ENTRIES = 64
"""Most ``ViewEntry`` items in one ``TickFrame.view`` (I1)."""
MAX_SIGN_PER_TICK = 2
"""Most headers a signer handle signs for its principal in one tick (K8, E5)."""


class TickFrame(Value):
    """Barrier opens tick ``tick``."""

    type: Literal["tick"] = "tick"
    """Frame type."""
    tick: Tick
    """Tick number."""
    epoch: Epoch | None
    """Current epoch of the connection's principal; ``None`` while suspended or revoked (D3)."""
    view: tuple[ViewEntry, ...]
    """The agent's view for this tick, sorted by obj, <= MAX_VIEW_ENTRIES; joins the tick's read_set (I1)."""

    @field_validator("view")
    @classmethod
    def _view(cls, v):
        if len(v) > MAX_VIEW_ENTRIES:
            raise ValueError(f"view longer than {MAX_VIEW_ENTRIES}")
        return _sorted_unique(v, lambda e: e.obj, "view obj")


class SubmitFrame(Value):
    """Agent submits one envelope for ``tick``."""

    type: Literal["submit"] = "submit"
    """Frame type."""
    tick: Tick
    """Tick this answers."""
    envelope: Envelope
    """Signed envelope."""


class NoopFrame(Value):
    """Agent has nothing to do this tick."""

    type: Literal["noop"] = "noop"
    """Frame type."""
    tick: Tick
    """Tick this answers."""


class ReplyFrame(Value):
    """Outcome returned to the submitting agent (not recorded; the record has only ``result_hash``)."""

    type: Literal["reply"] = "reply"
    """Frame type."""
    tick: Tick
    """Tick executed."""
    seq: Seq
    """Record seq."""
    record_id: RecordId
    """Record id."""
    decision: Decision
    """exec | deny | hold."""
    reason: Reason
    """Reason code."""
    result: JsonValue
    """Tool result (raw, exec only, else null)."""
    result_hash: Hash | None
    """Equals the record's ``result_hash``."""


class SignRequest(Value):
    """Ask the signer handle to sign an envelope header for its principal."""

    type: Literal["sign"] = "sign"
    """Frame type."""
    header: EnvelopeHeader
    """Header to sign (``sig`` must be null; checked by :func:`signer_refusal`, not here, so the refusal is
    the signer's to report)."""


class SignReply(Value):
    """Signature over ``header.signing_bytes()``."""

    type: Literal["signed"] = "signed"
    """Frame type."""
    sig: Sig
    """Ed25519 signature."""


SignRefusalReason = Literal["foreign_agent", "presigned", "rate", "schema", "stale_epoch", "suspended", "system_tool"]
SIGN_REFUSAL_REASONS: tuple[str, ...] = get_args(SignRefusalReason)
"""Closed vocabulary of :class:`SignRefusal` (v1.2): every :func:`signer_refusal` reason plus ``schema``."""


class SignRefusal(Value):
    """v1.2 (SKEL-01 finding 3): the signer refused the request; the agent should no-op this tick.
    Not a record and not signed; the console counts refusals."""

    type: Literal["sign_refusal"] = "sign_refusal"
    """Frame type."""
    reason: SignRefusalReason
    """One of :data:`SIGN_REFUSAL_REASONS`."""


Frame = Annotated[Union[TickFrame, SubmitFrame, NoopFrame, ReplyFrame, SignRequest, SignReply, SignRefusal],
                  Field(discriminator="type")]
_FRAME = TypeAdapter(Frame)


# -- witness link (v1.2) -------------------------------------------------------------------------------------

WITNESS_FILES_FDS = 2
"""Descriptors passed with :class:`WitnessFiles`: ``witness.jsonl`` (O_APPEND) then the ``witness-heads/`` dir."""


class WitnessInit(Value):
    """gw -> witness, first frame: key material for the witness's own signing key."""

    type: Literal["w.init"] = "w.init"
    """Frame type."""
    key_seed: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$", strict=True)] | None
    """``None`` in fresh mode: the witness generates its own key in memory and the gateway never holds it (E4).
    In repro mode the 32-byte derived seed, hex: repro = the gateway holds every key, including the witness's,
    which is why repro is never anchored (SKEL-01 finding 6)."""


class WitnessPub(Value):
    """witness -> gw: the witness public key (goes into ``keys.json`` before the run dir exists)."""

    type: Literal["w.pub"] = "w.pub"
    """Frame type."""
    pub: PubKey
    """Raw 32-byte Ed25519 public key, hex."""


class WitnessFiles(Value):
    """gw -> witness: carries :data:`WITNESS_FILES_FDS` descriptors by SCM_RIGHTS (``witness.jsonl`` O_APPEND,
    ``witness-heads/`` dir). The witness never opens a run-dir path (SKEL-01 finding 5)."""

    type: Literal["w.files"] = "w.files"
    """Frame type."""


class WitnessReady(Value):
    """witness -> gw: files accepted; the witness is ready for heads."""

    type: Literal["w.ready"] = "w.ready"
    """Frame type."""


class WitnessHead(Value):
    """gw -> witness: one head per tick, after the record flush. The ack is the signed
    :class:`~ks.contracts.record.WitnessCheckpoint` line. The witness never anchors a regressing head
    (tick not increasing, or seq decreasing); the gateway then sees no ack and raises a stall."""

    type: Literal["w.head"] = "w.head"
    """Frame type."""
    seq: Seq
    """Seq of the last flushed record."""
    head: Hash
    """``Record.hash`` at ``seq``."""
    tick: Tick
    """Tick the head closes."""

    @field_validator("head")
    @classmethod
    def _head(cls, v):
        if v == GENESIS_HASH:
            raise ValueError("a witnessed head is a real record hash")
        return v


class WitnessClose(Value):
    """gw -> witness: teardown; the witness closes its files and exits. Teardown writes no records."""

    type: Literal["w.close"] = "w.close"
    """Frame type."""


WitnessFrame = Annotated[Union[WitnessInit, WitnessPub, WitnessFiles, WitnessReady, WitnessHead, WitnessClose],
                         Field(discriminator="type")]
_WITNESS_FRAME = TypeAdapter(WitnessFrame)


def encode_frame(frame: Value) -> bytes:
    """Canonical bytes + LF."""
    data = canonical.dumps_line(frame.to_obj())
    if len(data) > MAX_FRAME_BYTES:
        raise canonical.CanonicalError("frame too large")
    return data


def decode_frame(line: bytes) -> Value:
    """Strictly decode one agent/signer frame (size, LF, depth, canonical form, known type, valid contents).
    Every failure is a :class:`~ks.contracts.canonical.CanonicalError` (gateway: ``deny/schema``)."""
    return _decode(line, _FRAME)


def decode_witness_frame(line: bytes) -> Value:
    """Strictly decode one witness-link frame (same rules as :func:`decode_frame`, :data:`WitnessFrame` union).
    Every failure is a :class:`~ks.contracts.canonical.CanonicalError`."""
    return _decode(line, _WITNESS_FRAME)


def _decode(line: bytes, adapter: TypeAdapter) -> Value:
    if not isinstance(line, (bytes, bytearray)):
        raise canonical.CanonicalError("decode_frame() takes bytes")
    if len(line) > MAX_FRAME_BYTES:
        raise canonical.CanonicalError("frame too large")
    obj = canonical.loads_line(bytes(line))
    try:
        f = adapter.validate_python(obj)
        again = encode_frame(f)
    except canonical.CanonicalError:
        raise
    except Exception as exc:  # ValidationError, RecursionError, ...
        raise canonical.ContractError(f"invalid frame: {exc.__class__.__name__}") from exc
    if again != line:
        raise canonical.NonCanonicalError("frame is not canonical")
    return f


def signer_refusal(req: SignRequest, *, principal: str, current_epoch: int | None, signed_this_tick: int) -> str | None:
    """The signer's refusal rule (E5/K8); ``None`` = sign. ``current_epoch`` is ``None`` while the principal is
    suspended or revoked. Reasons: ``rate``, ``foreign_agent``, ``system_tool``, ``presigned``, ``suspended``,
    ``stale_epoch`` (all in :data:`SIGN_REFUSAL_REASONS`; the signer answers ``SignRefusal{reason}``)."""
    h = req.header
    if signed_this_tick >= MAX_SIGN_PER_TICK:
        return "rate"
    if h.agent_id != principal:
        return "foreign_agent"
    if h.tool.startswith("ks."):
        return "system_tool"
    if h.sig is not None:
        return "presigned"
    if current_epoch is None:
        return "suspended"
    if h.epoch != current_epoch:
        return "stale_epoch"
    return None
