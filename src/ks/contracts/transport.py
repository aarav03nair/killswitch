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
or a suspended/revoked principal.

Reading (SEC-03 F8): the gateway reads at most ``MAX_FRAME_BYTES + 1`` bytes per connection per tick and
keeps no read-ahead queue. **Any exception from :func:`decode_frame` is a ``CanonicalError`` and is
recorded as ``deny/schema``**: oversize (then the connection is closed, raw_hash over the prefix),
too deep (``canonical.MAX_DEPTH``), non-canonical, unknown or invalid frames (G7).
"""

from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import Field, JsonValue, TypeAdapter, field_validator

from . import canonical
from ._base import Value
from .envelope import Envelope, EnvelopeHeader
from .ids import Epoch, Hash, RecordId, Seq, Sig, Tick
from .record import Decision, Reason
from .state import ViewEntry, _sorted_unique

__all__ = ["MAX_FRAME_BYTES", "MAX_VIEW_ENTRIES", "MAX_SIGN_PER_TICK", "TickFrame", "SubmitFrame", "NoopFrame",
           "ReplyFrame", "SignRequest", "SignReply", "Frame", "encode_frame", "decode_frame", "signer_refusal"]

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


Frame = Annotated[Union[TickFrame, SubmitFrame, NoopFrame, ReplyFrame, SignRequest, SignReply],
                  Field(discriminator="type")]
_FRAME = TypeAdapter(Frame)


def encode_frame(frame: Value) -> bytes:
    """Canonical bytes + LF."""
    data = canonical.dumps_line(frame.to_obj())
    if len(data) > MAX_FRAME_BYTES:
        raise canonical.CanonicalError("frame too large")
    return data


def decode_frame(line: bytes) -> Value:
    """Strictly decode one frame (size, LF, depth, canonical form, known type, valid contents).
    Every failure is a :class:`~ks.contracts.canonical.CanonicalError` (gateway: ``deny/schema``)."""
    if not isinstance(line, (bytes, bytearray)):
        raise canonical.CanonicalError("decode_frame() takes bytes")
    if len(line) > MAX_FRAME_BYTES:
        raise canonical.CanonicalError("frame too large")
    obj = canonical.loads_line(bytes(line))
    try:
        f = _FRAME.validate_python(obj)
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
    ``stale_epoch``."""
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
