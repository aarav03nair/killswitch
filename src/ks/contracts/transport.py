"""Transport: JSON lines over Unix sockets. One canonical frame per line (``canonical.dumps_line``).

Gateway socket (per agent connection)::

    gateway -> agent : TickFrame                     (barrier opens tick n)
    agent -> gateway : SubmitFrame | NoopFrame       (exactly one per tick)
    gateway -> agent : ReplyFrame                    (after the tick executes in agent_id order)

Signer socket (ADR-01 may refine): the signer only signs envelope headers for its own principal,
so the agent process never holds key bytes and cannot get other domains signed::

    agent -> signer  : SignRequest{header}  ->  SignReply{sig}

Frames over MAX_FRAME_BYTES, non-canonical or unknown are recorded as ``deny/schema``.
"""

from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import Field, JsonValue, TypeAdapter

from . import canonical
from ._base import Value
from .envelope import Envelope, EnvelopeHeader
from .ids import Hash, RecordId, Seq, Sig, Tick
from .record import Decision, Reason

__all__ = ["MAX_FRAME_BYTES", "TickFrame", "SubmitFrame", "NoopFrame", "ReplyFrame", "SignRequest", "SignReply",
           "Frame", "encode_frame", "decode_frame"]

MAX_FRAME_BYTES = 65536
"""Largest frame accepted, including the LF."""


class TickFrame(Value):
    """Barrier opens tick ``tick``."""

    type: Literal["tick"] = "tick"
    """Frame type."""
    tick: Tick
    """Tick number."""


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
    """Header to sign (``sig`` must be null)."""


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
    """Strictly decode one frame (size, LF, canonical form, known type)."""
    if len(line) > MAX_FRAME_BYTES:
        raise canonical.CanonicalError("frame too large")
    f = _FRAME.validate_python(canonical.loads_line(line))
    if encode_frame(f) != line:
        raise canonical.NonCanonicalError("frame is not canonical")
    return f
