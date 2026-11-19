"""Signer handle service (ADR-01 §3, E5). Runs inside the gateway; each agent reaches it over its own
path-less socketpair and gets ``SignRequest{header}`` -> ``SignReply{sig}``, nothing else.

A refused request gets no reply: transport has no refusal frame (see SKEL-01 notes), so the agent's
request simply goes unanswered and the barrier deadline turns its slot into a no-op.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ks.contracts import CanonicalError, SignReply, SignRequest, decode_frame, encode_frame, signer_refusal

from .keys import sign_hex

__all__ = ["SignerService"]


class SignerService:
    """Signs envelope headers for the principal bound to each handle, at most ``MAX_SIGN_PER_TICK`` per tick."""

    def __init__(self, keys: dict[str, Ed25519PrivateKey], epoch_of: Callable[[str], int | None]):
        self._keys = dict(keys)
        self._epoch_of = epoch_of
        self._tick = 0
        self._count: Counter[str] = Counter()
        self.refusals: list[tuple[int, str, str]] = []
        """(tick, principal, reason) of every refused request (for the console / tests)."""

    def begin_tick(self, tick: int) -> None:
        self._tick = tick
        self._count.clear()

    def handle(self, principal: str, line: bytes) -> bytes | None:
        """One request line from ``principal``'s handle -> one reply line, or ``None`` (refused/garbage)."""
        try:
            req = decode_frame(line)
        except CanonicalError:
            self.refusals.append((self._tick, principal, "schema"))
            return None
        if not isinstance(req, SignRequest):
            self.refusals.append((self._tick, principal, "schema"))
            return None
        why = signer_refusal(req, principal=principal, current_epoch=self._epoch_of(principal),
                             signed_this_tick=self._count[principal])
        if why is not None:
            self.refusals.append((self._tick, principal, why))
            return None
        self._count[principal] += 1
        return encode_frame(SignReply(sig=sign_hex(self._keys[principal], req.header.signing_bytes())))
