"""Signer handle service (ADR-01 §3, E5). Runs inside the gateway; each agent reaches it over its own
path-less socketpair and gets ``SignRequest{header}`` -> ``SignReply{sig}`` or, since contracts 1.2,
``SignRefusal{reason}`` (SKEL-01 finding 3), so a refused agent no-ops at once instead of waiting out the
barrier deadline. A refusal is not a record; ``refusals`` keeps the count for the console.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ks.contracts import (CanonicalError, SignRefusal, SignReply, SignRequest, decode_frame, encode_frame,
                          signer_refusal)

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

    def _refuse(self, principal: str, why: str) -> bytes:
        self.refusals.append((self._tick, principal, why))
        return encode_frame(SignRefusal(reason=why))

    def handle(self, principal: str, line: bytes) -> bytes:
        """One request line from ``principal``'s handle -> one reply line: ``SignReply`` or ``SignRefusal``."""
        try:
            req = decode_frame(line)
        except CanonicalError:
            return self._refuse(principal, "schema")
        if not isinstance(req, SignRequest):
            return self._refuse(principal, "schema")
        why = signer_refusal(req, principal=principal, current_epoch=self._epoch_of(principal),
                             signed_this_tick=self._count[principal])
        if why is not None:
            return self._refuse(principal, why)
        self._count[principal] += 1
        return encode_frame(SignReply(sig=sign_hex(self._keys[principal], req.header.signing_bytes())))
