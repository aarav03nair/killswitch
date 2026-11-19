"""Signer handle service (ADR-01 §3, E5). Runs inside the gateway; each agent reaches it over its own
path-less socketpair and gets ``SignRequest{header}`` -> ``SignReply{sig}`` or, since contracts 1.2,
``SignRefusal{reason}`` (SKEL-01 finding 3), so a refused agent no-ops at once instead of waiting out the
barrier deadline. A refusal is not a record; ``refusals`` keeps only counts for the console (B3-36 M2: never a
list, a flooding handle must not grow gateway memory). Each handle has a per-tick line budget; past it
``handle`` returns ``None`` and the barrier closes the connection.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ks.contracts import (CanonicalError, SignRefusal, SignReply, SignRequest, decode_frame, encode_frame,
                          signer_refusal)

from .keys import sign_hex

__all__ = ["SignerService", "MAX_SIGNER_LINES_PER_TICK"]

MAX_SIGNER_LINES_PER_TICK = 8
"""Request lines one handle may send per tick (signed + refused). An honest agent sends at most
``MAX_SIGN_PER_TICK`` (2); the rest is slack for refusals. Past this the connection is closed (SKEL-01 M2)."""


class SignerService:
    """Signs envelope headers for the principal bound to each handle, at most ``MAX_SIGN_PER_TICK`` per tick."""

    def __init__(self, keys: dict[str, Ed25519PrivateKey], epoch_of: Callable[[str], int | None]):
        self._keys = dict(keys)
        self._epoch_of = epoch_of
        self._tick = 0
        self._count: Counter[str] = Counter()
        self._lines: Counter[str] = Counter()
        self.refusals: Counter[tuple[str, str]] = Counter()
        """(principal, reason) -> how many requests were refused. Counted, never stored (M2)."""
        self.flooded: Counter[str] = Counter()
        """principal -> lines dropped over the per-tick budget."""

    def begin_tick(self, tick: int) -> None:
        self._tick = tick
        self._count.clear()
        self._lines.clear()

    def _refuse(self, principal: str, why: str) -> bytes:
        self.refusals[(principal, why)] += 1
        return encode_frame(SignRefusal(reason=why))

    def charge(self, principal: str) -> bool:
        """Count one signer-socket read that left an unterminated line (a drip) against the per-tick budget.
        ``False`` once over it: the caller closes the connection (B3-42)."""
        self._lines[principal] += 1
        if self._lines[principal] > MAX_SIGNER_LINES_PER_TICK:
            self.flooded[principal] += 1
            return False
        return True

    def handle(self, principal: str, line: bytes) -> bytes | None:
        """One request line from ``principal``'s handle -> one reply line: ``SignReply`` or ``SignRefusal``;
        ``None`` once the handle is over its per-tick line budget (no reply, caller closes the connection)."""
        self._lines[principal] += 1
        if self._lines[principal] > MAX_SIGNER_LINES_PER_TICK:
            self.flooded[principal] += 1
            return None
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
