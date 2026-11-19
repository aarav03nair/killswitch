"""ks.rng: the one RNG derivation (ADR-00 M1), ``sha256(canonical([seed, name, tick]))`` per consumer and tick,
so a dropped or diverging step shifts nobody else's later draws. Depends only on ks.contracts: world, agents and
the injector all draw from here, never from ks.runtime."""

from __future__ import annotations

import hashlib

from ks.contracts import canonical

__all__ = ["draw", "draw_hex", "draw_int"]


def draw(seed: int, name: str, tick: int) -> bytes:
    return hashlib.sha256(canonical.dumps([seed, name, tick])).digest()


def draw_hex(seed: int, name: str, tick: int, nbytes: int = 16) -> str:
    return draw(seed, name, tick)[:nbytes].hex()


def draw_int(seed: int, name: str, tick: int, bound: int) -> int:
    return int.from_bytes(draw(seed, name, tick)[:8], "big") % bound
