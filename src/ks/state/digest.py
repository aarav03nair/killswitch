"""Reconciliation digest (ADR-02 reconcile, C3 ``state_digest``): fold a record's write sets into heads.

``state_digest(fold(record))`` must equal ``Store.state_digest()`` for a store written only through the
gateway; a mismatch is ``RECONCILE`` (an unmediated write, class U). ``fold`` checks that each write's
``before`` is the previous ``after`` of that object, so a gap or a reordered write set is caught here
rather than silently producing a digest.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ks.contracts import VersionRef, WriteEntry, state_digest

__all__ = ["FoldError", "fold", "fold_digest"]


class FoldError(ValueError):
    """A write set does not chain: ``before`` differs from the folded head of that object."""


def _entries(items: Iterable[Any]) -> Iterable[WriteEntry]:
    for it in items:
        if isinstance(it, WriteEntry):
            yield it
        else:  # a Record (or anything with a write set); non-exec records have an empty write set
            yield from it.write_set


def fold(items: Iterable[Any]) -> dict[str, VersionRef]:
    """Records (in seq order) or ``WriteEntry`` items -> ``{obj: head VersionRef}``, tombstones included."""
    heads: dict[str, VersionRef] = {}
    for w in _entries(items):
        if w.before != heads.get(w.obj):
            raise FoldError(f"{w.obj}: write expects {w.before}, folded head is {heads.get(w.obj)}")
        heads[w.obj] = w.after
    return dict(sorted(heads.items()))


def fold_digest(items: Iterable[Any]) -> str:
    """``state_digest(fold(items))``."""
    return state_digest(fold(items))
