"""Contracts 1.8.0 (S4-34, ADR-05a §5 amended; Panel jury #2 M8): additive only.

``RevertEntry.to`` may be ``None``: an undo deletes an object a dependent created after the resolution (tombstone,
as ``RestoreStep.to = None`` since 1.4). Every 1.7 ``RevertEntry`` (``to`` a version) parses and hashes as before.
"""

from __future__ import annotations

import pytest

from ks import contracts as C
from ks.contracts import (TOMBSTONE_HASH, ActionRef, NonCanonicalError, RevertEntry, UnresolveStep, VersionRef,
                          canonical)

H = "a" * 64


def _v(ver: int, h: str = H) -> VersionRef:
    return VersionRef(ver=ver, hash=h)


def test_version_and_readme():
    assert tuple(map(int, C.CONTRACTS_VERSION.split("."))) >= (1, 8, 0)
    readme = (C.__file__.rsplit("/", 1)[0] + "/README.md")
    text = open(readme, encoding="utf-8").read()
    assert "### 1.8.0" in text and "`RevertEntry.to` may be `None`" in text


def test_revert_to_none_roundtrip_and_tombstone_hash():
    e = RevertEntry(obj="invoices:INV-0014", expect=_v(1), to=None)
    assert e.to_hash == TOMBSTONE_HASH
    assert RevertEntry.model_validate(canonical.loads(e.to_canonical())) == e
    v = RevertEntry(obj="suppliers:S-22", expect=_v(4), to=_v(3, "b" * 64))
    assert v.to_hash == "b" * 64


def test_17_revert_bytes_unchanged():
    """A 1.7 entry (``to`` a version) keeps its canonical bytes: ``to`` stays a plain object."""
    v = RevertEntry(obj="suppliers:S-22", expect=_v(4), to=_v(3))
    assert canonical.loads(v.to_canonical())["to"] == {"ver": 3, "hash": H}


def test_unresolve_step_with_delete():
    ref = ActionRef(seq=69, agent_id="ks.recovery", action_id="p-000066.1")
    s = UnresolveStep(n=0, reason="resolution_reverted", resolution=ref, resolution_plan_hash=H,
                      reverts=(RevertEntry(obj="suppliers:S-22", expect=_v(4), to=_v(3)),
                               RevertEntry(obj="invoices:INV-0014", expect=_v(1), to=None)),
                      reheld=(), rationale=("resolution_executed",))
    assert s.reverts[1].to is None


def test_missing_to_still_rejected():
    with pytest.raises((ValueError, NonCanonicalError)):
        RevertEntry.model_validate({"obj": "suppliers:S-22", "expect": {"ver": 4, "hash": H}})
