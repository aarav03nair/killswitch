"""Contracts 1.4.0 (B3-46, B3-45 option C): read entries tagged view|tool, two versions of one object in a read set
(Panel's B3-41 ruling), RestoreStep.to = None for a culprit-created object, RecoveryPlan.t0_seq_est_literal."""

from __future__ import annotations

import pytest

import ks.contracts as C
from ks.contracts import (OutboxItem, ReadEntry, RecoveryPlan, RestoreStep, TaintSet, VersionRef, ViewEntry,
                          canonical, check_read_set, merge_read_set, value_hash)

import samples as S

H1, H2 = value_hash({"v": 1}), value_hash({"v": 2})


def r(obj, ver, h=H1, src="tool"):
    return ReadEntry(obj=obj, ver=ver, hash=h, source=src)


def test_version_and_exports():
    assert tuple(map(int, C.CONTRACTS_VERSION.split("."))) >= (1, 4, 0)
    assert C.READ_SOURCES == ("view", "tool")
    for n in ("ReadSource", "READ_SOURCES", "check_read_set", "merge_read_set"):
        assert n in C.__all__


def test_source_default_is_omitted_and_view_is_serialized():
    """Additivity (kabir's B3-46 blocker): the default ``tool`` is left out of the canonical form, so a 1.3 read
    entry keeps its exact bytes; an explicit ``view`` is serialized and round-trips."""
    e = ReadEntry(obj="suppliers:S-17", ver=2, hash=H1)
    assert e.source == "tool"
    assert "source" not in e.to_obj()
    legacy = canonical.dumps({"obj": "suppliers:S-17", "ver": 2, "hash": H1})
    assert e.to_canonical() == legacy
    assert ReadEntry.from_canonical(legacy) == e
    v = ReadEntry(obj="suppliers:S-17", ver=2, hash=H1, source="view")
    assert v.to_obj()["source"] == "view"
    assert ReadEntry.from_canonical(v.to_canonical()) == v
    assert v.to_canonical() != legacy
    with pytest.raises(ValueError):
        ReadEntry(obj="suppliers:S-17", ver=2, hash=H1, source="agent")
    # strict canonical parse: an explicit default is not the canonical form
    explicit = canonical.dumps({"obj": "suppliers:S-17", "ver": 2, "hash": H1, "source": "tool"})
    with pytest.raises(canonical.NonCanonicalError):
        ReadEntry.from_canonical(explicit)


def test_additive_fields_nested_and_schema_optional():
    import json
    from ks.contracts.schema_gen import SCHEMA_DIR
    from ks.contracts._base import OMIT_DEFAULT_KEY
    # nested: a record's read_set entries omit the default too (view kept)
    rs = json.loads((SCHEMA_DIR / "c2.record.schema.json").read_text())
    assert "source" not in rs["$defs"]["ReadEntry"]["required"]
    assert {"obj", "ver", "hash"} <= set(rs["$defs"]["ReadEntry"]["required"])
    ps = json.loads((SCHEMA_DIR / "c5.recovery_plan.schema.json").read_text())
    assert "t0_seq_est_literal" not in ps["required"] and "t0_seq_est" in ps["required"]
    assert OMIT_DEFAULT_KEY not in (SCHEMA_DIR / "c2.record.schema.json").read_text()
    lin = (r("suppliers:S-17", 1, src="view"), r("suppliers:S-17", 2))
    objs = [x.to_obj() for x in check_read_set(lin)]
    assert objs[0]["source"] == "view" and "source" not in objs[1]


def test_view_entry_read_entry_is_tagged_view():
    v = ViewEntry(obj="suppliers:S-17", ver=1, hash=value_hash({"a": 1}), value={"a": 1})
    assert v.read_entry().source == "view"


def test_read_set_keeps_both_versions_of_one_object():
    rs = check_read_set((r("suppliers:S-17", 3, H2, "tool"), r("suppliers:S-17", 2, H1, "view")))
    assert [(e.ver, e.source) for e in rs] == [(2, "view"), (3, "tool")]  # sorted by (obj, ver)
    with pytest.raises(ValueError):  # same (obj, ver) twice
        check_read_set((r("suppliers:S-17", 2, H1, "view"), r("suppliers:S-17", 2, H1, "tool")))
    with pytest.raises(ValueError):  # two versions from one source
        check_read_set((r("suppliers:S-17", 2, H1, "tool"), r("suppliers:S-17", 3, H2, "tool")))


def test_record_and_lineage_use_the_rule():
    rec = S.record_exec()
    two = (r("suppliers:S-17", 4, S.H_OLD, "view"), r("suppliers:S-17", 5, S.H_NEW, "tool"))
    rec2 = rec.model_copy(update={"read_set": two})
    assert type(rec).model_validate(rec2.to_obj()).read_set == two
    bad = rec.to_obj()
    bad["read_set"] = [x.to_obj() for x in (r("suppliers:S-17", 4, S.H_OLD), r("suppliers:S-17", 5, S.H_NEW))]
    with pytest.raises(ValueError):
        type(rec).model_validate(bad)
    ob = S.outbox_item().to_obj()
    ob["lineage"] = [x.to_obj() for x in two]
    assert OutboxItem.model_validate(ob).lineage == two


def test_merge_read_set():
    view = (r("suppliers:S-17", 2, H1, "tool"), r("tickets:T-1", 1))  # mis-tagged input is re-tagged by position
    tool = (r("suppliers:S-17", 3, H2, "view"), r("tickets:T-1", 1))
    m = merge_read_set(view, tool)
    assert [(e.obj, e.ver, e.source) for e in m] == [("suppliers:S-17", 2, "view"), ("suppliers:S-17", 3, "tool"),
                                                     ("tickets:T-1", 1, "tool")]  # same version in both -> tool
    with pytest.raises(ValueError):
        merge_read_set((), (r("tickets:T-1", 1), r("tickets:T-1", 2)))
    assert merge_read_set((), ()) == ()


def test_restore_to_absent():
    s = RestoreStep(n=0, reason="tainted_create", obj="invoices:INV-9", expect=VersionRef(ver=1, hash=H1), to=None)
    assert s.to_absent and RestoreStep.from_canonical(s.to_canonical()) == s
    t = RestoreStep(n=0, reason="tainted_write", obj="invoices:INV-9", expect=VersionRef(ver=2, hash=H2),
                    to=VersionRef(ver=1, hash=H1))
    assert not t.to_absent


def _plan(**kw):
    base = dict(plan_id="p-000001", alert_id="a-000001", culprit="crm", t0_seq_est=10, as_of_seq=20,
                taint_set=TaintSet(versions=(), actions=(), outbox_ids=()), steps=(), diff=())
    return RecoveryPlan(**{**base, **kw})


def test_plan_t0_literal():
    p = _plan()
    assert p.t0_seq_est_literal is None and p.t0_delta is None
    q = _plan(t0_seq_est_literal=4)
    assert q.t0_delta == 6 and RecoveryPlan.from_canonical(q.to_canonical()) == q
    assert q.content_hash() != p.content_hash()  # the literal t0 is bound by the approval hash
    with pytest.raises(ValueError):
        _plan(t0_seq_est_literal=11)


def test_plan_literal_none_omitted():
    p = _plan()
    assert "t0_seq_est_literal" not in p.to_obj()
    assert "t0_seq_est_literal" in _plan(t0_seq_est_literal=4).to_obj()
    assert RecoveryPlan.from_canonical(p.to_canonical()) == p
