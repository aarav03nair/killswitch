"""B3-38: rate (soft, per-agent baseline) and tamper (never hard, names nobody, freezes by kind)."""

import pytest
from pydantic import ValidationError

from ks.contracts import (DETECTOR_KIND, HARD_ALLOWED, HARD_DETECTORS, Alert, AlertKind, Detector as D, Record)
from ks.monitor import Monitor

from .world import World, clean_world, hero_world


def scan(w, **kw):
    return Monitor().scan(w.ctx(**kw))


def of(alerts, det):
    return [a for a in alerts if a.detector == det]


def busy(w, agent, tick, n):
    for _ in range(n):
        w.act(agent, "report.run", tick=tick)


# --- rate ---------------------------------------------------------------------------------------------
def test_rate_burst_vs_own_baseline_fires_soft():
    w = clean_world()
    for t in range(50, 56):
        busy(w, "analytics", t, 1)
    busy(w, "analytics", 56, 9)
    w.checkpoint()
    (a,) = of(scan(w), D.RATE)
    assert not a.hard and a.kind == AlertKind.RATE and D.RATE not in HARD_DETECTORS
    assert a.root_candidates == ("analytics",) and len(a.evidence_seqs) == 8 and not a.evidence_versions


def test_rate_steady_busy_agent_is_silent_but_same_volume_from_quiet_agent_fires():
    w = clean_world()
    for t in range(50, 60):
        busy(w, "batch", t, 8)          # always busy: its own baseline
    for t in range(50, 59):
        busy(w, "quiet", t, 1)
    busy(w, "quiet", 59, 8)
    w.checkpoint()
    got = of(scan(w), D.RATE)
    assert [a.root_candidates for a in got] == [("quiet",)]


def test_rate_new_agent_warmup_and_below_min_are_silent():
    w = clean_world()
    busy(w, "newbie", 50, 20)           # first tick: no baseline yet
    busy(w, "small", 50, 1)
    busy(w, "small", 55, 5)             # below rate_min_count
    w.checkpoint()
    assert of(scan(w), D.RATE) == []


def test_rate_never_suspends_and_dedupes():
    w = clean_world()
    busy(w, "analytics", 50, 1)
    busy(w, "analytics", 56, 9)
    m = Monitor()
    assert len(of(m.scan(w.ctx()), D.RATE)) == 1
    assert of(m.scan(w.ctx()), D.RATE) == []
    from ks.monitor import suspect
    a = of(Monitor().scan(w.ctx()), D.RATE)[0]
    assert suspect(a, w.ctx().index) is None


def test_rate_cannot_be_hard():
    w = clean_world()
    busy(w, "analytics", 50, 1)
    busy(w, "analytics", 56, 9)
    a = of(scan(w), D.RATE)[0]
    with pytest.raises(ValidationError):
        Alert.model_validate({**a.to_obj(), "hard": True})


# --- tamper -------------------------------------------------------------------------------------------
def test_tamper_silent_when_disk_matches_memory_head():
    w = hero_world()
    r = w.records[-1]
    assert of(scan(w, memory_head=(r.seq, r.hash)), D.TAMPER) == []


def test_head_mismatch_fires_never_hard_and_names_nobody():
    w = hero_world()
    (a,) = of(scan(w, memory_head=(w.records[-1].seq, "f" * 64)), D.TAMPER)
    assert a.kind == AlertKind.TAMPER and a.hard is False and a.kind not in HARD_ALLOWED
    assert a.root_candidates == () and a.conn_id is None and not a.evidence_versions
    assert D.TAMPER not in HARD_DETECTORS and DETECTOR_KIND[D.TAMPER] == AlertKind.TAMPER
    with pytest.raises(ValidationError):
        Alert.model_validate({**a.to_obj(), "hard": True})
    with pytest.raises(ValidationError):
        Alert.model_validate({**a.to_obj(), "root_candidates": ["crm"]})


def test_truncated_disk_tail_fires():
    w = hero_world()
    head = (w.records[-1].seq, w.records[-1].hash)
    del w.records[-1]
    (a,) = of(scan(w, memory_head=head), D.TAMPER)
    assert a.evidence_seqs == (w.records[-1].seq,)


def test_edited_record_on_disk_fires_and_names_nobody():
    w = hero_world()
    i = len(w.records) // 2
    victim = w.records[i]
    forged = Record.model_validate({**victim.to_obj(), "tick": victim.tick + 1})   # hash no longer matches
    w.records[i] = forged
    got = of(scan(w), D.TAMPER)
    assert got and all(a.root_candidates == () and not a.hard for a in got)
    assert any(a.evidence_seqs == (forged.seq,) for a in got)


def test_seq_gap_and_chain_break_fire():
    w = hero_world()
    del w.records[5]
    probs = {a.evidence_seqs for a in of(scan(w), D.TAMPER)}
    assert (w.records[5].seq,) in probs


def test_tamper_alert_names_nobody_even_with_an_attributable_writer():
    """The tampered record is crm's: the alert still cites a seq only, and no agent is a suspect."""
    from ks.monitor import suspect
    w = hero_world()
    i = next(i for i, r in enumerate(w.records) if r.attributed_agent == "crm")
    w.records[i] = Record.model_validate({**w.records[i].to_obj(), "tick": w.records[i].tick + 1})
    ctx = w.ctx()
    for a in Monitor().scan(ctx):
        if a.detector == D.TAMPER:
            assert a.root_candidates == () and suspect(a, ctx.index) is None
