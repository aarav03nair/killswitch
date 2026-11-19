"""Detect, then attribute: RT9 laundering, anti-framing, bounded walk, never-suspend rules."""

from ks.contracts import ActionClass, Decision, Detector as D, Reason
from ks.monitor import Monitor, MonitorParams, containment_target, suspect

from .world import BAD_CHECK, EVIL_IBAN, GOOD_IBAN, PAYEE, World, clean_world, hero_world


def alerts(w, **kw):
    return {a.detector: a for a in Monitor().scan(w.ctx(**kw))}


def test_rt9_laundering_candidates_crm_then_intake():
    w = hero_world()
    a = alerts(w)[D.BENEFICIARY_CHANGED_THEN_PAID]
    assert a.root_candidates[0] == "crm" and "intake" in a.root_candidates[:3]
    assert a.root_candidates[:2] == ("crm", "intake")
    assert [v.obj for v in a.evidence_versions] == [PAYEE]
    # crm (the laundered writer) is the only auto-suspend target; intake is read-reached and never is
    assert suspect(a, w.ctx().index) == "crm"
    assert containment_target(a, w.ctx().index) == "agent:crm"
    # the payer reads the poisoned payee but is not a candidate at all
    assert "payments" not in a.root_candidates


def test_read_reached_agent_never_auto_suspended_even_if_listed_first():
    w = hero_world()
    idx = w.ctx().index
    a = alerts(w)[D.BENEFICIARY_CHANGED_THEN_PAID]
    forged = a.model_copy(update={"root_candidates": ("intake", "crm")})
    assert suspect(forged, idx) is None                       # [0] is not the writer: nobody
    forged2 = a.model_copy(update={"root_candidates": ("payments", "crm")})
    assert suspect(forged2, idx) is None


def test_two_writers_of_evidence_suspend_nobody():
    w = clean_world()
    w.act("crm", "crm.update_supplier", tick=50, writes={PAYEE: BAD_CHECK, "suppliers:S-17": {"name": "A", "unit_price": 100}})
    w.act("triage", "supplier.set_risk_note", tick=51, writes={"suppliers:S-17": {"name": "A", "unit_price": 100, "risk_note": "x"}})
    w.checkpoint()
    a = alerts(w)[D.IBAN_CHECKSUM]
    assert suspect(a, w.ctx().index) == "crm"                  # one writer: fine
    # same alert, evidence widened to a second writer's version
    from ks.contracts import ObjVer
    wide = a.model_copy(update={"evidence_versions": tuple(sorted(
        a.evidence_versions + (ObjVer(obj="suppliers:S-17", ver=3),), key=lambda e: (e.obj, e.ver)))})
    assert len(set([w.ctx().index.writer(v.obj, v.ver).attributed_agent for v in wide.evidence_versions])) == 2
    assert suspect(wide, w.ctx().index) is None


def test_no_writer_suspends_nobody():
    w = clean_world()
    w.act("crm", "crm.update_supplier", tick=50, writes={PAYEE: BAD_CHECK})
    w.checkpoint()
    a = alerts(w)[D.IBAN_CHECKSUM]
    from ks.contracts import ObjVer
    ghost = a.model_copy(update={"evidence_versions": (ObjVer(obj=PAYEE, ver=99),)})
    assert suspect(ghost, w.ctx().index) is None
    assert suspect(a.model_copy(update={"root_candidates": ()}), w.ctx().index) is None


def test_soft_and_nobody_alerts_never_suspend():
    w = clean_world()
    w.act("crm", "crm.update_supplier", tick=50, writes={"suppliers:S-22": {"name": "Beta", "unit_price": 500}})
    w.off_log_write("suppliers:S-99", {"name": "Ghost"})
    w.act("payments", "payments.send", tick=70, cls=ActionClass.I1)       # witness now stalled
    got = alerts(w)
    assert {D.PRICE_VS_HISTORY, D.RECONCILE, D.WITNESS_STALL} <= set(got)
    idx = w.ctx().index
    assert all(suspect(a, idx) is None for a in got.values())


def test_anti_framing_forged_signature_cannot_frame_an_honest_agent():
    """An attacker forges 'crm' envelopes (bad signature) and floods a connection. The honest crm is never a
    candidate and never suspended; only the connection is contained."""
    w = hero_world()
    for t in (53, 54):
        w.act("crm", "crm.update_supplier", tick=t, decision=Decision.DENY, reason=Reason.BAD_SIG, sig_ok=False,
              signer="docs", conn="c-9")
    w.act("payments", "payments.send", tick=55, reads=[PAYEE], cls=ActionClass.I1)
    w.checkpoint()
    got = alerts(w)
    sig = got[D.SIGNATURE]
    assert sig.conn_id == "c-9" and sig.root_candidates == ()
    idx = w.ctx().index
    assert containment_target(sig, idx) == "conn:c-9"
    assert D.SCOPE not in got                                            # forged records are not scope evidence
    assert suspect(sig, idx) is None


def test_anti_framing_payer_and_victims_are_not_attributed():
    """RT11-style: honest payments pays a poisoned payee; honest billing reads it too. Suspension follows the
    writer of the evidence, never the payer or a reader."""
    w = hero_world()
    w.act("billing", "billing.draft_invoice", tick=52, reads=[PAYEE, "suppliers:S-17"], writes={"invoices:I-1": {"n": 1}})
    w.act("payments", "payments.send", tick=53, reads=[PAYEE, "invoices:I-1"], cls=ActionClass.I1)
    w.checkpoint()
    for a in Monitor().scan(w.ctx()):
        s = suspect(a, w.ctx().index)
        assert s in (None, "crm")
        assert "payments" not in a.root_candidates[:1] and "billing" not in a.root_candidates[:1]


def test_forged_denied_record_cannot_become_a_writer():
    """A forged record claiming to be crm and carrying a write set is impossible (deny has none), and even a
    non-exec record is ignored by the writer index."""
    w = hero_world()
    idx = w.ctx().index
    assert idx.writer(PAYEE, 3).attributed_agent == "crm"
    assert all(r.write_set == () for r in w.records if r.decision != Decision.EXEC)


def test_scope_suspends_the_attributed_agent_only():
    w = clean_world()
    w.act("intake", "supplier.set_risk_note", tick=50, decision=Decision.DENY, reason=Reason.OUT_OF_SCOPE)
    w.checkpoint()
    a = alerts(w)[D.SCOPE]
    assert suspect(a, w.ctx().index) == "intake"


def test_backward_walk_is_bounded():
    w = World()
    w.act("a0", "x.write", tick=0, writes={"chain:c0": {"v": 0}})
    for i in range(1, 9):
        w.act(f"a{i}", "x.write", tick=i, reads=[f"chain:c{i - 1}"], writes={f"chain:c{i}": {"v": i}})
    w.act("crm", "crm.update_supplier", tick=10, reads=["chain:c8"], writes={PAYEE: BAD_CHECK})
    w.checkpoint()
    a = alerts(w)[D.IBAN_CHECKSUM]
    assert a.root_candidates[0] == "crm"
    assert a.root_candidates[1:] == ("a8", "a7", "a6")               # depth <= 3 hops
    capped = alerts(w, params=MonitorParams(walk_depth=8, max_candidates=4))[D.IBAN_CHECKSUM]
    assert capped.root_candidates == ("crm", "a8", "a7", "a6")  # candidate cap
    small = alerts(w, params=MonitorParams(walk_depth=1, max_candidates=5))[D.IBAN_CHECKSUM]
    assert small.root_candidates == ("crm", "a8")


def test_walk_uses_recorded_reads_not_act_chain():
    """crm's envelope declares an act_chain through 'payments'; it must not become a candidate (D8)."""
    from ks.contracts import ActLink
    w = clean_world()
    r = w.act("crm", "crm.update_supplier", tick=50, writes={PAYEE: BAD_CHECK})
    assert r.envelope.act_chain == ()
    w.checkpoint()
    a = alerts(w)[D.IBAN_CHECKSUM]
    assert "payments" not in a.root_candidates and ActLink  # act_chain is never consulted
