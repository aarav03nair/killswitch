"""B3-07: each detector fires on its fixture and stays silent on the clean one."""

import json

from ks.contracts import Detector as D, ActionClass, Decision, Reason
from ks.monitor import BarrierMiss, Monitor, MonitorParams, find_pii, iban_ok, iban_problem

from .world import BAD_CHECK, EVIL_IBAN, GOOD_IBAN, PAYEE, World, clean_world, hero_world


def scan(w, **kw):
    return Monitor().scan(w.ctx(**kw))


def one(alerts, det):
    got = [a for a in alerts if a.detector == det]
    assert len(got) == 1, [a.detector for a in alerts]
    return got[0]


def test_clean_fixture_is_silent():
    assert scan(clean_world()) == []


def test_iban_helpers():
    assert iban_ok(GOOD_IBAN) and iban_ok(EVIL_IBAN)
    assert iban_problem(BAD_CHECK) == "checksum"
    assert iban_problem("DE8937040044053201300") == "length"
    assert iban_problem("de89370400440532013000") == "format"
    assert iban_problem(5) == "not_a_string"


def test_iban_checksum_fires_hard_with_writer():
    w = clean_world()
    r = w.act("crm", "crm.update_supplier", tick=50, writes={PAYEE: BAD_CHECK})
    a = one(scan(w), D.IBAN_CHECKSUM)
    assert a.hard and a.evidence_seqs == (r.seq,)
    assert [(v.obj, v.ver) for v in a.evidence_versions] == [(PAYEE, 3)]
    assert a.root_candidates[0] == "crm"


def test_iban_checksum_accepts_dict_value_and_skips_redacted():
    w = clean_world()
    w.act("crm", "crm.update_supplier", tick=50, writes={PAYEE: {"iban": BAD_CHECK}})
    assert one(scan(w), D.IBAN_CHECKSUM)
    w2 = clean_world()
    w2.act("crm", "crm.update_supplier", tick=50, writes={PAYEE: BAD_CHECK})
    w2.side.redact(w2.head[PAYEE][1])
    w2.checkpoint()
    assert scan(w2) == []  # no value, no verdict (not a guess)


def test_checksum_valid_evil_iban_passes_checksum_but_beneficiary_catches_it():
    w = hero_world()
    dets = {a.detector for a in scan(w)}
    assert D.IBAN_CHECKSUM not in dets and D.BENEFICIARY_CHANGED_THEN_PAID in dets


def test_beneficiary_changed_then_paid_fires():
    a = one(scan(hero_world()), D.BENEFICIARY_CHANGED_THEN_PAID)
    assert a.hard and a.evidence_seqs == (9, 10)                       # B3-27: the payee write, then the payment
    assert [v.obj for v in a.evidence_versions] == [PAYEE]             # H4: payee field object only
    assert a.root_candidates[0] == "crm"


def test_beneficiary_silent_on_an_approved_restore_to_a_known_value():
    """B3-27: a ks.recover.restore (ks.recovery) back to a value the payee field already held is not a change."""
    from ks.monitor.detectors import _approved_restore
    from types import SimpleNamespace as N
    w = lambda o, v, h: N(obj=o, after=N(ver=v, hash=h))  # noqa: E731
    recs = {1: N(attributed_agent="ks.gateway", envelope=N(tool="ks.seed"), write_set=[w(PAYEE, 1, "a")]),
            2: N(attributed_agent="crm", envelope=N(tool="crm.update_supplier"), write_set=[w(PAYEE, 2, "b")]),
            3: N(attributed_agent="ks.recovery", envelope=N(tool="ks.recover.restore"), write_set=[w(PAYEE, 3, "a")]),
            4: N(attributed_agent="ks.recovery", envelope=N(tool="ks.recover.restore"), write_set=[w(PAYEE, 4, "z")])}
    ctx = N(index=N(writer=lambda o, v: recs.get(v)))
    assert _approved_restore(ctx, recs[3], PAYEE, 3)
    assert not _approved_restore(ctx, recs[4], PAYEE, 4)   # a new value is a change, whoever writes it
    assert not _approved_restore(ctx, recs[2], PAYEE, 2)


def test_beneficiary_silent_outside_window_and_on_old_version():
    w = clean_world()
    w.act("crm", "crm.update_supplier", tick=50, writes={PAYEE: EVIL_IBAN})
    w.act("payments", "payments.send", tick=50 + 13, reads=[PAYEE], cls=ActionClass.I1)  # window is 12
    w.checkpoint()
    assert scan(w) == []
    w2 = clean_world()  # payment reads v1 (creation) right after seeding: not a change
    w3 = World()
    w3.act("seeder", "world.seed", tick=0, writes={PAYEE: GOOD_IBAN})
    w3.act("payments", "payments.send", tick=1, reads=[PAYEE], cls=ActionClass.I1)
    w3.checkpoint()
    assert scan(w3) == [] and w2 is not None


def test_beneficiary_ignores_non_payment_tools_and_non_payee_objects():
    w = clean_world()
    w.act("crm", "crm.update_supplier", tick=50, writes={PAYEE: EVIL_IBAN})
    w.act("reporter", "docs.write", tick=51, reads=[PAYEE])            # reads it, doesn't pay
    w.act("payments", "payments.send", tick=52, reads=["suppliers:S-17"], cls=ActionClass.I1)  # payee not read
    w.checkpoint()
    assert scan(w) == []


def test_price_vs_history_is_soft():
    w = clean_world()
    r = w.act("crm", "crm.update_supplier", tick=50, writes={"suppliers:S-22": {"name": "Beta", "unit_price": 500}})
    w.checkpoint()
    a = one(scan(w), D.PRICE_VS_HISTORY)
    assert not a.hard and a.evidence_seqs == (r.seq,) and a.root_candidates == ("crm",)
    # within 2x of baseline (50): 60 in the clean world stayed silent; 101 fires
    w2 = clean_world()
    w2.act("crm", "crm.update_supplier", tick=50, writes={"suppliers:S-22": {"name": "Beta", "unit_price": 101}})
    w2.checkpoint()
    assert one(scan(w2), D.PRICE_VS_HISTORY)


def test_price_uses_frozen_baseline_param():
    w = clean_world()
    p = MonitorParams(price_baseline={"suppliers:S-22": 10})   # 60 is 6x a frozen 10
    assert one(scan(w, params=p), D.PRICE_VS_HISTORY)


def test_ledger_balance_hard_i_class():
    w = clean_world()
    r = w.act("billing", "ledger.post", tick=50, writes={"ledger:L-3": {"debit": 100, "credit": 90}})
    w.checkpoint()
    a = one(scan(w), D.LEDGER_BALANCE)
    assert a.hard and a.kind == "invariant" and a.evidence_seqs == (r.seq,) and a.root_candidates == ("billing",)


def test_scope_breach_on_sig_ok_out_of_scope_only():
    w = clean_world()
    r = w.act("intake", "supplier.set_risk_note", tick=50, decision=Decision.DENY, reason=Reason.OUT_OF_SCOPE)
    w.checkpoint()
    a = one(scan(w), D.SCOPE)
    assert a.hard and a.evidence_seqs == (r.seq,) and a.root_candidates == ("intake",)


def test_signature_names_connection_only():
    w = clean_world()
    w.act("billing", "ledger.post", tick=50, decision=Decision.DENY, reason=Reason.BAD_SIG, sig_ok=False,
          signer="docs", conn="c-9")
    w.checkpoint()
    al = scan(w)
    assert {a.detector for a in al} == {D.SIGNATURE}     # no scope alert for the claimed agent
    a = al[0]
    assert a.conn_id == "c-9" and a.root_candidates == () and a.hard


def test_reconcile_names_nobody_and_cites_alert_seq():
    w = clean_world()
    w.off_log_write("suppliers:S-22", {"name": "Beta", "unit_price": 999})
    a = one(scan(w), D.RECONCILE)
    assert a.hard and a.root_candidates == () and a.evidence_seqs == (a.seq,)
    assert [(v.obj, v.ver) for v in a.evidence_versions] == [("suppliers:S-22", 3)]


def test_reconcile_off_log_object_with_no_recorded_version():
    w = clean_world()
    w.off_log_write("suppliers:S-99", {"name": "Ghost", "unit_price": 1})
    a = one(scan(w), D.RECONCILE)
    assert a.root_candidates == () and a.evidence_versions[0].obj == "suppliers:S-99"


def test_witness_stall_never_hard():
    w = clean_world()
    w.act("crm", "crm.update_supplier", tick=60, reads=["suppliers:S-17"], writes={"suppliers:S-17": {"name": "A", "unit_price": 100}})
    a = one(scan(w), D.WITNESS_STALL)   # last checkpoint was tick 43; now 60
    assert not a.hard and a.kind == "witness_stall" and a.root_candidates == ()


def test_pii_egress_fires_and_alert_carries_no_pii():
    w = clean_world()
    pii = {"to": "x@example.com", "subject": "KYC", "body": "SSN 123-45-6789 and card 4111 1111 1111 1111"}
    r = w.queue_email("comms", tick=50, payload=pii)
    w.checkpoint()
    a = one(scan(w), D.PII_EGRESS)
    assert a.hard and a.evidence_seqs == (r.seq,) and a.root_candidates[0] == "comms"
    assert a.evidence_versions[0].obj.startswith("outbox:ob-")
    blob = json.dumps(a.to_obj())
    assert "123-45-6789" not in blob and "4111" not in blob          # rule 9: hashes only


def test_pii_patterns():
    assert find_pii({"body": "call 4111-1111-1111-1111"})            # Luhn-valid card
    assert not find_pii({"body": "order 4111111111111112 shipped"})  # Luhn-invalid
    assert find_pii({"body": "Aadhaar 1234 5678 9012"})
    assert find_pii({"body": f"pay to {GOOD_IBAN}"})
    assert find_pii({"ssn": "x"}, frozenset({"ssn"})) and not find_pii({"ssn": ""}, frozenset({"ssn"}))
    assert not find_pii({"body": "Order 17 shipped.", "n": 5})


def test_barrier_deadline_conn_only_empty_evidence():
    w = clean_world()
    al = scan(w, barrier_misses=[BarrierMiss(tick=44, conn_id="c-4")])
    a = one(al, D.BARRIER_DEADLINE)
    assert not a.hard and a.kind == "anomaly"
    assert a.evidence_seqs == () and a.evidence_versions == () and a.root_candidates == () and a.conn_id == "c-4"


def test_monitor_dedupes_and_numbers_alerts():
    w = hero_world()
    m = Monitor()
    first = m.scan(w.ctx())
    assert [a.alert_id for a in first] == ["a-000001"] and m.scan(w.ctx()) == []
    w.act("billing", "ledger.post", tick=53, writes={"ledger:L-3": {"debit": 1, "credit": 2}})
    w.checkpoint()
    assert [a.alert_id for a in m.scan(w.ctx())] == ["a-000002"]
