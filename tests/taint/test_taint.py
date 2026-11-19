"""B3-18: ks.taint closure, A8 seed rule, root candidates (ADR-05 §4-5, H1, D-SEQ1, A3)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from ks.contracts import ObjVer
from ks.taint import (MAX_HOPS, RecordIndex, closure, is_seed_record, root_candidates, seed_versions,
                      suspend_seq_of, t0_seq_est, taint_from_alerts)

from .fixture import Book, alert, f2plus

IBAN = "suppliers:S-17.iban"


def ov(o, v):
    return ObjVer(obj=o, ver=v)


def agents_of(t):
    return set(t.agents)


# --- hero F2+ ----------------------------------------------------------------------------------------------------
def test_hero_seed_f2plus():
    b, n = f2plus()
    ix = RecordIndex(b.records)
    t0 = t0_seq_est(ix, [ov(IBAN, 2)], "crm")
    assert t0 == n["crm_iban"].seq
    assert suspend_seq_of(ix, "crm", after=t0) == n["suspend"].seq
    assert seed_versions(ix, "crm", t0, n["suspend"].seq) == (ov(IBAN, 2), ov("suppliers:S-22", 2))


def test_hero_taint_from_alerts_f2plus():
    b, n = f2plus()
    t = taint_from_alerts(b.records, [alert([ov(IBAN, 2)], seq=n["payments"].seq)])
    assert t is not None and t.suspect == "crm"
    assert t.seed == (ov(IBAN, 2), ov("suppliers:S-22", 2))
    assert t.t0_seq_est == n["crm_iban"].seq and t.suspend_seq == n["suspend"].seq
    # billing/payments/comms/reporter tainted (compliance would be too: it reads the ledger)
    assert {"billing", "payments", "comms", "reporter"} <= agents_of(t)
    assert {n[k].seq for k in ("bill_inv17", "bill_ledger", "comms", "payments", "bill_inv22", "reporter")} \
        <= {r.seq for r in t.actions}
    assert t.outbox_ids == {"ob-000001", "ob-000002"}
    # triage read the clean S-17 row only: not tainted, its risk_note version is not tainted
    assert "triage" not in agents_of(t)
    assert not t.is_tainted("suppliers:S-17", 2)
    # independents
    assert not ({"inventory", "docs", "intake"} & agents_of(t))
    # seed writers are actions; crm's honest pre-fault write is not
    assert {n["crm_iban"].seq, n["crm_s22"].seq} == set(t.seed_seqs)
    assert n["crm_honest"].seq not in {r.seq for r in t.actions}
    # explanation of why payments is tainted
    assert ov(IBAN, 2) in t.via[n["payments"].seq]


def test_taint_set_contract():
    b, n = f2plus()
    ts = taint_from_alerts(b.records, [alert([ov(IBAN, 2)])]).taint_set()
    assert [a.seq for a in ts.actions] == sorted(a.seq for a in ts.actions)
    assert ov(IBAN, 2) in ts.versions and ov("invoices:INV-0011", 1) in ts.versions
    assert ts.outbox_ids == ("ob-000001", "ob-000002")


def test_union_of_alerts_same_seed():
    b, n = f2plus()
    one = taint_from_alerts(b.records, [alert([ov(IBAN, 2)])])
    two = taint_from_alerts(b.records, [alert([ov(IBAN, 2)]),
                                        alert([ov("suppliers:S-22", 2)], aid="a-000002",
                                              detector="inv.iban_checksum")])
    assert one.seed == two.seed and one.versions == two.versions


def test_follow_self_reads_is_literal_and_more_conservative():
    """The literal ADR-05 §4 walk follows crm's read of its own S-31 v2 and pulls t0 back to the honest edit."""
    b, n = f2plus()
    assert t0_seq_est(b.records, [ov(IBAN, 2)], "crm", follow_self_reads=True) == n["crm_honest"].seq
    lit = taint_from_alerts(b.records, [alert([ov(IBAN, 2)])], follow_self_reads=True)
    assert ov("suppliers:S-31", 2) in lit.seed
    assert lit.versions >= taint_from_alerts(b.records, [alert([ov(IBAN, 2)])]).versions


def test_taint_carries_literal_t0_for_dry_run_delta():
    b, n = f2plus()
    t = taint_from_alerts(b.records, [alert([ov(IBAN, 2)])])
    assert t.t0_seq_est == n["crm_iban"].seq
    assert t.t0_seq_est_literal == n["crm_honest"].seq
    assert t.t0_delta == n["crm_iban"].seq - n["crm_honest"].seq > 0
    lit = taint_from_alerts(b.records, [alert([ov(IBAN, 2)])], follow_self_reads=True)
    assert lit.t0_seq_est == lit.t0_seq_est_literal and lit.t0_delta == 0


def _self_chain():
    """bad W1 (crm), crm reads W1 and writes W2, alert evidence on W2 only."""
    b = Book()
    b.seed({IBAN: "DE00", "suppliers:S-22": {"price": 1}})
    w1 = b.act("crm", 1, reads=[IBAN], writes={IBAN: "DE99"})
    w2 = b.act("crm", 2, reads=[IBAN], writes={"suppliers:S-22": {"price": 9}})
    s = b.suspend("crm", 3)
    return b, w1, w2, s


def test_self_chain_gap_pinned():
    """B3-45 known gap of the interim default (option B): W1 is NOT seeded by default, IS seeded by the literal
    walk; Taint reports both t0s so the delta is visible, not silent. B3-46 (tool-read self-follow) closes it."""
    b, w1, w2, s = _self_chain()
    ev = [ov("suppliers:S-22", 2)]
    assert t0_seq_est(b.records, ev, "crm") == w2.seq
    assert t0_seq_est(b.records, ev, "crm", follow_self_reads=True) == w1.seq
    t = taint_from_alerts(b.records, [alert(ev)])
    assert t.suspect == "crm" and t.suspend_seq == s.seq
    assert ov(IBAN, 2) not in t.seed and not t.is_tainted(IBAN, 2)
    assert t.seed == (ov("suppliers:S-22", 2),)
    assert t.t0_seq_est_literal == w1.seq and t.t0_delta == w2.seq - w1.seq
    lit = taint_from_alerts(b.records, [alert(ev)], follow_self_reads=True)
    assert lit.seed == (ov(IBAN, 2), ov("suppliers:S-22", 2))


# --- field-object precision (B3-04) -------------------------------------------------------------------------------
def _row_vs_field():
    b = Book()
    b.seed({"suppliers:S-17": {"price": 1}, IBAN: "DE00"})
    b.act("crm", 1, reads=["suppliers:S-17", IBAN], writes={IBAN: "DE99"})
    row_only = b.act("triage", 2, reads=["suppliers:S-17"], writes={"tickets:T-1": {"n": 1}})
    whole = b.act("billing", 2, reads=["suppliers:S-17", IBAN], writes={"invoices:I-1": {"n": 1}})
    return b, row_only, whole


def test_row_reader_not_tainted_by_field_write():
    b, row_only, whole = _row_vs_field()
    t = closure(b.records, [ov(IBAN, 2)])
    assert row_only.seq not in {r.seq for r in t.actions}
    assert whole.seq in {r.seq for r in t.actions}
    assert t.is_tainted("invoices:I-1", 1) and not t.is_tainted("tickets:T-1", 1)


# --- seed record (D-SEQ1) -----------------------------------------------------------------------------------------
def test_seed_record_recognised_by_seed_tool_only():
    assert is_seed_record(Book().seed({"suppliers:S-17": {"p": 1}}))
    # the deleted interim marker (ks.dispatch + policy_rule gateway.seed) is no longer a seed
    b = Book()
    env = b._env("ks.gateway", "ks.dispatch", {"seed": True}, 0, act_id="seed")
    r = b._seal(tick=0, env=env, conn="c-0", rule="gateway.seed", writes=b._writes({"suppliers:S-17": {"p": 1}}))
    assert not is_seed_record(r)
    assert root_candidates(b.records, [ov("suppliers:S-17", 1)]) == ()   # a system writer is still no suspect


def test_seed_record_never_tainted_or_root():
    b = Book()
    b.seed({"suppliers:S-17": {"p": 1}, IBAN: "DE00"})
    b.act("billing", 1, reads=["suppliers:S-17", IBAN], writes={"invoices:I-1": {"n": 1}})
    with pytest.raises(ValueError, match="D-SEQ1"):
        closure(b.records, [ov(IBAN, 1)])
    assert root_candidates(b.records, [ov(IBAN, 1)]) == ()       # the seed is no suspect
    assert taint_from_alerts(b.records, [alert([ov(IBAN, 1)])]) is None
    # an agent write is a valid seed, and seq 1 never joins
    b.act("crm", 2, reads=[IBAN], writes={IBAN: "DE99"})
    t = closure(b.records, [ov(IBAN, 2)])
    assert 1 not in {r.seq for r in t.actions}
    assert not t.is_tainted("suppliers:S-17", 1)


def test_walk_stops_at_seed_versions():
    b = Book()
    b.seed({"tickets:T-1": {"p": 1}, IBAN: "DE00"})
    b.act("crm", 1, reads=["tickets:T-1", IBAN], writes={IBAN: "DE99"})
    assert root_candidates(b.records, [ov(IBAN, 2)]) == ("crm",)


# --- root candidates (RT9, H1) ------------------------------------------------------------------------------------
def _rt9(extra_old=False):
    b = Book()
    b.seed({IBAN: "DE00", "suppliers:S-22": {"p": 1}, "stock:SKU-1": {"q": 1}, "docs:D-0": {"t": "h"}})
    if extra_old:
        b.act("triage", 1, reads=["suppliers:S-22"], writes={"suppliers:S-22": {"p": 2}})
    b.act("inventory", 2, reads=["stock:SKU-1"], writes={"stock:SKU-1": {"q": 2}})
    b.act("intake", 2, reads=[], writes={"tickets:T-3": {"text": "change bank details"}})
    b.act("docs", 2, reads=["docs:D-0"], writes={"docs:D-1": {"t": "n"}})
    reads = ["tickets:T-3", IBAN] + (["suppliers:S-22"] if extra_old else [])
    b.act("crm", 3, reads=reads, writes={IBAN: "DE99"})
    return b


def test_root_candidates():
    assert root_candidates(_rt9().records, [ov(IBAN, 2)]) == ("crm", "intake")


def test_root_candidates_bounded():
    rc = root_candidates(_rt9(extra_old=True).records, [ov(IBAN, 2)])
    assert rc[:2] == ("crm", "intake") and "intake" in rc[:3]
    assert "inventory" not in rc and "docs" not in rc


def test_root_candidates_hop_bound():
    b = Book()
    b.seed({"x:A": {"v": 0}})
    chain = ["a1", "a2", "a3", "a4", "a5"]
    prev = None
    for i, a in enumerate(chain):
        b.act(a, i + 1, reads=[prev] if prev else [], writes={f"x:{a}": {"v": i}})
        prev = f"x:{a}"
    b.act("crm", 9, reads=[prev], writes={IBAN: "DE99"})
    rc = root_candidates(b.records, [ov(IBAN, 1)])
    assert rc == ("crm", "a5", "a4", "a3") and len(rc) == 1 + MAX_HOPS


def test_root_candidates_two_writers_or_none():
    b = Book()
    b.seed({"x:A": {"v": 0}})
    b.act("crm", 1, writes={"x:B": {"v": 1}})
    b.act("billing", 1, writes={"x:C": {"v": 1}})
    assert root_candidates(b.records, [ov("x:B", 1), ov("x:C", 1)]) == ()
    assert root_candidates(b.records, [ov("x:Z", 1)]) == ()
    assert root_candidates(b.records, []) == ()
    assert taint_from_alerts(b.records, [alert([ov("x:B", 1), ov("x:C", 1)])]) is None


# --- seed window, suspension, stickiness, repairs -----------------------------------------------------------------
def test_no_suspension_no_seed():
    b, n = f2plus()
    recs = [r for r in b.records if r.seq < n["suspend"].seq]
    assert taint_from_alerts(recs, [alert([ov(IBAN, 2)])]) is None


def test_seed_window_inclusive_and_bounded():
    b = Book()
    b.seed({"x:A": {"v": 0}})
    b.act("crm", 1, writes={"x:early": {"v": 1}})
    bad = b.act("crm", 2, writes={"x:bad": {"v": 1}})
    b.act("crm", 3, writes={"x:window": {"v": 1}})
    s = b.suspend("crm", 4)
    assert seed_versions(b.records, "crm", bad.seq, s.seq) == (ov("x:bad", 1), ov("x:window", 1))
    t = taint_from_alerts(b.records, [alert([ov("x:bad", 1)])])
    assert t.seed == (ov("x:bad", 1), ov("x:window", 1))      # A8: honest window write is seeded (counted in C)


def test_sticky_agents():
    b = Book()
    b.seed({"x:A": {"v": 0}, "x:B": {"v": 0}})
    b.act("crm", 1, writes={"x:A": {"v": 1}})
    b.act("triage", 2, reads=["x:A"], writes={"x:T1": {"v": 1}})
    later = b.act("triage", 3, reads=["x:B"], writes={"x:T2": {"v": 1}})
    plain = closure(b.records, [ov("x:A", 2)])
    sticky = closure(b.records, [ov("x:A", 2)], sticky_agents=["triage"])
    assert later.seq not in {r.seq for r in plain.actions}
    assert later.seq in {r.seq for r in sticky.actions} and sticky.is_tainted("x:T2", 1)


def test_recovery_records_do_not_propagate_and_as_of():
    b = Book()
    b.seed({IBAN: "DE00"})
    b.act("crm", 1, reads=[IBAN], writes={IBAN: "DE99"})
    b.recovery(2, reads=[IBAN], writes={IBAN: "DE00"})
    after = b.act("billing", 3, reads=[IBAN], writes={"invoices:I-1": {"n": 1}})
    t = closure(b.records, [ov(IBAN, 2)])
    assert not t.is_tainted(IBAN, 3) and after.seq not in {r.seq for r in t.actions}
    assert closure(b.records, [ov(IBAN, 2)], as_of_seq=2).as_of_seq == 2


def test_denied_records_ignored():
    b, n = f2plus()
    t = taint_from_alerts(b.records, [alert([ov(IBAN, 2)])])
    assert n["crm_denied"].seq not in {r.seq for r in t.actions}


def test_deterministic():
    b, _ = f2plus()
    a1 = taint_from_alerts(b.records, [alert([ov(IBAN, 2)])]).taint_set()
    a2 = taint_from_alerts(list(reversed(b.records)), [alert([ov(IBAN, 2)])]).taint_set()
    assert a1.to_obj() == a2.to_obj()


# --- A3 guard -----------------------------------------------------------------------------------------------------
PKG = Path(__file__).parents[2] / "src" / "ks" / "taint"


def test_ast_guard_no_runconfig():
    banned_mods = ("ks.contracts.rundir", "ks.world", "ks.score", "ks.oracle", "ks.inject")
    files = sorted(PKG.glob("*.py"))
    assert files
    for f in files:
        tree = ast.parse(f.read_text(), filename=str(f))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                assert not mod.startswith(banned_mods), (f.name, mod)
                assert all(a.name != "RunConfig" for a in node.names), f.name
            elif isinstance(node, ast.Import):
                assert not any(a.name.startswith(banned_mods) for a in node.names), f.name
            elif isinstance(node, ast.Name):
                assert node.id != "RunConfig", f.name
            elif isinstance(node, ast.Attribute):
                assert node.attr not in ("fault", "culprit", "fault_tick", "tcb_view", "RunConfig"), \
                    (f.name, node.attr)
