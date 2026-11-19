"""SKEL-01: 2 agent subprocesses -> signer handle -> gateway stub -> record -> witness -> ks verify."""

from ks.contracts import Decision, Exit, RunDir

from .conftest import ks_verify


def test_clean_run_verifies_anchored(clean_run):
    run, anchor, _ = clean_run
    code, rep = ks_verify(run, anchor)
    assert code == Exit.OK and rep.ok and rep.anchored and rep.unanchored_reason is None
    assert rep.last_witnessed_seq == 20


def test_clean_run_unanchored_is_consistent_not_anchored(clean_run):
    code, rep = ks_verify(clean_run[0])
    assert code == Exit.OK and not rep.anchored and rep.unanchored_reason == "no_anchor"


def test_run_dir_shape(clean_run):
    rd = RunDir(clean_run[0])
    assert rd.validate() == [] and rd.perm_problems() == []
    recs = list(rd.records())
    cps = list(rd.witness())
    assert [r.seq for r in recs] == list(range(1, 21))
    assert all(r.decision == Decision.EXEC and r.sig_ok for r in recs)
    # tick barrier: per tick, agent_00 (c-1) then agent_01 (c-2); ts_us = tick * tick_us + slot
    assert [(r.tick, r.conn_id, r.attributed_agent) for r in recs[:2]] == [(0, "c-1", "agent_00"), (0, "c-2", "agent_01")]
    assert all(r.ts_us == r.tick * 1000 + (r.seq - 1) % 2 for r in recs)
    assert [(c.count, c.tick, c.seq) for c in cps] == [(t + 1, t, 2 * (t + 1)) for t in range(10)]
    assert {r.envelope.tool for r in recs} == {"skel.echo", "skel.noop"}
