"""RT1 DB bypass. (a) strict perms: a rogue agent uid cannot find or open state.db. (b) an off-gateway write to the
live state (the honest picture of a single-uid / relaxed-perms deployment), made by the harness while the run is
paused, is flagged by reconciliation within one tick, names nobody and suspends nobody, and ``ks verify`` exits
RECONCILE.

THREAT-MODEL claims defended: state is written only through the gateway (per-agent uid, 0700 root run dir, B1);
an unmediated write is *detected* (reconcile, class U), never silently consumed, and never pinned on an honest agent.
"""

from __future__ import annotations

import sqlite3

import pytest

from ks.contracts import Exit

from .conftest import AGENTS, NEEDS_UIDS, verify, world_run

RT1A = '''
import os, sqlite3
GUESS = {guess!r}
def on_start(ctx):
    found = []
    for root in ("/tmp", "/run", "/var", "/root", "/home"):
        for d, subs, files in os.walk(root, onerror=lambda e: None):
            if "state.db" in files:
                found.append(os.path.join(d, "state.db"))
            if d.count(os.sep) > 6:
                subs[:] = []
    for p in found + [GUESS]:
        try:
            db = sqlite3.connect(f"file:{{p}}?mode=rw", uri=True)
            db.execute("UPDATE objects SET head_hash = ? WHERE obj = ?", ("0" * 64, "suppliers:S-17.iban"))
            db.commit()
            ctx.report(kind="bypass_ok", path=p)
        except Exception as e:
            ctx.report(kind="bypass_fail", path=p, err=type(e).__name__, msg=str(e)[:100])
def on_tick(ctx, t):
    pass
'''


@NEEDS_UIDS
def test_rt1a_strict_perms_rogue_cannot_reach_state_db(base):
    guess = str(base / "rt1a" / "workspace" / "state.db")  # a juror who guesses the path exactly
    run = world_run(base, "rt1a", rogue=RT1A.format(guess=guess), ticks=6)
    log = run.rogue_log()
    assert not [e for e in log if e["kind"] == "bypass_ok"], log
    assert [e for e in log if e["kind"] == "bypass_fail" and e["path"] == guess], log
    code, rep = verify(run.dir, run.anchor)
    assert code == Exit.OK and rep["anchored"] is True


T_BYPASS = 8


def _bypass(run_dir):
    db = sqlite3.connect(run_dir / "workspace" / "state.db")
    try:
        n = db.execute("UPDATE objects SET head_ver = head_ver + 1, head_hash = ? WHERE obj = ?",
                       ("ab" * 32, "suppliers:S-17.iban")).rowcount
        db.commit()
    finally:
        db.close()
    assert n == 1
    return {"ok": True}


def _then_resume(run_dir):
    from ks.runtime.operator import operator_request
    _bypass(run_dir)
    return operator_request(run_dir, {"op": "resume"})


@pytest.fixture(scope="module")
def rt1b(base):
    return world_run(base, "rt1b", rogue="def on_tick(ctx, t):\n    pass\n", ticks=14,
                     actions={T_BYPASS: [_then_resume]})


def test_rt1b_offlog_write_flagged_names_nobody(rt1b):
    al = [a for a in rt1b.alerts() if a["detector"] == "reconcile"]
    assert al and al[0]["hard"] is True, rt1b.alerts()
    assert al[0]["tick"] - T_BYPASS <= 1
    assert al[0]["root_candidates"] == []
    assert all(rt1b.status(f"agent:{a}") == "active" for a in AGENTS)
    code, rep = verify(rt1b.dir, rt1b.anchor)
    assert (code, rep["reason"]) == (Exit.RECONCILE, "reconcile_mismatch"), rep
