"""RT1c (S4-28, Panel M3): an off-gateway edit of a state *value* mid-run (hash kept) must not crash the gateway.
It raises a hard reconcile alert naming nobody, suspends nobody, and the run ends with a RunAnchor; verify reports
RECONCILE. The edit is made while the run is paused (the harness stands in for a rogue root writer)."""

from __future__ import annotations

import json
import sqlite3

from ks.contracts import Exit

from .conftest import AGENTS, verify, world_run

T_EDIT = 8


def _edit_value(run_dir):
    from ks.runtime.operator import operator_request
    db = sqlite3.connect(run_dir / "workspace" / "state.db")
    try:
        rows = db.execute("SELECT obj, head_value FROM objects WHERE head_redacted = 0 AND obj LIKE 'suppliers:%' "
                          "AND obj NOT LIKE '%.%' ORDER BY obj").fetchall()
        assert rows
        for obj, v in rows:  # every visible supplier row, so some agent's view certainly holds one
            d = json.loads(v)
            d["name"] = "EVIL"
            db.execute("UPDATE objects SET head_value = ? WHERE obj = ?", (json.dumps(d), obj))
        db.commit()
    finally:
        db.close()
    return operator_request(run_dir, {"op": "resume"})


def test_rt1c_value_edit_alerts_not_crash(base):
    run = world_run(base, "rt1c", rogue="def on_tick(ctx, t):\n    pass\n", ticks=14,
                    actions={T_EDIT: [_edit_value]})
    assert run.anchor is not None
    al = [a for a in run.alerts() if a["detector"] == "reconcile"]
    assert al and al[0]["hard"] is True and al[0]["root_candidates"] == [], run.alerts()
    assert al[0]["tick"] - T_EDIT <= 1
    assert all(run.status(f"agent:{a}") == "active" for a in AGENTS)
    code, rep = verify(run.dir, run.anchor)
    assert (code, rep["reason"]) == (Exit.RECONCILE, "reconcile_mismatch"), rep

    # Tool reads fail closed too (kabir, S4-28): the edited value never reaches a payload, a state write or the
    # side store; the only place it survives is the edited head itself (the reconcile alert is the evidence).
    db = sqlite3.connect(run.dir / "workspace" / "state.db")
    try:
        assert not db.execute("SELECT 1 FROM side WHERE value LIKE '%EVIL%'").fetchall()
        left = [o for (o,) in db.execute("SELECT obj FROM objects WHERE head_value LIKE '%EVIL%'")]
        assert all(o.startswith("suppliers:") for o in left), left  # nothing laundered into other objects
    finally:
        db.close()
    assert "EVIL" not in (run.dir / "record.jsonl").read_text()
