"""The in-process world driver's run dir passes ks.verify (maya, B3-28 review; needed by B3-27, the hero record).

Regression: the containment suspend used to be appended at ts_us slot 0 outside the gateway's slot counter, so the
next record of that tick took slot 0 again and verify failed with hash_mismatch (B3-15 ts_us rule)."""

from __future__ import annotations

from ks.contracts import CONTROL_TOOL, SYSTEM_CONN, ControlOp, Decision
from ks.verify import verify

from . import world as W


def _quiet(_s: str) -> None:
    pass


def test_f2plus_driver_run_verifies(tmp_path):
    w = W.run(tmp_path / "f2.db")
    rep = verify(w.rundir.path, log=_quiet)
    assert rep.ok and rep.reason == "ok", rep
    assert rep.last_witnessed_seq == w.records[-1].seq  # the last tick is witnessed
    sus = [r for r in w.records if r.control is not None and r.control.op == ControlOp.SUSPEND]
    assert len(sus) == 1
    s = sus[0]
    assert (s.tick, s.conn_id, s.envelope.agent_id, s.envelope.tool, s.decision) == (
        W.CONTAIN_AT, SYSTEM_CONN, "ks.monitor", CONTROL_TOOL, Decision.EXEC)
    # crm acts nothing after the suspend (the gateway's FoldedControl folded it)
    assert not [k for k in w.log if k[1] == W.CULPRIT and k[0] >= W.CONTAIN_AT]


def test_sstar_driver_run_verifies(tmp_path):
    s = W.run(tmp_path / "sstar.db", fault=None)
    assert verify(s.rundir.path, log=_quiet).ok


def test_ts_us_slots_strictly_increase_within_each_tick(tmp_path):
    w = W.run(tmp_path / "f2.db")
    cfg = w.gateway.config
    last: dict[int, int] = {}
    for r in w.records:
        slot = r.ts_us - cfg.start_ts_us - r.tick * cfg.tick_us
        assert slot > last.get(r.tick, -1), r.seq
        last[r.tick] = slot
