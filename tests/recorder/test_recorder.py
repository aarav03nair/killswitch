"""B3-09: recorder txn semantics (seq at txn start, append after commit), GatewayHooks, one checkpoint per tick."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "contracts"))
import samples as S  # noqa: E402

from ks.contracts import Exit, RunAnchor, RunDir, VerifyReport  # noqa: E402
from ks.recorder import GatewayHooks, Recorder, RecorderAborted  # noqa: E402
from ks.verify import verify  # noqa: E402

REPO = Path(__file__).resolve().parents[2]

# One writing "gateway" step: reserve seq, commit state under it, append the record (or die in between).
CHILD = textwrap.dedent("""
    import os, sys
    sys.path[:0] = [sys.argv[1] + "/src", sys.argv[1] + "/tests/contracts"]
    import samples as S
    from ks.contracts import *
    from ks.recorder import Recorder
    from ks.state import open_store
    from pathlib import Path

    run, crash = Path(sys.argv[2]), sys.argv[3] == "crash"
    rd = RunDir(run)
    rec = Recorder(rd, lambda b: S.sign("ks.gateway", b))
    store = open_store(run / "workspace" / "state.db")

    def step(n, crash_before_append):
        txn = rec.begin()                                   # seq taken at txn start
        with store.txn():                                   # state commit
            w = store.put("suppliers:S-17", {"v": n}, author="crm", seq=txn.seq, action_id=f"a-{n}")
        if crash_before_append:
            os.kill(os.getpid(), 9)                         # killed between commit and append
        env = S.envelope(action_id=f"a-{n}", nonce=f"{n:032x}")
        r = txn.append(tick=9 + n, ts_us=1_000_000_000 + (9 + n) * 1000, conn_id="c-3", envelope=env.header(),
                       envelope_hash=env.content_hash(), sig_ok=True, decision=Decision.EXEC, reason=Reason.OK,
                       policy_rule=None, action_class=ActionClass.R, read_set=(), write_set=(w,), outbox_ids=(),
                       result_hash=result_hash({"ok": True}), control=None, reexec_of=None)
        rd.append(S.witness(r, count=n))                    # a checkpoint after each record
    step(1, False)
    step(2, crash)
""")


def _fresh_run(tmp_path) -> Path:
    base = tmp_path / "b"
    base.mkdir(parents=True)
    return RunDir.create(base / "run", S.run_config(), S.keyring()).path


def _child(run: Path, mode: str) -> int:
    p = subprocess.run([sys.executable, "-c", CHILD, str(REPO), str(run), mode], timeout=60, capture_output=True, text=True)
    if p.returncode > 0:
        print(p.stderr[-1500:])
    return p.returncode


def test_crash_commit_append_is_reconcile_never_silent(tmp_path):
    clean = _fresh_run(tmp_path / "clean")
    assert _child(clean, "clean") == 0
    assert verify(clean).exit == Exit.OK, verify(clean)

    crashed = _fresh_run(tmp_path / "crash")
    assert _child(crashed, "crash") == -9           # the process died between commit and append
    rep = verify(crashed)
    assert (rep.ok, rep.exit, rep.reason) == (False, Exit.RECONCILE, "reconcile_mismatch")
    # the record itself is intact and witnessed: only the state is ahead of it
    assert len((crashed / "record.jsonl").read_bytes().splitlines()) == 1


def test_missing_state_with_writes_is_no_state_and_without_writes_is_ok(tmp_path):
    run = _fresh_run(tmp_path / "a")
    assert _child(run, "clean") == 0
    (run / "workspace" / "state.db").unlink()
    rep = verify(run)
    assert (rep.exit, rep.reason) == (Exit.RECONCILE, "no_state")


def test_failed_append_aborts_the_recorder(tmp_path):
    rd = RunDir.create(tmp_path / "run", S.run_config(), S.keyring())
    rec = Recorder(rd, lambda b: S.sign("ks.gateway", b))
    txn = rec.begin()
    assert txn.seq == 1
    with pytest.raises(RecorderAborted):
        rec.begin()                                  # one open txn at a time
    boom = OSError("disk full")
    rd.append = lambda doc: (_ for _ in ()).throw(boom)   # the append fails after the (notional) commit
    with pytest.raises(OSError):
        txn.append(**_denial())
    assert rec.aborted and rec.seq == 0
    with pytest.raises(RecorderAborted):
        rec.begin()                                  # the run is over: never silent, never reuse seq 1


def test_rollback_releases_the_seq_without_a_gap(tmp_path):
    rd = RunDir.create(tmp_path / "run", S.run_config(), S.keyring())
    rec = Recorder(rd, lambda b: S.sign("ks.gateway", b))
    t = rec.begin()
    t.rollback()
    r = rec.append(**_denial())
    assert r.seq == 1


def _denial() -> dict:
    from ks.contracts import ActionClass, Decision, Reason
    env = S.envelope()
    return dict(tick=1, ts_us=1_000_001_000, conn_id="c-3", envelope=env.header(), envelope_hash=env.content_hash(),
                sig_ok=False, decision=Decision.DENY, reason=Reason.BAD_SIG, policy_rule=None,
                action_class=ActionClass.R, read_set=(), write_set=(), outbox_ids=(), result_hash=None,
                control=None, reexec_of=None)


def test_gateway_hooks_exist_and_are_noops():
    h = GatewayHooks()
    assert h.skip_checkpoint(0) is False and h.skip_checkpoint(10**6) is False
    assert h.between_check_and_txn(object()) is None


def test_gateway_accepts_hooks():
    import inspect

    from ks.gateway import Gateway
    assert "hooks" in inspect.signature(Gateway.__init__).parameters


# --- one checkpoint per tick; a stalled tick is witness_ack=false (test_hung_witness) -------------------------
def _run(tmp_path, **kw):
    from ks.runtime.run import run
    return run(agents=2, ticks=8, seed=3, key_mode="fresh", out=tmp_path / "r", tick_deadline_ms=400,
               say=lambda s: None, **kw)


def test_hung_witness_marks_tick_unacked_and_run_still_verifies(tmp_path, monkeypatch):
    import ks.runtime.run as runmod
    real = runmod.WitnessLink.push
    stalled = {3, 4}

    def push(self, seq, head, tick, timeout_s):
        return real(self, seq, head, tick, 0.0 if tick in stalled else timeout_s)  # deadline already passed

    monkeypatch.setattr(runmod.WitnessLink, "push", push)
    res = _run(tmp_path)
    timing = [json.loads(l) for l in (res.rundir.path / "timing.jsonl").read_text().splitlines()]
    acked = {t["tick"]: t["witness_ack"] for t in timing}
    assert acked[3] is False and acked[4] is False and acked[5] is True
    cps = list(res.rundir.witness())
    ticks = [c.tick for c in cps]
    assert ticks == sorted(set(ticks)), "at most one checkpoint per tick, strictly increasing"
    assert res.stalls >= 2
    rep = verify(res.rundir.path, res.anchor)
    assert rep.ok and rep.anchored


def test_skip_checkpoint_hook_withholds_the_push(tmp_path, monkeypatch):
    import ks.runtime.run as runmod

    class Skip(GatewayHooks):
        def skip_checkpoint(self, tick):
            return tick >= 5

    orig = runmod.Gateway

    class G(orig):
        def __init__(self, *a, **k):
            super().__init__(*a, hooks=Skip(), **k)

    monkeypatch.setattr(runmod, "Gateway", G)
    res = _run(tmp_path)
    assert max(c.tick for c in res.rundir.witness()) < 5
