"""B3-31: dispatch window (F4), alerts.jsonl cross-check (F6), side-store check, freeze from chained alerts, skeleton rule."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "contracts"))
import samples as S  # noqa: E402
from test_contracts_13 import _rechain, _run, _seal  # noqa: E402

from ks.contracts import (ActionClass, Control, ControlOp, Decision, Envelope, Exit, ObjVer, Reason, Record,  # noqa: E402
                          ReadEntry, SideDomain, SideEntry, VersionRef, WriteEntry, sidestore_relpath)
from ks.contracts.control import Alert, AlertKind  # noqa: E402
from ks.verify import verify  # noqa: E402
from ks.verify.window import Violation, frozen_from_records, window_pass  # noqa: E402

Q = dict(log=lambda s: None)
H64 = "a" * 64


def _rec(seq, tick, agent, tool, args, *, control=None, write_set=(), read_set=(), outbox_ids=(), conn=None):
    sysp = agent.startswith("ks.")
    env = Envelope(agent_id=agent, action_id=f"{tool}-{seq}", parent_action_id=None, act_chain=(), tool=tool, args=args,
                   nonce=f"{seq:032x}", expiry_tick=tick, epoch=0, claimed_ts_us=None, claimed_seq=None, sig=None)
    env = env.with_sig(S.sign(agent, env.signing_bytes()))
    return Record.seal(prev_hash="0" * 64, seq=seq, tick=tick, ts_us=1_000_000_000 + tick * 1000 + seq,
                       record_id=f"r-{seq:06d}", conn_id=conn or ("c-0" if sysp else "c-1"), envelope=env.header(),
                       envelope_hash=env.content_hash(), sig_ok=True, decision=Decision.EXEC, reason=Reason.OK,
                       policy_rule=None, action_class=ActionClass.I1 if not sysp else ActionClass.R, read_set=read_set,
                       write_set=write_set, outbox_ids=outbox_ids, result_hash=None, control=control, reexec_of=None)


def _w(ver):
    return WriteEntry(obj="outbox:ob-000001", before=None if ver == 1 else VersionRef(ver=ver - 1, hash=H64),
                      after=VersionRef(ver=ver, hash=H64))


def _create(seq=2, tick=10):
    return _rec(seq, tick, "payments", "payments.send", {"x": 1}, write_set=(_w(1),), outbox_ids=("ob-000001",))


def _dispatch(seq, tick):
    return _rec(seq, tick, "ks.gateway", "ks.dispatch", {"outbox": "ob-000001"}, write_set=(_w(2),))


def _ctl(seq, tick, op, target, **kw):
    manual = op in (ControlOp.UNHOLD, ControlOp.RELEASE)
    issuer = "ks.operator" if manual else "ks.gateway"
    epoch = 1 if target.startswith("agent:") and op in (ControlOp.SUSPEND, ControlOp.RELEASE) else None
    c = Control(control_id=f"k-{seq:06d}", op=op, target=target, epoch=epoch, alert_id=None, issued_by=issuer,
                auto=not manual, reason="lineage_hold")
    return _rec(seq, tick, issuer, "ks.control", c.to_obj(), control=c)


def _alert(seq, tick, aid, kind=AlertKind.TAMPER, detector="verify", versions=()):
    a = Alert(alert_id=f"a-{aid:06d}", tick=tick, seq=seq - 1, detector=detector, kind=kind, hard=False,
              evidence_seqs=(1,), evidence_versions=versions, root_candidates=(), conn_id=None)
    return _rec(seq, tick, "ks.monitor", "ks.alert", a.to_obj()), a


def _side(run: Path, a: Alert):
    from ks.contracts import args_hash
    h = args_hash(a.to_obj())
    p = run / sidestore_relpath(h)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(SideEntry(hash=h, domain=SideDomain.ARGS, value=a.to_obj(), redacted=False).to_canonical())


def _cfg():
    return S.run_config()  # hold_window_ticks=3


def _ok(recs):
    window_pass(Path("/nonexistent"), _rechain(_seal(), *recs), _cfg())


def _bad(recs):
    with pytest.raises(Violation) as e:
        _ok(recs)
    return e.value


def test_dispatch_window_clean_and_early():
    _ok([_create(2, 10), _dispatch(3, 13)])
    v = _bad([_create(2, 10), _dispatch(3, 12)])
    assert (v.reason, v.first_bad) == ("window_violation", 3)


def test_dispatch_window_hold_without_unhold():
    v = _bad([_create(2, 10), _ctl(3, 11, ControlOp.HOLD, "outbox:ob-000001"), _dispatch(4, 13)])
    assert (v.reason, v.first_bad) == ("window_violation", 4)
    _ok([_create(2, 10), _ctl(3, 11, ControlOp.HOLD, "outbox:ob-000001"),
         _ctl(4, 12, ControlOp.UNHOLD, "outbox:ob-000001"), _dispatch(5, 13)])


def test_dispatch_window_author_suspend_and_release():
    v = _bad([_create(2, 10), _ctl(3, 11, ControlOp.SUSPEND, "agent:payments"), _dispatch(4, 13)])
    assert v.reason == "window_violation"
    _ok([_create(2, 10), _ctl(3, 11, ControlOp.SUSPEND, "agent:payments"),
         _ctl(4, 12, ControlOp.RELEASE, "agent:payments"), _dispatch(5, 13)])


def test_dispatch_window_taint_seed_and_double_dispatch(tmp_path):
    ent = ReadEntry(obj="suppliers:S-17", ver=2, hash=H64)
    cr = _rec(2, 10, "payments", "payments.send", {"x": 1}, write_set=(_w(1),), outbox_ids=("ob-000001",),
              read_set=(ent,))
    al, a = _alert(3, 11, 1, AlertKind.TAMPER, "verify", (ObjVer(obj="suppliers:S-17", ver=2),))
    run = tmp_path / "r"
    _side(run, a)
    with pytest.raises(Violation):
        window_pass(run, _rechain(_seal(), cr, al, _dispatch(4, 13)), _cfg())
    with pytest.raises(Violation):
        _ok([_create(2, 10), _dispatch(3, 13), _dispatch(4, 14)])


def test_dispatch_without_creating_record():
    assert _bad([_dispatch(2, 13)]).first_bad == 2


def _run_with(tmp_path, recs, alerts=()):
    run = _run(tmp_path, _rechain(_seal(), *recs))
    for a in alerts:
        _side(run, a)
    return run


def test_verify_window_violation_exit(tmp_path):
    run = _run_with(tmp_path, [_create(2, 10), _dispatch(3, 11)])
    rep = verify(run, **Q)
    assert (rep.exit, rep.reason, rep.first_bad) == (Exit.TAMPER, "window_violation", 3)


def _alerts_run(tmp_path, copy: bool = True):
    r1, a1 = _alert(2, 10, 1)
    r2, a2 = _alert(3, 11, 2, AlertKind.WITNESS_STALL, "witness_stall")
    run = _run_with(tmp_path, [r1, r2], (a1, a2))
    if copy:
        (run / "alerts.jsonl").write_bytes(a1.to_canonical() + b"\n" + a2.to_canonical() + b"\n")
    return run, a1, a2


def test_alerts_cross_check(tmp_path):
    run, a1, a2 = _alerts_run(tmp_path)
    assert verify(run, **Q).reason == "ok"
    (run / "alerts.jsonl").write_bytes(a2.to_canonical() + b"\n")  # tamper alert deleted from the copy
    rep = verify(run, **Q)
    assert (rep.exit, rep.reason, rep.first_bad) == (Exit.TAMPER, "alert_mismatch", 2)


def test_alerts_extra_forged_alert(tmp_path):
    run, a1, a2 = _alerts_run(tmp_path)
    extra, _ = _alert(9, 12, 3)
    forged = Alert(alert_id="a-000003", tick=12, seq=3, detector="rate", kind=AlertKind.RATE, hard=False,
                   evidence_seqs=(1,), evidence_versions=(), root_candidates=(), conn_id=None)
    with open(run / "alerts.jsonl", "ab") as f:
        f.write(forged.to_canonical() + b"\n")
    rep = verify(run, **Q)
    assert (rep.reason, rep.first_bad) == ("alert_mismatch", 4)


def test_live_edit_freezes(tmp_path):
    """FROZEN comes from chained ks.alert records only; the alerts.jsonl copy neither freezes nor unfreezes."""
    run, a1, a2 = _alerts_run(tmp_path)
    recs = list(__import__("ks.contracts", fromlist=["RunDir"]).RunDir(run).records())
    assert frozen_from_records(run, recs) == 2
    (run / "alerts.jsonl").write_bytes(b"")
    assert frozen_from_records(run, recs) == 2
    clean, _ = _run_with(tmp_path / "c", [_create(2, 10)]), None
    crecs = list(__import__("ks.contracts", fromlist=["RunDir"]).RunDir(clean).records())
    assert frozen_from_records(clean, crecs) is None


def test_side_entry_tamper(tmp_path):
    run, a1, _ = _alerts_run(tmp_path)
    from ks.contracts import args_hash
    p = run / sidestore_relpath(args_hash(a1.to_obj()))
    p.write_bytes(p.read_bytes().replace(b"verify", b"Xerify"))
    rep = verify(run, **Q)
    assert (rep.exit, rep.reason) == (Exit.TAMPER, "side_entry_mismatch")


def test_skeleton_read_set_or_outbox_ids_fails(tmp_path):
    from test_contracts_13 import _env
    rd = _run(tmp_path, [_seal(read_set=(), write_set=())], seed_state=False)
    assert rd.exists()
    cfg = S.run_config(scenario="skeleton")
    from ks.contracts import RunDir
    for kw in (dict(read_set=(ReadEntry(obj="suppliers:S-17", ver=1, hash=H64),)), dict(outbox_ids=("ob-000001",))):
        rdir = RunDir.create(tmp_path / f"s{len(kw)}{list(kw)[0]}", cfg, S.keyring())
        r = _rec(1, 0, "crm", "crm.read", {}, **kw)
        r = _rechain(r)[0]
        rdir.append(r)
        rdir.append(S.witness(r, count=1))
        rep = verify(rdir.path, **Q)
        assert (rep.reason, rep.first_bad) == ("seed_invalid", 1)


# --- B3-31 round 2 (kabir probes p31) ---------------------------------------------------------------------------
def test_created_after_seed_dispatch_needs_unhold(tmp_path):
    ent = ReadEntry(obj="suppliers:S-17", ver=2, hash=H64)
    al, a = _alert(2, 9, 1, AlertKind.TAMPER, "verify", (ObjVer(obj="suppliers:S-17", ver=2),))
    cr = _rec(3, 10, "payments", "payments.send", {"x": 1}, write_set=(_w(1),), outbox_ids=("ob-000001",), read_set=(ent,))
    run = tmp_path / "r"
    _side(run, a)
    with pytest.raises(Violation):
        window_pass(run, _rechain(_seal(), al, cr, _dispatch(4, 13)), _cfg())


def test_rerun_recreated_item_dispatch_needs_unhold():
    cr2 = _rec(4, 11, "payments", "payments.send", {"x": 1}, write_set=(_w(2),), outbox_ids=("ob-000001",))
    _bad([_create(2, 10), _ctl(3, 10, ControlOp.HOLD, "outbox:ob-000001"), cr2, _dispatch(5, 14)])


def test_delete_alert_side_entries_is_failure(tmp_path):
    from ks.contracts import args_hash
    run, a1, a2 = _alerts_run(tmp_path)
    for a in (a1, a2):
        (run / sidestore_relpath(args_hash(a.to_obj()))).unlink()
    rep = verify(run, **Q)
    assert (rep.reason, rep.first_bad) == ("side_entry_mismatch", 2)


# --- B3-51 / contracts 1.6: NO-LINEAGE-HOLD contrast run skips ONLY the taint flag -----------------------------------

def _contrast(lineage_hold: bool):
    from ks.contracts import RunConfig
    return RunConfig.model_validate({**_cfg().to_obj(), "hold_window_ticks": 0, "lineage_hold": lineage_hold})


def test_contrast_run_skips_only_the_taint_flag(tmp_path):
    ent = ReadEntry(obj="suppliers:S-17", ver=2, hash=H64)
    cr = _rec(2, 10, "payments", "payments.send", {"x": 1}, write_set=(_w(1),), outbox_ids=("ob-000001",),
              read_set=(ent,))
    al, a = _alert(3, 11, 1, AlertKind.TAMPER, "verify", (ObjVer(obj="suppliers:S-17", ver=2),))
    run = tmp_path / "r"
    _side(run, a)
    tainted = _rechain(_seal(), cr, al, _dispatch(4, 11))
    window_pass(run, tainted, _contrast(False))  # the contrast run lets the tainted item leave
    with pytest.raises(Violation) as e:  # the same dispatch in a normal H=0 run is a window_violation
        window_pass(run, tainted, _contrast(True))
    assert (e.value.reason, e.value.first_bad) == ("window_violation", 4)
    # everything else is still enforced in a contrast run
    for recs in ([_create(2, 10), _ctl(3, 10, ControlOp.HOLD, "outbox:ob-000001"), _dispatch(4, 11)],
                 [_create(2, 10), _ctl(3, 10, ControlOp.SUSPEND, "agent:payments"), _dispatch(4, 11)],
                 [_create(2, 10), _dispatch(3, 10), _dispatch(4, 11)],
                 [_dispatch(2, 10)]):
        with pytest.raises(Violation):
            window_pass(Path("/nonexistent"), _rechain(_seal(), *recs), _contrast(False))
