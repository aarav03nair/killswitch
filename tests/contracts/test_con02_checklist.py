"""CON-02 checklist (CALL-02/resolutions.md) + amendments X1, X2, X7, X8-F1 + PMO S5: one test per item."""

import re
from pathlib import Path

import pytest

import ks.contracts as C
from ks.contracts import (
    APPROVE_TOOL, BASELINES_DIR, CONTROL_TOOL, HARD_ALLOWED, HARD_DETECTORS, MAX_SIGN_PER_TICK, MAX_VIEW_ENTRIES,
    REASONS_FOR, SCORER_ONLY_FIELDS, SYSTEM_CONN, SYSTEM_PRINCIPALS, VERIFY_REASONS, WITNESS_HEADS_DIR, ActionClass,
    Alert, AlertKind, Approval, CanonicalError, ContractError, Control, ControlOp, Decision, Detector, Envelope,
    Exit, KeyEntry, Keyring, ReadEntry, Reason, Record, RecoverArgs, RecoveryPlan, RunConfig, RunDir, SignRequest,
    TickFrame, VerifyReport, ViewEntry, WitnessCheckpoint, canonical, decode_frame, field_obj_id, is_field_obj,
    make_obj_id, recover_tool, row_obj_id, signer_refusal, split_obj_id, system_tool_signers, value_hash,
)
from ks.contracts import rundir as C6

import samples as S

SRC = Path(C.__file__).resolve().parent


# ===================================== helpers =====================================================
def sys_env(agent, tool, args, action_id="s-1"):
    e = Envelope(agent_id=agent, action_id=action_id, parent_action_id=None, act_chain=(), tool=tool, args=args,
                 nonce="0123456789abcdef0123456789abcdef", expiry_tick=12, epoch=0, claimed_ts_us=None,
                 claimed_seq=None, sig=None)
    return e.with_sig(S.sign(agent if agent.startswith("ks.") or True else agent, e.signing_bytes()))


def rec(env, *, conn="c-0", decision="exec", reason="ok", sig_ok=True, control=None, tick=12, seq=5, **kw):
    return Record.model_validate(Record.seal(
        prev_hash="0" * 64, seq=seq, tick=tick, ts_us=1, record_id=f"r-{seq:06d}", conn_id=conn,
        envelope=env.header(), envelope_hash=env.content_hash(), sig_ok=sig_ok, decision=decision, reason=reason,
        policy_rule=None, action_class=kw.pop("action_class", ActionClass.R), read_set=(), write_set=(),
        outbox_ids=(), result_hash=None, control=control, reexec_of=None, **kw).to_obj())


def ctl(issued_by="ks.monitor", auto=True, op="suspend", target="agent:crm", epoch=1):
    return Control(control_id="k-000009", op=op, target=target, epoch=epoch, alert_id=None, issued_by=issued_by,
                   auto=auto, reason="t")


def alert(**over):
    base = S.alert_invariant().to_obj()
    base.update(over)
    return Alert.model_validate(base)


# ===================================== C1 ==========================================================
def test_c1_constants():
    assert C.MAX_EXPIRY_TICKS == 8 and C.MAX_DEPTH == 32 and canonical.MAX_DEPTH == 32


@pytest.mark.parametrize("bad", [
    b'{"tick":true,"type":"noop"}\n', b'{"tick":1,"type":"bogus"}\n', b'{"tick":1}\n', b"\xff\n", b"[]\n",
    b'{"tick":' + b"9" * 400 + b',"type":"noop"}\n', b'{"tick":1.5,"type":"noop"}\n', b'{"tick":1,"type":"noop"}',
    b'{"epoch":0,"tick":1,"type":"tick","view":[{"hash":"' + b"0" * 64 + b'","obj":"a:b","value":1,"ver":1}]}\n',
    b'{"envelope":{},"tick":1,"type":"submit"}\n', b"[" * 40 + b"]" * 40 + b"\n", "x", None, 5,
])
def test_c1_every_decode_exception_is_canonical_error(bad):
    with pytest.raises(CanonicalError):
        decode_frame(bad)


def test_c1_from_canonical_wraps_validation():
    obj = canonical.loads(S.record_exec().to_canonical())
    obj["tick"] = -1
    with pytest.raises(ContractError):
        Record.from_canonical(canonical.dumps(obj))


# ===================================== transport ===================================================
def _view(obj="suppliers:S-17", value=None):
    value = {"name": "Acme Steel"} if value is None else value
    return ViewEntry(obj=obj, ver=4, hash=value_hash(value), value=value)


def test_transport_tickframe_epoch_and_view():
    assert {"epoch", "view"} <= set(TickFrame.model_fields)
    t = TickFrame(tick=1, epoch=3, view=(_view("tickets:T-3", 1), _view()))
    assert [v.obj for v in t.view] == ["suppliers:S-17", "tickets:T-3"]          # sorted
    assert t.view[0].read_entry() == ReadEntry(obj="suppliers:S-17", ver=4, hash=value_hash({"name": "Acme Steel"}))
    with pytest.raises(ValueError):
        ViewEntry(obj="suppliers:S-17", ver=4, hash=S.H_OLD, value={"name": "x"})  # hash checked
    with pytest.raises(ValueError):
        TickFrame(tick=1, epoch=0, view=(_view(), _view()))                     # duplicate obj
    assert MAX_VIEW_ENTRIES == 64
    many = tuple(_view(f"tickets:T-{i}", i) for i in range(MAX_VIEW_ENTRIES + 1))
    with pytest.raises(ValueError):
        TickFrame(tick=1, epoch=0, view=many)
    TickFrame(tick=1, epoch=0, view=many[:MAX_VIEW_ENTRIES])


def test_transport_signer_refusals():
    assert MAX_SIGN_PER_TICK == 2
    hdr = S.envelope().header().model_copy(update={"sig": None})
    ok = SignRequest(header=hdr)
    kw = dict(principal="crm", current_epoch=0, signed_this_tick=0)
    assert signer_refusal(ok, **kw) is None
    assert signer_refusal(ok, **{**kw, "signed_this_tick": MAX_SIGN_PER_TICK}) == "rate"
    assert signer_refusal(ok, **{**kw, "principal": "billing"}) == "foreign_agent"
    assert signer_refusal(SignRequest(header=hdr.model_copy(update={"tool": "ks.control"})), **kw) == "system_tool"
    assert signer_refusal(SignRequest(header=S.envelope().header()), **kw) == "presigned"
    assert signer_refusal(ok, **{**kw, "current_epoch": None}) == "suspended"
    assert signer_refusal(ok, **{**kw, "current_epoch": 4}) == "stale_epoch"


# ===================================== C2 ==========================================================
def test_c2_witness_count_field():
    with pytest.raises(ValueError):
        WitnessCheckpoint.model_validate({**S.witness(S.chain()[-1]).to_obj(), "count": None})
    with pytest.raises(ValueError):
        WitnessCheckpoint.model_validate({**S.witness(S.chain()[-1]).to_obj(), "witness_id": "ks.gateway"})


def test_c2_new_reasons():
    assert Reason.LATE_FRAME in REASONS_FOR[Decision.DENY] and Reason.OVER_QUOTA in REASONS_FOR[Decision.DENY]
    assert Reason.STALE_PLAN in REASONS_FOR[Decision.HOLD]
    restore = S.plan().steps[0]
    env = sys_env("ks.recovery", recover_tool("restore"), S.plan().recover_args(0).to_obj())
    rec(env, decision="hold", reason="stale_plan")
    with pytest.raises(ValueError, match="stale_plan"):
        rec(sys_env("ks.monitor", CONTROL_TOOL, ctl().to_obj()), decision="hold", reason="stale_plan")
    base = S.record_exec().to_obj()
    Record.model_validate({**base, "decision": "deny", "reason": "late_frame", "read_set": [], "write_set": [],
                           "result_hash": None})
    assert restore.op == "restore"


def test_c2_n1_sig_ok_requires_sig():
    e = S.envelope().model_copy(update={"sig": None})
    base = S.record_exec().to_obj()
    with pytest.raises(ValueError, match="sig_ok requires"):
        Record.model_validate({**base, "envelope": e.header().to_obj()})


def test_c2_k4_system_principal_conn_both_ways():
    assert SYSTEM_CONN == "c-0"
    c = ctl()
    env = sys_env("ks.monitor", CONTROL_TOOL, c.to_obj())
    rec(env, control=c)                                                      # c-0, verified: fine
    with pytest.raises(ValueError, match="c-0"):                             # system id verified on c-3
        rec(env, conn="c-3", control=c)
    rec(env, conn="c-3", sig_ok=False, decision="deny", reason="bad_sig")    # E1: bad_sig, unverified
    agent = S.envelope()
    with pytest.raises(ValueError, match="c-0 carries system envelopes only"):
        rec(agent, conn="c-0")


def test_c2_sec03_f2_probes():
    c = ctl()
    # exec ks.control signed by agent crm
    crm_ctl = Envelope.model_validate({**sys_env("ks.monitor", CONTROL_TOOL, c.to_obj()).to_obj(), "agent_id": "crm",
                                       "sig": None})
    crm_ctl = crm_ctl.with_sig(S.sign("crm", crm_ctl.signing_bytes()))
    with pytest.raises(ValueError, match="always denied"):
        rec(crm_ctl, conn="c-3", control=c)
    rec(crm_ctl, conn="c-3", decision="deny", reason="out_of_scope")         # what the gateway records
    # exec ks.control from ks.operator carrying issued_by=ks.monitor
    op_ctl = sys_env("ks.operator", CONTROL_TOOL, c.to_obj())
    with pytest.raises(ValueError, match="issued_by"):
        rec(op_ctl, control=c)
    # exec ks.recover.restore from crm
    crm_rec = Envelope.model_validate({**sys_env("ks.recovery", recover_tool("restore"), {}).to_obj(),
                                       "agent_id": "crm", "sig": None})
    crm_rec = crm_rec.with_sig(S.sign("crm", crm_rec.signing_bytes()))
    with pytest.raises(ValueError):
        rec(crm_rec, conn="c-3")
    # a system principal executes only its own ks.* tools
    with pytest.raises(ValueError, match="may not execute"):
        rec(sys_env("ks.monitor", "ks.dispatch", {}))
    with pytest.raises(ValueError, match="may not execute"):
        rec(sys_env("ks.gateway", "crm.update_supplier", {}))
    with pytest.raises(ValueError, match="may not execute"):
        rec(sys_env("ks.recovery", "ks.recover.rollback", {}))
    rec(sys_env("ks.gateway", "ks.dispatch", {}))
    rec(sys_env("ks.monitor", "ks.alert", S.alert_invariant().to_obj()))
    assert system_tool_signers("ks.recover.rerun") == {"ks.recovery"}
    assert system_tool_signers("ks.unknown") == frozenset()


def test_c2_determinism_view_projection():
    r = S.record_exec()
    v = C.determinism_view(r)
    assert set(r.to_obj()) - set(v) == {"hash", "prev_hash", "gw_sig"}
    assert "sig" not in v["envelope"] and v["envelope_hash"] == r.envelope_hash
    assert C.determinism_view(S.record_garbage(r.hash))["envelope"] is None
    assert C.determinism_view(S.alert_invariant()) == S.alert_invariant().to_obj()


# ===================================== C3 / X1 / X2 ================================================
def test_c3_field_obj_id_roundtrip():
    o = field_obj_id("suppliers", "S-17", "iban")
    assert o == "suppliers:S-17.iban" and split_obj_id(o) == ("suppliers", "S-17", "iban")
    assert row_obj_id(o) == "suppliers:S-17" and row_obj_id("suppliers:S-17") == "suppliers:S-17"
    assert is_field_obj(o) and not is_field_obj("outbox:ob-000001")
    assert make_obj_id("suppliers", "S-17") == "suppliers:S-17"
    for bad in (("suppliers", "S.17", "iban"), ("suppliers", "S-17", "Iban"), ("suppliers", "S-17", "a.b")):
        with pytest.raises(ValueError):
            field_obj_id(*bad)
    assert C.state.OBJ_ID_RE == r"^[a-z][a-z0-9_]{0,31}:[A-Za-z0-9_.-]{1,128}$"   # B1: unchanged


def test_c3_sensitive_field_objects_from_config():
    cfg = S.run_config(sensitive_fields=("customers.email", "suppliers.iban"))
    assert cfg.field_objs_of("suppliers:S-17") == ("suppliers:S-17.iban",)     # X2: whole-row read adds these
    assert cfg.field_objs_of("customers:C-1") == ("customers:C-1.email",)
    assert cfg.field_objs_of("tickets:T-3") == ()
    with pytest.raises(ValueError):
        cfg.field_objs_of("suppliers:S-17.iban")
    doc = C.state.__doc__
    for phrase in ("whole-row read", "omits the field", "does not bump the row", "Aggregates enumerate rows",
                   "tombstone", "seq > *s*", "``ks.recovery``"):
        assert phrase in doc, phrase


# ===================================== C4 ==========================================================
def test_c4_tamper_and_stall_never_hard():
    assert AlertKind.TAMPER not in HARD_ALLOWED and AlertKind.WITNESS_STALL not in HARD_ALLOWED
    for kind, det in ((AlertKind.TAMPER, Detector.TAMPER), (AlertKind.WITNESS_STALL, Detector.WITNESS_STALL)):
        with pytest.raises(ValueError):
            alert(kind=kind, detector=det, hard=True, root_candidates=[])
        alert(kind=kind, detector=det, hard=False, root_candidates=[])


def test_hard_table():
    assert HARD_DETECTORS == {"inv.beneficiary_changed_then_paid", "inv.ledger_balance", "inv.iban_checksum",
                              "inv.pii_egress", "scope", "reconcile", "sig"}
    for det in ("anomaly.price_vs_history", "rate", "barrier.deadline", "verify", "witness_stall", "inv.custom"):
        assert det not in HARD_DETECTORS
    with pytest.raises(ValueError, match="H3"):
        alert(hard=False)                                          # a hard detector must be hard
    with pytest.raises(ValueError):
        alert(detector="inv.custom")                               # unlisted detectors are soft
    alert(detector="inv.custom", hard=False)
    with pytest.raises(ValueError, match="kind"):
        alert(detector="scope")                                    # detector/kind must agree
    alert(detector="scope", kind="scope")
    alert(detector="anomaly.price_vs_history", kind="anomaly", hard=False)
    with pytest.raises(ValueError):
        alert(detector="rate", kind="rate", hard=True)


def test_c4_empty_evidence_cases():
    # M3 + PMO S5: barrier.deadline may carry conn_id, empty evidence, and never names an agent
    b = alert(detector="barrier.deadline", kind="anomaly", hard=False, evidence_seqs=[], evidence_versions=[],
              root_candidates=[], conn_id="c-5")
    assert b.conn_id == "c-5" and b.root_candidates == ()
    alert(detector="barrier.deadline", kind="anomaly", hard=False, evidence_seqs=[], root_candidates=[])
    with pytest.raises(ValueError, match="never an agent"):
        alert(detector="barrier.deadline", kind="anomaly", hard=False, evidence_seqs=[], root_candidates=["crm"],
              conn_id="c-5")
    with pytest.raises(ValueError, match="never an agent"):
        alert(detector="barrier.deadline", kind="anomaly", hard=False, evidence_seqs=[], root_candidates=["crm"])
    # K6 + PMO S5: reconcile with empty evidence names nobody
    alert(detector="reconcile", kind="reconcile", evidence_seqs=[], evidence_versions=[], root_candidates=[])
    with pytest.raises(ValueError, match="name nobody"):
        alert(detector="reconcile", kind="reconcile", evidence_seqs=[], root_candidates=["crm"])
    with pytest.raises(ValueError, match="conn_id"):
        alert(detector="reconcile", kind="reconcile", evidence_seqs=[], root_candidates=[], conn_id="c-5")
    # every other alert still needs evidence
    with pytest.raises(ValueError, match="non-empty"):
        alert(evidence_seqs=[])
    with pytest.raises(ValueError, match="non-empty"):
        alert(detector="anomaly.price_vs_history", kind="anomaly", hard=False, evidence_seqs=[])
    with pytest.raises(ValueError, match="conn_id"):
        alert(conn_id="c-5")


def test_c4_docs_m9_m10_k15_release():
    assert "root_candidates[0]" in Alert.model_fields["root_candidates"].description
    assert "never stored" in Alert.model_fields["root_candidates"].description
    assert "re-executes the held envelope" in (SRC / "control.py").read_text()
    assert "issued_by == envelope.agent_id" in C.control.__doc__
    assert "never reuses the pre-suspend one" in C.control.__doc__


def test_c4_operator_issues_manual_controls():
    ctl(issued_by="ks.operator", auto=False, op="revoke", epoch=2)
    with pytest.raises(ValueError):
        ctl(issued_by="ks.monitor", auto=True, op="revoke", epoch=2)


# ===================================== C5 ==========================================================
def test_c5_t0_seq_est_and_no_m13():
    assert "t0_seq_est" in RecoveryPlan.model_fields and "t0_seq" not in RecoveryPlan.model_fields
    bad = S.plan().to_obj()
    bad["t0_seq_est"] = 99
    with pytest.raises(ValueError):
        RecoveryPlan.model_validate(bad)
    assert "fault_tick" in RecoveryPlan.model_fields["t0_seq_est"].description   # documented as never read
    assert "culprit's after-version" in C.RestoreStep.model_fields["expect"].description


def test_recover_bound_to_approval():
    p = S.plan()
    a = p.approval()
    assert isinstance(a, Approval) and a.plan_hash == p.content_hash() and a.steps == tuple(range(len(p.steps)))
    assert p.approval((3, 0)).steps == (0, 3)
    with pytest.raises(ValueError):
        Approval(plan_id=p.plan_id, plan_hash=a.plan_hash, steps=(1, 1))
    ra = p.recover_args(2)
    assert ra.step == p.steps[2] and ra.n == 2 and ra.plan_hash == a.plan_hash
    with pytest.raises(ValueError):
        RecoverArgs(plan_id=p.plan_id, plan_hash=a.plan_hash, n=1, step=p.steps[2])
    assert recover_tool("cancel_outbox") == "ks.recover.cancel_outbox" and APPROVE_TOOL == "ks.approve"
    rec(sys_env("ks.operator", APPROVE_TOOL, a.to_obj()))
    rec(sys_env("ks.recovery", recover_tool(ra.step.op), ra.to_obj()))
    with pytest.raises(ValueError, match="may not execute"):
        rec(sys_env("ks.monitor", APPROVE_TOOL, a.to_obj()))
    with pytest.raises(ValueError):
        rec(sys_env("ks.operator", recover_tool("restore"), ra.to_obj()))
    edited = p.to_obj()
    edited["steps"][0]["reason"] = "edited"
    assert RecoveryPlan.model_validate(edited).content_hash() != a.plan_hash      # an edited plan file no longer binds


# ===================================== C6 ==========================================================
def test_c6_run_config_new_fields():
    c = S.run_config()
    assert (c.fault_tick, c.key_mode, c.decision_latency_ticks) == (12, "fresh", 2)
    with pytest.raises(ValueError, match="fault_tick"):
        S.run_config(fault_tick=None)
    with pytest.raises(ValueError, match="fault_tick"):
        S.run_config(fault=None, culprit=None)                 # fault_tick left set
    S.run_config(fault=None, culprit=None, fault_tick=None)
    for t in (9, 21):
        with pytest.raises(ValueError, match="A2"):
            S.run_config(fault_tick=t)                         # [T/4, T/2] = [10, 20]
    S.run_config(fault_tick=10), S.run_config(fault_tick=20)
    for f in ("F2+x", "F2+c", "rogue"):
        S.run_config(fault=f)
    with pytest.raises(ValueError):
        S.run_config(decision_latency_ticks=-1)


def test_tcb_blind():
    c = S.run_config()
    t = c.tcb_view()
    assert SCORER_ONLY_FIELDS == ("fault", "culprit", "fault_tick")
    assert (t.fault, t.culprit, t.fault_tick) == (None, None, None)
    assert {k: v for k, v in t.to_obj().items() if k not in SCORER_ONLY_FIELDS} == \
        {k: v for k, v in c.to_obj().items() if k not in SCORER_ONLY_FIELDS}
    assert b'"culprit":null' in t.to_canonical() and b'"fault_tick":null' in t.to_canonical()


def test_keyring_complete():
    k = S.keyring()
    assert k.problems(S.run_config()) == []
    no_op = tuple(e for e in k.keys if e.principal != "ks.operator")
    with pytest.raises(ValueError, match="ks.operator"):
        Keyring(keys=no_op)
    no_agent = Keyring(keys=tuple(e for e in k.keys if e.principal != "triage"))
    assert no_agent.problems(S.run_config()) == ["missing key: triage"]
    extra = Keyring(keys=tuple(sorted(k.keys + (KeyEntry(principal="zed", pub=S.pub("zed")),),
                                      key=lambda e: e.principal)))
    assert extra.problems(S.run_config()) == ["unexpected key: zed"]
    with pytest.raises(ValueError, match="incomplete keyring"):
        RunDir.create(Path("/nonexistent-never-created"), S.run_config(), no_agent)


def test_c6_rundir_layout(tmp_path):
    rd = RunDir.create(tmp_path / "r", S.run_config(), S.keyring())
    assert (rd.path / WITNESS_HEADS_DIR).is_dir() and (rd.path / BASELINES_DIR).is_dir()
    assert WITNESS_HEADS_DIR == "witness-heads" and BASELINES_DIR == "baselines"
    assert rd.validate() == []
    with pytest.raises(ValueError, match="escapes"):
        rd.write("../outside.json", b"{}")


def test_c6_exit_and_verify_reasons():
    assert Exit.DIVERGED == 6 and Exit.USAGE == 64
    k16 = {"ok", "parse_error", "hash_mismatch", "seq_gap", "gw_sig_invalid", "agent_sig_mismatch",
           "side_entry_mismatch", "witness_missing", "witness_sig_invalid", "witness_mismatch", "count_mismatch",
           "truncated", "head_mismatch", "keyring_mismatch", "reconcile_mismatch", "no_state"}
    assert k16 <= set(VERIFY_REASONS)
    assert VERIFY_REASONS["parse_error"] == Exit.TAMPER and VERIFY_REASONS["truncated"] == Exit.WITNESS
    assert VERIFY_REASONS["side_entry_mismatch"] == Exit.TAMPER and VERIFY_REASONS["diverged"] == Exit.DIVERGED
    kw = dict(last_witnessed_seq=0, anchored=False, unanchored_reason="no_anchor")
    VerifyReport(ok=False, exit=int(Exit.WITNESS), first_bad=5, reason="truncated", **kw)
    with pytest.raises(ValueError, match="implies"):
        VerifyReport(ok=False, exit=int(Exit.IO), first_bad=1, reason="parse_error", **kw)   # K16: TAMPER, not IO
    with pytest.raises(ValueError, match="unknown"):
        VerifyReport(ok=False, exit=2, first_bad=1, reason="weird", **kw)
    with pytest.raises(ValueError):
        VerifyReport(ok=True, exit=0, first_bad=3, reason="ok", **kw)
    assert "verify != OK" in C.recovery.__doc__ and "rest of the run" in C.recovery.__doc__   # M12


def test_c6_sensitive_fields_doc():
    d = RunConfig.model_fields["sensitive_fields"].description
    for phrase in ("table:pk.field", "max(tick + H, v + 2H)", "hold_window_ticks", "reason=sensitive_field"):
        assert phrase in d, phrase


# ===================================== ids / X7 ====================================================
def test_ids_operator_replaces_console():
    assert SYSTEM_PRINCIPALS == {"ks.gateway", "ks.monitor", "ks.operator", "ks.recovery", "ks.witness"}
    with pytest.raises(ValueError):
        KeyEntry(principal="ks.console", pub=S.pub("x"))
    with pytest.raises(ValueError):
        Envelope.model_validate({**S.envelope().to_obj(), "agent_id": "ks.console"})
    with pytest.raises(ValueError):
        Envelope.model_validate({**S.envelope().to_obj(), "agent_id": "ks.nobody"})
    offenders = [p.name for p in SRC.rglob("*.py") if re.search(r"ks\.console", p.read_text(encoding="utf-8"))]
    offenders += [p.name for p in (SRC / "schema").glob("*.json") if "ks.console" in p.read_text(encoding="utf-8")]
    assert offenders == []


def test_contracts_version_bumped():
    # 1.1.0 at CON-02; later additive bumps (1.2.0, B3-01) keep this check honest without pinning the minor.
    assert tuple(map(int, C.CONTRACTS_VERSION.split("."))) >= (1, 1, 0)
    assert S.run_config().contracts_version == C.CONTRACTS_VERSION
    assert all(f"/schema/{C.CONTRACTS_VERSION}/" in p.read_text() for p in (SRC / "schema").glob("*.json"))
