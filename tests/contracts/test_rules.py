"""Contract invariants that encode CALL-01 decisions and kabir's day-one rules."""

import jsonschema
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ks.contracts import (
    TOMBSTONE_HASH, ActionClass, Alert, AlertKind, Control, ControlOp, Decision, Envelope, Exit, OutboxStatus,
    Reason, Record, RecoveryPlan, RunConfig, SideDomain, SideEntry, VerifyReport, VersionRef, WriteEntry,
    args_hash, canonical, idempotency_key, make_obj_id, split_obj_id,
)

import samples as S
from test_schema import load_schema


def _rec(**over):
    base = S.record_exec().to_obj()
    base.update(over)
    return base


def _verify(principal, sig_hex, data):
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(S.pub(principal))).verify(bytes.fromhex(sig_hex), data)


# --- action class: unknown rejected, U fail-closed (rule 6) -------------------------------------
@pytest.mark.parametrize("bad", ["X", "r", "I3", "", None, 1])
def test_unknown_action_class_rejected(bad):
    with pytest.raises(ValueError):
        Record.model_validate(_rec(action_class=bad))
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(_rec(action_class=bad), load_schema("c2.record"))


def test_class_u_must_be_denied():
    with pytest.raises(ValueError, match="class U"):
        Record.model_validate(_rec(action_class="U"))


def test_reason_must_match_decision():
    with pytest.raises(ValueError):
        Record.model_validate(_rec(reason="bad_sig"))
    with pytest.raises(ValueError):
        Record.model_validate(_rec(decision="deny", reason="ok"))


def test_unknown_reason_rejected():
    with pytest.raises(ValueError):
        Record.model_validate(_rec(decision="deny", reason="nope", read_set=[], write_set=[], result_hash=None))


def test_deny_has_no_effects():  # rule 11 + no effects
    with pytest.raises(ValueError):
        Record.model_validate(_rec(decision="deny", reason="expired"))


# --- attribution: Q9 / D7 anti-framing ---------------------------------------------------------
def test_forged_record_not_attributed():
    forged = S.chain()[1]
    assert forged.claimed_agent == "billing"
    assert forged.attributed_agent is None
    assert S.record_exec().attributed_agent == "crm"


def test_sig_ok_false_only_for_bad_sig_or_schema():
    with pytest.raises(ValueError, match="sig_ok"):
        Record.model_validate(_rec(sig_ok=False))
    r = S.chain()[1].to_obj()
    r["sig_ok"] = True
    with pytest.raises(ValueError):
        Record.model_validate(r)


def test_signature_alert_names_connection_only():
    with pytest.raises(ValueError):
        Alert.model_validate({**S.alert_signature().to_obj(), "root_candidates": ["billing"]})
    with pytest.raises(ValueError):
        Alert.model_validate({**S.alert_signature().to_obj(), "conn_id": None})


def test_tamper_alert_names_nobody_and_anomaly_never_hard():
    base = {**S.alert_invariant().to_obj(), "kind": "tamper"}
    with pytest.raises(ValueError):
        Alert.model_validate(base)
    Alert.model_validate({**base, "root_candidates": []})
    with pytest.raises(ValueError):
        Alert.model_validate({**S.alert_invariant().to_obj(), "kind": "anomaly"})


def test_alert_has_no_suspect_field_and_candidates_ranked():
    assert "suspect" not in Alert.model_fields
    a = S.alert_invariant()
    assert a.root_candidates == ("crm", "intake")
    with pytest.raises(ValueError):
        Alert.model_validate({**a.to_obj(), "root_candidates": ["crm", "crm"]})


# --- controls (rule 10, D7) ----------------------------------------------------------------------
def test_control_targets():
    c = S.control_suspend().to_obj()
    Control.model_validate({**c, "target": "conn:c-9", "epoch": None})
    for bad in ("crm", "agent:ks.console", "conn:9", "action:crm-7"):
        with pytest.raises(ValueError):
            Control.model_validate({**c, "target": bad})
    with pytest.raises(ValueError):  # hold cannot target an agent
        Control.model_validate({**c, "op": "hold", "epoch": None})


def test_revoke_never_auto():
    c = S.samples()["control_revoke"].to_obj()
    with pytest.raises(ValueError):
        Control.model_validate({**c, "auto": True, "issued_by": "ks.monitor"})
    with pytest.raises(ValueError):
        Control.model_validate({**c, "issued_by": "ks.recovery"})


def test_epoch_required_for_agent_suspend():
    with pytest.raises(ValueError):
        Control.model_validate({**S.control_suspend().to_obj(), "epoch": None})


def test_control_record_binds_args():
    r = S.chain()[3]
    assert r.integrity_problems() == []
    assert r.control == S.control_suspend()
    other = {**S.control_suspend().to_obj(), "target": "agent:docs"}
    tampered = Record.model_construct(**{**r.__dict__, "control": Control.model_validate(other)})
    assert "control does not match envelope args_hash" in tampered.integrity_problems()


# --- envelope ------------------------------------------------------------------------------------
def test_envelope_signature_verifies_over_header_and_survives_redaction():
    e = S.envelope()
    h = e.header()
    _verify("crm", e.sig, h.signing_bytes())         # verify needs only the header (args redacted OK)
    assert h.args_hash == args_hash(e.args)
    assert e.content_hash() == h.content_hash()
    assert "args" not in h.to_obj() and "iban" not in h.to_canonical().decode()


def test_envelope_rejects_floats_unknown_keys_and_bad_chain():
    e = S.envelope().to_obj()
    with pytest.raises(ValueError):
        Envelope.model_validate({**e, "args": {"amount": 12.5}})
    with pytest.raises(ValueError):
        Envelope.model_validate({**e, "seq": 1})  # unknown key -> deny/schema at the gateway
    with pytest.raises(ValueError):
        Envelope.model_validate({**e, "parent_action_id": "other"})
    with pytest.raises(ValueError):
        Envelope.model_validate({**e, "expiry_tick": "12"})  # ticks are integers, no coercion
    with pytest.raises(ValueError):
        Envelope.model_validate({**e, "agent_id": "Crm"})


def test_claimed_fields_are_evidence_only():
    e = S.envelope(claimed_ts_us=5, claimed_seq=1)
    assert e.header().claimed_seq == 1  # kept, signed, recorded; Record.seq is gateway-assigned


# --- record integrity ----------------------------------------------------------------------------
def test_record_chain_and_signatures():
    recs = S.chain()
    assert recs[0].prev_hash == "0" * 64
    for a, b in zip(recs, recs[1:]):
        assert b.prev_hash == a.hash
    for r in recs:
        assert r.integrity_problems() == []
        _verify("ks.gateway", r.gw_sig, r.signing_bytes())
    w = S.witness(recs[-1])
    _verify("ks.witness", w.sig, w.signing_bytes())


def test_tampered_record_detected():
    r = S.record_exec()
    edited = Record.model_validate({**r.to_obj(), "tick": 99})
    assert "hash mismatch" in edited.integrity_problems()


def test_record_holds_no_raw_values():
    for r in S.chain():
        text = r.to_canonical().decode()
        assert S.NEW_IBAN["iban"] not in text and S.OLD_IBAN["iban"] not in text


def test_record_id_and_seq():
    with pytest.raises(ValueError):
        Record.model_validate(_rec(record_id="r-000002"))
    with pytest.raises(ValueError):
        Record.model_validate(_rec(seq=0, record_id="r-000000"))


def test_sets_normalised_sorted():
    r = S.record_exec()
    assert [e.obj for e in r.read_set] == sorted(e.obj for e in r.read_set)


# --- state / outbox / side store -----------------------------------------------------------------
def test_write_versions_monotonic_and_tombstone():
    WriteEntry(obj="t:1", before=None, after=VersionRef(ver=1, hash=TOMBSTONE_HASH))
    with pytest.raises(ValueError):
        WriteEntry(obj="t:1", before=VersionRef(ver=1, hash=TOMBSTONE_HASH), after=VersionRef(ver=3, hash=TOMBSTONE_HASH))


def test_obj_ids():
    assert split_obj_id(make_obj_id("suppliers", "S-17")) == ("suppliers", "S-17")
    with pytest.raises(ValueError):
        make_obj_id("Suppliers", "x")


def test_idempotency_key_deterministic_and_scoped():
    k = idempotency_key("payments", "pay-3", "payments")
    assert k == idempotency_key("payments", "pay-3", "payments")
    assert k != idempotency_key("docs", "pay-3", "payments")  # another agent cannot collide on purpose


def test_outbox_dispatched_seq_iff_dispatched():
    o = S.outbox_item().to_obj()
    with pytest.raises(ValueError):
        type(S.outbox_item()).model_validate({**o, "status": "dispatched"})
    type(S.outbox_item()).model_validate({**o, "status": "dispatched", "dispatched_seq": 9})
    assert {s.value for s in OutboxStatus} == {"queued", "held", "released", "dispatched", "cancelled"}


def test_side_entry_hash_checked():
    with pytest.raises(ValueError):
        SideEntry(hash=S.H_OLD, domain=SideDomain.VALUE, value=S.NEW_IBAN, redacted=False)
    with pytest.raises(ValueError):
        SideEntry(hash=S.H_OLD, domain=SideDomain.VALUE, value=S.OLD_IBAN, redacted=True)


# --- plan / run config / verify ------------------------------------------------------------------
def test_plan_steps_ordered_and_approval():
    p = S.plan()
    assert [s.op for s in p.steps] == ["restore", "rerun", "cancel_outbox", "replan", "compensate", "flag"]
    assert p.needs_approval == (3, 4, 5)
    bad = p.to_obj()
    bad["steps"][1]["n"] = 7
    with pytest.raises(ValueError):
        RecoveryPlan.model_validate(bad)
    bad = p.to_obj()
    bad["steps"][0]["op"] = "rollback"
    with pytest.raises(ValueError):
        RecoveryPlan.model_validate(bad)


def test_run_config_rules():
    c = S.samples()["run_config"].to_obj()
    assert c["hold_window_ticks"] == 3 and c["sensitive_fields"] == ["suppliers.iban"]
    with pytest.raises(ValueError):
        RunConfig.model_validate({**c, "culprit": None})
    with pytest.raises(ValueError):
        RunConfig.model_validate({**c, "agents": ["crm", "billing"], "culprit": "crm"})


def test_verify_exit_codes_and_report():
    assert (Exit.OK, Exit.IO, Exit.TAMPER, Exit.WITNESS, Exit.RECONCILE, Exit.FROZEN) == (0, 1, 2, 3, 4, 5)
    VerifyReport(ok=False, exit=int(Exit.TAMPER), first_bad=7, reason="hash_mismatch", last_witnessed_seq=6)
    with pytest.raises(ValueError):
        VerifyReport(ok=True, exit=int(Exit.TAMPER), first_bad=None, reason="ok", last_witnessed_seq=0)


def test_enums_are_closed():
    assert {c.value for c in ActionClass} == {"R", "C", "I1", "I2", "U"}
    assert {d.value for d in Decision} == {"exec", "deny", "hold"}
    assert {o.value for o in ControlOp} == {"suspend", "revoke", "release", "hold", "unhold"}
    assert AlertKind.RECONCILE == "reconcile"
    assert Reason.NONCE_REUSED == "nonce_reused"
    assert canonical.dumps(Reason.OK) == b'"ok"'
