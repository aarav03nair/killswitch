"""Deterministic sample instances of every contract (shared by tests and the cross-process stability test)."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ks.contracts import (
    CONTRACTS_VERSION, GENESIS_HASH, ActionClass, ActionRef, ActLink, Alert, AlertKind, CancelOutboxStep,
    CompensateStep, Control, ControlOp, Decision, DiffEntry, Envelope, FlagStep, HistoryEntry, KeyEntry, Keyring,
    ObjVer, OutboxItem, OutboxStatus, ReadEntry, Reason, Record, RecoveryPlan, ReplanStep, RerunStep, RestoreStep,
    RunAnchor, RunConfig, SideDomain, SideEntry, StateRead, TaintSet, VerifyReport, VersionRef, WitnessCheckpoint, WriteEntry,
    CONTROL_TOOL, args_hash, idempotency_key, raw_hash, result_hash, value_hash,
)


def key(principal: str) -> Ed25519PrivateKey:
    """Test-only deterministic key. Real keys are generated in memory by ks.identity."""
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"test-key:" + principal.encode()).digest())


def pub(principal: str) -> str:
    return key(principal).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def sign(principal: str, data: bytes) -> str:
    return key(principal).sign(data).hex()


OLD_IBAN = {"name": "Acme Steel", "iban": "DE89370400440532013000"}
NEW_IBAN = {"name": "Acme Steel", "iban": "GB33BUKB20201555555555"}
H_OLD, H_NEW = value_hash(OLD_IBAN), value_hash(NEW_IBAN)


def envelope(agent="crm", action_id="crm-7", tool="crm.update_supplier", args=None, signer=None, **kw) -> Envelope:
    e = Envelope(agent_id=agent, action_id=action_id, parent_action_id=kw.pop("parent_action_id", "T-3"),
                 act_chain=kw.pop("act_chain", (ActLink(principal="intake", action_id="T-3"),)), tool=tool,
                 args=args if args is not None else {"supplier": "S-17", "iban": NEW_IBAN["iban"]},
                 nonce=kw.pop("nonce", "00112233445566778899aabbccddeeff"), expiry_tick=kw.pop("expiry_tick", 12),
                 epoch=kw.pop("epoch", 0), claimed_ts_us=kw.pop("claimed_ts_us", None),
                 claimed_seq=kw.pop("claimed_seq", None), sig=None, **kw)
    return e.with_sig(sign(signer or agent, e.signing_bytes()))


def record_exec(prev=GENESIS_HASH, seq=1) -> Record:
    env = envelope()
    r = Record.seal(
        prev_hash=prev, seq=seq, tick=10, ts_us=1_000_010_000, record_id=f"r-{seq:06d}", conn_id="c-3",
        envelope=env.header(), envelope_hash=env.content_hash(), sig_ok=True, decision=Decision.EXEC,
        reason=Reason.OK, policy_rule=None, action_class=ActionClass.R,
        read_set=(ReadEntry(obj="suppliers:S-17", ver=4, hash=H_OLD), ReadEntry(obj="approvals:A-1", ver=1, hash=H_OLD)),
        write_set=(WriteEntry(obj="suppliers:S-17", before=VersionRef(ver=4, hash=H_OLD),
                              after=VersionRef(ver=5, hash=H_NEW)),),
        outbox_ids=(), result_hash=result_hash({"ok": True}), control=None, reexec_of=None)
    return r.with_gw_sig(sign("ks.gateway", r.signing_bytes()))


def record_forged(prev: str, seq=2) -> Record:
    env = envelope(agent="billing", action_id="b-1", signer="docs", nonce="ffeeddccbbaa99887766554433221100")
    r = Record.seal(prev_hash=prev, seq=seq, tick=11, ts_us=1_000_011_000, record_id=f"r-{seq:06d}",
                    conn_id="c-9", envelope=env.header(), envelope_hash=env.content_hash(), sig_ok=False,
                    decision=Decision.DENY, reason=Reason.BAD_SIG, policy_rule=None, action_class=ActionClass.R,
                    read_set=(), write_set=(), outbox_ids=(), result_hash=None, control=None, reexec_of=None)
    return r.with_gw_sig(sign("ks.gateway", r.signing_bytes()))


def record_garbage(prev: str, seq=3) -> Record:
    r = Record.seal(prev_hash=prev, seq=seq, tick=11, ts_us=1_000_011_001, record_id=f"r-{seq:06d}",
                    conn_id="c-9", envelope=None, envelope_hash=raw_hash(b'{"seq":1}'), sig_ok=False,
                    decision=Decision.DENY, reason=Reason.SCHEMA, policy_rule=None, action_class=ActionClass.U,
                    read_set=(), write_set=(), outbox_ids=(), result_hash=None, control=None, reexec_of=None)
    return r.with_gw_sig(sign("ks.gateway", r.signing_bytes()))


def control_suspend() -> Control:
    return Control(control_id="k-000001", op=ControlOp.SUSPEND, target="agent:crm", epoch=1, alert_id="a-000001",
                   issued_by="ks.monitor", auto=True, reason="hard_alert")


def record_control(prev: str, seq=4) -> Record:
    c = control_suspend()
    env = Envelope(agent_id="ks.monitor", action_id="k-000001", parent_action_id=None, act_chain=(),
                   tool=CONTROL_TOOL, args=c.to_obj(), nonce="0123456789abcdef0123456789abcdef", expiry_tick=12,
                   epoch=0, claimed_ts_us=None, claimed_seq=None, sig=None)
    env = env.with_sig(sign("ks.monitor", env.signing_bytes()))
    r = Record.seal(prev_hash=prev, seq=seq, tick=12, ts_us=1_000_012_000, record_id=f"r-{seq:06d}",
                    conn_id="c-0", envelope=env.header(), envelope_hash=env.content_hash(), sig_ok=True,
                    decision=Decision.EXEC, reason=Reason.OK, policy_rule="hard_alert_suspend",
                    action_class=ActionClass.R, read_set=(), write_set=(), outbox_ids=(), result_hash=None,
                    control=c, reexec_of=None)
    return r.with_gw_sig(sign("ks.gateway", r.signing_bytes()))


def chain() -> list[Record]:
    r1 = record_exec()
    r2 = record_forged(r1.hash)
    r3 = record_garbage(r2.hash)
    r4 = record_control(r3.hash)
    return [r1, r2, r3, r4]


def witness(rec: Record, count: int = 1) -> WitnessCheckpoint:
    w = WitnessCheckpoint(witness_id="ks.witness", seq=rec.seq, tick=rec.tick, head=rec.hash, count=count, sig=None)
    return w.with_sig(sign("ks.witness", w.signing_bytes()))


def outbox_item() -> OutboxItem:
    return OutboxItem(outbox_id="ob-000001", author="payments", action_id="pay-3", created_seq=7, sink="payments",
                      action_class="I1", payload_hash=value_hash({"to": NEW_IBAN["iban"], "minor": 125000}),
                      idempotency_key=idempotency_key("payments", "pay-3", "payments"),
                      lineage=(ReadEntry(obj="suppliers:S-17", ver=5, hash=H_NEW),), status=OutboxStatus.HELD,
                      release_tick=14, dispatched_seq=None)


def alert_invariant() -> Alert:
    return Alert(alert_id="a-000001", tick=11, seq=7, detector="inv.beneficiary_changed_then_paid", kind=AlertKind.INVARIANT,
                 hard=True, evidence_seqs=(1, 7), evidence_versions=(ObjVer(obj="suppliers:S-17", ver=5),),
                 root_candidates=("crm", "intake"), conn_id=None)


def alert_signature() -> Alert:
    return Alert(alert_id="a-000002", tick=11, seq=2, detector="sig", kind=AlertKind.SIGNATURE, hard=True,
                 evidence_seqs=(2,), evidence_versions=(), root_candidates=(), conn_id="c-9")


def plan() -> RecoveryPlan:
    pay = ActionRef(seq=7, agent_id="payments", action_id="pay-3")
    bill = ActionRef(seq=6, agent_id="billing", action_id="bill-2")
    return RecoveryPlan(
        plan_id="p-000001", alert_id="a-000001", culprit="crm", t0_seq_est=1, as_of_seq=9,
        taint_set=TaintSet(versions=(ObjVer(obj="suppliers:S-17", ver=5),), actions=(bill, pay),
                           outbox_ids=("ob-000001",)),
        steps=(RestoreStep(n=0, reason="tainted_write", obj="suppliers:S-17", expect=VersionRef(ver=5, hash=H_NEW),
                           to=VersionRef(ver=4, hash=H_OLD)),
               RerunStep(n=1, reason="tainted_read", action=bill),
               CancelOutboxStep(n=2, reason="tainted_lineage", outbox_id="ob-000001"),
               ReplanStep(n=3, reason="llm_step", action=pay),
               CompensateStep(n=4, reason="class_c", action=bill, compensator="tickets.close"),
               FlagStep(n=5, reason="write_write_conflict", obj="crm_notes:N-2", action=None)),
        diff=(DiffEntry(obj="suppliers:S-17", current=VersionRef(ver=5, hash=H_NEW), planned_hash=H_OLD),))


AGENTS = ("billing", "comms", "compliance", "crm", "docs", "intake", "inventory", "payments", "reporter", "triage")
PRINCIPALS = tuple(sorted(AGENTS + ("ks.gateway", "ks.monitor", "ks.operator", "ks.recovery", "ks.witness")))


def run_config(**over) -> RunConfig:
    base = dict(run_id="seed0-F2plus", contracts_version=CONTRACTS_VERSION, seed=0, scenario="acme", fault="F2+",
                culprit="crm", fault_tick=12, key_mode="fresh", decision_latency_ticks=2, ticks=40, tick_us=1000,
                start_ts_us=1_000_000_000, hold_window_ticks=3, sensitive_fields=("suppliers.iban",), agents=AGENTS)
    base.update(over)
    return RunConfig(**base)


def keyring(keyfn=None) -> Keyring:
    keyfn = keyfn or pub
    return Keyring(keys=tuple(KeyEntry(principal=p, pub=keyfn(p)) for p in PRINCIPALS))


def samples() -> dict[str, object]:
    recs = chain()
    return {
        "envelope": envelope(),
        "envelope_header": envelope().header(),
        "record_exec": recs[0], "record_forged": recs[1], "record_garbage": recs[2], "record_control": recs[3],
        "witness": witness(recs[-1]),
        "outbox_item": outbox_item(),
        "side_value": SideEntry(hash=H_NEW, domain=SideDomain.VALUE, value=NEW_IBAN, redacted=False),
        "side_args": SideEntry(hash=args_hash(envelope().args), domain=SideDomain.ARGS, value=envelope().args,
                               redacted=False),
        "side_raw": SideEntry(hash=raw_hash(b'{"seq":1}'), domain=SideDomain.RAW, value=b'{"seq":1}'.hex(),
                              redacted=False),
        "side_redacted": SideEntry(hash=H_OLD, domain=SideDomain.VALUE, value=None, redacted=True),
        "history_entry": HistoryEntry(obj="suppliers:S-17", ver=5, hash=H_NEW, author="crm", seq=1,
                                      action_id="crm-7"),
        "state_read": StateRead(obj="suppliers:S-17", value=NEW_IBAN, ver=5, author="crm", hash=H_NEW),
        "alert_invariant": alert_invariant(), "alert_signature": alert_signature(),
        "control_suspend": control_suspend(),
        "control_suspend_conn": Control(control_id="k-000002", op=ControlOp.SUSPEND, target="conn:c-9", epoch=None,
                                        alert_id="a-000002", issued_by="ks.gateway", auto=True, reason="bad_sig"),
        "control_hold": Control(control_id="k-000003", op=ControlOp.HOLD, target="outbox:ob-000001", epoch=None,
                                alert_id="a-000001", issued_by="ks.monitor", auto=True, reason="lineage_hold"),
        "control_revoke": Control(control_id="k-000004", op=ControlOp.REVOKE, target="agent:crm", epoch=2,
                                  alert_id="a-000001", issued_by="ks.operator", auto=False, reason="operator"),
        "plan": plan(),
        "run_config": run_config(),
        "keyring": keyring(),
        "verify_report": VerifyReport(ok=True, exit=0, first_bad=None, reason="ok", last_witnessed_seq=4,
                                      anchored=True, unanchored_reason=None),
        "run_anchor": RunAnchor.of(witness(recs[-1]), keyring(), run_config()),
        "approval": plan().approval(),
        "recover_args": plan().recover_args(0),
        "alert_barrier": Alert(alert_id="a-000003", tick=12, seq=4, detector="barrier.deadline",
                               kind=AlertKind.ANOMALY, hard=False, evidence_seqs=(), evidence_versions=(),
                               root_candidates=(), conn_id="c-5"),
    }


# schema file each sample validates against
SCHEMA_OF = {
    "envelope": "c1.envelope", "envelope_header": "c1.envelope_header", "record_exec": "c2.record",
    "record_forged": "c2.record", "record_garbage": "c2.record", "record_control": "c2.record",
    "witness": "c2.witness_checkpoint", "outbox_item": "c3.outbox_item", "side_value": "c3.side_entry",
    "side_args": "c3.side_entry", "side_raw": "c3.side_entry", "side_redacted": "c3.side_entry",
    "history_entry": "c3.history_entry", "state_read": "c3.state_read", "alert_invariant": "c4.alert",
    "alert_signature": "c4.alert", "control_suspend": "c4.control", "control_suspend_conn": "c4.control",
    "control_hold": "c4.control", "control_revoke": "c4.control", "plan": "c5.recovery_plan",
    "run_config": "c6.run_config", "keyring": "c6.keyring", "verify_report": "c6.verify_report",
    "run_anchor": "c6.run_anchor", "approval": "c5.approval", "recover_args": "c5.recover_args",
    "alert_barrier": "c4.alert",
}

if __name__ == "__main__":  # used by the cross-process byte-stability test
    import sys
    for name, obj in sorted(samples().items()):
        sys.stdout.write(f"{name} {obj.to_canonical().hex()}\n")
