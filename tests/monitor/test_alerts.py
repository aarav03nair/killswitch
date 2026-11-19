"""C4 conformance: hard table pinned to the validator, ks.alert envelope helper, AST guard, determinism."""

import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

from ks.contracts import (DETECTOR_KIND, HARD_ALLOWED, HARD_DETECTORS, SCORER_ONLY_FIELDS, Alert, Decision,
                          Detector, Envelope, Record, ActionClass, Reason, args_hash)
from ks.contracts import canonical
from ks.monitor import DETECTORS, Monitor, alert_envelope, BarrierMiss

from .world import PAYEE, World, hero_world, clean_world, BAD_CHECK

MONITOR_DIR = Path(__file__).parents[2] / "src" / "ks" / "monitor"


def everything():
    """A world that trips every catalogue detector at once."""
    w = hero_world()
    w.act("crm", "crm.update_supplier", tick=53, writes={"suppliers:S-31.iban": BAD_CHECK} if False else {PAYEE: BAD_CHECK})
    w.act("crm", "crm.update_supplier", tick=54, writes={"suppliers:S-22": {"name": "Beta", "unit_price": 900}})
    w.act("billing", "ledger.post", tick=55, writes={"ledger:L-9": {"debit": 2, "credit": 1}})
    w.act("intake", "supplier.set_risk_note", tick=56, decision=Decision.DENY, reason=Reason.OUT_OF_SCOPE)
    w.act("billing", "ledger.post", tick=57, decision=Decision.DENY, reason=Reason.BAD_SIG, sig_ok=False,
          signer="docs", conn="c-9")
    w.queue_email("comms", tick=58, payload={"body": "SSN 123-45-6789"})
    w.off_log_write("suppliers:S-99", {"x": 1})
    w.act("analytics", "report.run", tick=50)          # its own baseline, then a burst
    for i in range(8):
        w.act("analytics", "report.run", tick=59)
    return w


def test_hard_table():
    """Every catalogue detector emits exactly the C4 table: hard iff in HARD_DETECTORS, kind per DETECTOR_KIND."""
    w = everything()
    got = Monitor().scan(w.ctx(barrier_misses=[BarrierMiss(tick=60, conn_id="c-2")], memory_head=(1, "f" * 64)))
    assert {a.detector for a in got} == set(DETECTORS) == {
        Detector.IBAN_CHECKSUM, Detector.BENEFICIARY_CHANGED_THEN_PAID, Detector.PRICE_VS_HISTORY,
        Detector.LEDGER_BALANCE, Detector.SCOPE, Detector.SIGNATURE, Detector.RECONCILE, Detector.WITNESS_STALL,
        Detector.PII_EGRESS, Detector.BARRIER_DEADLINE, Detector.RATE, Detector.TAMPER}
    for a in got:
        assert a.hard == (a.detector in HARD_DETECTORS)
        assert a.kind == DETECTOR_KIND[a.detector]
        assert (a.kind in HARD_ALLOWED) or not a.hard
        Alert.model_validate(a.to_obj())                                   # round-trips through the validator
    assert {a.detector for a in got if not a.hard} == {
        Detector.PRICE_VS_HISTORY, Detector.WITNESS_STALL, Detector.BARRIER_DEADLINE, Detector.RATE,
        Detector.TAMPER}
    # the validator is the pin: flipping hard on any emitted alert is rejected
    for a in got:
        with pytest.raises(ValidationError):
            Alert.model_validate({**a.to_obj(), "hard": not a.hard})


def test_witness_stall_and_tamper_never_hard_in_contract():
    assert Detector.WITNESS_STALL not in HARD_DETECTORS and Detector.TAMPER not in HARD_DETECTORS


def test_alert_envelope_helper():
    from tests.contracts.samples import pub, sign
    a = Monitor().scan(hero_world().ctx())[0]
    env = alert_envelope(a, lambda b: sign("ks.monitor", b))
    assert env.tool == "ks.alert" and env.agent_id == "ks.monitor" and env.args == a.to_obj()
    assert Alert.model_validate(env.args) == a
    # a gateway-side record of it on c-0 is accepted by the Record validators
    r = Record.seal(prev_hash="0" * 64, seq=1, tick=a.tick, ts_us=1, record_id="r-000001", conn_id="c-0",
                    envelope=env.header(), envelope_hash=env.content_hash(), sig_ok=True, decision=Decision.EXEC,
                    reason=Reason.OK, policy_rule=None, action_class=ActionClass.R, read_set=(), write_set=(),
                    outbox_ids=(), result_hash=None, control=None, reexec_of=None)
    assert r.envelope.args_hash == args_hash(a.to_obj())
    # deterministic nonce/action id: the same alert gives the same envelope bytes
    assert alert_envelope(a, lambda b: sign("ks.monitor", b)).signing_bytes() == env.signing_bytes()


def test_monitor_is_deterministic():
    a1 = [a.to_obj() for a in Monitor().scan(everything().ctx())]
    a2 = [a.to_obj() for a in Monitor().scan(everything().ctx())]
    assert a1 == a2 and canonical.dumps(a1) == canonical.dumps(a2)
    assert [a["alert_id"] for a in a1] == [f"a-{i:06d}" for i in range(1, len(a1) + 1)]


def test_monitor_never_reads_runconfig_fault_or_culprit():
    """AST guard (A3): no RunConfig, no scorer-only field names anywhere in ks.monitor."""
    banned = set(SCORER_ONLY_FIELDS) | {"RunConfig", "tcb_view"}
    hits = []
    for f in sorted(MONITOR_DIR.glob("*.py")):
        for n in ast.walk(ast.parse(f.read_text())):
            names = []
            if isinstance(n, ast.Attribute):
                names.append(n.attr)
            elif isinstance(n, ast.Name):
                names.append(n.id)
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                names += [a.name.split(".")[-1] for a in n.names]
            elif isinstance(n, ast.keyword) and n.arg:
                names.append(n.arg)
            hits += [(f.name, x) for x in names if x in banned]
    assert hits == []


def test_monitor_attribution_uses_attributed_agent_only():
    """Attribution never touches ``claimed_agent`` or ``envelope.agent_id`` directly (Q9)."""
    for f in MONITOR_DIR.glob("*.py"):
        for n in ast.walk(ast.parse(f.read_text())):
            assert not (isinstance(n, ast.Attribute) and n.attr in {"claimed_agent", "agent_id"}), f.name
