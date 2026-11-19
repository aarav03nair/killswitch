"""Contracts 1.2.0 (B3-01, additive): witness link frames, SignRefusal, RunConfig.isolation (+ VerifyReport echo),
RunConfig.decisions_from (R3), verify reason reexec_invalid (F9). Closes SKEL-01 findings 2-4."""

import os
import re
import socket
import threading
from pathlib import Path

import pytest

import ks.contracts as C
from ks.contracts import (GENESIS_HASH, SIGN_REFUSAL_REASONS, VERIFY_REASONS, WITNESS_FILES_FDS, CanonicalError,
                          Exit, NoopFrame, RunConfig, SignRefusal, SignReply, SignRequest, VerifyReport,
                          WitnessCheckpoint, WitnessClose, WitnessFiles, WitnessHead, WitnessInit, WitnessPub,
                          WitnessReady, canonical, decode_frame, decode_witness_frame, encode_frame, signer_refusal)

import samples as S

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "ks"
H = S.record_exec().hash
H2 = "ab" * 32

WITNESS_FRAMES = [
    WitnessInit(key_seed=None), WitnessInit(key_seed="ab" * 32), WitnessPub(pub=S.pub("ks.witness")),
    WitnessFiles(), WitnessReady(), WitnessHead(seq=4, head=H, tick=12), WitnessHead(seq=1, head=H, tick=0),
    WitnessClose(),
]


def test_version_is_1_2_0():
    assert C.CONTRACTS_VERSION == "1.2.0"
    assert "### 1.2.0" in (SRC / "contracts" / "README.md").read_text(encoding="utf-8")


# --- witness link frames (finding 2) --------------------------------------------------------------
@pytest.mark.parametrize("frame", WITNESS_FRAMES, ids=lambda f: f.type)
def test_witness_frame_roundtrip(frame):
    line = encode_frame(frame)
    assert line.endswith(b"\n") and line.count(b"\n") == 1
    assert decode_witness_frame(line) == frame
    assert type(frame).from_canonical(line[:-1]) == frame


@pytest.mark.parametrize("frame", WITNESS_FRAMES, ids=lambda f: f.type)
def test_witness_frame_rejects_unknown_key(frame):
    obj = {**frame.to_obj(), "zz_extra": 1}
    with pytest.raises(CanonicalError):
        decode_witness_frame(canonical.dumps_line(obj))
    with pytest.raises(ValueError):
        type(frame).model_validate(obj)


@pytest.mark.parametrize("frame", WITNESS_FRAMES, ids=lambda f: f.type)
def test_witness_frame_rejects_missing_field(frame):
    obj = frame.to_obj()
    if len(obj) == 1:
        return  # type-only frame
    obj.pop(next(k for k in sorted(obj) if k != "type"))
    with pytest.raises(CanonicalError):
        decode_witness_frame(canonical.dumps_line(obj))


def test_witness_and_agent_unions_are_disjoint():
    for f in WITNESS_FRAMES:
        with pytest.raises(CanonicalError):
            decode_frame(encode_frame(f))
    for f in (NoopFrame(tick=1), SignRefusal(reason="rate"), SignReply(sig=S.envelope().sig)):
        with pytest.raises(CanonicalError):
            decode_witness_frame(encode_frame(f))


def test_witness_frame_field_rules():
    with pytest.raises(ValueError):
        WitnessHead(seq=1, head=GENESIS_HASH, tick=0)  # never anchor genesis
    with pytest.raises(ValueError):
        WitnessHead(seq=0, head=H, tick=0)             # seq starts at 1
    with pytest.raises(ValueError):
        WitnessHead(seq=1, head=H, tick=-1)
    with pytest.raises(ValueError):
        WitnessInit(key_seed="ab" * 31)                # 32-byte seed, hex
    with pytest.raises(ValueError):
        WitnessInit(key_seed="AB" * 32)                # lower-case hex only
    with pytest.raises(ValueError):
        WitnessPub(pub="00")
    with pytest.raises(CanonicalError):
        decode_witness_frame(b'{"type":"w.bogus"}\n')
    with pytest.raises(CanonicalError):
        decode_witness_frame(b'{"head":"' + H.encode() + b'","tick":1,"type":"w.head","seq":1}\n')  # not canonical


def test_witness_server_speaks_contract_frames(tmp_path):
    """The real ks.witness.server main() over a socketpair: Init -> Pub, Files(+fds) -> Ready, Head -> signed
    checkpoint, regressing Head -> no ack, garbage -> no ack, Close -> exit 0."""
    from ks.identity import verify_hex
    from ks.witness import server
    from ks.witness.link import WitnessLink, open_witness_fds

    gw, wit = socket.socketpair()
    rc = {}
    t = threading.Thread(target=lambda: rc.setdefault("rc", server.main([str(wit.detach())])), daemon=True)
    t.start()

    class _Proc:  # WitnessLink.close() waits on a process; here the "process" is the thread
        def wait(self, timeout=None):
            t.join(timeout)

        def kill(self):
            pass

    link = WitnessLink(gw, _Proc())
    pub = link.init(None, timeout_s=10)
    (tmp_path / "heads").mkdir()
    (tmp_path / "witness.jsonl").touch()
    wfd, hfd = open_witness_fds(tmp_path / "witness.jsonl", tmp_path / "heads")
    link.attach(wfd, hfd, timeout_s=10)  # closes both descriptors
    cp = link.push(1, H, 0, timeout_s=10)
    assert isinstance(cp, WitnessCheckpoint) and (cp.seq, cp.head, cp.tick, cp.count) == (1, H, 0, 1)
    assert verify_hex(pub, cp.sig, cp.signing_bytes())
    assert link.push(1, H, 0, timeout_s=10) == cp      # same (seq, head, tick): the existing checkpoint (B3-08)
    assert link.push(1, H2, 0, timeout_s=0.3) is None  # another head for the same tick: no ack (stall)
    gw.sendall(b"not a frame\n")                       # garbage: no ack, no crash
    cp2 = link.push(2, H, 1, timeout_s=10)
    assert cp2 is not None and cp2.count == 2
    link.close(timeout_s=10)
    assert rc["rc"] == 0
    lines = (tmp_path / "witness.jsonl").read_bytes().splitlines()
    assert [WitnessCheckpoint.from_canonical(x) for x in lines] == [cp, cp2]


def test_witness_and_identity_use_no_adhoc_dicts():
    """Acceptance: ks.witness and ks.identity build and parse link messages only through contract types."""
    offenders = []
    for d in ("witness", "identity"):
        for p in (SRC / d).glob("*.py"):
            text = p.read_text(encoding="utf-8")
            if re.search(r"canonical\.(loads_line|dumps_line|loads|dumps)\(|\bmsg\(|\"type\"\s*:", text):
                offenders.append(p.name)
    assert offenders == []


# --- SignRefusal (finding 3) ----------------------------------------------------------------------
@pytest.mark.parametrize("reason", SIGN_REFUSAL_REASONS)
def test_sign_refusal_roundtrip(reason):
    f = SignRefusal(reason=reason)
    assert decode_frame(encode_frame(f)) == f


def test_sign_refusal_closed_vocabulary():
    assert set(SIGN_REFUSAL_REASONS) == {"rate", "foreign_agent", "system_tool", "presigned", "suspended",
                                         "stale_epoch", "schema"}
    with pytest.raises(ValueError):
        SignRefusal(reason="nope")
    with pytest.raises(CanonicalError):
        decode_frame(b'{"reason":"tired","type":"sign_refusal"}\n')
    with pytest.raises(CanonicalError):
        decode_frame(b'{"extra":1,"reason":"rate","type":"sign_refusal"}\n')   # unknown key
    with pytest.raises(CanonicalError):
        decode_frame(b'{"type":"sign_refusal"}\n')                             # missing reason


def test_every_signer_refusal_reason_is_in_the_vocabulary():
    h = S.envelope().header().model_copy(update={"sig": None})
    cases = [
        dict(req=SignRequest(header=h), principal="crm", current_epoch=h.epoch, signed_this_tick=2),
        dict(req=SignRequest(header=h), principal="billing", current_epoch=h.epoch, signed_this_tick=0),
        dict(req=SignRequest(header=h.model_copy(update={"tool": "ks.control"})), principal="crm",
             current_epoch=h.epoch, signed_this_tick=0),
        dict(req=SignRequest(header=S.envelope().header()), principal="crm", current_epoch=h.epoch,
             signed_this_tick=0),
        dict(req=SignRequest(header=h), principal="crm", current_epoch=None, signed_this_tick=0),
        dict(req=SignRequest(header=h), principal="crm", current_epoch=h.epoch + 1, signed_this_tick=0),
    ]
    got = {signer_refusal(**c) for c in cases}
    assert got == set(SIGN_REFUSAL_REASONS) - {"schema"}


# --- RunConfig.isolation / VerifyReport.isolation (finding 4) -------------------------------------
def test_run_config_isolation():
    assert S.run_config().isolation == "degraded"  # a config that does not say claims nothing
    per = S.run_config(isolation="per_agent_uid")
    assert per.isolation == "per_agent_uid"
    assert RunConfig.from_canonical(per.to_canonical()) == per
    assert per.content_hash() != S.run_config().content_hash()  # covered by config_hash
    assert per.tcb_view().isolation == "per_agent_uid"
    for bad in ("shared", "", None, "PER_AGENT_UID"):
        with pytest.raises(ValueError):
            S.run_config(isolation=bad)


def test_verify_report_isolation_echo():
    kw = dict(ok=True, exit=0, first_bad=None, reason="ok", last_witnessed_seq=4, anchored=True,
              unanchored_reason=None)
    assert VerifyReport(**kw).isolation is None  # config unreadable
    for iso in ("per_agent_uid", "degraded"):
        r = VerifyReport(**kw, isolation=iso)
        assert VerifyReport.from_canonical(r.to_canonical()) == r
    with pytest.raises(ValueError):
        VerifyReport(**kw, isolation="weird")


# --- RunConfig.decisions_from (R3) ----------------------------------------------------------------
def test_decisions_from():
    src = S.run_config(fault=None, culprit=None, fault_tick=None).content_hash()
    c = S.run_config(decisions_from=src)
    assert c.decisions_from == src and RunConfig.from_canonical(c.to_canonical()) == c
    assert c.content_hash() != S.run_config().content_hash()
    assert S.run_config().decisions_from is None
    with pytest.raises(ValueError, match="rogue"):
        S.run_config(fault="rogue", decisions_from=src)
    with pytest.raises(ValueError, match="repro"):
        S.run_config(key_mode="repro", decisions_from=src)
    with pytest.raises(ValueError):
        S.run_config(decisions_from="not-a-hash")
    S.run_config(key_mode="repro")     # repro alone stays allowed (not a security run)
    S.run_config(fault="rogue")        # rogue alone stays allowed


# --- reexec_invalid (F9) --------------------------------------------------------------------------
def test_reexec_invalid_is_tamper():
    assert VERIFY_REASONS["reexec_invalid"] is Exit.TAMPER
    kw = dict(first_bad=9, last_witnessed_seq=8, anchored=False, unanchored_reason="no_anchor")
    VerifyReport(ok=False, exit=int(Exit.TAMPER), reason="reexec_invalid", **kw)
    with pytest.raises(ValueError):
        VerifyReport(ok=False, exit=int(Exit.WITNESS), reason="reexec_invalid", **kw)


def test_additive_only():
    """Nothing from 1.1 was renamed or removed: every 1.1 reason keeps its exit, every 1.1 export still exists."""
    v11 = {"ok", "missing_file", "unreadable", "parse_error", "hash_mismatch", "seq_gap", "gw_sig_invalid",
           "agent_sig_mismatch", "side_entry_mismatch", "alert_mismatch", "epoch_regression", "expired_admitted",
           "window_violation", "witness_missing", "witness_sig_invalid", "witness_mismatch", "count_mismatch",
           "truncated", "head_mismatch", "keyring_mismatch", "config_mismatch", "reconcile_mismatch", "no_state",
           "frozen", "diverged", "usage"}
    assert v11 <= set(VERIFY_REASONS) and set(VERIFY_REASONS) - v11 == {"reexec_invalid"}
    for name in ("TickFrame", "SubmitFrame", "NoopFrame", "ReplyFrame", "SignRequest", "SignReply", "signer_refusal",
                 "RunConfig", "VerifyReport", "decode_frame", "encode_frame"):
        assert name in C.__all__
    assert WITNESS_FILES_FDS == 2
