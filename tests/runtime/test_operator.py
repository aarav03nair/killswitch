"""B3-13: c-0 system envelopes (ks.gateway.system) and the J1 operator socket (ks.runtime.operator), pacing (L1).

Acceptance: system envelopes go through the pipeline on c-0 and are signature-verified; a system agent_id on c-1.. is
bad_sig and a c-0 frame with an agent id is rejected; the operator socket lives in a 0700 dir owned by the gateway
uid and refuses any other peer uid (test_operator_sock_rejects_agent); ks.console is no principal and no issuer;
verify refuses a ks.* tool executed by anyone but its signers on c-0.
"""

from __future__ import annotations

import os
import re
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from ks.contracts import (APPROVE_TOOL, CONTROL_TOOL, SYSTEM_CONN, SYSTEM_PRINCIPALS, ActionClass, Control,
                          ControlOp, Decision, Exit, Reason, RunDir)
from ks.gateway import Gateway
from ks.gateway.control import FoldedControl
from ks.gateway.system import SystemEnvelopeError, SystemQueue, SystemRequest, system_envelope
from ks.identity import verify_hex
from ks.runtime.operator import (OPERATOR_DIR, OperatorError, OperatorServer, operator_request, parse_request,
                                 peer_uid, socket_path)
from ks.world.agents import AGENT_IDS
from tests.gateway.test_pipeline import build as build_gateway
from tests.gateway.test_pipeline import frame
from tests.skeleton.conftest import ENV, REPO, ks, ks_verify

A = "triage"
SUBMITTERS = ("ks.gateway", "ks.monitor", "ks.operator", "ks.recovery")
LINUX_ROOT = sys.platform == "linux" and os.geteuid() == 0


def system_gateway(tmp_path):
    """The B3-11 world gateway, re-wired like ks.runtime.run: FoldedControl + a SystemQueue of all submitters."""
    g, keys, _ctl, store, ring = build_gateway(tmp_path)
    g.control = FoldedControl(AGENT_IDS)
    q = SystemQueue({p: keys.signer(p) for p in SUBMITTERS})
    g.system = q
    return g, keys, q, ring


def control_req(principal, op, target, *, out=None, epoch=True):
    def build(gw, tick, seq):
        ident = target.split(":", 1)[1]
        e = gw.control.next_epoch(ident) if epoch and target.startswith("agent:") else None
        return Control(control_id=f"k-{seq:06d}", op=ControlOp(op), target=target, epoch=e, alert_id=None,
                       issued_by=principal, auto=principal in ("ks.monitor", "ks.gateway"), reason="test").to_obj()
    return SystemRequest(principal, CONTROL_TOOL, build=build, done=(out.append if out is not None else None))


# --- acceptance 1: system envelopes on c-0 -----------------------------------------------------------------------
@pytest.mark.parametrize("principal", ["ks.operator", "ks.monitor", "ks.recovery", "ks.gateway"])
def test_system_control_is_signed_verified_and_recorded_on_c0(tmp_path, principal):
    g, keys, q, ring = system_gateway(tmp_path)
    g.open(0, AGENT_IDS)
    out: list = []
    q.put(control_req(principal, "suspend", f"agent:{A}", out=out))
    frames = g.open(1, AGENT_IDS)
    [adm] = out
    r = adm.record
    assert (r.conn_id, r.decision, r.reason, r.envelope.agent_id, r.envelope.tool) == (
        SYSTEM_CONN, Decision.EXEC, Reason.OK, principal, CONTROL_TOOL)
    assert r.sig_ok and verify_hex(ring.pub(principal), r.envelope.sig, r.envelope.signing_bytes())
    assert r.control is not None and r.control.issued_by == principal and r.control.epoch == 1
    assert frames[A].epoch is None  # the control phase lands before the frames of this tick (ADR-00 step 1)
    assert g.control.agent_denial(A) == Reason.SUSPENDED
    # the agent's next frame is denied by the fold, and the denial is recorded
    assert g.admit("c-1", frame(keys, tick=1, action="after")).record.reason == Reason.SUSPENDED


def test_scope_inverted_wrong_principal_is_recorded_out_of_scope(tmp_path):
    g, keys, q, _ = system_gateway(tmp_path)
    g.open(0, AGENT_IDS)
    out: list = []
    args = {"plan_id": "p-000001", "plan_hash": "0" * 64, "steps": [0]}
    q.put(SystemRequest("ks.monitor", APPROVE_TOOL, build=lambda gw, t, s: args, done=out.append))  # only ks.operator
    g.open(1, AGENT_IDS)
    [adm] = out
    assert (adm.record.conn_id, adm.record.decision, adm.record.reason) == (SYSTEM_CONN, Decision.DENY,
                                                                            Reason.OUT_OF_SCOPE)


def test_forged_system_signature_is_bad_sig_on_c0(tmp_path):
    g, keys, q, _ = system_gateway(tmp_path)
    g.open(1, AGENT_IDS)
    c = Control(control_id="k-000002", op=ControlOp.SUSPEND, target=f"agent:{A}", epoch=1, alert_id=None,
                issued_by="ks.operator", auto=False, reason="test")
    env = system_envelope("ks.operator", CONTROL_TOOL, c.to_obj(), action_id="operator-x", tick=1,
                          sign=keys.signer(A))  # an agent's key, claiming ks.operator
    adm = g.admit_system(env)
    assert (adm.record.decision, adm.record.reason, adm.record.sig_ok) == (Decision.DENY, Reason.BAD_SIG, False)
    assert g.control.epoch_of(A) == 0  # nothing applied


def test_system_agent_id_on_agent_conn_is_bad_sig(tmp_path):
    """Both ways (1/2): a correctly signed ks.operator envelope on c-1 is never verified (X7)."""
    g, keys, q, _ = system_gateway(tmp_path)
    g.open(1, AGENT_IDS)
    adm = g.admit("c-1", frame(keys, agent="ks.operator", tool=CONTROL_TOOL, action="x"))
    assert (adm.record.conn_id, adm.record.sig_ok, adm.record.decision, adm.record.reason) == (
        "c-1", False, Decision.DENY, Reason.BAD_SIG)


def test_agent_id_on_c0_is_rejected(tmp_path):
    """Both ways (2/2): c-0 has no wire, and an agent envelope handed to the system path is never recorded."""
    g, keys, q, _ = system_gateway(tmp_path)
    g.open(1, AGENT_IDS)
    seq = g.recorder.seq
    with pytest.raises(SystemEnvelopeError):
        g.admit(SYSTEM_CONN, frame(keys))
    env = system_envelope(A, "ticket.set_priority", {"id": "T-0000", "priority": "high"}, action_id="a-x", tick=1,
                          sign=keys.signer(A))
    with pytest.raises(SystemEnvelopeError):
        g.admit_system(env)
    assert g.recorder.seq == seq


def test_unserved_recover_raises_and_unknown_hold_is_tool_error(tmp_path):
    g, keys, q, _ = system_gateway(tmp_path)
    g.open(1, AGENT_IDS)
    seq = g.recorder.seq
    hold = Control(control_id="k-000002", op=ControlOp.HOLD, target="outbox:ob-000001", epoch=None, alert_id=None,
                   issued_by="ks.operator", auto=False, reason="test").to_obj()
    env = system_envelope("ks.recovery", "ks.recover.restore", {}, action_id="x-rec", tick=1,
                          sign=keys.signer("ks.recovery"))
    with pytest.raises(NotImplementedError):
        g.admit_system(env)
    assert g.recorder.seq == seq
    # hold/unhold are served now (B3-19): a hold of an item that does not exist is a recorded tool_error
    env = system_envelope("ks.operator", CONTROL_TOOL, hold, action_id="x-hold", tick=1, sign=keys.signer("ks.operator"))
    assert g.admit_system(env).record.reason == Reason.TOOL_ERROR and g.recorder.seq == seq + 1


def test_epoch_regression_is_tool_error_and_not_applied(tmp_path):
    g, keys, q, _ = system_gateway(tmp_path)
    g.open(0, AGENT_IDS)
    out: list = []
    q.put(control_req("ks.operator", "suspend", f"agent:{A}", out=out))
    stale = Control(control_id="k-000099", op=ControlOp.RELEASE, target=f"agent:{A}", epoch=1, alert_id=None,
                    issued_by="ks.operator", auto=False, reason="test").to_obj()  # epoch 1 again: not monotonic
    q.put(SystemRequest("ks.operator", CONTROL_TOOL, build=lambda gw, t, s: stale, done=out.append))
    g.open(1, AGENT_IDS)
    assert [a.record.reason for a in out] == [Reason.OK, Reason.TOOL_ERROR]
    assert g.control.agent_denial(A) == Reason.SUSPENDED


def test_control_phase_cap_carries_surplus_in_order(tmp_path):
    g, keys, q, _ = system_gateway(tmp_path)
    q.cap = 2
    g.open(0, AGENT_IDS)
    out: list = []
    for a in ("crm", "docs", "triage"):
        q.put(control_req("ks.operator", "suspend", f"agent:{a}", out=out))
    g.open(1, AGENT_IDS)
    assert [a.record.tick for a in out] == [1, 1] and len(q) == 1
    g.open(2, AGENT_IDS)
    assert [a.record.tick for a in out] == [1, 1, 2]
    assert [a.record.control.target for a in out] == ["agent:crm", "agent:docs", "agent:triage"]


# --- operator requests -------------------------------------------------------------------------------------------
@pytest.mark.parametrize("obj,msg", [
    ({"op": "hold", "target": f"agent:{A}"}, "targets action"), ({"op": "recover"}, "B3-30"), ({"op": "nope"}, "unknown op"),
    ({"op": "revoke", "target": f"agent:{A}"}, "confirm"), ({"op": "suspend", "target": "conn:c-0"}, "c-0"),
    ({"op": "suspend", "target": "agent:ghost"}, "not an agent"), ({"op": "suspend", "target": "action:r-000001"}, "targets"),
    ({"op": "suspend", "target": f"agent:{A}", "issued_by": "ks.monitor"}, "unknown fields"),
    ({"op": "suspend", "target": f"agent:{A}", "reason": "Bad Reason"}, "token"),
    ({"op": "suspend", "target": f"agent:{A}", "alert_id": "x"}, "alert_id"), ("suspend", "object"),
])
def test_parse_request_refuses(obj, msg):
    with pytest.raises(OperatorError, match=msg):
        parse_request(obj, AGENT_IDS)


def test_operator_request_is_always_ks_operator_auto_false(tmp_path):
    g, keys, q, _ = system_gateway(tmp_path)
    g.open(0, AGENT_IDS)
    req = parse_request({"op": "suspend", "target": f"agent:{A}", "reason": "operator"}, AGENT_IDS)
    out: list = []
    req.done = out.append
    q.put(req)
    g.open(1, AGENT_IDS)
    c = out[0].record.control
    assert (out[0].record.envelope.agent_id, c.issued_by, c.auto, c.epoch) == ("ks.operator", "ks.operator", False, 1)


def test_operator_approve_is_recorded_on_c0(tmp_path):
    g, keys, q, _ = system_gateway(tmp_path)
    g.open(0, AGENT_IDS)
    req = parse_request({"op": "approve", "plan_id": "p-000001", "plan_hash": "a" * 64, "steps": [0, 2]}, AGENT_IDS)
    out: list = []
    req.done = out.append
    q.put(req)
    g.open(1, AGENT_IDS)
    r = out[0].record
    assert (r.conn_id, r.envelope.agent_id, r.envelope.tool, r.decision) == (SYSTEM_CONN, "ks.operator", APPROVE_TOOL,
                                                                            Decision.EXEC)


@pytest.fixture
def live_base():
    import shutil
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="ks-b313-", dir="/tmp"))
    os.chmod(d, 0o711)
    yield d
    shutil.rmtree(d, ignore_errors=True)


# --- acceptance 2: the J1 socket ---------------------------------------------------------------------------------
def _drain(g, q, stop, t0=1):
    """Stand-in for the barrier: open a tick whenever something is queued."""
    t = t0
    while not stop.is_set():
        if len(q):
            g.open(t, AGENT_IDS)
            t += 1
        time.sleep(0.01)


def short_dir(tmp_path) -> Path:
    return tmp_path  # operator.py binds by relative name, so long pytest paths are fine


def test_socket_dir_is_0700_owned_by_us_and_serves_our_uid(tmp_path):
    g, keys, q, _ = system_gateway(tmp_path)
    g.open(0, AGENT_IDS)
    run = tmp_path / "live"
    run.mkdir()
    stop = threading.Event()
    with OperatorServer(run, q, AGENT_IDS) as srv:
        st = os.lstat(run / OPERATOR_DIR)
        assert stat.S_IMODE(st.st_mode) == 0o700 and st.st_uid == os.geteuid()
        assert stat.S_IMODE(os.lstat(socket_path(run)).st_mode) == 0o600
        got: dict = {}

        def client() -> None:  # the gateway (sqlite) stays on this thread, like the barrier
            try:
                got["rep"] = operator_request(run, {"op": "suspend", "target": f"agent:{A}"}, timeout_s=10)
                got["bad"] = operator_request(run, {"op": "revoke", "target": f"agent:{A}"}, timeout_s=10)
                got["res"] = operator_request(run, {"op": "resume"}, timeout_s=10)
            finally:
                stop.set()
        th = threading.Thread(target=client, daemon=True)
        th.start()
        _drain(g, q, stop)
        th.join(2)
        assert srv.wake.is_set()
    rep, bad = got["rep"], got["bad"]
    assert got["res"] == {"ok": True, "resumed": True}
    assert rep["ok"] and rep["decision"] == "exec" and rep["result"]["op"] == "suspend"
    rec = list(RunDir(tmp_path / "run").records())[rep["seq"] - 1]
    assert (rec.conn_id, rec.envelope.agent_id, rec.control.issued_by) == (SYSTEM_CONN, "ks.operator", "ks.operator")
    assert not bad["ok"] and "confirm" in bad["error"]
    assert not (run / OPERATOR_DIR).exists()  # removed at close


def test_socket_refuses_existing_dir(tmp_path):
    (tmp_path / OPERATOR_DIR).mkdir(mode=0o777)
    with pytest.raises(FileExistsError):
        OperatorServer(tmp_path, SystemQueue({}), AGENT_IDS).start()


def test_peer_uid_is_kernel_reported():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with a, b:
        assert peer_uid(a) == os.geteuid()


def test_operator_sock_rejects_agent(live_base):
    """J1: a peer whose kernel-reported uid is not the operator uid gets no reply and queues nothing. As Linux root
    this is a real agent uid (60001) in a child process; elsewhere the server's allowed uid is set away from ours."""
    q = SystemQueue({"ks.operator": lambda b: "00"})
    run = live_base / "live"  # parents traversable (0711): a refusal comes from the operator dir or peercred
    run.mkdir()
    os.chmod(run, 0o711)
    if LINUX_ROOT:
        from ks.runtime.spawn import agent_uid
        uid = agent_uid(1)
        with OperatorServer(run, q, AGENT_IDS) as srv:
            assert srv.allowed_uid == 0
            # 1: the 0700 uid-0 dir: an agent uid cannot even reach the socket path
            code = ("import socket,sys; s=socket.socket(socket.AF_UNIX); "
                    f"s.connect({str(socket_path(run))!r})")
            p = subprocess.run([sys.executable, "-c", code], user=uid, capture_output=True, text=True, timeout=30)
            assert p.returncode != 0 and "PermissionError" in p.stderr, p.stderr
            # 2: even handed a connected socket (dir bypassed), the peercred check refuses the agent uid
            os.chmod(run / OPERATOR_DIR, 0o711)
            os.chmod(socket_path(run), 0o666)
            child = code + ("\ntry:\n    s.sendall(b'{\"op\":\"resume\"}\\n'); got = s.recv(100)\n"
                            "except ConnectionResetError:\n    got = b''\nsys.exit(3 if got else 0)")  # closed: no reply
            p = subprocess.run([sys.executable, "-c", child], user=uid, capture_output=True, text=True, timeout=30)
            assert p.returncode == 0, p.stderr
            time.sleep(0.3)
            assert srv.refused and srv.refused[-1] == (uid, "peer_uid") and not srv.wake.is_set()
    else:
        with OperatorServer(run, q, AGENT_IDS, allowed_uid=os.geteuid() + 1) as srv:
            with pytest.raises(ConnectionError):
                operator_request(run, {"op": "suspend", "target": f"agent:{A}"}, timeout_s=10)
            assert srv.refused == [(os.geteuid(), "peer_uid")] and not srv.wake.is_set()
    assert len(q) == 0


# --- acceptance 3: ks.console is no principal and no issuer -------------------------------------------------------
def test_ks_console_is_not_a_principal_or_issuer():
    assert "ks.console" not in SYSTEM_PRINCIPALS
    hits = []
    for p in (REPO / "src" / "ks").rglob("*.py"):
        for n, line in enumerate(p.read_text().splitlines(), 1):
            if re.search(r"""["']ks\.console["']""", line):
                hits.append(f"{p.relative_to(REPO)}:{n}: {line.strip()}")
    assert hits == []


# --- verify enforces it ------------------------------------------------------------------------------------------
def test_verify_refuses_system_tool_executed_by_wrong_principal(tmp_path):
    """A gateway that recorded ks.monitor's ks.approve as executed (the TCB bug verify must catch, K13)."""
    from ks.verify.core import _Fail, _record_pass
    g, keys, q, ring = system_gateway(tmp_path)
    g.open(0, AGENT_IDS)
    out: list = []
    args = {"plan_id": "p-000001", "plan_hash": "0" * 64, "steps": [0]}
    q.put(SystemRequest("ks.monitor", APPROVE_TOOL, build=lambda gw, t, s: args, done=out.append))
    g.open(1, AGENT_IDS)
    adm = out[0]
    assert adm.record.reason == Reason.OUT_OF_SCOPE  # the real pipeline denies it (only ks.operator approves)
    rd = g.recorder.rundir
    # forge: the same envelope, recorded EXEC by a buggy gateway (still gw-signed: verify must not trust it).
    # (An agent's ks.* envelope recorded EXEC is already refused by the Record validator, at parse.)
    import hashlib

    from ks.contracts import canonical
    data = (rd.path / "record.jsonl").read_bytes()
    last = list(rd.records())[-1]
    forged = last.model_copy(update={"decision": Decision.EXEC, "reason": Reason.OK, "gw_sig": None})  # no validation
    forged = forged.model_copy(update={"hash": hashlib.sha256(forged.signing_bytes()).hexdigest()})
    forged = forged.model_copy(update={"gw_sig": keys.signer("ks.gateway")(forged.signing_bytes())})
    lines = data.splitlines(keepends=True)
    lines[-1] = canonical.dumps_line(forged.to_obj())
    with pytest.raises(_Fail) as e:
        _record_pass(b"".join(lines), ring, [], rd.config())
    # the Record validator inside verify refuses it at parse; the K13 verify rule is the second line
    assert e.value.reason in ("parse_error", "agent_sig_mismatch") and e.value.first_bad == last.seq
    assert e.value.reason == "agent_sig_mismatch" or "ks.monitor may not execute ks.approve" in e.value.detail


# --- runtime: pacing + live operator, end to end ------------------------------------------------------------------
def _popen_run(out: Path, *extra: str) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-m", "ks", "run", "--scenario", "world", "--seed", "7",
                             "--out", str(out), *extra], cwd=REPO, env=ENV, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True)


def _wait_line(p: subprocess.Popen, needle: str, timeout: float = 120) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        line = p.stdout.readline()
        if not line:
            raise AssertionError(f"run ended before {needle!r}: {p.stderr.read()}")
        if needle in line:
            return
    raise AssertionError(f"timeout waiting for {needle!r}")


def test_paused_run_takes_ks_contain_and_verifies(live_base):
    """ADR-07 L1 + J1: a paused run is live; `ks contain` lands as a ks.operator Control on c-0 at the paused tick,
    resumes the run, and the finished run verifies OK."""
    out = live_base / "paused"
    p = _popen_run(out, "--ticks", "14", "--pause-at", "5,9")
    try:
        _wait_line(p, "paused before tick 5")
        c = ks("contain", "suspend", "agent:crm", out)
        assert c.returncode == Exit.OK, c.stderr
        _wait_line(p, "paused before tick 9")
        r = ks("contain", "release", "agent:crm", out)
        assert r.returncode == Exit.OK, r.stderr
        assert p.wait(120) == 0, p.stderr.read()
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
    ctl = [r for r in RunDir(out).records() if r.control is not None and r.envelope.agent_id == "ks.operator"]
    assert [(r.tick, r.conn_id, r.control.op.value, r.control.epoch) for r in ctl] == [
        (5, SYSTEM_CONN, "suspend", 1), (9, SYSTEM_CONN, "release", 2)]
    crm = [r for r in RunDir(out).records() if r.envelope is not None and r.envelope.agent_id == "crm"]
    assert all(r.reason == Reason.SUSPENDED for r in crm if 5 <= r.tick < 9)
    assert ks("contain", "suspend", "agent:crm", out).returncode == Exit.IO  # finished run: no socket
    code, rep = ks_verify(out)
    assert code == Exit.OK, rep


def test_pause_identical_record(live_base):
    """ADR-07 L1: pausing changes no record (repro keys, so byte-identical deterministic files)."""
    secret = live_base / "repro.secret"
    fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, b"b3-13 pause test secret, not for security runs")
    os.close(fd)
    keys = ("--key-mode", "repro", "--repro-secret", str(secret), "--ticks", "8")
    plain = ks("run", "--scenario", "world", "--seed", "7", "--out", live_base / "plain", *keys)
    assert plain.returncode == 0, plain.stderr
    p = _popen_run(live_base / "step", *keys, "--step")
    try:
        for t in range(1, 8):
            _wait_line(p, f"paused before tick {t}")
            assert operator_request(live_base / "step", {"op": "resume"}, timeout_s=30)["ok"]
        assert p.wait(120) == 0, p.stderr.read()
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
    a, b = (RunDir(live_base / n).determinism_files() for n in ("plain", "step"))
    assert a == b and a


def test_unadmitted_request_is_pending_not_refused_and_resume_is_still_served(tmp_path):
    """B3-19 (kabir B3-13): a request nobody drains must not report a false outcome, and a blocked request must not
    turn away `resume` (one thread per connection)."""
    from ks.runtime.operator import PENDING_REPLY
    q = SystemQueue({"ks.operator": lambda b: "00"})
    run = tmp_path / "live"
    run.mkdir()
    with OperatorServer(run, q, AGENT_IDS, wait_s=1.5) as srv:
        got: dict = {}
        th = threading.Thread(target=lambda: got.update(
            rep=operator_request(run, {"op": "suspend", "target": f"agent:{A}"}, timeout_s=10)), daemon=True)
        th.start()
        time.sleep(0.4)
        assert operator_request(run, {"op": "resume"}, timeout_s=5) == {"ok": True, "resumed": True}
        th.join(10)
        assert got["rep"] == PENDING_REPLY and got["rep"]["ok"] is None and len(q) == 1  # still queued: it may land
        # a client that gives up first also says pending, never "no live run"
        assert operator_request(run, {"op": "suspend", "target": f"agent:{A}"}, timeout_s=0.3)["pending"] is True
