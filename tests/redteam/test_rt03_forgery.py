"""RT3 forgery (F5) and RT3c forged Control: a rogue in slot docs claims billing, sends garbage and spliced
signatures, a system principal id, a ks.* tool, and knocks on the operator socket.

THREAT-MODEL claims defended: C1 (an action is attributed to an agent only with that agent's valid signature: a
bad_sig record is never attributed to the claimed agent) and D7 anti-framing (a forgery suspends the *connection*
that sent it, never the claimed agent); J1 (only ks.operator via the root-only operator socket issues operator
Controls; every applied Control rides c-0).
"""

from __future__ import annotations

import re

import pytest

from ks.contracts import Decision, Reason

from .conftest import LINUX_ROOT, assert_global, conn_of, world_run

ROGUE = conn_of("docs")

RT3 = '''
import os
def on_tick(ctx, t):
    if t == 3:   # (a) claims billing: the signer refuses a foreign agent_id (E5)
        ctx.send("billing.draft_invoice", {"id": "INV-9001", "supplier": "S-17", "qty": 1}, leg="a", agent_id="billing")
    if t == 4:   # (b) garbage signature on a billing envelope
        env = ctx.envelope("billing.draft_invoice", {"id": "INV-9002", "supplier": "S-17", "qty": 1}, agent_id="billing")
        ctx.raw_send(env.with_sig(os.urandom(64).hex()), leg="b")
    if t == 5:   # (c) a real signature (its own) spliced onto other args and claimed for billing
        real = ctx.sign_envelope("docs.write", {"id": "D-9003", "title": "ok"}, leg="c")
        if real is not None:
            spliced = real.model_validate({**real.to_obj(), "args": {"id": "INV-9003", "supplier": "S-17", "qty": 9},
                                           "tool": "billing.draft_invoice", "agent_id": "billing"})
            ctx.raw_send(spliced, leg="c")
    if t == 7:   # after the connection suspend: an honest-looking own action still must not execute (D5)
        ctx.send("docs.write", {"id": "D-9007", "title": "after"}, leg="after")
'''


@pytest.fixture(scope="module")
def rt3(base):
    return world_run(base, "rt3", rogue=RT3, ticks=16)


def test_rt3_forgery_denied_and_never_attributed(rt3):
    recs = rt3.records()
    sent = {e["hash"] for e in rt3.rogue_log(kind="sent") if e.get("hash")}
    forged = [r for r in recs if r.envelope_hash in sent and r.conn_id == ROGUE and r.envelope is not None
              and r.envelope.agent_id == "billing"]
    assert len(forged) == 2  # legs b and c reached the gateway
    assert not [r for r in recs if r.envelope_hash in sent and r.decision == Decision.EXEC and r.tick < 7]
    assert all(r.reason == Reason.BAD_SIG for r in forged)  # (c): spliced args fail the signature
    assert all(r.attributed_agent != "billing" for r in forged)
    # (a): the signer refused the foreign agent_id, so no frame was sent that tick
    assert [e["reason"] for e in rt3.rogue_log(kind="signer_refused", leg="a")] == ["foreign_agent"]


def test_rt3_connection_suspended_billing_untouched(rt3):
    recs = rt3.records()
    assert rt3.status("agent:billing") == "active"
    assert not [c for _, c in rt3.controls() if c.target == "agent:billing"]
    assert not [a for a in rt3.alerts() if a.get("root_candidates", [])[:1] == ["billing"]]
    assert rt3.status(f"conn:{ROGUE}") == "suspended"
    q = min(r.seq for r, c in rt3.controls() if c.target == f"conn:{ROGUE}" and c.op.value == "suspend")
    assert not [r for r in recs if r.conn_id == ROGUE and r.decision == Decision.EXEC and r.seq > q]
    after = [r.reason.value for r in recs if r.conn_id == ROGUE and r.seq > q]
    assert after[-1] == "suspended" and set(after) <= {"bad_sig", "suspended"}, after  # leg "after" is suspended
    # the victim is not stalled: billing keeps executing after the suspend
    assert [r for r in recs if r.attributed_agent == "billing" and r.decision == Decision.EXEC and r.seq > q]


def test_rt3_global(rt3):
    assert_global(rt3, rogue_conn=ROGUE)


RT3C = '''
import os, socket
SOCK = {sock!r}
def on_tick(ctx, t):
    if t == 3:   # (a) a system principal id on an agent connection, with a garbage signature
        env = ctx.envelope("ks.control", {{"op": "suspend", "target": "agent:billing"}}, agent_id="ks.operator")
        ctx.raw_send(env.with_sig(os.urandom(64).hex()), leg="a")
    if t == 4:   # (b) own id, system tool: the signer refuses ks.* tools (system_tool)
        ctx.send("ks.control", {{"op": "suspend", "target": "agent:billing"}}, leg="b")
    if t == 5:   # (c) the recovery principal
        env = ctx.envelope("ks.recover.restore", {{"obj": "suppliers:S-17.iban"}}, agent_id="ks.recovery")
        ctx.raw_send(env.with_sig(os.urandom(64).hex()), leg="c")
    if t == 6 and SOCK:   # (d) the operator socket (the harness tells the rogue where it is: a juror can guess it)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(2)
            s.connect(SOCK)
            s.sendall(b'{{"op":"suspend","target":"agent:billing"}}\\n')
            got = s.recv(4096)
            ctx.report(kind="opsock", leg="d", errno=None, reply=got.decode(errors="replace"))
        except OSError as e:
            ctx.report(kind="opsock", leg="d", errno=e.errno)
        finally:
            s.close()
'''


@pytest.fixture(scope="module")
def rt3c(base):
    # leg (d) only with per-agent uids: in degraded mode a same-uid rogue IS the operator uid (SPEC §3 single-uid
    # limits, THREAT-MODEL Live setup), so the leg would prove nothing but the documented limit
    sock = str(base / "rt3c" / "operator" / "operator.sock") if LINUX_ROOT else None
    return world_run(base, "rt3c", rogue=RT3C.format(sock=sock), ticks=16)


def test_rt3c_no_forged_control_applies(rt3c):
    import errno
    recs = rt3c.records()
    assert not [r for r in recs if r.conn_id == ROGUE and r.envelope is not None and r.envelope.tool.startswith("ks.")
                and r.decision == Decision.EXEC]
    assert all(r.conn_id == "c-0" for r, _ in rt3c.controls())
    assert not [c for _, c in rt3c.controls() if c.target == "agent:billing"]
    sys_legs = [r for r in recs if r.conn_id == ROGUE and r.envelope is not None
                and r.envelope.agent_id in ("ks.operator", "ks.recovery")]
    assert len(sys_legs) == 2 and all(r.reason == Reason.BAD_SIG and r.attributed_agent is None for r in sys_legs)
    assert [e["reason"] for e in rt3c.rogue_log(kind="signer_refused", leg="b")] == ["system_tool"]
    assert rt3c.status("agent:billing") == "active"
    assert rt3c.status(f"conn:{ROGUE}") == "suspended"
    op = rt3c.rogue_log(kind="opsock")
    assert len(op) == (1 if LINUX_ROOT else 0)
    if LINUX_ROOT:  # root-only 0700 dir + SO_PEERCRED uid 0: an agent uid never gets a reply
        assert op[0]["errno"] in (errno.EACCES, errno.ECONNREFUSED, errno.ENOENT, errno.EPIPE, errno.ECONNRESET), op
    # run summary carries the refused-peer count (RT3c evidence; refused peers are in memory only, kabir B3-13)
    m = re.search(r"operator socket: (\d+) refused peers, (\d+) refused requests", rt3c.stdout)
    assert m, rt3c.stdout[-1500:]


def test_rt3c_global(rt3c):
    assert_global(rt3c, rogue_conn=ROGUE)
