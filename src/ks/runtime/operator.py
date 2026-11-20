"""Operator socket (J1, ADR-00 "Operator channel", THREAT-MODEL B5). Owner: maya (B3-13).

``<run>/operator/operator.sock`` in a 0700 directory owned by the gateway uid (uid 0 in the live setup). A
connection is served only if the kernel-reported peer uid (``SO_PEERCRED`` on Linux, ``LOCAL_PEERCRED`` on macOS)
equals :func:`allowed_operator_uid`: 0 when the gateway runs as root, else the gateway's own uid (degraded mode,
where per-agent attribution is already VOID, so an agent sharing our uid could also reach this socket: the admitted
gap). Agent uids (60001+) are refused, and as root they cannot even traverse the 0700 directory.

Protocol: one canonical JSON line in, one canonical JSON line out, one request per connection. Requests are never
signed by the client; the gateway turns each into a ``ks.operator``-signed envelope at the next control phase
(``ks.gateway.system.SystemQueue``), so every operator action is a verified, recorded c-0 envelope. The reply
carries the record (seq, record_id, tick, decision, reason, result). A refused request writes nothing.

Served ops: ``suspend`` / ``release`` / ``revoke`` (target ``agent:<id>`` or ``conn:<id>``; revoke needs
``"confirm": true``), ``hold`` / ``unhold`` (target ``action:<record id>`` or ``outbox:<id>``, B3-19), ``approve``
(``plan_id``, ``plan_hash``, ``steps``; the G6 args), ``recover`` (same three keys, B3-30) and ``apply`` (same
keys: the approve and the recover requests queued together, B3-27): served only when the
run has a recovery service (``ks.runtime.recover.RecoveryService``, world scenario); it queues one ``ks.recovery``
request per approved envelope step and replies once every step landed or was refused (``steps``: one reply each;
``ok`` only if every step executed). The steps are bound to the operator's earlier recorded ``ks.approve`` by the
gateway, not by this socket.

Outcome honesty (B3-19): a reply is ``ok: true/false`` only from the recorded result. A request not admitted within
the wait (or a client that times out first) gets ``ok: null, pending: true``: the request is still queued and may land.

Pacing (ADR-07 §2, L1): every request this socket accepts (passes the peer uid and parses) sets :attr:`wake`, which
resumes a run paused by ``--pause-at``/``--step``; the request itself lands in the control phase of the tick the run
resumes into. ``{"op": "resume"}`` only sets ``wake``: it is pacing, like the keypress, not an operator action, so
it writes nothing and the record of a paused run equals that of an unpaused one.
"""

from __future__ import annotations

import contextlib
import os
import socket
import stat
import struct
import sys
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ks.contracts import (APPROVE_TOOL, CONTROL_TOOL, Approval, CanonicalError, Control, ControlOp, TargetKind,
                          canonical, parse_target)
from ks.gateway.system import SystemQueue, SystemRequest

__all__ = ["OPERATOR_DIR", "OPERATOR_SOCK", "OperatorError", "OperatorServer", "allowed_operator_uid", "peer_uid",
           "operator_request", "PENDING_REPLY", "parse_request", "socket_path", "SERVED_OPS", "NOT_SERVED", "RESUME_OP",
           "APPLY_OP"]

OPERATOR_DIR = "operator"
OPERATOR_SOCK = "operator.sock"
MAX_REQUEST_BYTES = 8192
PENDING_REPLY = {"ok": None, "pending": True,
                 "error": "pending: queued, not admitted yet; it lands at the next control phase if the run continues. "
                          "The record is authoritative: check record.jsonl before retrying"}
SERVED_OPS = ("suspend", "release", "revoke", "approve", "hold", "unhold")
RESUME_OP = "resume"
APPLY_OP = "apply"
"""B3-27: ``{"op": "apply", plan_id, plan_hash, steps}`` = ``approve`` then ``recover`` queued together (one reply)."""
NOT_SERVED = {"recover": "B3-30: served by the run's recovery service, not parse_request"}
_TOKEN_OK = set("abcdefghijklmnopqrstuvwxyz0123456789_.-")


class OperatorError(ValueError):
    """A request the operator socket refuses (nothing is queued or recorded)."""


def socket_path(run: str | os.PathLike[str]) -> Path:
    return Path(run) / OPERATOR_DIR / OPERATOR_SOCK


def allowed_operator_uid() -> int:
    """uid 0 in the live setup; our own uid when not root (degraded, e.g. native macOS)."""
    return 0 if os.geteuid() == 0 else os.geteuid()


def peer_uid(conn: socket.socket) -> int | None:
    """Kernel-reported uid of the peer of a connected AF_UNIX socket (``None`` = cannot tell: refuse)."""
    try:
        if sys.platform == "linux":
            _pid, uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                                  struct.calcsize("3i")))
            return uid
        if sys.platform == "darwin":  # SOL_LOCAL=0, LOCAL_PEERCRED=1 -> struct xucred {u_int version; uid_t uid; ..}
            buf = conn.getsockopt(0, 0x001, 76)
            return struct.unpack_from("I", buf, 4)[0]
    except OSError:
        return None
    return None


@contextlib.contextmanager
def _in_dir(d: Path):
    """AF_UNIX paths are limited to ~104 bytes; bind/connect by a relative name from inside the directory.
    Only used while the calling process has no other thread that depends on the cwd."""
    old = os.open(".", os.O_RDONLY)
    try:
        os.chdir(d)
        yield
    finally:
        os.fchdir(old)
        os.close(old)


def _token(v: Any, what: str) -> str:
    if not isinstance(v, str) or not 1 <= len(v) <= 64 or not v[0].isalpha() or not set(v) <= _TOKEN_OK:
        raise OperatorError(f"{what} must be a short lowercase token")
    return v


def parse_request(obj: Any, agents: Iterable[str]) -> SystemRequest:
    """Validate one operator request -> the ``ks.operator`` SystemRequest that will be signed and admitted."""
    if not isinstance(obj, dict) or not isinstance(obj.get("op"), str):
        raise OperatorError("request must be an object with an op")
    op = obj["op"]
    if op in NOT_SERVED:
        raise OperatorError(f"op {op!r} is not served yet ({NOT_SERVED[op]})")
    if op not in SERVED_OPS:
        raise OperatorError(f"unknown op {op!r} (one of {', '.join(SERVED_OPS)})")
    if op == "approve":
        if set(obj) != {"op", "plan_id", "plan_hash", "steps"}:
            raise OperatorError("approve takes exactly plan_id, plan_hash, steps")
        try:
            ap = Approval.model_validate_json(canonical.dumps({k: v for k, v in obj.items() if k != "op"}))
        except Exception as e:
            raise OperatorError(f"bad approval: {str(e).splitlines()[0][:200]}") from None
        args = ap.to_obj()
        return SystemRequest("ks.operator", APPROVE_TOOL, build=lambda gw, tick, seq: args)
    extra = set(obj) - {"op", "target", "reason", "alert_id", "confirm"}
    if extra:
        raise OperatorError(f"unknown fields {sorted(extra)}")
    try:
        kind, ident = parse_target(obj.get("target", ""))
    except (ValueError, TypeError):
        raise OperatorError("target must be agent:<id>, conn:<id>, action:<record id> or outbox:<id>") from None
    if op in ("hold", "unhold"):  # B3-19: ks.gateway.holds; the Control validator pins the kinds
        if kind not in (TargetKind.ACTION, TargetKind.OUTBOX):
            raise OperatorError(f"{op} targets action:<record id> or outbox:<id>")
        reason = _token(obj.get("reason", "operator"), "reason")
        alert_id = obj.get("alert_id")
        if alert_id is not None and (not isinstance(alert_id, str) or not alert_id.startswith("a-")):
            raise OperatorError("alert_id must be an a-NNNNNN id")
        target = obj["target"]
        return SystemRequest("ks.operator", CONTROL_TOOL, build=lambda gw, tick, seq: Control(
            control_id=f"k-{seq:06d}", op=ControlOp(op), target=target, epoch=None, alert_id=alert_id,
            issued_by="ks.operator", auto=False, reason=reason).to_obj())
    if kind not in (TargetKind.AGENT, TargetKind.CONN):
        raise OperatorError(f"{op} targets an agent or a connection")
    if kind == TargetKind.AGENT and ident not in set(agents):
        raise OperatorError(f"{ident} is not an agent of this run")
    if kind == TargetKind.CONN and ident == "c-0":
        raise OperatorError("c-0 is the gateway's own connection")
    if op == "revoke" and obj.get("confirm") is not True:
        raise OperatorError("revoke needs confirm: true (permanent)")
    reason = _token(obj.get("reason", "operator"), "reason")
    alert_id = obj.get("alert_id")
    if alert_id is not None and (not isinstance(alert_id, str) or not alert_id.startswith("a-")):
        raise OperatorError("alert_id must be an a-NNNNNN id")
    target = obj["target"]

    def build(gw, tick: int, seq: int) -> dict:
        epoch = gw.control.next_epoch(ident) if kind == TargetKind.AGENT else None
        return Control(control_id=f"k-{seq:06d}", op=ControlOp(op), target=target, epoch=epoch, alert_id=alert_id,
                       issued_by="ks.operator", auto=False, reason=reason).to_obj()

    return SystemRequest("ks.operator", CONTROL_TOOL, build=build)


def _reply_of(result: Any) -> dict:
    if isinstance(result, Exception):
        return {"ok": False, "error": f"{type(result).__name__}: {str(result)[:300]}"}
    r = result.record
    return {"ok": r.decision.value == "exec", "seq": r.seq, "record_id": r.record_id, "tick": r.tick,
            "decision": r.decision.value, "reason": r.reason.value,
            "result": result.reply.result if result.reply is not None else None}


class OperatorServer:
    """Accepts operator connections on a background thread; requests are queued for the control phase."""

    def __init__(self, run: str | os.PathLike[str], queue: SystemQueue, agents: Iterable[str], *,
                 allowed_uid: int | None = None, wait_s: float = 60.0, io_timeout_s: float = 2.0,
                 recover: Any = None):
        self.dir = Path(run) / OPERATOR_DIR
        self.path = self.dir / OPERATOR_SOCK
        self.queue = queue
        self.agents = tuple(agents)
        self.allowed_uid = allowed_operator_uid() if allowed_uid is None else allowed_uid
        self.wait_s, self.io_timeout_s = wait_s, io_timeout_s
        self.recover = recover
        """B3-30: ``recover(obj) -> list[SystemRequest]`` (``RecoveryService.requests``), or None (not served)."""
        self.refused: list[tuple[int | None, str]] = []
        """(peer uid, why) per refused connection or request (evidence for tests and the banner)."""
        self.wake = threading.Event()
        """Set by every accepted request (and by the keypress reader of a paused run): resume (ADR-07 L1)."""
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None

    # --- lifecycle ---------------------------------------------------------------------------------
    def start(self) -> OperatorServer:
        """Create the 0700 directory and bind the socket (call before any other thread uses the cwd)."""
        os.mkdir(self.dir, 0o700)  # fails if it exists: never adopt a directory someone else made
        os.chmod(self.dir, 0o700)
        st = os.lstat(self.dir)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
            raise RuntimeError(f"{self.dir}: not a 0700 directory owned by uid {os.geteuid()}")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        with _in_dir(self.dir):
            s.bind(OPERATOR_SOCK)
            os.chmod(OPERATOR_SOCK, 0o600)
        s.listen(8)
        s.settimeout(0.2)
        self._sock = s
        self._thread = threading.Thread(target=self._serve, name="ks-operator", daemon=True)
        self._thread.start()
        return self

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(5)
        if self._sock is not None:
            self._sock.close()
        self.queue.fail_all("run ended before the request was admitted")
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()
        with contextlib.suppress(OSError):
            self.dir.rmdir()

    def __enter__(self) -> OperatorServer:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.close()

    # --- serving -----------------------------------------------------------------------------------
    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return
            # One thread per connection: a request waiting for the next control phase must not turn away a
            # `resume` (kabir B3-13: the blocked single server deadlocked a paused run).
            threading.Thread(target=self._serve_one, args=(conn,), name="ks-operator-conn", daemon=True).start()

    def _serve_one(self, conn: socket.socket) -> None:
        with conn:
            try:
                self._handle(conn)
            except OSError:
                pass

    def _send(self, conn: socket.socket, obj: dict) -> None:
        conn.sendall(canonical.dumps_line(obj))

    def _handle(self, conn: socket.socket) -> None:
        uid = peer_uid(conn)
        if uid is None or uid != self.allowed_uid:  # J1: SO_PEERCRED uid == 0 (never an agent uid)
            self.refused.append((uid, "peer_uid"))
            return  # close without a word: nothing is read from a refused peer
        conn.settimeout(self.io_timeout_s)
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = conn.recv(MAX_REQUEST_BYTES + 1 - len(buf))
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_REQUEST_BYTES:
                break
        try:
            if len(buf) > MAX_REQUEST_BYTES:
                raise OperatorError("request too large")
            obj = canonical.loads_line(buf)
            if obj == {"op": RESUME_OP}:  # pacing only: nothing queued, nothing recorded
                self.wake.set()
                self._send(conn, {"ok": True, "resumed": True})
                return
            if isinstance(obj, dict) and obj.get("op") == "recover":
                if self.recover is None:
                    raise OperatorError("recover is not served by this run (no recovery service: world scenario only)")
                try:
                    reqs = self.recover(obj)
                except ValueError as e:
                    raise OperatorError(f"recover refused: {str(e).splitlines()[0][:200]}") from None
                return self._handle_many(conn, reqs)
            if isinstance(obj, dict) and obj.get("op") == APPLY_OP:
                # B3-27: approve + recover queued together, so a paused run admits the ks.approve and then every
                # step in one control phase, before any agent acts on the tainted state again
                if self.recover is None:
                    raise OperatorError("apply is not served by this run (no recovery service: world scenario only)")
                body = {k: v for k, v in obj.items() if k != "op"}
                approve = parse_request({"op": "approve", **body}, self.agents)
                try:
                    reqs = self.recover({"op": "recover", **body})
                except ValueError as e:
                    raise OperatorError(f"apply refused: {str(e).splitlines()[0][:200]}") from None
                return self._handle_many(conn, [approve, *reqs], approve_first=True)
            req = parse_request(obj, self.agents)
        except (OperatorError, CanonicalError) as e:
            self.refused.append((uid, str(e)[:200]))
            self._send(conn, {"ok": False, "error": str(e)[:300]})
            return
        done = threading.Event()
        box: list[Any] = []

        def on_done(result: Any) -> None:
            box.append(result)
            done.set()

        req.done = on_done
        self.queue.put(req)
        self.wake.set()  # a paused run resumes into the control phase that admits this request
        if not done.wait(self.wait_s):
            # Never a false outcome: the request stays queued and WILL be admitted at a later control phase (or fail
            # at teardown). Say so; the record, not this reply, is authoritative.
            self._send(conn, PENDING_REPLY)
            return
        self._send(conn, _reply_of(box[0]))

    def _handle_many(self, conn: socket.socket, reqs: list[SystemRequest], *, approve_first: bool = False) -> None:
        """B3-30 ``recover``: queue every step, wait for each, reply once (``pending`` if any is not admitted yet).
        ``approve_first`` (B3-27 ``apply``): ``reqs[0]`` is the ks.approve; its reply goes under ``approve``."""
        events = [threading.Event() for _ in reqs]
        boxes: list[list[Any]] = [[] for _ in reqs]
        for req, ev, box in zip(reqs, events, boxes):
            def on_done(result: Any, ev=ev, box=box) -> None:
                box.append(result)
                ev.set()
            req.done = on_done
            self.queue.put(req)
        self.wake.set()
        for ev in events:
            if not ev.wait(self.wait_s):
                self._send(conn, PENDING_REPLY)
                return
        steps = [_reply_of(b[0]) for b in boxes]
        if approve_first:
            a, steps = steps[0], steps[1:]
            self._send(conn, {"ok": a.get("ok") is True and all(s.get("ok") is True for s in steps), "approve": a,
                              "steps": steps})
            return
        self._send(conn, {"ok": all(s.get("ok") is True for s in steps), "steps": steps})


def operator_request(run: str | os.PathLike[str], obj: dict, *, timeout_s: float = 90.0) -> dict:
    """See below. A client timeout returns the pending reply (the request may still land), never an error."""
    try:
        return _operator_request(run, obj, timeout_s=timeout_s)
    except TimeoutError:
        return dict(PENDING_REPLY)


def _operator_request(run: str | os.PathLike[str], obj: dict, *, timeout_s: float) -> dict:
    """Client side (``ks contain``, ``ks recover --apply``): send one request, return the reply object. Raises
    ``OSError`` if the socket is unreachable (no live run, or not the operator uid) and ``ConnectionError`` if the
    gateway closed without replying (e.g. a refused peer uid)."""
    path = socket_path(run)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout_s)
    with s:
        with _in_dir(path.parent):
            s.connect(OPERATOR_SOCK)
        s.sendall(canonical.dumps_line(obj))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    if not buf:
        raise ConnectionError("operator socket closed without a reply (refused)")
    return canonical.loads_line(buf)
