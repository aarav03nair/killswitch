"""Recovery apply via c-0, approval-bound (B3-30; ADR-05 §6-8, CALL-02 G6/F5/B2, contracts C5). Owner: maya.

An approved plan's steps run as ``ks.recover.<op>`` envelopes signed by ``ks.recovery`` on ``c-0``, one record per
step, in the gateway's control phase (ADR-00 step 1). Nothing here signs as ``ks.operator``: the approval is the
operator's own recorded ``ks.approve`` (operator socket, J1).

Gateway side, :class:`RecoveryService` (``Gateway.recovery``; ``ks.gateway.system.admit_system`` calls
:meth:`RecoveryService.serve` after signature, expiry, nonce and scope, steps 3/5/6/10). Per step, in this order:

1. args are a C5 ``RecoverArgs``, the tool is ``ks.recover.<step.op>`` and the action id is ``<plan_id>.<n>``
   (so a second apply of a step is ``deny/nonce_reused``: one apply per step), else ``deny/tool_error``;
2. **freeze** (M12, F5): an executed chained ``ks.alert`` of kind tamper / witness_stall -> ``deny/recovery_frozen``
   (``ks.verify.window.frozen_from_records``, the same rule ``ks verify`` and ``ks recover`` use);
3. **binding** (G6, SEC-03 F5): an earlier executed ``ks.approve`` by ``ks.operator`` on c-0 with this ``plan_id``
   and ``plan_hash`` that lists ``n``; and ``plans/<plan_id>.json`` hashes to ``plan_hash`` with ``steps[n]`` equal to
   the step carried. Otherwise ``deny/out_of_scope`` (``ks.recovery`` holds no authority beyond the approval; an
   edited plan file is caught here and by ``ks verify``, reason ``recovery_unbound``);
4. ``BEGIN IMMEDIATE``, then the **M8 re-check in the same txn** (``ks.recovery.conflict.recheck``): stale ->
   ``ROLLBACK`` and a ``hold/stale_plan`` record; the apply **halts** there (later steps of the plan are refused
   before any record; the console builds a new plan with a later ``as_of_seq``);
5. execute and record (class R, system record):

   * ``restore``: ``ks.recovery.apply_restore`` (author ``ks.recovery``, action id ``<plan_id>.<n>``); read set = the
     ``to`` version (never the culprit's ``expect``, which would re-taint the restore); tombstone if ``to`` is None.
   * ``rerun`` (also ``c_rerun_identical``): ``ks.recovery.ToolRerunner`` with the gateway's own dispatcher and the
     args from the side store: the dry-run's code path, here on the live txn, so dry-run and apply agree by
     construction (M14: original agent/action ids and idempotency keys; dispatched items get no outbox write and
     ``Outbox.create`` is never called, so a dispatched item cannot raise). The re-run's tool writes are re-checked
     after it ran (the dry-run's "new object" stale rule) before COMMIT. Read set = the re-run's tool reads (= the
     re-held items' lineage); ``outbox_ids`` = the re-held items.
     **Repairs:** an object the original wrote whose head is still the original's (tainted) version and that the
     re-run did not write (adapters skip unchanged writes: the re-run's value equals the head) gets a repair version,
     same value, author and action id of the original, so the record states the repair and the new head is clean in
     the forward closure. Listed in the result as ``repaired``.
     **Hold records** (ADR-03 §7: holds are Controls): after the re-run record, one ``ks.control`` hold per re-held
     item, issued by ``ks.recovery`` (``auto=false``: the approval is the human act), reason ``rerun_reheld``, whose
     write set is the item's status change. A re-held item leaves only by an unhold (X4); the outbox's provenance
     check accepts the re-run record as its creating record (``ks.gateway.outbox.Outbox._unrecorded``).
   * ``cancel_outbox``: the item's status change to ``cancelled`` (already cancelled: executed, no write).
   * ``resolve`` (D-18, ADR-05a §4): M8 (O's head is still ``expect``), then ``ks.recovery.resolver.rebase`` with the
     same ``ToolRerunner``: O to value(``to``) and H's tool and args re-run in a rolled-back savepoint, the result
     landed as **one** version (author ``ks.recovery``); a hash other than ``rebased_hash``, an unknown rule or a
     dirty re-run is ``deny/tool_error`` and the apply halts. Read set = the re-run's tool reads with O at ``to``.
   * ``unresolve`` (ADR-05a §5): ``unresolve_problems`` re-checked in the txn (heads, no foreign touch, no re-held
     item released or dispatched; else ``hold/stale_plan``), each revert lands as a new version (author
     ``ks.recovery``, read entry = the version copied), then one ``ks.control`` hold per ``reheld`` item with
     reason ``resolution_reverted``.
   * ``compensate``: ``deny/tool_error``: no compensator is registered in ks.world (ADR-05 §6.4: ``no_compensator``
     is a flag or a cleared ``c_rerun_identical`` re-run). ``flag`` and ``replan`` create no envelope.

Operator side: :meth:`RecoveryService.requests` turns the socket's ``{"op": "recover", plan_id, plan_hash, steps}``
into one ``SystemRequest`` per step (action id ``<plan_id>.<n>``); a request built after the plan halted raises
:class:`RecoveryHalted` and writes nothing. CLI side: :func:`cli_dry_run`, :func:`cli_apply`.

Bench approver (X4, ADR-05 Consequences): :func:`bench_releasable` lists only items whose latest hold is a
``rerun_reheld`` hold by ``ks.recovery`` and that are still held: never a rider / replan / flagged item (those stay
held under their ``lineage_hold``, ADR-05 §6.1 amended, B3-48).
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from ks.contracts import (APPROVE_TOOL, CONTROL_TOOL, SYSTEM_CONN, ActionClass, Approval,
                          CancelOutboxStep, CompensateStep, Control, ControlOp, Decision, Envelope, OutboxStatus,
                          ReadEntry, Reason, RecoverArgs, RecoveryPlan, RerunStep, ResolveStep, RestoreStep,
                          SideDomain, SideEntry, UnresolveStep, canonical, recover_tool, result_hash,
                          sidestore_relpath)
from ks.contracts.rundir import PLANS_DIR
from ks.gateway.system import SystemRequest, system_envelope
from ks.gateway.txn import writes_at

if TYPE_CHECKING:
    from ks.gateway.stub import Admission, Gateway

__all__ = ["RecoveryService", "RecoveryHalted", "Halt", "ENVELOPE_OPS", "REHELD_REASON", "bench_releasable",
           "approved_steps", "load_plan", "cli_dry_run", "cli_apply", "DryRunResult", "restored_releasable",
           "cli_unresolve", "UNRESOLVED_REASON"]

ENVELOPE_OPS = ("restore", "rerun", "cancel_outbox", "compensate", "resolve", "unresolve")
"""Step ops that run as a ``ks.recover.<op>`` envelope (ADR-05 §8); ``flag`` and ``replan`` create none."""
REHELD_REASON = "rerun_reheld"
"""Control reason of the hold record a re-run writes for each re-held outbox item (ADR-03 §7)."""
UNRESOLVED_REASON = "resolution_reverted"
"""Control reason of the hold an undo of a resolution writes for each re-held item (ADR-05a §5); never bench-released."""
RECOVERY = "ks.recovery"
OPERATOR = "ks.operator"


class RecoveryHalted(RuntimeError):
    """A step queued after its plan halted (stale, frozen, unbound, error): refused before any record."""


@dataclass(frozen=True)
class Halt:
    """Where an apply stopped: the step's record (decision/reason) and why."""

    n: int
    seq: int
    decision: str
    reason: str
    detail: str


def load_plan(run: str | Path, plan_id: str) -> RecoveryPlan:
    if not isinstance(plan_id, str) or not plan_id.startswith("p-") or "/" in plan_id:
        raise ValueError(f"bad plan id {plan_id!r}")
    return RecoveryPlan.from_canonical((Path(run) / PLANS_DIR / f"{plan_id}.json").read_bytes())


def approved_steps(plan: RecoveryPlan, extra: Iterable[int] = ()) -> tuple[int, ...]:
    """What ``ks recover --apply`` approves: every restore / resolve / unresolve / rerun / cancel_outbox step (ADR-05a
    §3: a resolve is approved with the plan, like a restore), plus the steps a person named with ``--approve``
    (``compensate``, ``replan``, ``flag``; ADR-07: a flag is never applied, approving it only records that a person
    saw it)."""
    extra = set(extra)
    bad = extra - set(range(len(plan.steps)))
    if bad:
        raise ValueError(f"--approve names steps the plan does not have: {sorted(bad)}")
    return tuple(s.n for s in plan.steps if s.op in ("restore", "resolve", "unresolve", "rerun", "cancel_outbox")
                 or s.n in extra)


def _side(run: Path, h: str) -> Any:
    try:
        e = SideEntry.from_canonical((run / sidestore_relpath(h)).read_bytes())
    except Exception:
        return None
    return None if e.redacted else e.value


class RecoveryService:
    """Serves ``ks.recover.<op>`` on c-0 (see module doc). One per gateway; thread-safe for :meth:`requests`."""

    def __init__(self, run: str | Path, sign: Callable[[bytes], str], *, dispatcher: Any,
                 args_of: Callable[[Any], Any] | None = None):
        from ks.recovery import ToolRerunner, args_from_sidestore

        self.run = Path(run)
        self._sign = sign
        self.rerunner = ToolRerunner(dispatcher, args_of or args_from_sidestore(self.run))
        self.halts: dict[str, Halt] = {}
        """plan_hash -> the first step that did not execute (the apply stopped there)."""
        self.applied: list[tuple[str, int, int]] = []
        """(plan_hash, n, seq) of every executed step, in order."""
        self._lock = threading.Lock()

    # --- operator side (socket thread) -----------------------------------------------------------------------------
    def requests(self, obj: dict) -> list[SystemRequest]:
        """``{"op": "recover", "plan_id", "plan_hash", "steps"}`` -> one queued request per envelope step listed.
        Raises ``ValueError`` (the socket replies with it; nothing is queued) for a missing or edited plan file."""
        if set(obj) != {"op", "plan_id", "plan_hash", "steps"}:
            raise ValueError("recover takes exactly plan_id, plan_hash, steps")
        ap = Approval.model_validate_json(canonical.dumps({k: obj[k] for k in ("plan_id", "plan_hash", "steps")}))
        try:
            plan = load_plan(self.run, ap.plan_id)
        except (OSError, ValueError) as e:
            raise ValueError(f"plan {ap.plan_id}: {str(e).splitlines()[0][:160]}") from None
        if plan.content_hash() != ap.plan_hash:
            raise ValueError(f"plans/{ap.plan_id}.json does not hash to {ap.plan_hash[:16]} (edited or replaced)")
        bad = [n for n in ap.steps if n >= len(plan.steps)]
        if bad:
            raise ValueError(f"steps {bad} are not in plan {ap.plan_id}")
        out = []
        for n in ap.steps:
            step = plan.steps[n]
            if step.op not in ENVELOPE_OPS:
                continue
            out.append(SystemRequest(RECOVERY, recover_tool(step.op), build=self._builder(plan, n),
                                     action_id=f"{plan.plan_id}.{n}"))
        return out

    def _builder(self, plan: RecoveryPlan, n: int):
        args = plan.recover_args(n).to_obj()
        h = plan.content_hash()

        def build(gw, tick: int, seq: int) -> dict:
            with self._lock:
                halt = self.halts.get(h)
            if halt is not None:
                raise RecoveryHalted(f"plan {plan.plan_id} halted at step {halt.n} ({halt.decision}/{halt.reason}): "
                                     f"step {n} not run")
            return args
        return build

    # --- gateway side (control phase, gateway thread) ----------------------------------------------------------
    def serve(self, gw: Gateway, env: Envelope, header, ehash: str, deny) -> Admission:
        try:
            args = RecoverArgs.model_validate_json(canonical.dumps(env.args))
            ok = env.tool == recover_tool(args.step.op) and env.action_id == f"{args.plan_id}.{args.n}"
        except Exception:
            args, ok = None, False
        if not ok:
            return self._stop(args, deny(Reason.TOOL_ERROR), "args are not the RecoverArgs of this tool/action id")
        records = list(gw.recorder.rundir.records())
        from ks.verify.window import frozen_from_records
        fz = frozen_from_records(self.run, records)
        if fz is not None:
            return self._stop(args, deny(Reason.RECOVERY_FROZEN), f"tamper/stall alert at seq {fz}")
        why = self._unbound(records, args)
        if why is not None:
            return self._stop(args, deny(Reason.OUT_OF_SCOPE), why)
        plan = load_plan(self.run, args.plan_id)
        step = args.step
        if isinstance(step, RestoreStep):
            adm, detail = self._restore(gw, env, header, ehash, plan, step)
        elif isinstance(step, RerunStep):
            adm, detail = self._rerun(gw, env, header, ehash, plan, step)
        elif isinstance(step, CancelOutboxStep):
            adm, detail = self._cancel(gw, env, header, ehash, plan, step)
        elif isinstance(step, ResolveStep):
            adm, detail = self._resolve(gw, env, header, ehash, plan, step)
        elif isinstance(step, UnresolveStep):
            adm, detail = self._unresolve(gw, env, header, ehash, plan, step)
        elif isinstance(step, CompensateStep):
            adm, detail = deny(Reason.TOOL_ERROR), "no compensator is registered in this world"
        else:  # flag / replan carry no envelope; the tool name check above already refuses them
            adm, detail = deny(Reason.TOOL_ERROR), f"{step.op} creates no envelope"
        if adm.record.decision != Decision.EXEC:
            return self._stop(args, adm, detail)
        with self._lock:
            self.applied.append((args.plan_hash, args.n, adm.record.seq))
        return adm

    def _stop(self, args: RecoverArgs | None, adm: Admission, detail: str) -> Admission:
        if args is not None:
            r = adm.record
            with self._lock:
                self.halts.setdefault(args.plan_hash, Halt(args.n, r.seq, r.decision.value, r.reason.value, detail))
        return adm

    def _unbound(self, records: list, args: RecoverArgs) -> str | None:
        """G6: a prior matching approval, and the plan file still hashes to it (see module doc, step 3)."""
        if not any(_approval_covers(self.run, r, args) for r in records):
            return f"no executed ks.approve of {args.plan_id} {args.plan_hash[:16]} listing step {args.n}"
        try:
            plan = load_plan(self.run, args.plan_id)
        except (OSError, ValueError):
            return f"plans/{args.plan_id}.json missing or unreadable"
        if plan.content_hash() != args.plan_hash:
            return f"plans/{args.plan_id}.json does not hash to the approved plan_hash (edited)"
        if args.n >= len(plan.steps) or plan.steps[args.n] != args.step:
            return f"step {args.n} differs from the plan file"
        return None

    # --- steps -------------------------------------------------------------------------------------------------
    def _view(self, gw: Gateway, plan: RecoveryPlan, outcome: Any = None, seq: int | None = None):
        """What ``conflict.recheck`` reads from a DryRun: the plan, the re-runs' landed records, and (after the
        re-run executed) its tool writes."""
        recs = {s.action.seq: gw._record_at(s.action.seq) for s in plan.steps if isinstance(s, RerunStep)}
        return SimpleNamespace(plan=plan, planned=SimpleNamespace(rerun_records=recs, c_candidates={}),
                               outcomes={} if outcome is None else {seq: outcome})

    def _txn(self, gw: Gateway, header, ehash: str, body):
        """Reserve the seq, ``BEGIN IMMEDIATE``, run ``body(store, seq)`` -> ("exec", result, reads, writes,
        outbox_ids) | ("stale", Stale) | ("error", detail); COMMIT or ROLLBACK; record."""
        store = gw.store
        rtxn = gw.recorder.begin()
        try:
            store.conn.execute("BEGIN IMMEDIATE")
            try:
                out = body(store, rtxn.seq)
            except Exception as e:
                out = ("error", f"{type(e).__name__}: {str(e)[:160]}")
            if out[0] != "exec":
                if store.conn.in_transaction:
                    store.conn.execute("ROLLBACK")
                if out[0] == "stale":
                    adm = gw._done(SYSTEM_CONN, header, ehash, True, Decision.HOLD, Reason.STALE_PLAN, ActionClass.R,
                                   rtxn=rtxn)
                    return adm, out[1].detail
                adm = gw._done(SYSTEM_CONN, header, ehash, True, Decision.DENY, Reason.TOOL_ERROR, ActionClass.R,
                               rtxn=rtxn)
                return adm, out[1]
            _, result, reads, writes, oids = out
            rh = result_hash(result)
            gw.recorder.put_side(SideDomain.RESULT, rh, result)
            store.conn.execute("COMMIT")
        except BaseException:
            if store.conn.in_transaction:
                store.conn.execute("ROLLBACK")
            rtxn.rollback()
            raise
        adm = gw._done(SYSTEM_CONN, header, ehash, True, Decision.EXEC, Reason.OK, ActionClass.R, result=result,
                       result_hash=rh, read_set=tuple(sorted(reads, key=lambda e: (e.obj, e.ver))),
                       write_set=writes, outbox_ids=oids, rtxn=rtxn)
        return adm, "ok"

    def _restore(self, gw, env, header, ehash, plan, step: RestoreStep):
        from ks.recovery import apply_restore, recheck
        from ks.state import StaleExpect

        def body(store, seq):
            stale = recheck(store, self._view(gw, plan), step)
            if stale is not None:
                return ("stale", stale)
            try:
                apply_restore(store, step, seq=seq, action_id=env.action_id)
            except StaleExpect as e:
                return ("stale", SimpleNamespace(detail=str(e)))
            reads = () if step.to is None else (ReadEntry(obj=step.obj, ver=step.to.ver, hash=step.to.hash),)
            res = {"plan_id": plan.plan_id, "n": step.n, "op": "restore", "obj": step.obj}
            return ("exec", res, reads, writes_at(store, seq), ())
        return self._txn(gw, header, ehash, body)

    def _cancel(self, gw, env, header, ehash, plan, step: CancelOutboxStep):
        from ks.recovery import recheck

        def body(store, seq):
            stale = recheck(store, self._view(gw, plan), step)
            if stale is not None:
                return ("stale", stale)
            d = gw.outbox.get(step.outbox_id)
            res = {"plan_id": plan.plan_id, "n": step.n, "op": "cancel_outbox", "outbox": step.outbox_id}
            if d.item.status == OutboxStatus.CANCELLED:
                return ("exec", res, (d.read_entry(),), (), ())
            gw.outbox.set_status(d, OutboxStatus.CANCELLED, seq=seq, author=RECOVERY, action_id=env.action_id)
            return ("exec", res, (d.read_entry(),), writes_at(store, seq), ())
        return self._txn(gw, header, ehash, body)

    def _rerun(self, gw, env, header, ehash, plan, step: RerunStep):
        from ks.recovery import recheck

        rec = gw._record_at(step.action.seq)
        if rec is None or rec.envelope is None or rec.decision != Decision.EXEC or (
                rec.envelope.agent_id, rec.envelope.action_id) != (step.action.agent_id, step.action.action_id):
            return self._txn(gw, header, ehash, lambda s, q: ("error", f"seq {step.action.seq} is not the step's action"))
        reheld: list[str] = []

        def body(store, seq):
            stale = recheck(store, self._view(gw, plan), step)
            if stale is not None:
                return ("stale", stale)
            out = self.rerunner(store, step, rec, seq)
            stale = recheck(store, self._view(gw, plan, out, step.action.seq), step)  # the re-run's new objects
            if stale is not None:
                return ("stale", stale)
            repaired = _repair(store, rec, out, seq)
            reheld.extend(e.outbox_id for e in out.effects if e.disposition in ("reheld", "reheld_same"))
            res = {"plan_id": plan.plan_id, "n": step.n, "op": "rerun", "agent_id": rec.envelope.agent_id,
                   "action_id": rec.envelope.action_id, "error": out.error, "repaired": list(repaired),
                   "effects": [[e.outbox_id or "-", e.disposition] for e in out.effects]}
            return ("exec", res, out.reads, writes_at(store, seq), tuple(reheld))
        adm, detail = self._txn(gw, header, ehash, body)
        if adm.record.decision == Decision.EXEC:
            for oid in reheld:
                self._hold(gw, plan, step.n, oid)
        return adm, detail

    def _resolve(self, gw, env, header, ehash, plan, step: ResolveStep):
        """ADR-05a §4: one signed c-0 record, one new version of O (see module doc)."""
        from ks.recovery import recheck
        from ks.recovery.resolver import rebase, rule_known

        rec = gw._record_at(step.rebased.seq)
        if not rule_known(step):
            return self._txn(gw, header, ehash, lambda s, q: ("error", f"unknown rule {step.rule}/{step.rule_version}"))
        if rec is None or rec.envelope is None or rec.decision != Decision.EXEC or (
                rec.envelope.agent_id, rec.envelope.action_id) != (step.rebased.agent_id, step.rebased.action_id):
            return self._txn(gw, header, ehash, lambda s, q: ("error", f"seq {step.rebased.seq} is not the rebased action"))
        taint = frozenset((v.obj, v.ver) for v in plan.taint_set.versions)

        def body(store, seq):
            stale = recheck(store, self._view(gw, plan), step)
            if stale is not None:
                return ("stale", stale)
            rb = rebase(store, step, rec, self.rerunner, seq, env.action_id, taint)
            if not rb.ok:
                return ("error", f"rebase refused: {rb.why}")
            if not self._hash_ok(rb.value_hash, step):
                return ("error", f"rebased hash {rb.value_hash[:12]} is not the plan's {step.rebased_hash[:12]}")
            res = {"plan_id": plan.plan_id, "n": step.n, "op": "resolve", "obj": step.obj,
                   "rule": f"{step.rule}/{step.rule_version}", "rebased": step.rebased.action_id,
                   "rebased_hash": rb.value_hash}
            return ("exec", res, rb.reads, writes_at(store, seq), ())
        return self._txn(gw, header, ehash, body)

    @staticmethod
    def _hash_ok(value_hash: str | None, step: ResolveStep) -> bool:
        """The landed rebased value must be the one the approved dry-run showed (``rebased_hash``)."""
        return value_hash == step.rebased_hash

    def _unresolve(self, gw, env, header, ehash, plan, step: UnresolveStep):
        """ADR-05a §5: put back what the resolution (and its dependent re-runs) wrote; re-hold their items."""
        from ks.recovery.resolver import RESOLVE_TOOL, unresolve_problems

        rr = gw._record_at(step.resolution.seq)
        if rr is None or rr.envelope is None or rr.decision != Decision.EXEC or rr.envelope.tool != RESOLVE_TOOL \
                or rr.envelope.action_id != step.resolution.action_id:
            return self._txn(gw, header, ehash, lambda s, q: ("error", f"seq {step.resolution.seq} is not the resolution"))
        records = list(gw.recorder.rundir.records())

        def status(oid: str):
            try:
                return gw.outbox.get(oid).item.status
            except Exception:
                return None

        def body(store, seq):
            why = unresolve_problems(records, rr, step.reverts, step.reheld, status)
            if why is not None:
                return ("stale", SimpleNamespace(detail=f"unresolve blocked: {why}"))
            reads = []
            for e in step.reverts:
                head = store.get(e.obj)
                if head is None or head.ver != e.expect.ver or head.hash != e.expect.hash:
                    return ("stale", SimpleNamespace(detail=f"{e.obj}: head moved"))
                store.put(e.obj, store.value_at(e.obj, e.to.ver), author=RECOVERY, seq=seq, action_id=env.action_id)
                reads.append(ReadEntry(obj=e.obj, ver=e.to.ver, hash=e.to.hash))
            res = {"plan_id": plan.plan_id, "n": step.n, "op": "unresolve", "resolution": step.resolution.action_id,
                   "reverted": [e.obj for e in step.reverts], "reheld": list(step.reheld)}
            return ("exec", res, tuple(reads), writes_at(store, seq), ())
        adm, detail = self._txn(gw, header, ehash, body)
        if adm.record.decision == Decision.EXEC:
            for oid in step.reheld:
                self._hold(gw, plan, step.n, oid, reason=UNRESOLVED_REASON)
        return adm, detail

    def _hold(self, gw: Gateway, plan: RecoveryPlan, n: int, oid: str, reason: str = REHELD_REASON) -> None:
        """ADR-03 §7: the re-held item's hold is a recorded Control (``ks.recovery``, ``rerun_reheld``, or
        ``resolution_reverted`` after an undo, ADR-05a §5)."""
        tick = gw._tick
        rtxn = gw.recorder.begin()
        store = gw.store
        ctl = Control(control_id=f"k-{rtxn.seq:06d}", op=ControlOp.HOLD, target=f"outbox:{oid}", epoch=None,
                      alert_id=plan.alert_id, issued_by=RECOVERY, auto=False, reason=reason)
        aid = f"{plan.plan_id}.{n}.hold.{oid}"
        try:
            env = system_envelope(RECOVERY, CONTROL_TOOL, ctl.to_obj(), action_id=aid, tick=tick, sign=self._sign)
            gw._nonces[(RECOVERY, env.nonce)] = tick
            gw._actions.add((RECOVERY, aid))
            header = env.header()
            gw.recorder.put_side(SideDomain.ARGS, header.args_hash, env.args)
            store.conn.execute("BEGIN IMMEDIATE")
            d = gw.outbox.get(oid)
            w = gw.outbox.set_status(d, OutboxStatus.HELD, seq=rtxn.seq, author=RECOVERY, action_id=aid)
            result = {"control_id": ctl.control_id, "op": "hold", "target": ctl.target, "epoch": None}
            rh = result_hash(result)
            gw.recorder.put_side(SideDomain.RESULT, rh, result)
            store.conn.execute("COMMIT")
        except BaseException:
            if store.conn.in_transaction:
                store.conn.execute("ROLLBACK")
            rtxn.rollback()
            raise
        reads = tuple(sorted((*d.item.lineage, d.read_entry()), key=lambda e: (e.obj, e.ver)))
        gw._done(SYSTEM_CONN, header, env.content_hash(), True, Decision.EXEC, Reason.OK, ActionClass.R,
                 result=result, result_hash=rh, read_set=reads, write_set=(w,), rtxn=rtxn, control=ctl)


def _repair(store: Any, rec: Any, out: Any, seq: int) -> tuple[str, ...]:
    """Repair versions (module doc): the original's landed writes the re-run left as head because its value equals
    the head. Tombstones and redacted heads are left alone (nothing to re-write)."""
    from ks.state import RedactedValue

    done = {w.obj for w in out.tool_writes} | {w.obj for w in out.outbox_writes}
    env = rec.envelope
    fixed = []
    for w in rec.write_set:
        if w.obj.startswith("outbox:") or w.obj in done:
            continue
        try:
            head = store.get(w.obj)
        except RedactedValue:
            continue
        if head is None or head.value is None or head.ver != w.after.ver or head.hash != w.after.hash:
            continue
        store.put(w.obj, head.value, author=env.agent_id, seq=seq, action_id=env.action_id)
        fixed.append(w.obj)
    return tuple(sorted(fixed))


def _approval_covers(run: Path, r: Any, args: RecoverArgs) -> bool:
    env = r.envelope
    if env is None or env.tool != APPROVE_TOOL or r.decision != Decision.EXEC or r.conn_id != SYSTEM_CONN \
            or env.agent_id != OPERATOR or not r.sig_ok:
        return False
    v = _side(run, env.args_hash)
    try:
        ap = Approval.model_validate_json(canonical.dumps(v))
    except Exception:
        return False
    return ap.plan_id == args.plan_id and ap.plan_hash == args.plan_hash and args.n in ap.steps


def bench_releasable(records: Iterable[Any], status_of: Callable[[str], OutboxStatus | None]) -> tuple[str, ...]:
    """Outbox ids the bench approver may unhold (X4): the latest hold record of the item is a ``rerun_reheld``
    hold by ``ks.recovery`` and the item is still held. Rider / replan / flagged items (still under the gateway's
    ``lineage_hold``) are never listed (ADR-05 §6.1 amended, B3-48)."""
    last: dict[str, Any] = {}
    for r in records:
        c = r.control
        if c is not None and r.decision == Decision.EXEC and c.target.startswith("outbox:") \
                and c.op in (ControlOp.HOLD, ControlOp.UNHOLD):
            last[c.target[len("outbox:"):]] = c
    return tuple(sorted(oid for oid, c in last.items()
                        if c.op == ControlOp.HOLD and c.issued_by == RECOVERY and c.reason == REHELD_REASON
                        and status_of(oid) == OutboxStatus.HELD))


def restored_releasable(run: str | Path) -> tuple[str, ...]:
    """B3-27, for the operator after an apply: outbox ids the gateway held with reason ``sensitive_field`` (ADR-03 G3:
    a payee field the item read changed after creation) that are still held, whose lineage holds no tainted version
    (forward closure of the chained alerts) and whose every sensitive field now has the value the item read again
    (the restore put it back). Releasing them is the operator's call (``ks contain unhold``); the release phase
    re-checks taint and the sensitive field before it dispatches. Honest items that read the original bank details
    would otherwise stay held for good."""
    from ks.contracts import OutboxItem, RunDir, split_obj_id
    from ks.contracts.rundir import STATE_DB
    from ks.taint import taint_from_alerts
    from ks.world.scenario import open_world_store

    run = Path(run)
    rd = RunDir(run)
    records = list(rd.records())
    sens = set(rd.config().sensitive_fields)
    taint = taint_from_alerts(records, _alerts(run, records))
    last: dict[str, Any] = {}
    for r in records:
        c = r.control
        if c is not None and r.decision == Decision.EXEC and c.target.startswith("outbox:") \
                and c.op in (ControlOp.HOLD, ControlOp.UNHOLD):
            last[c.target[len("outbox:"):]] = c
    want = sorted(o for o, c in last.items()
                  if c.op == ControlOp.HOLD and c.issued_by == "ks.gateway" and c.reason == "sensitive_field")
    out = []
    store = open_world_store(run / STATE_DB)
    try:
        for oid in want:
            head = store.get(f"outbox:{oid}")
            item = OutboxItem.from_obj(head.value) if head is not None and head.value is not None else None
            if item is None or item.status != OutboxStatus.HELD:
                continue
            if taint is not None and any(taint.is_tainted(e.obj, e.ver) for e in item.lineage):
                continue
            ok = True
            for e in item.lineage:
                t, _, f = split_obj_id(e.obj)
                if f is None or f"{t}.{f}" not in sens:
                    continue
                cur = store.get(e.obj)
                if cur is None or (cur.ver != e.ver and cur.hash != e.hash):
                    ok = False
                    break
            if ok:
                out.append(oid)
    finally:
        store.close()
    return tuple(out)


# --- CLI side --------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class DryRunResult:
    plan: RecoveryPlan
    text: str
    path: Path
    stale: bool


def _alerts(run: Path, records: list) -> list:
    from ks.contracts import Alert
    out = []
    for r in records:
        e = r.envelope
        if e is not None and e.tool == "ks.alert" and r.decision == Decision.EXEC:
            v = _side(run, e.args_hash)
            if isinstance(v, dict):
                out.append(Alert.model_validate_json(canonical.dumps(v)))
    return out


def cli_dry_run(run: str | Path, *, alerts: list | None = None, store: Any = None) -> DryRunResult:
    """``ks recover RUN --dry-run``: taint from the chained alerts, plan, simulate the re-runs (rolled back),
    write ``plans/<plan_id>.json``. Raises ``ks.recovery.NoPlan``-like ``ValueError`` when there is nothing to plan."""
    from ks.contracts import RunDir
    from ks.contracts.rundir import STATE_DB
    from ks.recovery import ToolRerunner, args_from_sidestore, dry_run, plan_recovery, render, write_plan
    from ks.taint import taint_from_alerts
    from ks.world.scenario import open_world_store
    from ks.world.tools import WorldDispatcher

    run = Path(run)
    rd = RunDir(run)
    records = list(rd.records())
    alerts = _alerts(run, records) if alerts is None else alerts
    if not alerts:
        raise ValueError("no chained ks.alert in the record: nothing to recover")
    taint = taint_from_alerts(records, alerts)
    if taint is None:
        raise ValueError("no suspended suspect: no seed and no plan (ADR-05 §4)")
    own = store is None
    st = open_world_store(run / STATE_DB) if own else store
    resolver = rd.config().tcb_view().resolver  # ADR-05a: off by default; ks run --resolver ww_rebase/1
    args_of = args_from_sidestore(run)
    try:
        planned = plan_recovery(records, taint, alert_id=alerts[0].alert_id, state=st, resolver=resolver,
                                alerts=tuple(alerts), args_of=args_of)
        dr = dry_run(st, planned, rerunner=ToolRerunner(WorldDispatcher(), args_of), on_stale="halt")
    finally:
        if own:
            st.close()
    path = write_plan(dr.plan, rd)
    return DryRunResult(dr.plan, render(dr), path, dr.stale is not None)


def cli_unresolve(run: str | Path, ref: str, *, store: Any = None) -> DryRunResult:
    """``ks recover RUN --unresolve <plan_id>.<n>`` (ADR-05a §5): write the undo plan ``plans/p-<as_of_seq>.json``
    (one ``unresolve`` step, or ``flag(unresolve_blocked)``); the operator applies it with ``--apply`` like any plan,
    so the undo is approved, recorded and verified. Raises ``ValueError`` for an unknown or already undone ref."""
    from ks.contracts import RunDir
    from ks.contracts.rundir import STATE_DB
    from ks.recovery import write_plan
    from ks.recovery.resolver import label, plan_unresolve
    from ks.world.scenario import open_world_store
    from ks.recovery.rerun import args_from_sidestore

    run = Path(run)
    rd = RunDir(run)
    records = list(rd.records())
    args_of = args_from_sidestore(run)
    own = store is None
    st = open_world_store(run / STATE_DB) if own else store
    try:
        from ks.recovery.planner import _outbox_status
        plan, why = plan_unresolve(records, ref, plan_of=lambda pid: load_plan(run, pid), args_value=args_of,
                                   status_of=lambda oid: _outbox_status(st, oid))
    finally:
        if own:
            st.close()
    path = write_plan(plan, rd)
    s = plan.steps[0]
    lines = [f"plan {plan.plan_id}  hash {plan.content_hash()[:16]}  alert {plan.alert_id}  culprit {plan.culprit}  "
             f"as_of_seq {plan.as_of_seq}  {label(rd.config().resolver)}"]
    if s.op == "unresolve":
        r0 = s.reverts[0]
        lines.append(f"unresolve    {s.resolution.action_id}: {r0.obj} back to v{r0.to.ver}, flag raised again; "
                     f"re-held {', '.join(s.reheld) or '-'}" + "".join(f"; {e.obj} back to v{e.to.ver}"
                                                                      for e in s.reverts[1:]))
    else:
        lines.append(f"flag         unresolve_blocked {s.obj} {s.action.action_id}: {why}  (a person decides)")
    for e in plan.diff:
        lines.append(f"diff         {e.obj}  v{e.current.ver} {e.current.hash[:12]} -> {e.planned_hash[:12]}")
    return DryRunResult(plan, "\n".join(lines) + "\n", path, False)


def cli_apply(run: str | Path, plan_id: str, approve: Iterable[int] = (), *,
              send: Callable[[dict], dict] | None = None) -> tuple[RecoveryPlan, dict, dict]:
    """``ks recover RUN --apply PLAN_ID``: the operator approves (``ks.approve``) then asks the gateway to run the
    approved envelope steps. Returns (plan, approve reply, recover reply). ``send`` defaults to the J1 socket."""
    from .operator import operator_request

    send = send or (lambda obj: operator_request(run, obj))
    plan = load_plan(run, plan_id)
    steps = approved_steps(plan, approve)
    h = plan.content_hash()
    # B3-27: one ``apply`` request (approve + recover queued together): on a paused run the approval and every step
    # land in one control phase, before agents act again. The gateway still binds each step to the recorded approve.
    rep = send({"op": "apply", "plan_id": plan.plan_id, "plan_hash": h, "steps": list(steps)})
    if rep.get("pending") or "approve" not in rep:
        return plan, rep, ({} if not rep.get("pending") else rep)
    a = rep["approve"]
    if not a.get("ok"):
        return plan, a, {}
    return plan, a, {"ok": rep.get("ok"), "steps": rep.get("steps", [])}


def frozen(run: str | Path) -> str | None:
    """M12 / F5 for the CLI: ``ks verify`` not OK, or a tamper / witness-stall alert in the chained record."""
    from ks.contracts import RunDir
    from ks.verify import verify
    from ks.verify.window import frozen_from_records

    rep = verify(run, log=lambda s: None)
    if not rep.ok:
        return f"verify {rep.reason} at seq {rep.first_bad}"
    fz = frozen_from_records(Path(run), list(RunDir(run).records()))
    return None if fz is None else f"tamper/stall alert at seq {fz}"

