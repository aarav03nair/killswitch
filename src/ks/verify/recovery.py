"""B3-30: recovery records are bound to an approval and to the plan file (CALL-02 G6, SEC-03 F5, ADR-05 §8).

:func:`recovery_pass` (reason ``recovery_unbound``, TAMPER; contracts 1.5.0, additive): every admitted (exec or
hold) ``ks.recover.<op>`` record must

* carry readable C5 ``RecoverArgs`` (side store, ARGS) whose ``step.op`` is the tool's ``<op>``;
* follow an executed, verified ``ks.approve`` of ``ks.operator`` on c-0 with the same ``plan_id`` and ``plan_hash``
  that lists ``n``;
* match ``plans/<plan_id>.json``: the file hashes to ``plan_hash`` and its ``steps[n]`` equals the step carried
  (an edited plan file is detected);
* be the only executed record of that (``plan_hash``, ``n``) (one apply per step).

Denied ``ks.recover.*`` records executed nothing and are not checked. Owner: maya (verify internals: arjun).

:func:`resolution_pass` (reason ``resolution_invalid``, TAMPER; contracts 1.7.0, D-18, ADR-05a §6; owner vikram) runs
after :func:`recovery_pass`, so binding is already proven. It catches a validly signed and approved resolution that
the rule does not support, and names the failing check. Per executed ``ks.recover.resolve`` record r of plan P:
(1) the rule is in ``resolver.RULES``; (2) ``resolver.eligible`` on the records <= ``P.as_of_seq`` re-derives every
record-only check and the fields ``culprit_ver``, ``expect``, ``to``, ``rebased``, ``unblocked``, ``rationale``;
(3) the landed record writes exactly O, ``before == expect``, ``after.hash == rebased_hash``, author ``ks.recovery``,
and reads (O, ``to``) and nothing tainted (``sim_clean`` proven on the record); (4) r.seq > ``P.as_of_seq``, one
executed resolve per (``plan_id``, ``n``), no resolve of (O, H) after an executed undo of (O, H), the restores the
check depends on ran before r and the re-runs that read ``vH`` did not run before r. Per executed
``ks.recover.unresolve`` u: (5) it names an executed resolve (earlier, same plan hash) that no earlier undo named; its
reverts and re-held items are the ones the record implies (the resolved object back to ``vH``; each object a dependent
wrote back to the version it replaced, or deleted if a dependent created it; S4-34: dependents include later honest
actions, ``ks.recovery.resolver.dependents``); it wrote exactly those values; every re-held item gets a ``ks.control``
hold by ``ks.recovery`` with reason ``resolution_reverted`` after u.

Not checked (TCB residual, ADR-05a §6): verify does not re-run H's tool; the rebased value is trusted to ``ks.recovery``.
"""

from __future__ import annotations

from pathlib import Path

from ks.contracts import (APPROVE_TOOL, RECOVER_TOOL_PREFIX, SYSTEM_CONN, Approval, Decision, RecoverArgs,
                          RecoveryPlan, Record, canonical)
from ks.contracts.rundir import PLANS_DIR

from .window import Violation, _side_value

__all__ = ["recovery_pass", "resolution_pass"]

_RESOLUTION_TOOLS = ("ks.recover.resolve", "ks.recover.unresolve")


def recovery_pass(run: Path, records: list[Record]) -> None:
    approvals: list[Approval] = []
    done: set[tuple[str, int]] = set()
    plans: dict[str, RecoveryPlan | None] = {}

    def bad(r: Record, why: str):
        raise Violation("recovery_unbound", r.seq, f"{r.envelope.tool} at seq {r.seq}: {why}")

    for r in records:
        env = r.envelope
        if env is None:
            continue
        if env.tool == APPROVE_TOOL and r.decision == Decision.EXEC and r.conn_id == SYSTEM_CONN and r.sig_ok \
                and env.agent_id == "ks.operator":
            try:
                approvals.append(Approval.model_validate_json(canonical.dumps(_side_value(run, env.args_hash))))
            except Exception:
                pass  # an unreadable approval binds nothing
            continue
        if not env.tool.startswith(RECOVER_TOOL_PREFIX) or r.decision == Decision.DENY:
            continue
        try:
            a = RecoverArgs.model_validate_json(canonical.dumps(_side_value(run, env.args_hash)))
        except Exception:
            bad(r, "RecoverArgs missing or unreadable in the side store")
        if env.tool != RECOVER_TOOL_PREFIX + a.step.op:
            bad(r, f"tool does not match step op {a.step.op}")
        if not any(ap.plan_id == a.plan_id and ap.plan_hash == a.plan_hash and a.n in ap.steps for ap in approvals):
            bad(r, f"no prior ks.approve of {a.plan_id} {a.plan_hash[:16]} listing step {a.n}")
        if a.plan_id not in plans:
            try:
                plans[a.plan_id] = RecoveryPlan.from_canonical((run / PLANS_DIR / f"{a.plan_id}.json").read_bytes())
            except Exception:
                plans[a.plan_id] = None
        plan = plans[a.plan_id]
        if plan is None:
            bad(r, f"plans/{a.plan_id}.json missing or unreadable")
        if plan.content_hash() != a.plan_hash:
            bad(r, f"plans/{a.plan_id}.json does not hash to the approved plan_hash (edited)")
        if a.n >= len(plan.steps) or plan.steps[a.n] != a.step:
            bad(r, f"step {a.n} differs from plans/{a.plan_id}.json")
        if r.decision == Decision.EXEC and env.tool not in _RESOLUTION_TOOLS:  # those: resolution_pass names it
            if (a.plan_hash, a.n) in done:
                bad(r, f"step {a.n} of {a.plan_id} applied twice")
            done.add((a.plan_hash, a.n))


def resolution_pass(run: Path, records: list[Record]) -> None:
    """See module doc (ADR-05a §6, reason ``resolution_invalid``)."""
    from ks.contracts import Alert, ResolveStep, RerunStep, UnresolveStep
    from ks.recovery.resolver import (CHECKS, RECOVERY, RESOLVE_TOOL, UNRESOLVE_REASON, UNRESOLVE_TOOL, Context,
                                      eligible, expected_reverts, rule_known, unblocked_for, undone_pairs)
    from ks.taint import RecordIndex

    recs = sorted(records, key=lambda r: r.seq)
    if not any(r.envelope is not None and r.envelope.tool in _RESOLUTION_TOOLS and r.decision == Decision.EXEC
               for r in recs):
        return
    plans: dict[str, RecoveryPlan | None] = {}
    done: set[tuple[str, int]] = set()
    undone: set[tuple[str, int]] = set()
    resolves: dict[int, tuple[Record, RecoverArgs]] = {}
    unresolved: set[int] = set()

    def bad(r: Record, why: str):
        raise Violation("resolution_invalid", r.seq, f"{r.envelope.tool} at seq {r.seq}: {why}")

    def args_value(r: Record):
        return _side_value(run, r.envelope.args_hash)

    def args_ok(r: Record) -> bool:
        from ks.contracts import args_hash
        v = args_value(r)
        return isinstance(v, dict) and args_hash(v) == r.envelope.args_hash

    def plan_of(r: Record, pid: str) -> RecoveryPlan:
        if pid not in plans:
            try:
                plans[pid] = RecoveryPlan.from_canonical((run / PLANS_DIR / f"{pid}.json").read_bytes())
            except Exception:
                plans[pid] = None
        if plans[pid] is None:
            bad(r, f"plans/{pid}.json missing or unreadable")
        return plans[pid]

    def executed(pid: str, n: int, tool: str) -> list[Record]:
        aid = f"{pid}.{n}"
        return [x for x in recs if x.envelope is not None and x.decision == Decision.EXEC and x.envelope.tool == tool
                and x.envelope.agent_id == RECOVERY and x.envelope.action_id == aid]

    for r in recs:
        env = r.envelope
        if env is None or r.decision != Decision.EXEC or env.tool not in _RESOLUTION_TOOLS:
            continue
        try:
            a = RecoverArgs.model_validate_json(canonical.dumps(args_value(r)))
        except Exception:
            bad(r, "RecoverArgs missing or unreadable")
        if env.tool == RESOLVE_TOOL:
            step = a.step
            if not isinstance(step, ResolveStep):
                bad(r, "args carry no resolve step")
            P = plan_of(r, a.plan_id)
            if not rule_known(step):  # (1)
                bad(r, f"rule {step.rule}/{step.rule_version} is not a known resolver rule")
            if r.seq <= P.as_of_seq:  # (4) order
                bad(r, f"out of order: resolution at seq {r.seq} is not after the plan's as_of_seq {P.as_of_seq}")
            if (a.plan_id, a.n) in done:
                bad(r, f"replayed: step {a.n} of {a.plan_id} resolved twice")
            if (step.obj, step.rebased.seq) in undone:
                bad(r, f"replayed: {step.obj} / seq {step.rebased.seq} resolved again after a person undid it")
            sub = [x for x in recs if x.seq <= P.as_of_seq]
            ix = RecordIndex(sub)
            alerts = []
            for x in sub:
                if x.envelope is not None and x.envelope.tool == "ks.alert" and x.decision == Decision.EXEC:
                    try:
                        alerts.append(Alert.model_validate_json(canonical.dumps(args_value(x))))
                    except Exception:
                        pass
            taint = frozenset((v.obj, v.ver) for v in P.taint_set.versions)
            ctx = Context(ix=ix, as_of=P.as_of_seq, suspect=P.culprit, taint=taint,
                          restored=frozenset(s.obj for s in P.steps if s.op == "restore"),
                          alerts=tuple(alerts),
                          args_ok=args_ok, undone=undone_pairs(sub, args_value))
            el = eligible(ctx, step.obj, step.rebased)  # (2)
            if not el.ok:
                bad(r, f"check {el.failed} fails: {el.detail}")
            for f in ("culprit_ver", "expect", "to", "rebased"):
                if getattr(el, f) != getattr(step, f):
                    bad(r, f"field {f} is not what the record implies")
            if tuple(step.rationale) != CHECKS:
                bad(r, f"rationale {list(step.rationale)} is not the rule's checks")
            if any(s.op == "replan" and s.action.seq == step.rebased.seq for s in P.steps):
                bad(r, "check honest_deterministic fails: the plan re-plans the rebased action (LLM step)")
            reruns = [ix.by_seq[s.action.seq] for s in P.steps if isinstance(s, RerunStep) and s.action.seq in ix.by_seq]
            if tuple(step.unblocked) != unblocked_for(step.obj, step.culprit_ver.ver, step.expect.ver, reruns, P):
                bad(r, "unblocked items are not the plan's dependent re-runs' items")
            ws = r.write_set  # (3) sim_clean on the record
            if r.attributed_agent != RECOVERY or len(ws) != 1 or ws[0].obj != step.obj or ws[0].before != step.expect \
                    or ws[0].after.hash != step.rebased_hash:
                bad(r, "check sim_clean fails: the landed write is not one version of the object with rebased_hash "
                       "over expect")
            reads = {(e.obj, e.ver) for e in r.read_set}
            if (step.obj, step.to.ver) not in reads or reads & taint:
                bad(r, "check sim_clean fails: the landed read set lacks the clean base or reads a tainted version")
            for s in P.steps:  # (4) order against the plan's own steps
                if s.op == "restore" and s.obj in el.seed_objs and \
                        not any(x.seq < r.seq for x in executed(P.plan_id, s.n, "ks.recover.restore")):
                    bad(r, f"out of order: restore of {s.obj} (step {s.n}) did not run before the resolution")
                if isinstance(s, RerunStep) and s.action.seq in ix.by_seq and \
                        any((e.obj, e.ver) == (step.obj, step.expect.ver) for e in ix.by_seq[s.action.seq].read_set) \
                        and any(x.seq < r.seq for x in executed(P.plan_id, s.n, "ks.recover.rerun")):
                    bad(r, f"out of order: re-run step {s.n} (reader of v{step.expect.ver}) ran before the resolution")
            done.add((a.plan_id, a.n))
            resolves[r.seq] = (r, a)
            continue
        # (5) unresolve
        step = a.step
        if not isinstance(step, UnresolveStep):
            bad(r, "args carry no unresolve step")
        got = resolves.get(step.resolution.seq)
        if got is None or got[0].envelope.action_id != step.resolution.action_id:
            bad(r, f"names no executed resolution at seq {step.resolution.seq}")
        rr, ra = got
        if ra.plan_hash != step.resolution_plan_hash:
            bad(r, "resolution_plan_hash is not the resolution's plan hash")
        if rr.seq in unresolved:
            bad(r, f"resolution at seq {rr.seq} undone twice")
        want, reheld = expected_reverts(recs, rr, ra.step, ra.plan_id, r.seq)
        if list(step.reverts) != want or list(step.reheld) != reheld:
            bad(r, "reverts or re-held items are not what the record implies")
        if sorted((w.obj, w.after.hash) for w in r.write_set) != sorted((e.obj, e.to_hash) for e in step.reverts):
            bad(r, "the landed writes are not the reverts")
        for oid in step.reheld:
            if not any(x.seq > r.seq and x.control is not None and x.decision == Decision.EXEC
                       and x.control.target == f"outbox:{oid}" and x.control.issued_by == RECOVERY
                       and x.control.reason == UNRESOLVE_REASON for x in recs):
                bad(r, f"outbox:{oid} has no resolution_reverted hold after the undo")
        unresolved.add(rr.seq)
        undone.add((ra.step.obj, ra.step.rebased.seq))
