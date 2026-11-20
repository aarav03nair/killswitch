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
"""

from __future__ import annotations

from pathlib import Path

from ks.contracts import (APPROVE_TOOL, RECOVER_TOOL_PREFIX, SYSTEM_CONN, Approval, Decision, RecoverArgs,
                          RecoveryPlan, Record, canonical)
from ks.contracts.rundir import PLANS_DIR

from .window import Violation, _side_value

__all__ = ["recovery_pass"]


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
        if r.decision == Decision.EXEC:
            if (a.plan_hash, a.n) in done:
                bad(r, f"step {a.n} of {a.plan_id} applied twice")
            done.add((a.plan_hash, a.n))
