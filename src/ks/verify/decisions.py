"""R3 / X6 anchored decisions replay (B3-20). ``ks run --decisions SRC`` replays the operator's Controls of a source
run; this module decides whether SRC may be trusted and checks that a replayed run really did what the source did.

* :func:`load_decisions` refuses a source that has no anchor, uses repro keys, or fails ``verify --head``; it returns
  only ``ks.operator``-signed, executed, verified c-0 Controls (what a human decided), never monitor/agent records.
* ``RunConfig.decisions_from`` = :func:`anchor_hash` of the source anchor (sha256 of the anchor's canonical line).
* :func:`approval_verdict`: an approval whose ``plan_hash`` differs from the recomputed plan is ``hold/stale_plan``.
* :func:`verify_replay` runs ordinary ``verify`` on the new run, then every difference from the source is a failure
  with ``first_bad`` (reason ``replay_mismatch``, exit DIVERGED; contracts 1.5, B3-47).
Honest limit: records hold ``args_hash``, not args, so an approval is compared by ``args_hash``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ks.contracts import (APPROVE_TOOL, SYSTEM_CONN, VERIFY_REASONS, Control, Decision, Reason, Record, RunAnchor,
                          RunConfig, VerifyReport)
from ks.contracts.hashing import sha256_hex
from ks.contracts.rundir import CONFIG, RECORD

from .core import _lines, verify

__all__ = ["DecisionsRefused", "ReplayedControl", "ReplayedApproval", "SourceDecisions", "anchor_hash",
           "load_decisions", "approval_verdict", "verify_replay", "refuse_with_rogue"]

OPERATOR = "ks.operator"


class DecisionsRefused(Exception):
    """The source cannot be replayed; ``reason`` is ``no_anchor``, ``repro_keys``, ``rogue`` or a verify reason."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"decisions refused: {reason}" + (f" ({detail})" if detail else ""))
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ReplayedControl:
    seq: int
    tick: int
    control: Control


@dataclass(frozen=True, slots=True)
class ReplayedApproval:
    seq: int
    tick: int
    args_hash: str
    decision: str = "exec"
    reason: str = "ok"


@dataclass(frozen=True, slots=True)
class SourceDecisions:
    anchor_hash: str
    controls: tuple[ReplayedControl, ...]
    approvals: tuple[ReplayedApproval, ...]


def anchor_hash(anchor: RunAnchor) -> str:
    """The value ``RunConfig.decisions_from`` carries."""
    return sha256_hex(anchor.to_canonical())


def refuse_with_rogue(decisions, rogue) -> None:
    """``--decisions`` with ``--rogue`` is refused (R3): a jury script's run is not a replay of a trusted source."""
    if decisions is not None and rogue is not None:
        raise DecisionsRefused("rogue", "--decisions cannot be combined with --rogue")


def _operator_rows(run: Path, upto: int | None = None):
    for line in _lines((run / RECORD).read_bytes()):
        rec = Record.from_canonical(line)
        if upto is not None and rec.seq > upto:
            break  # the unwitnessed tail is never trusted
        env = rec.envelope
        if env is not None and env.agent_id == OPERATOR and rec.conn_id == SYSTEM_CONN and rec.sig_ok:
            yield rec


def _extract(run: Path, upto: int | None = None) -> tuple[tuple[ReplayedControl, ...], tuple[ReplayedApproval, ...]]:
    ctl, appr = [], []
    for rec in _operator_rows(run, upto):
        if rec.decision == Decision.EXEC and rec.control is not None and rec.control.issued_by == OPERATOR:
            ctl.append(ReplayedControl(rec.seq, rec.tick, rec.control))
        elif rec.envelope.tool == APPROVE_TOOL:
            appr.append(ReplayedApproval(rec.seq, rec.tick, rec.envelope.args_hash, rec.decision.value, rec.reason.value))
    return tuple(ctl), tuple(appr)


def load_decisions(source: str | Path, anchor: RunAnchor | None) -> SourceDecisions:
    source = Path(source)
    if anchor is None:
        raise DecisionsRefused("no_anchor", "the source needs an anchor (verify --head)")
    try:
        cfg = RunConfig.from_canonical((source / CONFIG).read_bytes())
    except Exception as e:
        raise DecisionsRefused("unreadable", str(e)[:120]) from None
    if cfg.key_mode == "repro":
        raise DecisionsRefused("repro_keys", "a repro-key run is never anchored")
    rep = verify(source, anchor, log=lambda s: None)
    if not rep.ok:
        raise DecisionsRefused(rep.reason, f"source fails verify --head (first_bad={rep.first_bad})")
    if not rep.anchored:
        raise DecisionsRefused(rep.unanchored_reason or "no_anchor")
    controls, approvals = _extract(source, anchor.seq)
    return SourceDecisions(anchor_hash(anchor), controls, approvals)


def approval_verdict(approved_plan_hash: str, current_plan_hash: str) -> tuple[Decision, Reason]:
    """M8: an approval binds a plan by hash; a replayed approval for another plan is held, never executed."""
    if approved_plan_hash != current_plan_hash:
        return Decision.HOLD, Reason.STALE_PLAN
    return Decision.EXEC, Reason.OK


def verify_replay(run: str | Path, src: SourceDecisions, anchor: RunAnchor | None = None) -> VerifyReport:
    """Ordinary ``verify`` first (a failure is returned as is); then ``decisions_from`` and every replayed decision."""
    run = Path(run)
    base = verify(run, anchor, log=lambda s: None)
    if not base.ok:
        return base

    def bad(first: int | None, reason: str = "replay_mismatch") -> VerifyReport:
        return base.model_copy(update=dict(ok=False, exit=int(VERIFY_REASONS[reason]), reason=reason, first_bad=first,
                                           anchored=False, unanchored_reason="no_anchor"))

    cfg = RunConfig.from_canonical((run / CONFIG).read_bytes())
    if cfg.decisions_from != src.anchor_hash:
        return bad(None)
    got_c, got_a = _extract(run)
    n = len(list(_lines((run / RECORD).read_bytes())))
    for i, want in enumerate(src.controls):
        if i >= len(got_c):
            return bad(n + 1)
        g = got_c[i]
        w, c = want.control, g.control
        if (g.tick, c.op, c.target, c.epoch, c.reason, c.auto) != (want.tick, w.op, w.target, w.epoch, w.reason,
                                                                   w.auto):
            return bad(g.seq)
    if len(got_c) > len(src.controls):
        return bad(got_c[len(src.controls)].seq)  # a decision the source never made
    # approvals: same args_hash replays (exec); a different plan must have been held as stale_plan
    for i, want in enumerate(src.approvals):
        if i >= len(got_a):
            return bad(n + 1)
        g = got_a[i]
        if g.args_hash == want.args_hash:
            ok = (g.decision, g.reason) == (want.decision, want.reason)
        else:  # a different plan: must be held, never executed
            ok = (g.decision, g.reason) == ("hold", "stale_plan")
        if not ok:
            return bad(g.seq)
    if len(got_a) > len(src.approvals):
        return bad(got_a[len(src.approvals)].seq)
    return base
