"""RT15 (S4-21): stale-plan race on recovery apply. An approved plan must never overwrite work that landed after
its dry-run.

Attack: between ``ks recover --dry-run`` (the diff the operator approves) and the apply, an honest agent writes, through
the real gateway, to an object a planned re-run will write. If the apply executed anyway it would silently
replace that honest version with the re-run's value. That would be an undo nobody approved, made on a diff the
operator never saw.

THREAT-MODEL claim defended (C6): "Recovery appends compensating records; a held outbox item is cancelled only by
an approved plan step after the dry-run diff". The guard is the M8 re-check in the apply transaction
(``ks.runtime.recover``: ``ks.recovery.recheck`` after ``BEGIN IMMEDIATE``). A step that is stale gets
``hold/stale_plan``, with no write and no later step. The mutation gate (M12) switches that re-check off and this
module must fail.

Harness: the in-process world (``tests/recovery/world.py``): the real ``Gateway``, ``Recorder``, ``RecoveryService``,
signer and witness, with no sockets or uids. It is in process because the attacker gets something the world
scenario never schedules: one extra honest write at a chosen tick. Measured (kabir, S4-21, seed 2, F2+): with
``ks run --step`` and the apply delayed 0, 3 or 8 ticks after the dry-run, no honest agent wrote a re-run object,
and every step executed.
"""

from __future__ import annotations

from ks.contracts import Decision, Reason
from ks.verify import verify

from tests.recovery import world as W
from tests.runtime.test_recover import _side, approve, recover, setup, tick


def _q(_s):
    pass


def _race(w):
    """The honest racing write: billing re-drafts the invoice its tainted h+1 draft wrote (qty 6), via the gateway."""
    inv = w.log[(W.H + 1, "billing")]
    late = W.extra_tick(w, "billing", "billing.draft_invoice", {**_side(w, inv.envelope.args_hash), "qty": 6})
    assert late.decision == Decision.EXEC and [x.obj for x in late.write_set] == ["invoices:INV-0031"]
    return late.write_set[0]


def _assert_held_not_clobbered(w, r, honest):
    recs = [x.record for x in r if not isinstance(x, Exception)]
    halted = [x for x in r if isinstance(x, Exception)]
    stale = recs[-1]
    assert (stale.decision, stale.reason) == (Decision.HOLD, Reason.STALE_PLAN), [
        (x.envelope.tool, x.decision.value, x.reason.value) for x in recs]
    assert stale.envelope.tool == "ks.recover.rerun" and not stale.write_set
    assert halted and len(r) == len(recs) + len(halted)  # nothing after the stale step is recorded
    head = w.store.get("invoices:INV-0031")
    assert (head.ver, head.hash, head.author) == (honest.after.ver, honest.after.hash, "billing")  # honest work kept
    assert verify(w.rundir.path, log=_q).ok


def test_rt15a_honest_write_after_dry_run_holds_the_apply(tmp_path):
    """Write lands between the dry-run and the approve+apply (the console's normal pace)."""
    w = W.run(tmp_path / "f2.db")
    dr = setup(w)
    honest = _race(w)
    approve(w, dr.plan)
    r = recover(w, dr.plan)
    tick(w)
    _assert_held_not_clobbered(w, r, honest)


def test_rt15b_approval_is_not_a_blank_cheque(tmp_path):
    """The ``ks.approve`` record lands first and the honest write comes after it. The recorded approval does not
    cover state that moved after the dry-run, so the apply is still re-checked inside its own transaction."""
    w = W.run(tmp_path / "f2.db")
    dr = setup(w)
    approve(w, dr.plan)
    tick(w)
    honest = _race(w)
    r = recover(w, dr.plan)
    tick(w)
    _assert_held_not_clobbered(w, r, honest)
