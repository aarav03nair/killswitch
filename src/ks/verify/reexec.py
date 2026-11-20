"""B3-25 (F9, ``reexec_invalid``): cross-record check of every ``reexec_of``.

A record with ``reexec_of = k`` must be the one re-execution of record k, where record k is a verified (sig_ok)
``hold/needs_approval`` agent envelope (not a re-execution itself, not on c-0) with the same ``envelope_hash``, run by
the same agent on the same connection, and an executed ``unhold action:<record k id>`` Control issued by a human
(``ks.operator``) or ``ks.recovery`` (not ``auto``) sits between them. Only approval holds re-run; a hold is
re-executed at most once.
"""

from __future__ import annotations

from ks.contracts import SYSTEM_CONN, ControlOp, Decision, Reason, Record

from .window import Violation

__all__ = ["reexec_pass"]

MANUAL_UNHOLD = frozenset({"ks.operator", "ks.recovery"})


def reexec_pass(recs: list[Record]) -> None:
    by_seq = {r.seq: r for r in recs}
    unholds: dict[str, list[int]] = {}  # hold record id -> seqs of executed manual unhold Controls
    done: set[int] = set()
    for r in recs:
        c = r.control
        if c is not None and c.op == ControlOp.UNHOLD and r.decision == Decision.EXEC and not c.auto \
                and c.issued_by in MANUAL_UNHOLD and c.target.startswith("action:"):
            unholds.setdefault(c.target[len("action:"):], []).append(r.seq)
        if r.reexec_of is None:
            continue

        def bad(why: str, r=r):
            raise Violation("reexec_invalid", r.seq, f"re-execution at seq {r.seq}: {why}")

        h = by_seq.get(r.reexec_of)
        if h is None or h.decision != Decision.HOLD or not h.sig_ok or h.envelope is None \
                or h.conn_id == SYSTEM_CONN or h.reexec_of is not None:
            bad(f"seq {r.reexec_of} is not a held agent envelope")
        if h.reason != Reason.NEEDS_APPROVAL:
            bad(f"seq {h.seq} is a {h.reason} hold, not an approval hold")
        if r.envelope is None or r.envelope_hash != h.envelope_hash:
            bad("envelope_hash differs from the hold's")
        if r.envelope.agent_id != h.envelope.agent_id or r.conn_id != h.conn_id:
            bad("not the held agent / connection")
        if h.seq in done:
            bad(f"hold seq {h.seq} was already re-executed")
        if not any(h.seq < s < r.seq for s in unholds.get(h.record_id, ())):
            bad("no executed unhold between the hold and the re-execution")
        done.add(h.seq)
