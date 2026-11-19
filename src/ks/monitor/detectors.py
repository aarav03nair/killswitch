"""ADR-04 section 1: the detector catalogue. Pure functions ``Context -> list[Finding]``, no LLM, no clock.

Detectors find bad data and cite evidence (record seqs, object versions). They never name anyone;
:mod:`ks.monitor.attribute` does that afterwards, from ``Record.attributed_agent`` only.
Hard or soft is not decided here: :mod:`ks.monitor.alerts` takes it from the C4 contract.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from typing import Any

from ks.contracts import (GENESIS_HASH, TOMBSTONE_HASH, ActionClass, Decision, Detector, ObjVer, Reason, split_obj_id,
                          is_field_obj)

from .ibanlib import iban_ok, iban_problem
from .model import MISSING, Context, Finding, agent_of

__all__ = ["DETECTORS", "iban_checksum", "beneficiary_changed_then_paid", "price_vs_history", "ledger_balance",
           "scope_breach", "signature", "reconcile", "witness_stall", "pii_egress", "barrier_deadline",
           "find_pii", "rate", "tamper"]


def _exec(ctx: Context) -> Iterator:
    return (r for r in ctx.index.records if r.decision == Decision.EXEC)


def _is_payee(ctx: Context, obj: str) -> bool:
    t, _, f = split_obj_id(obj)
    return f is not None and f"{t}.{f}" in ctx.params.payee_fields


def _iban_of(value: Any) -> Any:
    return value.get("iban") if isinstance(value, dict) else value


def iban_checksum(ctx: Context) -> list[Finding]:
    """Hard (I-class): a payee field was written with a malformed or mod-97-invalid IBAN."""
    out = []
    for r in _exec(ctx):
        for w in r.write_set:
            if not _is_payee(ctx, w.obj) or w.after.hash == TOMBSTONE_HASH:
                continue
            v = ctx.value(w.after.hash)
            if v is MISSING or v is None:
                continue
            if iban_problem(_iban_of(v)) is not None:
                out.append(Finding(Detector.IBAN_CHECKSUM, (r.seq,), (ObjVer(obj=w.obj, ver=w.after.ver),)))
    return out


def beneficiary_changed_then_paid(ctx: Context) -> list[Finding]:
    """Hard: a payment read a payee field version that was written (version > 1) within the window before it.
    H4: evidence_versions is the payee field object only; the payment is in evidence_seqs."""
    out = []
    for pay in _exec(ctx):
        if pay.envelope is None or pay.envelope.tool not in ctx.params.payment_tools:
            continue
        for e in pay.read_set:
            if e.ver < 2 or not _is_payee(ctx, e.obj):
                continue
            wr = ctx.index.writer(e.obj, e.ver)
            if wr is None or wr.seq >= pay.seq:
                continue
            if 0 <= pay.tick - wr.tick <= ctx.params.beneficiary_window_ticks:
                out.append(Finding(Detector.BENEFICIARY_CHANGED_THEN_PAID, (pay.seq,),
                                   (ObjVer(obj=e.obj, ver=e.ver),)))
    return out


def _price(value: Any, key: str) -> int | None:
    p = value.get(key) if isinstance(value, dict) else None
    return p if isinstance(p, int) and not isinstance(p, bool) else None


def price_vs_history(ctx: Context) -> list[Finding]:
    """Soft: a written price is more than ``price_factor`` times above, or below 1/factor of, its frozen baseline."""
    out = []
    pr = ctx.params
    for r in _exec(ctx):
        for w in r.write_set:
            t, _, f = split_obj_id(w.obj)
            if f is not None or t not in pr.price_keys or w.before is None or w.after.hash == TOMBSTONE_HASH:
                continue
            new = _price(ctx.value(w.after.hash), pr.price_keys[t])
            base = pr.price_baseline.get(w.obj)
            if base is None:
                hist = ctx.state.history(w.obj)
                base = _price(ctx.value(hist[0].hash), pr.price_keys[t]) if hist else None
            if new is None or base is None or base <= 0:
                continue
            if new > base * pr.price_factor or new * pr.price_factor < base:
                out.append(Finding(Detector.PRICE_VS_HISTORY, (r.seq,), (ObjVer(obj=w.obj, ver=w.after.ver),)))
    return out


def ledger_balance(ctx: Context) -> list[Finding]:
    """Hard (I-class): a current ledger posting has debit != credit."""
    out = []
    prefix = ctx.params.ledger_table + ":"
    for obj, ref in sorted(ctx.state.heads().items()):
        if not obj.startswith(prefix) or ref.hash == TOMBSTONE_HASH:
            continue
        v = ctx.value(ref.hash)
        if not isinstance(v, dict) or v.get("debit") == v.get("credit"):
            continue
        wr = ctx.index.writer(obj, ref.ver)
        if wr is not None:
            out.append(Finding(Detector.LEDGER_BALANCE, (wr.seq,), (ObjVer(obj=obj, ver=ref.ver),)))
    return out


def scope_breach(ctx: Context) -> list[Finding]:
    """Hard: a signature-verified record denied ``out_of_scope`` (ADR-03 ``p.scope``). Cites the denied record."""
    out = []
    for r in ctx.index.records:
        if r.sig_ok and r.decision == Decision.DENY and r.reason == Reason.OUT_OF_SCOPE:
            a = agent_of(r)
            out.append(Finding(Detector.SCOPE, (r.seq,), hint_agents=(a,) if a else ()))
    return out


def signature(ctx: Context) -> list[Finding]:
    """Hard, connection only: bad signatures. One finding per connection (first few seqs)."""
    by_conn: dict[str, list[int]] = {}
    for r in ctx.index.records:
        if r.reason == Reason.BAD_SIG:
            by_conn.setdefault(r.conn_id, []).append(r.seq)
    return [Finding(Detector.SIGNATURE, tuple(s[:8]), conn_id=c, key=(Detector.SIGNATURE, c))
            for c, s in sorted(by_conn.items())]


def reconcile(ctx: Context) -> list[Finding]:
    """Hard, names nobody: fold(record) differs from the live state (unmediated write, class U)."""
    fold: dict[str, tuple[int, str]] = {}
    for r in _exec(ctx):
        for w in r.write_set:
            fold[w.obj] = (w.after.ver, w.after.hash)
    live = ctx.state.heads()
    bad = sorted(o for o in set(fold) | set(live)
                 if (o in fold) != (o in live) or (o in fold and fold[o] != (live[o].ver, live[o].hash)))
    if not bad:
        return []
    vers = tuple(ObjVer(obj=o, ver=live[o].ver) for o in bad if o in live)
    return [Finding(Detector.RECONCILE, (ctx.index.last_seq,), vers,
                    key=(Detector.RECONCILE, tuple((o, live[o].ver if o in live else 0) for o in bad)))]


def witness_stall(ctx: Context) -> list[Finding]:
    """Never hard: the witness head stopped advancing for more than ``witness_stall_ticks``."""
    if not ctx.index.records:
        return []
    last_w = max((c.tick for c in ctx.witness), default=0)
    if ctx.index.last_tick - last_w <= ctx.params.witness_stall_ticks:
        return []
    return [Finding(Detector.WITNESS_STALL, (ctx.index.last_seq,),
                    key=(Detector.WITNESS_STALL, max((c.seq for c in ctx.witness), default=0)))]


_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_AADHAAR = re.compile(r"\b\d{4} \d{4} \d{4}\b")
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")


def _luhn(digits: str) -> bool:
    s, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        s += d
        alt = not alt
    return s % 10 == 0


def _strings(v: Any, keys: frozenset[str], hit: list[bool]) -> Iterator[str]:
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            if k.lower() in keys and x not in (None, "", [], {}):
                hit.append(True)
            yield from _strings(x, keys, hit)
    elif isinstance(v, list):
        for x in v:
            yield from _strings(x, keys, hit)


def find_pii(payload: Any, keys: frozenset[str] = frozenset()) -> bool:
    """True if the payload carries a PII-keyed field, an SSN or Aadhaar pattern, a Luhn-valid card number or a
    valid IBAN. Pure; the matched text is never returned (rule 9)."""
    hit: list[bool] = []
    for s in _strings(payload, keys, hit):
        if _SSN.search(s) or _AADHAAR.search(s) or any(m.group(0) and _IBAN.fullmatch(m.group(0)) and
                                                     iban_ok(m.group(0)) for m in _IBAN.finditer(s)):
            return True
        for m in _CARD.finditer(s):
            d = re.sub(r"\D", "", m.group(0))
            if 13 <= len(d) <= 19 and _luhn(d):
                return True
    return bool(hit)


def pii_egress(ctx: Context) -> list[Finding]:
    """Hard (I1, F3): a queued ``comms.send_email`` outbox item whose payload carries PII. Seeds the queued
    ``outbox:<id>`` version, written by the emailing agent."""
    out = []
    for r in _exec(ctx):
        if r.envelope is None or r.envelope.tool not in ctx.params.email_tools or not r.outbox_ids:
            continue
        queued = {f"outbox:{o}" for o in r.outbox_ids}
        for w in r.write_set:
            if w.obj not in queued:
                continue
            item = ctx.value(w.after.hash)
            ph = item.get("payload_hash") if isinstance(item, dict) else None
            payload = ctx.value(ph) if ph else MISSING
            if payload is not MISSING and find_pii(payload, ctx.params.pii_keys):
                out.append(Finding(Detector.PII_EGRESS, (r.seq,), (ObjVer(obj=w.obj, ver=w.after.ver),)))
    return out


def barrier_deadline(ctx: Context) -> list[Finding]:
    """Soft: a connection missed a tick barrier. No record exists, so the evidence is empty and the alert
    names a connection only (M3, PMO S5)."""
    return [Finding(Detector.BARRIER_DEADLINE, conn_id=m.conn_id,
                    key=(Detector.BARRIER_DEADLINE, m.tick, m.conn_id)) for m in ctx.barrier_misses]


def rate(ctx: Context) -> list[Finding]:
    """Soft (alert only): an agent's records in one tick exceed ``rate_factor`` x its own rolling baseline.
    The baseline is per agent, so a quiet agent bursting is caught and a busy agent is judged against itself."""
    pr = ctx.params
    counts: dict[str, dict[int, list[int]]] = {}
    for r in ctx.index.records:
        a = agent_of(r)
        if a is not None:
            counts.setdefault(a, {}).setdefault(r.tick, []).append(r.seq)
    out = []
    for a, per in sorted(counts.items()):
        first = min(per)
        for t, seqs in sorted(per.items()):
            if len(seqs) < pr.rate_min_count or t - first < pr.rate_warmup_ticks:
                continue
            span = min(pr.rate_window_ticks, t - first)
            base = sum(len(per.get(u, ())) for u in range(t - span, t)) / span
            if len(seqs) > pr.rate_factor * max(base, 1.0):
                out.append(Finding(Detector.RATE, tuple(seqs[:8]), hint_agents=(a,), key=(Detector.RATE, a, t)))
    return out


def tamper(ctx: Context) -> list[Finding]:
    """Never hard, names nobody: the on-disk record disagrees with itself (hash, envelope hash, chain link, seq
    gap) or with the in-memory head. Recovery freezes by kind; no agent is suspended or named."""
    recs = ctx.index.records
    if not recs:
        return []
    out = []
    prev_seq, prev_hash = 0, GENESIS_HASH
    for r in recs:
        probs = [p for p in r.integrity_problems() if p != "unsigned record"]
        if r.seq != prev_seq + 1:
            probs.append("seq gap")
        if r.prev_hash != prev_hash:
            probs.append("chain break")
        for p in probs:
            out.append(Finding(Detector.TAMPER, (r.seq,), key=(Detector.TAMPER, p, r.seq)))
        prev_seq, prev_hash = r.seq, r.hash
    if ctx.memory_head is not None and ctx.memory_head != (recs[-1].seq, recs[-1].hash):
        out.append(Finding(Detector.TAMPER, (recs[-1].seq,), key=(Detector.TAMPER, "head", recs[-1].seq,
                                                                  ctx.memory_head)))
    return out


DETECTORS: dict[str, Callable[[Context], list[Finding]]] = {
    Detector.IBAN_CHECKSUM: iban_checksum,
    Detector.BENEFICIARY_CHANGED_THEN_PAID: beneficiary_changed_then_paid,
    Detector.PRICE_VS_HISTORY: price_vs_history,
    Detector.LEDGER_BALANCE: ledger_balance,
    Detector.SCOPE: scope_breach,
    Detector.SIGNATURE: signature,
    Detector.RECONCILE: reconcile,
    Detector.WITNESS_STALL: witness_stall,
    Detector.PII_EGRESS: pii_egress,
    Detector.BARRIER_DEADLINE: barrier_deadline,
    Detector.RATE: rate,
    Detector.TAMPER: tamper,
}
"""Detector name -> function, in scan order. Names are the C4 ``Detector`` constants."""
