"""B3-31: the record-derived passes of ``ks verify`` that need the whole log.

* :func:`window_pass` (ADR-02 F4, reason ``window_violation``): every executed ``ks.dispatch`` must release an item
  whose creating record checks out, no earlier than its release tick, with no hold / taint seed / author suspension
  in ``(created_seq, dispatched_seq)`` left unlifted by an unhold / release.
* :func:`alerts_pass` (F6, ``alert_mismatch``): ``alerts.jsonl`` is only a copy; it must equal, in order, the
  executed chained ``ks.alert`` records (compared by ``args_hash``).
* :func:`side_pass` (``side_entry_mismatch``): every ``sidestore/`` file parses, is named by its hash, and a
  non-redacted value hashes to it; entries for a record's args/result hash carry the right domain.
  Honest limit: taint seeds are the alert's direct ``evidence_versions`` only; versions derived from them are not
  followed (TaintView does follow them).
* :func:`frozen_from_records`: the recovery freeze (M12) derived from chained ``ks.alert`` records only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ks.contracts import SYSTEM_PRINCIPALS, ControlOp, Decision, Record, RunConfig, SideDomain, SideEntry, args_hash
from ks.contracts.rundir import ALERTS, SIDESTORE_DIR
from ks.contracts.state import split_obj_id

__all__ = ["Violation", "window_pass", "alerts_pass", "side_pass", "frozen_from_records"]

ALERT_TOOL, DISPATCH_TOOL = "ks.alert", "ks.dispatch"
FREEZE_KINDS = frozenset({"tamper", "witness_stall"})


class Violation(Exception):
    def __init__(self, reason: str, first_bad: int | None, detail: str):
        super().__init__(reason)
        self.reason, self.first_bad, self.detail = reason, first_bad, detail


def _side_value(run: Path, h: str) -> Any | None:
    """The raw value behind ``h`` from the side store, or None (missing, redacted, unreadable)."""
    p = run / SIDESTORE_DIR / h[:2] / f"{h}.json"
    try:
        e = SideEntry.from_canonical(p.read_bytes())
    except Exception:
        return None
    return None if e.redacted else e.value


def _alert_value(run: Path, r: Record) -> dict | None:
    env = r.envelope
    if env is None or env.tool != ALERT_TOOL or r.decision != Decision.EXEC:
        return None
    v = _side_value(run, env.args_hash)
    return v if isinstance(v, dict) else None


def _is_system(r: Record) -> bool:
    return r.envelope is not None and r.envelope.agent_id in SYSTEM_PRINCIPALS


def _outbox_of(r: Record) -> str | None:
    ids = [w.obj for w in r.write_set if w.obj.startswith("outbox:")]
    return ids[0][len("outbox:"):] if len(ids) == 1 else None


def window_pass(run: Path, records: list[Record], config: RunConfig) -> None:
    h = config.hold_window_ticks
    written_tick: dict[tuple[str, int], int] = {}  # (obj, ver) -> tick of the record that wrote it
    items: dict[str, dict] = {}
    seeds_seen: set[tuple[str, int]] = set()  # direct alert evidence versions so far (derived versions: not followed)

    def sensitive(obj: str) -> bool:
        try:
            table, _, field = split_obj_id(obj)
        except ValueError:
            return False
        return field is not None and f"{table}.{field}" in config.sensitive_fields

    def release_tick(rec: Record) -> int:
        t = rec.tick + h
        if h == 0:
            return t
        vs = [written_tick[(e.obj, e.ver)] for e in rec.read_set if sensitive(e.obj) and (e.obj, e.ver) in written_tick]
        return max(t, max(vs) + 2 * h) if vs else t

    for r in records:
        env = r.envelope
        ex = r.decision == Decision.EXEC
        if env is not None and ex:
            if not _is_system(r):
                for oid in r.outbox_ids:  # (re)creation: a new window starts here
                    lineage = {(e.obj, e.ver) for e in r.read_set}
                    flags: set[str] = set()
                    if seeds_seen & lineage:
                        flags.add("taint")  # created after the alert: the gateway creates it held (ADR-04)
                    if any(w.obj == f"outbox:{oid}" and w.before is not None for w in r.write_set):
                        flags.add("hold")  # B2 re-creation: back on hold by creation until unheld
                    items[oid] = dict(rec=r, flags=flags, done=False, author=env.agent_id, lineage=lineage)
            elif env.tool == DISPATCH_TOOL:
                _check_dispatch(r, items, release_tick)
            elif env.tool == ALERT_TOOL:
                a = _alert_value(run, r)
                seeds = {(ov["obj"], ov["ver"]) for ov in (a or {}).get("evidence_versions", ())
                         if isinstance(ov, dict)}
                seeds_seen |= seeds
                for it in items.values():
                    if not it["done"] and seeds & it["lineage"]:
                        it["flags"].add("taint")
            elif r.control is not None:
                _apply_control(r, items)
        for w in r.write_set:
            written_tick.setdefault((w.obj, w.after.ver), r.tick)


def _apply_control(r: Record, items: dict) -> None:
    c = r.control
    kind, _, ident = c.target.partition(":")
    if kind == "outbox" and ident in items:
        if c.op == ControlOp.HOLD:
            items[ident]["flags"].add("hold")
        elif c.op == ControlOp.UNHOLD:
            items[ident]["flags"] -= {"hold", "taint"}
    elif kind == "agent":
        for it in items.values():
            if it["author"] == ident and not it["done"]:
                if c.op in (ControlOp.SUSPEND, ControlOp.REVOKE):
                    it["flags"].add("suspend")
                elif c.op == ControlOp.RELEASE:
                    it["flags"].discard("suspend")


def _check_dispatch(r: Record, items: dict, release_tick) -> None:
    def bad(why: str):
        raise Violation("window_violation", r.seq, f"dispatch at seq {r.seq}: {why}")

    oid = _outbox_of(r)
    it = items.get(oid) if oid else None
    if it is None:
        bad("no creating agent record for the item")
    cr: Record = it["rec"]
    if it["done"]:
        bad(f"{oid} already dispatched")
    if cr.envelope is None or f"outbox:{oid}" not in {w.obj for w in cr.write_set}:
        bad("creating record does not write the item")
    if r.tick < release_tick(cr):
        bad(f"tick {r.tick} is before the item's release tick {release_tick(cr)}")
    if it["flags"]:
        bad(f"{oid} has an unlifted {'/'.join(sorted(it['flags']))} since seq {cr.seq}")
    it["done"] = True


def alerts_pass(run: Path, records: list[Record]) -> None:
    chained = [(r.seq, r.envelope.args_hash) for r in records
               if r.envelope is not None and r.envelope.tool == ALERT_TOOL and r.decision == Decision.EXEC]
    p = run / ALERTS
    try:
        data = p.read_bytes() if p.is_file() else b""
    except OSError as e:
        raise Violation("alert_mismatch", None, f"alerts.jsonl unreadable: {e}") from None
    from ks.contracts import Alert, CanonicalError
    copy: list[str] = []
    for i, line in enumerate(data.split(b"\n")[:-1] if data.endswith(b"\n") else data.split(b"\n") if data else [], 1):
        try:
            copy.append(args_hash(Alert.from_canonical(line).to_obj()))
        except CanonicalError as e:
            raise Violation("alert_mismatch", chained[i - 1][0] if i <= len(chained) else len(records) + 1,
                            f"alerts.jsonl line {i} does not parse: {str(e)[:100]}") from None
    for i, (seq, h) in enumerate(chained):
        if i >= len(copy) or copy[i] != h:
            raise Violation("alert_mismatch", seq, f"alerts.jsonl differs from the chained ks.alert at seq {seq}")
    if len(copy) > len(chained):
        raise Violation("alert_mismatch", len(records) + 1, "alerts.jsonl has an alert no chained record carries")


def side_pass(run: Path, records: list[Record]) -> None:
    # alerts hold no PII, so are never redactable: a chained ks.alert whose side entry is missing / redacted / not an
    # Alert would let deleting unsigned evidence lift the freeze or drop taint seeds (F5).
    for r in records:
        if r.envelope is not None and r.envelope.tool == ALERT_TOOL and r.decision == Decision.EXEC:
            v = _side_value(run, r.envelope.args_hash)
            ok = False
            if isinstance(v, dict):
                try:
                    from ks.contracts import Alert
                    ok = args_hash(Alert.model_validate(v).to_obj()) == r.envelope.args_hash
                except Exception:
                    ok = False
            if not ok:
                raise Violation("side_entry_mismatch", r.seq, f"ks.alert at seq {r.seq}: side entry missing, redacted or not an Alert")
    root = run / SIDESTORE_DIR
    if not root.is_dir():
        return
    want: dict[str, SideDomain] = {}
    first: dict[str, int] = {}
    for r in records:
        if r.envelope is not None:
            want.setdefault(r.envelope.args_hash, SideDomain.ARGS)
            first.setdefault(r.envelope.args_hash, r.seq)
        if r.result_hash:
            want.setdefault(r.result_hash, SideDomain.RESULT)
            first.setdefault(r.result_hash, r.seq)
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        try:
            e = SideEntry.from_canonical(p.read_bytes())
        except Exception as ex:
            raise Violation("side_entry_mismatch", None, f"{p.name}: {str(ex)[:100]}") from None
        if p.name != f"{e.hash}.json" or p.parent.name != e.hash[:2]:
            raise Violation("side_entry_mismatch", first.get(e.hash), f"{p.name} is not named by its hash")
        if e.hash in want and e.domain != want[e.hash] and not (e.domain == SideDomain.VALUE):
            raise Violation("side_entry_mismatch", first.get(e.hash), f"{p.name} has the wrong domain {e.domain}")


def frozen_from_records(run: Path, records: list[Record]) -> int | None:
    """Seq of the first executed chained ``ks.alert`` of kind tamper / witness_stall, else None. ``alerts.jsonl``
    is never read: editing it can neither freeze nor unfreeze (F5, test_live_edit_freezes)."""
    for r in records:
        a = _alert_value(run, r)
        if a is not None and a.get("kind") in FREEZE_KINDS:
            return r.seq
    return None
