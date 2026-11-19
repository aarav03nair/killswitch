"""Re-run simulation (B3-24, ADR-05 §6.3 M14, §7): re-execute a tainted honest action's **original tool and
args** against the restored state inside :meth:`ks.state.Store.simulate`, and report what it would write and emit.

:class:`ToolRerunner` is the :class:`~ks.recovery.dryrun.Rerunner` that :func:`~ks.recovery.dryrun.dry_run` calls,
once per ``rerun`` step in seq order, after every restore. It takes

* a ``ToolDispatcher`` (``ks.gateway.dispatch`` protocol; the world passes ``ks.world.tools.WorldDispatcher()``).
  This package does not import ``ks.world`` (A3 guard): the caller injects the world's tools;
* an args source ``args_of(record) -> dict`` (M14: args come from the side store, ARGS domain, keyed by the
  record's ``envelope.args_hash``; :func:`args_from_sidestore` for a run dir, :func:`args_from_mapping` for tests).
  Missing or redacted args raise :class:`ArgsUnavailable`; the dry-run turns that step into
  ``flag(redacted_args)`` (M14 "redacted args give flag");

The tool runs in a :class:`~ks.gateway.dispatch.GatewayTxn` at the dry-run's seq with the **original**
``agent_id``/``action_id`` (M14: idempotency keys derive from those, not from the recovery envelope), so its
writes carry the original author. Effects (M14 outbox dedupe), per ``Execution.outbox`` request ``i`` paired with
``record.outbox_ids[i]``:

* the key is ``idempotency_key(agent_id, action_id, sink, i)``; an existing ``outbox:<id>`` with another key is a
  :class:`RerunError` (the record and the outbox disagree);
* queued/held/released item -> v+1 of the **same** ``outbox:<id>``, **back on hold** (CALL-02 B2): status
  ``held``, ``payload_hash`` of the simulated payload, ``lineage`` = the re-run's read set, ``created_seq`` = the
  re-run's seq, ``release_tick`` and ``author`` (the original agent) unchanged; the version is written by the
  original agent, as ``ks.gateway.outbox.Outbox.create`` does for a re-created key (B3-23). Disposition
  ``reheld``, or ``reheld_same`` when the payload hash is unchanged. ADR-05 M14 text says ``queued`` with a fresh
  ``release_tick``; B2 ("back on hold") and the B3-23 outbox use ``held``, which is the stricter: the bench
  approver releases it (ADR-05 Consequences, X4);
* no readable ``outbox:<id>`` object (record and store disagree) -> nothing written, disposition ``missing``
  (the planner has already flagged it ``outbox_missing``);
* dispatched item -> nothing written or emitted; ``dispatched_same`` when the simulated payload hash equals the
  dispatched one (the dry-run drops the planner's conservative ``flag(dispatched_tainted)``), else
  ``dispatched_tainted`` (the flag stays, scored in R);
* cancelled item -> nothing (``cancelled``);
* a request with no original id -> ``new``: the re-run would create an effect the original never had. Counted in
  :attr:`DryRun.reemitted`; never written (the hero target is 0);
* an original id with no request any more -> ``dropped``: a held item gets v+1 ``cancelled`` in the simulation.

Re-run lineage (for B3-30 apply): the read set of a re-run, and so the ``lineage`` of a re-held item, is the
**tool reads only** (``merge_read_set((), tool_reads)``, every entry ``source="tool"``). The live record's read set
is view + tool (``merge_read_set(view, tool)``, B3-46): a re-run has no tick and no ``TickFrame.view``, so it
cannot have view reads, and its lineage is narrower than the original's. Conservative in the useful direction for
release (fewer, exact reads) but a re-held item's lineage will not list the view objects the original saw.
The tool's ``write_set`` is checked against the store (``ks.gateway.txn.writes_at``) as the gateway does.

Records hold hashes only; :class:`RerunOutcome` carries hashes, never values or args.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ks.contracts import (OutboxItem, OutboxStatus, ReadEntry, SideDomain, SideEntry, WriteEntry, args_hash,
                          idempotency_key, merge_read_set, value_hash)
from ks.contracts.recovery import RerunStep
from ks.contracts.record import Record
from ks.gateway.dispatch import GatewayTxn
from ks.gateway.txn import writes_at

__all__ = ["ArgsUnavailable", "RerunError", "Effect", "RerunOutcome", "ToolRerunner", "args_from_mapping",
           "args_from_sidestore"]

ArgsSource = Callable[[Record], Mapping[str, Any]]


class ArgsUnavailable(LookupError):
    """The original args are missing or redacted: the re-run step becomes ``flag(redacted_args)`` (M14)."""


class RerunError(RuntimeError):
    """The record and the store disagree about an outbox item (idempotency key mismatch)."""


@dataclass(frozen=True)
class Effect:
    """One outbox effect of a re-run (hashes only)."""

    outbox_id: str | None
    sink: str
    ordinal: int
    idempotency_key: str
    payload_hash: str | None
    """Simulated payload hash (``None`` for ``dropped``)."""
    original_payload_hash: str | None
    """From the existing ``outbox:<id>`` item; ``None`` when there is none (``missing``)."""
    disposition: str
    """``reheld`` · ``reheld_same`` · ``missing`` · ``dispatched_same`` · ``dispatched_tainted`` · ``cancelled`` · ``new`` ·
    ``dropped``."""


@dataclass(frozen=True)
class RerunOutcome:
    """What one re-run would do. ``writes`` = tool writes + simulated outbox versions (what the diff sees)."""

    seq: int
    """Original record seq."""
    sim_seq: int
    agent_id: str
    action_id: str
    tool: str
    reads: tuple[ReadEntry, ...]
    tool_writes: tuple[WriteEntry, ...]
    outbox_writes: tuple[WriteEntry, ...]
    effects: tuple[Effect, ...]
    error: str | None
    """``result.error`` of the tool (e.g. ``not_found``), else ``None``."""
    changed: tuple[str, ...]
    """Objects whose re-run value hash differs from the original's after-hash (or written only by one side)."""

    @property
    def writes(self) -> tuple[WriteEntry, ...]:
        return tuple(sorted((*self.tool_writes, *self.outbox_writes), key=lambda w: w.obj))


def args_from_mapping(m: Mapping[str, Mapping[str, Any]]) -> ArgsSource:
    """``args_hash -> args`` (tests, in-process runs). The args are re-hashed against the record."""

    def of(r: Record) -> Mapping[str, Any]:
        h = r.envelope.args_hash
        a = m.get(h)
        if a is None or args_hash(dict(a)) != h:
            raise ArgsUnavailable(f"seq {r.seq}: args {h[:12]} not available")
        return a
    return of


def args_from_sidestore(run_path: str | os.PathLike[str]) -> ArgsSource:
    """Args from ``<run>/sidestore/<h[:2]>/<h>.json`` (C3 SideEntry, ARGS domain), re-hashed against the record.
    The path is spelled here so this package need not import the run-dir module (A3 guard)."""
    root = Path(run_path)

    def of(r: Record) -> Mapping[str, Any]:
        h = r.envelope.args_hash
        p = root / "sidestore" / h[:2] / f"{h}.json"
        try:
            e = SideEntry.model_validate(json.loads(p.read_bytes()))
        except (OSError, ValueError) as exc:
            raise ArgsUnavailable(f"seq {r.seq}: args {h[:12]} unreadable ({exc.__class__.__name__})") from exc
        if e.domain != SideDomain.ARGS or e.redacted or e.hash != h or not isinstance(e.value, dict) \
                or args_hash(e.value) != h:
            raise ArgsUnavailable(f"seq {r.seq}: args {h[:12]} redacted or not matching")
        return e.value
    return of


def _changed(store: Any, record: Record, writes: tuple[WriteEntry, ...]) -> tuple[str, ...]:
    """Objects whose value after the re-run differs from the original's after-hash. An adapter writes only
    changed objects, so an original write the re-run did not repeat is compared against the current head."""
    orig = {w.obj: w.after.hash for w in record.write_set if not w.obj.startswith("outbox:")}
    new = {w.obj: w.after.hash for w in writes}
    out = []
    for o in sorted(orig.keys() | new.keys()):
        if o in new:
            h = new[o]
        else:
            cur = store.get(o)
            h = None if cur is None else cur.hash
        if orig.get(o) != h:
            out.append(o)
    return tuple(out)


class ToolRerunner:
    """The B3-24 ``Rerunner``: ``rerunner(store, step, record, seq) -> RerunOutcome`` (see module doc).
    Deterministic: same store, record and args give the same outcome."""

    def __init__(self, dispatcher: Any, args_of: ArgsSource):
        self.dispatcher = dispatcher
        self.args_of = args_of

    def __call__(self, store: Any, step: RerunStep, record: Record, seq: int) -> RerunOutcome:
        if record.seq != step.action.seq or record.envelope is None:
            raise RerunError(f"step {step.n}: record seq {record.seq} is not the step's action")
        env = record.envelope
        args = dict(self.args_of(record))
        call = SimpleNamespace(agent_id=env.agent_id, action_id=env.action_id, tool=env.tool, args=args)
        with store.savepoint():  # a raising tool leaves nothing behind inside the simulation
            ex = self.dispatcher.execute(call, GatewayTxn(store, seq))
            tool_writes = tuple(sorted(ex.write_set, key=lambda w: w.obj))
            if tool_writes != writes_at(store, seq):  # the gateway's set authority (B3-41), same check
                raise RerunError(f"step {step.n}: the tool's write_set disagrees with the store")
        try:  # tool reads only: a re-run gets no tick view (module doc, "Re-run lineage")
            reads = merge_read_set((), ex.read_set)
        except ValueError as exc:
            raise RerunError(f"step {step.n}: {exc}") from exc
        effects, outbox_writes = self._effects(store, record, ex.outbox, reads, seq)
        err = ex.result.get("error") if isinstance(ex.result, dict) else None
        return RerunOutcome(seq=record.seq, sim_seq=seq, agent_id=env.agent_id, action_id=env.action_id,
                            tool=env.tool, reads=reads, tool_writes=tool_writes, outbox_writes=outbox_writes,
                            effects=effects, error=err if isinstance(err, str) else None,
                            changed=_changed(store, record, tool_writes))

    def _effects(self, store: Any, record: Record, requests: tuple[Any, ...], reads: tuple[ReadEntry, ...],
                 seq: int) -> tuple[tuple[Effect, ...], tuple[WriteEntry, ...]]:
        env = record.envelope
        ids = record.outbox_ids
        out: list[Effect] = []
        writes: list[WriteEntry] = []
        for i, req in enumerate(requests):
            key = idempotency_key(env.agent_id, env.action_id, req.sink, i)
            ph = value_hash(req.payload)
            if i >= len(ids):
                out.append(Effect(None, req.sink, i, key, ph, None, "new"))
                continue
            oid = ids[i]
            item = self._item(store, oid)
            if item is None:
                out.append(Effect(oid, req.sink, i, key, ph, None, "missing"))
                continue
            if item.idempotency_key != key:
                raise RerunError(f"outbox:{oid}: idempotency key differs from the re-run's (M14)")
            if item.status == OutboxStatus.DISPATCHED:
                same = item.payload_hash == ph
                out.append(Effect(oid, req.sink, i, key, ph, item.payload_hash,
                                  "dispatched_same" if same else "dispatched_tainted"))
                continue
            if item.status == OutboxStatus.CANCELLED:
                out.append(Effect(oid, req.sink, i, key, ph, item.payload_hash, "cancelled"))
                continue
            lineage = [e.to_obj() for e in sorted(reads, key=lambda e: (e.obj, e.ver))]
            new = OutboxItem.model_validate({**item.to_obj(), "payload_hash": ph, "lineage": lineage,
                                             "status": OutboxStatus.HELD.value, "created_seq": seq})
            writes.append(store.put(f"outbox:{oid}", new.to_obj(), author=env.agent_id, seq=seq,
                                    action_id=env.action_id))
            out.append(Effect(oid, req.sink, i, key, ph, item.payload_hash,
                              "reheld_same" if item.payload_hash == ph else "reheld"))
        for i in range(len(requests), len(ids)):
            oid = ids[i]
            item = self._item(store, oid)
            sink = item.sink if item is not None else "-"
            key = item.idempotency_key if item is not None else idempotency_key(env.agent_id, env.action_id, sink, i)
            if item is not None and item.status in (OutboxStatus.QUEUED, OutboxStatus.HELD, OutboxStatus.RELEASED):
                cancelled = OutboxItem.model_validate({**item.to_obj(), "status": OutboxStatus.CANCELLED.value})
                writes.append(store.put(f"outbox:{oid}", cancelled.to_obj(), author=env.agent_id, seq=seq,
                                        action_id=env.action_id))
            out.append(Effect(oid, sink, i, key, None, None if item is None else item.payload_hash, "dropped"))
        return tuple(out), tuple(writes)

    @staticmethod
    def _item(store: Any, oid: str) -> OutboxItem | None:
        cur = store.get(f"outbox:{oid}")
        if cur is None or cur.value is None:
            return None
        return OutboxItem.model_validate(cur.value)
