"""The S* run: the pure world, fault off, in its own marked oracle run dir (ADR-06-metrics §2, A1, X3a)."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from ks.contracts import canonical, idempotency_key, split_obj_id
from ks.inject import InjectSpec
from ks.world.agents import AGENT_IDS, Schedule, step
from ks.world.registry import SENSITIVE_FIELDS
from ks.world.scenario import SEED_AUTHOR, build_view, open_world_store, seed_state
from ks.world.tools import WorldDispatcher, WorldTxn

from .ledger import LedgerBuilder, b_set, read_ledger

__all__ = ["ORACLE_MARKER", "OracleRunError", "OracleResult", "is_oracle_run", "run_pure", "run_s_star",
           "oracle_self_test"]

ORACLE_MARKER = "ORACLE_RUN"
EFFECTS = "effects.jsonl"
_SECURITY_FILES = ("config.json", "record.jsonl", "keys.json", "keyring.json")


class OracleRunError(RuntimeError):
    pass


@dataclass(frozen=True)
class OracleResult:
    path: Path
    effects: list

    @property
    def ledger_bytes(self) -> bytes:
        return (self.path / EFFECTS).read_bytes()


def is_oracle_run(path: str | os.PathLike[str]) -> bool:
    return (Path(path) / ORACLE_MARKER).is_file()


def _fresh_dir(out: Path) -> None:
    if out.exists():
        raise FileExistsError(f"{out} exists: an oracle run needs its own new directory")
    if any((out.parent / f).exists() for f in _SECURITY_FILES):
        raise OracleRunError(f"{out.parent} looks like a security run dir: oracle runs never share one")
    out.mkdir(parents=True, mode=0o700)


def run_pure(spec: InjectSpec, out: str | os.PathLike[str], *, faulted: bool, suspend_tick: int | None = None,
             hold: int = 0, bypass: Callable[[object, int], None] | None = None) -> OracleResult:
    """Run the world in-process (no gateway, no TCB) over ticks ``0..T-1`` like ``ks.runtime``.
    ``faulted=False`` is S* (``spec.oracle_schedule``); ``True`` is the faulty world (tests, harness). With
    ``suspend_tick`` the culprit does not act from that tick (X3a: S* mirrors the faulty run's suspension; ``None``
    is S0). ``hold`` is ``RunConfig.hold_window_ticks`` H (0 is a valid bench value): an outbox item created at tick t
    has ``release_tick = t + H`` (G3, H > 0: ``max(t + H, v + 2H)`` when its reads hold a sensitive-field version
    written at tick v) and dispatches at the release phase of tick ``max(release_tick, t + 1)``, as the gateway does
    (ADR-06-metrics §2); items still queued at the end never leave. ``bypass(store, tick)`` is a test hook that
    writes behind the dispatcher (its versions land in the ledger with ``seq`` null)."""
    out = Path(out)
    _fresh_dir(out)
    sched: Schedule = spec.schedule if faulted else spec.oracle_schedule
    (out / ORACLE_MARKER).write_bytes(canonical.dumps_line(
        {"contract": "ks.oracle_run/1", "kind": "oracle" if not faulted else "pure_faulty",
         "not_a_security_run": True, "seed": spec.seed, "ticks": spec.ticks, "fault_off": not faulted,
         "suspend_tick": suspend_tick, "hold": hold}))
    store = open_world_store(out / "state.db")
    try:
        lb = LedgerBuilder(store)
        with store.txn():
            seed_state(store, seq=1)
        lb.mark_recorded(1, SEED_AUTHOR)
        disp, seq = WorldDispatcher(), 1
        tick_of_seq, pending = {1: 0}, []  # pending: (dispatch_tick, delivery)
        lb.observe(0)
        for t in range(spec.ticks):
            snap = seq + 1
            deliveries = [d for due, d in pending if due <= t]  # the release phase runs before the tick's views
            pending = [(due, d) for due, d in pending if due > t]
            for a in AGENT_IDS:
                if suspend_tick is not None and a == spec.culprit and t >= suspend_tick:
                    continue
                act = step(a, spec.seed, t, build_view(store, a, visible_to=snap), sched)
                if act is None:
                    continue
                seq += 1
                env = SimpleNamespace(agent_id=a, action_id=act.action_id, tool=act.tool, args=act.args)
                with store.txn():
                    ex = disp.execute(env, WorldTxn(store, seq))
                lb.mark_recorded(seq, a, act.action_id)
                tick_of_seq[seq] = t
                for i, ob in enumerate(ex.outbox):
                    rel = t + hold
                    if hold > 0:
                        vs = [tick_of_seq.get(store.history(r.obj)[r.ver - 1].seq) for r in ex.read_set
                              if split_obj_id(r.obj)[2] is not None
                              and f"{split_obj_id(r.obj)[0]}.{split_obj_id(r.obj)[2]}" in SENSITIVE_FIELDS]
                        rel = max([rel] + [v + 2 * hold for v in vs if v is not None])
                    pending.append((max(rel, t + 1), {"agent": a, "sink": ob.sink, "payload": ob.payload,
                                                      "seq": seq,
                                                      "idem_key": idempotency_key(a, act.action_id, ob.sink, i)}))
            if bypass is not None:
                bypass(store, t)
            lb.observe(t, deliveries)
        (out / EFFECTS).write_bytes(lb.dumps())
        return OracleResult(out, lb.effects)
    finally:
        store.close()


def run_s_star(spec: InjectSpec, out: str | os.PathLike[str], *, suspend_tick: int | None = None,
               hold: int = 0) -> OracleResult:
    """S*: same seed and config, fault off. Pass the faulty run's ``suspend_tick`` for the mirrored oracle."""
    return run_pure(spec, out, faulted=False, suspend_tick=suspend_tick, hold=hold)


def oracle_self_test(spec: InjectSpec, workdir: str | os.PathLike[str], *, hold: int = 0) -> set[str]:
    """Run S* twice into ``workdir/a`` and ``workdir/b``; raise unless byte-identical. Returns B of S* vs S*
    (must be empty: ``test_oracle_self``)."""
    w = Path(workdir)
    a, b = run_s_star(spec, w / "a", hold=hold), run_s_star(spec, w / "b", hold=hold)
    if a.ledger_bytes != b.ledger_bytes:
        raise OracleRunError("S* is not deterministic: same seed, different ledger bytes")
    return b_set(read_ledger(a.path / EFFECTS), read_ledger(b.path / EFFECTS))
