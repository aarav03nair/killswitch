"""Taint closure, seed rule (A8/X3) and root candidates (H1). Records in, hashes only; see the package doc.

Vocabulary: a *version* is ``(obj, ver)``; the *writer* of a version is the exec record whose ``write_set`` has it
as ``after``. Records are indexed once (:class:`RecordIndex`); every function takes the index or a record list.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from ks.contracts.control import CONTROL_TOOL, Alert, ControlOp
from ks.contracts.ids import SEED_TOOL, SYSTEM_PRINCIPALS
from ks.contracts.record import Decision, Record
from ks.contracts.recovery import ActionRef, TaintSet
from ks.contracts.state import ObjVer

__all__ = ["MAX_HOPS", "SEED_SEQ", "RecordIndex", "Taint", "closure", "is_seed_record", "root_candidates",
           "seed_versions", "suspend_seq_of", "t0_seq_est", "taint_from_alerts"]

MAX_HOPS = 3
"""Bound of the backward walk (ADR-05 §5, H1)."""
SEED_SEQ = 1
"""D-SEQ1: record seq 1 is the seed record."""
_REPAIR_PRINCIPAL = "ks.recovery"
"""Records by ks.recovery are repairs (a restore re-writes an untainted value, ADR-05 §2b): they do not propagate."""

Ver = tuple[str, int]


def is_seed_record(r: Record) -> bool:
    """D-SEQ1/D-15: the executed ``ks.seed`` record at seq 1, tick 0, verified ``ks.gateway`` (contracts 1.3).
    A record that fails ``Record.seed_problems()`` is not trusted as the seed (verify reports ``seed_invalid``)."""
    env = r.envelope
    if r.seq != SEED_SEQ or r.tick != 0 or r.decision != Decision.EXEC or env is None:
        return False
    if r.attributed_agent != "ks.gateway":
        return False
    return env.tool == SEED_TOOL and not r.seed_problems()


def _ver(e) -> Ver:
    return (e.obj, e.ver)


class RecordIndex:
    """Records in seq order plus ``(obj, ver) -> writer record``. Raises ``ValueError`` on duplicate seqs or two
    writers of one version (a corrupt record; verify catches it first)."""

    def __init__(self, records: Iterable[Record]):
        self.records: tuple[Record, ...] = tuple(sorted(records, key=lambda r: r.seq))
        self.by_seq: dict[int, Record] = {}
        self._writer: dict[Ver, Record] = {}
        for r in self.records:
            if r.seq in self.by_seq:
                raise ValueError(f"duplicate record seq {r.seq}")
            self.by_seq[r.seq] = r
            if r.decision != Decision.EXEC:
                continue
            for w in r.write_set:
                k = (w.obj, w.after.ver)
                if k in self._writer:
                    raise ValueError(f"two writers of {k}: seq {self._writer[k].seq} and {r.seq}")
                self._writer[k] = r
        self.seed: Record | None = self.by_seq.get(SEED_SEQ) if SEED_SEQ in self.by_seq and \
            is_seed_record(self.by_seq[SEED_SEQ]) else None

    @classmethod
    def of(cls, records: RecordIndex | Iterable[Record]) -> RecordIndex:
        return records if isinstance(records, RecordIndex) else cls(records)

    def writer(self, obj: str, ver: int) -> Record | None:
        return self._writer.get((obj, ver))

    def is_seed_version(self, obj: str, ver: int) -> bool:
        w = self.writer(obj, ver)
        return w is not None and w is self.seed

    @property
    def last_seq(self) -> int:
        return self.records[-1].seq if self.records else 0


# --------------------------------------------------------------------------------------------------------------
# Backward walk and ranking (ADR-05 §5, H1)
# --------------------------------------------------------------------------------------------------------------
def _evidence_writers(ix: RecordIndex, evidence: Iterable[ObjVer]) -> list[Record | None]:
    return [ix.writer(e.obj, e.ver) for e in evidence]


def _walk(ix: RecordIndex, start: Iterable[Record], *, skip_self_reads_of: str | None = None,
          max_hops: int = MAX_HOPS) -> tuple[dict[int, int], dict[int, set[int]]]:
    """Bounded backward walk through read sets. Returns ``seq -> hop`` (start records at hop 0) and the subgraph
    edges ``seq -> parent seqs`` (writers of what it read). Stops at seed versions (D-SEQ1) and unknown writers.
    ``skip_self_reads_of``: do not follow an edge from a record of that agent to a version that agent wrote."""
    dist: dict[int, int] = {}
    parents: dict[int, set[int]] = {}
    frontier = []
    for r in start:
        if r.seq not in dist:
            dist[r.seq] = 0
            frontier.append(r)
    for hop in range(1, max_hops + 1):
        nxt = []
        for r in frontier:
            ps = parents.setdefault(r.seq, set())
            for e in r.read_set:
                w = ix.writer(e.obj, e.ver)
                if w is None or w is ix.seed or w.seq >= r.seq:
                    continue
                if skip_self_reads_of is not None and r.attributed_agent == skip_self_reads_of \
                        and w.attributed_agent == skip_self_reads_of:
                    continue
                ps.add(w.seq)
                if w.seq not in dist:
                    dist[w.seq] = hop
                    nxt.append(w)
        frontier = nxt
    for s in dist:
        parents.setdefault(s, set())
    return dist, parents


def _sole_writer(ix: RecordIndex, evidence: Sequence[ObjVer]) -> str | None:
    """H1: the attributed agent of the record(s) that wrote ``evidence``; ``None`` if none, unknown, a system
    principal (the seed) or two or more distinct writers."""
    ws = _evidence_writers(ix, evidence)
    if not ws or any(w is None for w in ws):
        return None
    who = {w.attributed_agent for w in ws}
    if len(who) != 1:
        return None
    (a,) = who
    return None if a is None or a in SYSTEM_PRINCIPALS else a


def root_candidates(records: RecordIndex | Iterable[Record], evidence: Iterable[ObjVer]) -> tuple[str, ...]:
    """Ranked root candidates (ADR-05 §5, H1, M9). ``[0]`` = the sole writer of ``evidence``; then agents reached
    by the bounded backward walk, ranked by hop distance, then latest causal write (higher seq first), then
    tainted descendants in the walk (more first), then ``agent_id``. ``()`` when there is no sole writer.
    Not a verdict: agents after ``[0]`` are reached only through reads and are never auto-suspended (H2)."""
    ix = RecordIndex.of(records)
    ev = tuple(evidence)
    root = _sole_writer(ix, ev)
    if root is None:
        return ()
    start = [w for w in _evidence_writers(ix, ev) if w is not None]
    dist, parents = _walk(ix, start)
    children: dict[int, set[int]] = {s: set() for s in dist}
    for s, ps in parents.items():
        for p in ps:
            children.setdefault(p, set()).add(s)

    def descendants(s: int) -> set[int]:
        out, stack = set(), [s]
        while stack:
            for c in children.get(stack.pop(), ()):
                if c not in out:
                    out.add(c)
                    stack.append(c)
        return out

    stats: dict[str, tuple[int, int, set[int]]] = {}
    for s, hop in dist.items():
        a = ix.by_seq[s].attributed_agent
        if a is None or a in SYSTEM_PRINCIPALS or a == root:
            continue
        h0, latest, desc = stats.get(a, (hop, 0, set()))
        stats[a] = (min(h0, hop), max(latest, s), desc | descendants(s))
    ranked = sorted(stats, key=lambda a: (stats[a][0], -stats[a][1], -len(stats[a][2]), a))
    return (root, *ranked)


def t0_seq_est(records: RecordIndex | Iterable[Record], evidence: Iterable[ObjVer], suspect: str, *,
               follow_self_reads: bool = False) -> int | None:
    """A2/X3: the earliest write by ``suspect`` in the bounded backward closure of ``evidence`` (all alerts'
    ``evidence_versions``). ``None`` if ``suspect`` wrote nothing there.

    ``follow_self_reads=False`` (default) does not follow the suspect's reads of its own earlier versions. Under
    the I1 read rule every view row is a read, so an agent always "reads" its own recent writes and the literal
    walk would pull t0 back to the suspect's first write in scope (in the world: crm's tick-3 ``S-31`` edit),
    seeding honest work. Laundering through another agent is still followed. ``True`` is the literal ADR-05 §4
    walk (more conservative); :class:`Taint` carries both so the planner reports the delta. Decided B3-45 (option C,
    built as B3-46: tag reads view|tool, follow self-reads through tool reads only); this default is the interim.
    Known gap pinned in tests: a self-chain (bad W1, suspect reads W1, writes W2, alert on W2) seeds W2 only."""
    ix = RecordIndex.of(records)
    start = [w for w in _evidence_writers(ix, evidence) if w is not None]
    dist, _ = _walk(ix, start, skip_self_reads_of=None if follow_self_reads else suspect)
    seqs = [s for s in dist if ix.by_seq[s].attributed_agent == suspect and ix.by_seq[s].write_set]
    return min(seqs) if seqs else None


def suspend_seq_of(records: RecordIndex | Iterable[Record], agent: str, *, after: int = 0) -> int | None:
    """Seq of the first executed ``ks.control`` suspend (or revoke) of ``agent:<agent>`` with seq > ``after``."""
    ix = RecordIndex.of(records)
    target = f"agent:{agent}"
    for r in ix.records:
        if r.seq <= after or r.decision != Decision.EXEC or r.control is None:
            continue
        if r.envelope is not None and r.envelope.tool == CONTROL_TOOL and r.control.target == target \
                and r.control.op in (ControlOp.SUSPEND, ControlOp.REVOKE):
            return r.seq
    return None


# --------------------------------------------------------------------------------------------------------------
# Seed (A8) and forward closure (ADR-05 §4)
# --------------------------------------------------------------------------------------------------------------
def seed_versions(records: RecordIndex | Iterable[Record], suspect: str, t0: int, suspend_seq: int) -> \
        tuple[ObjVer, ...]:
    """A8: every after-version written by ``suspect`` with ``t0 <= seq <= suspend_seq``, sorted by (obj, ver).
    Never includes the seed record's versions (D-SEQ1)."""
    ix = RecordIndex.of(records)
    out = []
    for r in ix.records:
        if t0 <= r.seq <= suspend_seq and r.decision == Decision.EXEC and r is not ix.seed \
                and r.attributed_agent == suspect:
            out += [ObjVer(obj=w.obj, ver=w.after.ver) for w in r.write_set]
    return tuple(sorted(out, key=lambda v: (v.obj, v.ver)))


@dataclass(frozen=True)
class Taint:
    """Result of :func:`closure`. ``versions`` includes the seed. ``actions`` are tainted exec records (seed writers
    and readers), seq order. ``via[seq]`` = the tainted versions that record read (empty for seed writers and
    sticky-only taint), for the console's "why". ``t0_seq_est`` is the t0 actually used (default walk, skips the
    suspect's self-reads); ``t0_seq_est_literal`` is the literal ADR-05 §4 walk's t0 (follows self-reads), carried
    so the dry-run can report the delta (B3-45: interim option B; B3-46 will follow self-reads via tool reads)."""

    suspect: str | None
    t0_seq_est: int | None
    suspend_seq: int | None
    as_of_seq: int
    seed: tuple[ObjVer, ...]
    versions: frozenset[Ver]
    actions: tuple[Record, ...]
    outbox_ids: frozenset[str]
    via: dict[int, tuple[ObjVer, ...]] = field(default_factory=dict)
    seed_seqs: frozenset[int] = frozenset()
    t0_seq_est_literal: int | None = None

    @property
    def t0_delta(self) -> int | None:
        """``t0_seq_est - t0_seq_est_literal`` (>= 0; > 0 means the literal walk reaches earlier suspect writes the
        seed leaves out). ``None`` when either is unknown."""
        if self.t0_seq_est is None or self.t0_seq_est_literal is None:
            return None
        return self.t0_seq_est - self.t0_seq_est_literal

    def is_tainted(self, obj: str, ver: int) -> bool:
        return (obj, ver) in self.versions

    @property
    def agents(self) -> tuple[str, ...]:
        """Agents with at least one tainted action, sorted."""
        return tuple(sorted({r.attributed_agent for r in self.actions if r.attributed_agent}))

    def taint_set(self) -> TaintSet:
        """The C5 ``TaintSet`` for the plan."""
        return TaintSet(
            versions=tuple(ObjVer(obj=o, ver=v) for o, v in sorted(self.versions)),
            actions=tuple(ActionRef(seq=r.seq, agent_id=r.envelope.agent_id, action_id=r.envelope.action_id)
                          for r in self.actions),
            outbox_ids=tuple(sorted(self.outbox_ids)))


def closure(records: RecordIndex | Iterable[Record], seed: Iterable[ObjVer], *, as_of_seq: int | None = None,
            sticky_agents: Iterable[str] = (), suspect: str | None = None, t0: int | None = None,
            suspend_seq: int | None = None, t0_literal: int | None = None) -> Taint:
    """Forward taint (ADR-05 §4): one pass in seq order (a version written at seq s is visible only to seq > s,
    M2, so one pass is exact). An exec record whose ``read_set`` hits a tainted ``(obj, ver)`` is tainted; its
    after-versions and ``outbox_ids`` join (D8). Seed writers are tainted actions. Never tainted: the seed record
    (D-SEQ1), records by ks.recovery (repairs), non-exec records (no effects). ``sticky_agents`` (LLM agents,
    conservative default per ADR-05): once tainted, every later exec action of that agent is tainted."""
    ix = RecordIndex.of(records)
    seed = tuple(sorted(set(seed), key=lambda v: (v.obj, v.ver)))
    seed_keys = {(v.obj, v.ver) for v in seed}
    for o, v in seed_keys:
        w = ix.writer(o, v)
        if w is not None and w is ix.seed:
            raise ValueError(f"seed version {o} v{v} was written by the seed record (D-SEQ1)")
    seed_seqs = frozenset(w.seq for w in (ix.writer(o, v) for o, v in seed_keys) if w is not None)
    end = ix.last_seq if as_of_seq is None else as_of_seq
    sticky = set(sticky_agents)
    stuck: set[str] = set()
    tainted: set[Ver] = set(seed_keys)
    outbox: set[str] = set()
    actions: list[Record] = []
    via: dict[int, tuple[ObjVer, ...]] = {}
    start = min(seed_seqs) if seed_seqs else end + 1
    for r in ix.records:
        if r.seq < start or r.seq > end:
            continue
        if r.decision != Decision.EXEC or r is ix.seed or r.attributed_agent == _REPAIR_PRINCIPAL:
            continue
        hits = tuple(ObjVer(obj=e.obj, ver=e.ver) for e in r.read_set if _ver(e) in tainted)
        agent = r.attributed_agent
        if not (hits or r.seq in seed_seqs or (agent in stuck)):
            continue
        actions.append(r)
        via[r.seq] = hits
        tainted.update((w.obj, w.after.ver) for w in r.write_set)
        outbox.update(r.outbox_ids)
        if agent in sticky:
            stuck.add(agent)
    return Taint(suspect=suspect, t0_seq_est=t0, suspend_seq=suspend_seq, as_of_seq=end, seed=seed,
                 versions=frozenset(tainted), actions=tuple(actions), outbox_ids=frozenset(outbox), via=via,
                 seed_seqs=seed_seqs, t0_seq_est_literal=t0_literal)


def taint_from_alerts(records: RecordIndex | Iterable[Record], alerts: Iterable[Alert], *, suspect: str | None = None,
                      as_of_seq: int | None = None, sticky_agents: Iterable[str] = (),
                      follow_self_reads: bool = False) -> Taint | None:
    """End to end for the planner: evidence = union of the alerts' ``evidence_versions``; ``suspect`` defaults to
    ``root_candidates(evidence)[0]`` (a person may choose another candidate); ``t0_seq_est`` from the walk;
    ``suspend_seq`` = the suspect's first suspend after t0; seed (A8); forward closure. ``None`` when there is no
    suspect, no t0 or no suspension ("no suspended suspect gives no seed and no plan"). The literal-walk t0 is always
    computed too and carried as ``Taint.t0_seq_est_literal``."""
    ix = RecordIndex.of(records)
    evidence = tuple(sorted({(v.obj, v.ver): v for a in alerts for v in a.evidence_versions}.values(),
                            key=lambda v: (v.obj, v.ver)))
    if suspect is None:
        rc = root_candidates(ix, evidence)
        suspect = rc[0] if rc else None
    if suspect is None:
        return None
    t0 = t0_seq_est(ix, evidence, suspect, follow_self_reads=follow_self_reads)
    t0_lit = t0 if follow_self_reads else t0_seq_est(ix, evidence, suspect, follow_self_reads=True)
    if t0 is None:
        return None
    ss = suspend_seq_of(ix, suspect, after=t0)
    if ss is None:
        return None
    seed = seed_versions(ix, suspect, t0, ss)
    return closure(ix, seed, as_of_seq=as_of_seq, sticky_agents=sticky_agents, suspect=suspect, t0=t0,
                   suspend_seq=ss, t0_literal=t0_lit)
