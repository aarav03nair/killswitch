"""C6 Run directory: the only thing the scorer, ``ks verify`` and the jury read.

Layout (constants below; modes per SEC-03 F1 / X8, set explicitly, independent of the umask)::

    <run>/               0711 gateway uid (traverse only: agents cannot list it)
      config.json        RunConfig (seed, scenario, hold window, sensitive fields, agents)  0600 [canonical]
      keys.json          Keyring: PUBLIC keys only (agents + ks.* principals)               0600 [canonical]
      record.jsonl       C2 Records, one canonical line each, seq 1..n                       0600 gateway only
      witness.jsonl      C2 WitnessCheckpoints, one per tick                                 0600 owner=witness uid
      witness-heads/     witness-private head store (F6)                                     0700 owner=witness uid
      alerts.jsonl       C4 Alerts (copy; the chained ks.alert records are authoritative)    0600
      plans/             C5 RecoveryPlans, ``<plan_id>.json``                                0700 / 0600
      sidestore/         C3 SideEntries, ``<hash[:2]>/<hash>.json`` (redactable)             0700 / 0600
      oracle/            S* artefacts (ks.oracle, ADR-06)                                    0700
      baselines/         ``<name>/`` baseline run dirs (``ks inject --with-baselines``, L2)   0700
      effects.jsonl      world effect ledger (schema: ADR-06, tara)                          0600
      score.json         ks.score output (keys: ADR-06, tara)                                0600
      timing.jsonl       wall-clock measurements: the ONLY non-deterministic file           0600
      workspace/         gateway-private (state.db); 0700, never read by the scorer

Agents (uids 60001+) get EACCES on every file: they can read neither the record (cross-agent
history) nor the side store (cleartext IBANs/PII). Private keys never touch the run dir (generated in
memory; in fresh mode the witness makes its own key, E4). ``validate`` flags any file that looks like
private key material; :meth:`RunDir.perm_problems` flags group/other-readable files.

**Determinism (C4/C5).** :data:`DETERMINISTIC_FILES` are identical for the same seed and config, *even in
fresh key mode*: record and witness through :func:`~ks.contracts.record.determinism_view`, everything else
byte for byte. ``keys.json`` is not deterministic (private keys are never a function of the seed).
:meth:`RunDir.determinism_files` returns exactly the bytes to compare (T1, T1b, ``ks repro`` ->
``Exit.DIVERGED``).
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterator
from enum import IntEnum
from pathlib import Path
from typing import Annotated, ClassVar, Literal, TypeVar

from pydantic import Field, StringConstraints, field_validator, model_validator

from . import canonical
from ._base import Document, Value
from .control import Alert
from .hashing import GENESIS_HASH, Domain
from .ids import SYSTEM_PRINCIPALS, AgentId, Hash, NonNeg, PrincipalId, PubKey, Seq, Tick
from .recovery import RecoveryPlan
from .record import Record, WitnessCheckpoint, determinism_view
from .state import SideEntry, field_obj_id, split_obj_id

__all__ = [
    "CONFIG", "KEYS", "RECORD", "WITNESS", "ALERTS", "PLANS_DIR", "SIDESTORE_DIR", "ORACLE_DIR", "EFFECTS",
    "SCORE", "TIMING", "WORKSPACE_DIR", "STATE_DB", "WITNESS_HEADS_DIR", "BASELINES_DIR", "DETERMINISTIC_FILES",
    "PROJECTED_FILES", "SCORER_ONLY_FIELDS", "SensitiveField", "RunConfig", "KeyEntry", "Keyring", "Exit",
    "VERIFY_REASONS", "VerifyReport", "Isolation", "RunAnchor", "anchor_status", "RunDir", "sidestore_relpath",
]

CONFIG = "config.json"
KEYS = "keys.json"
RECORD = "record.jsonl"
WITNESS = "witness.jsonl"
ALERTS = "alerts.jsonl"
PLANS_DIR = "plans"
SIDESTORE_DIR = "sidestore"
ORACLE_DIR = "oracle"
EFFECTS = "effects.jsonl"
SCORE = "score.json"
TIMING = "timing.jsonl"
WORKSPACE_DIR = "workspace"
STATE_DB = "workspace/state.db"
WITNESS_HEADS_DIR = "witness-heads"
BASELINES_DIR = "baselines"

DETERMINISTIC_FILES = (CONFIG, RECORD, WITNESS, ALERTS, EFFECTS, ORACLE_DIR + "/**", SCORE, PLANS_DIR + "/**",
                       SIDESTORE_DIR + "/**")
"""C4: same seed and config => identical, even in fresh key mode. ``dir/**`` = every file below ``dir``.
:data:`PROJECTED_FILES` compare through ``determinism_view``; the rest byte for byte. ``keys.json`` is
**not** here (SEC-03 B2); nor are ``timing.jsonl``, ``workspace/``, ``witness-heads/``, ``baselines/``."""
PROJECTED_FILES = (RECORD, WITNESS)
"""Files compared through :func:`~ks.contracts.record.determinism_view` (C5)."""

SCORER_ONLY_FIELDS = ("fault", "culprit", "fault_tick")
"""Ground truth (A3): read by ks.score/ks.oracle only. The TCB gets :meth:`RunConfig.tcb_view`."""

Isolation = Literal["per_agent_uid", "degraded"]
"""v1.2: ``RunConfig.isolation`` / ``VerifyReport.isolation`` (SKEL-01 finding 4)."""

SensitiveField = Annotated[str, StringConstraints(strict=True, pattern=r"^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}$")]
"""``table.field``, e.g. ``suppliers.iban``."""


class RunConfig(Document):
    """``config.json``: everything needed to reproduce a seeded run, and what the scorer must know."""

    CONTRACT: ClassVar[str] = "ks.run_config/1"
    DOMAIN: ClassVar[bytes] = Domain.RUN

    contract: Literal["ks.run_config/1"] = "ks.run_config/1"
    """Contract id."""
    run_id: Annotated[str, StringConstraints(strict=True, pattern=r"^[A-Za-z0-9_.-]{1,64}$")]
    """Run name (directory name by convention)."""
    contracts_version: Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]
    """``ks.contracts.CONTRACTS_VERSION`` the run was produced with."""
    seed: NonNeg
    """RNG seed; same seed => byte-identical deterministic files."""
    scenario: Annotated[str, StringConstraints(strict=True, pattern=r"^[A-Za-z0-9_.+-]{1,64}$")]
    """World scenario, e.g. ``acme``."""
    fault: Annotated[str, StringConstraints(strict=True, pattern=r"^(F[0-9]+(\+[a-z0-9]{0,8})?|rogue)$")] | None
    """Injected fault id, e.g. ``F2+``, bench variants ``F2+x``/``F2+c``, or ``rogue`` (``--rogue FILE --slot``);
    ``None`` for a clean run. **Scorer-only** (A3)."""
    culprit: AgentId | None
    """Agent the fault is injected into (rogue: the slot). **Scorer-only** (A3): never read by ks.monitor,
    ks.policy, ks.taint or ks.recovery; the TCB gets :meth:`tcb_view`."""
    fault_tick: Tick | None
    """t_inject (A2): the seeded fault tick, in ``[ticks // 4, ticks // 2]``; set iff ``fault`` is set. The oracle's
    t0 is the min tick over B >= fault_tick; rogue slots no-op from it in S*. **Scorer-only** (A3, M2):
    the planner's ``RecoveryPlan.t0_seq_est`` is an estimate from the record and must not read it."""
    key_mode: Literal["fresh", "repro"]
    """C3: ``fresh`` = keys generated in memory per run (the witness makes its own, E4); the only mode for
    security runs. ``repro`` = keys derived from a secret outside the run dir (0600 uid 0) for byte-identical
    replays; labelled "not a security run", forces ``VerifyReport.anchored = false`` (X7, ``repro_keys``),
    banned for D11/RT2/RT8 and refused with ``fault == "rogue"`` (validator)."""
    decision_latency_ticks: NonNeg
    """L (C1): a plan approval blocks the barrier; tick ``plan_tick + L`` does not open until the decision
    arrives (an early click waits). Other operator Controls land at the next control phase."""
    ticks: NonNeg
    """Number of ticks to run."""
    tick_us: Annotated[int, Field(strict=True, ge=1, le=canonical.MAX_SAFE_INT)]
    """Logical microseconds per tick; ``Record.ts_us = start_ts_us + tick*tick_us + slot``."""
    start_ts_us: NonNeg
    """Logical time of tick 0."""
    hold_window_ticks: NonNeg
    """Hold window: ticks a new outbox item waits before release. 0 = no hold (demo toggle)."""
    sensitive_fields: tuple[SensitiveField, ...]
    """``table.field`` entries, sorted. Two effects, both generic (no IBAN-specific code):

    1. **Field objects (B1/X1/X2).** Each entry is its own versioned object ``table:pk.field``
       (:func:`~ks.contracts.state.field_obj_id`); the rest of the row stays ``table:pk`` and its value hash
       excludes these fields. A whole-row read also lists the row's field objects (:meth:`field_objs_of`);
       a read that omits the field lists only the row. A ``.suffix`` on an object id must name an entry
       for that table (:meth:`check_obj`).
    2. **Early hold (G3/K17).** Only when ``hold_window_ticks`` H > 0. At creation, an I-class outbox item
       whose lineage holds a sensitive-field version written at tick v gets
       ``release_tick = max(tick + H, v + 2H)``. A change after creation makes the dispatcher hold it via a
       recorded ``Control{hold, outbox:<id>, reason=sensitive_field}``. ``release`` never lifts such holds."""
    agents: tuple[AgentId, ...]
    """Agents in tick-barrier order (agent_id order), sorted."""
    isolation: Isolation = "degraded"
    """v1.2 (SKEL-01 finding 4): the uid isolation the run was started with, fixed before spawn and covered by
    ``config_hash``. ``per_agent_uid`` = each agent under its own uid, the witness under its own; ``degraded``
    = shared or unverified uids, so **per-agent attribution is VOID** for the run (RT3b). The runtime aborts if
    the /proc readback contradicts it; verify echoes it as ``VerifyReport.isolation``. Defaults to
    ``degraded`` so a config that does not say claims nothing."""
    decisions_from: Hash | None = None
    """v1.2 (R3): ``RunConfig.content_hash()`` of the anchored source run whose operator decisions ``--decisions``
    replays; ``None`` for a live run. Refused with ``fault == "rogue"`` and with ``key_mode == "repro"``
    (validator; the X6 replay checks are gateway code, B3-20)."""

    @field_validator("sensitive_fields", "agents")
    @classmethod
    def _sorted(cls, v):
        if list(v) != sorted(set(v)):
            raise ValueError("must be sorted and unique")
        return v

    @model_validator(mode="after")
    def _culprit(self) -> RunConfig:
        if (self.fault is None) != (self.culprit is None):
            raise ValueError("fault and culprit are set together")
        if self.culprit is not None and self.culprit not in self.agents:
            raise ValueError("culprit must be one of agents")
        if (self.fault is None) != (self.fault_tick is None):
            raise ValueError("fault_tick is set iff fault is set")
        if self.fault_tick is not None and not self.ticks // 4 <= self.fault_tick <= self.ticks // 2:
            raise ValueError("fault_tick must be in [ticks // 4, ticks // 2] (A2)")
        if self.key_mode == "repro" and self.fault == "rogue":
            raise ValueError("repro key mode is refused with a rogue slot (X7: not a security run)")
        if self.decisions_from is not None and self.fault == "rogue":
            raise ValueError("decisions_from is refused with a rogue slot (R3)")
        if self.decisions_from is not None and self.key_mode == "repro":
            raise ValueError("decisions_from is refused with repro keys (R3: the source must be anchored)")
        return self

    def tcb_view(self) -> RunConfig:
        """The config the TCB (gateway, monitor, policy, taint, recovery) may see: scorer-only fields blanked
        (A3). Same everything else, so the record of a run is identical whichever view the TCB got."""
        return RunConfig.model_validate({**self.to_obj(), **{f: None for f in SCORER_ONLY_FIELDS}})

    def sensitive_fields_of(self, table: str) -> tuple[str, ...]:
        """Field names configured as sensitive for ``table``."""
        return tuple(f.partition(".")[2] for f in self.sensitive_fields if f.partition(".")[0] == table)

    def field_objs_of(self, row_obj: str) -> tuple[str, ...]:
        """Field object ids of a row (X2): what a whole-row read lists besides the row (those that exist)."""
        t, pk, f = split_obj_id(row_obj)
        if f is not None:
            raise ValueError(f"{row_obj!r} is a field object, not a row")
        return tuple(field_obj_id(t, pk, name) for name in self.sensitive_fields_of(t))

    def check_obj(self, obj: str) -> None:
        """Kabir R1: an object id is a dot-free row id, or ``table:pk.field`` naming a sensitive field of that
        table. Raises ``ValueError`` otherwise (gateway: the adapter call fails closed)."""
        t, _, f = split_obj_id(obj)
        if f is not None and f not in self.sensitive_fields_of(t):
            raise ValueError(f"{obj!r}: '.{f}' is not a sensitive field of table {t!r}")


class KeyEntry(Value):
    """One public key."""

    principal: PrincipalId
    """Agent id or ``ks.*`` principal."""
    alg: Literal["ed25519"] = "ed25519"
    """Signature algorithm."""
    pub: PubKey
    """Raw 32-byte Ed25519 public key, hex."""


class Keyring(Document):
    """``keys.json``: public keys ``verify`` checks signatures against. Never private keys.

    E3/K5: exactly one key each for ``ks.gateway``, ``ks.witness``, ``ks.monitor``, ``ks.operator``,
    ``ks.recovery`` (validator) and every ``RunConfig.agents`` entry, and nothing else
    (:meth:`problems`, which ``RunDir.validate`` and verify apply; fail closed). Controls are signed by
    their ``issued_by`` principal. Bound to the run by ``RunAnchor.keyring_hash`` (RT8(h))."""

    CONTRACT: ClassVar[str] = "ks.keyring/1"
    DOMAIN: ClassVar[bytes] = Domain.KEYS

    contract: Literal["ks.keyring/1"] = "ks.keyring/1"
    """Contract id."""
    keys: tuple[KeyEntry, ...]
    """Sorted by principal, one per principal."""

    @field_validator("keys")
    @classmethod
    def _k(cls, v):
        if [k.principal for k in v] != sorted({k.principal for k in v}) or len(v) != len({k.principal for k in v}):
            raise ValueError("keys must be sorted by principal and unique")
        missing = SYSTEM_PRINCIPALS - {k.principal for k in v}
        if missing:
            raise ValueError(f"keyring lacks system principals {sorted(missing)}")
        return v

    def problems(self, config: RunConfig) -> list[str]:
        """Completeness against ``config``: missing agent keys and keys for unknown principals."""
        have = {k.principal for k in self.keys}
        want = set(SYSTEM_PRINCIPALS) | set(config.agents)
        return [f"missing key: {p}" for p in sorted(want - have)] + \
               [f"unexpected key: {p}" for p in sorted(have - want)]

    def pub(self, principal: str) -> str | None:
        return next((k.pub for k in self.keys if k.principal == principal), None)


class Exit(IntEnum):
    """Exit codes of ``ks verify`` / ``ks recover`` (ks.verify re-exports as ``ks.verify.Exit``). Use names, not numbers."""

    OK = 0
    IO = 1          # config, keys or record missing/unreadable (only that; a bad record line is TAMPER)
    TAMPER = 2      # bad record line, chain, hash or signature mismatch, seq gap, side entry re-hashed
    WITNESS = 3     # witness missing/bad, record disagrees with a checkpoint, truncation, anchor mismatch
    RECONCILE = 4   # fold(record) != live state
    FROZEN = 5      # ks recover refused (M12): verify != OK, or a tamper/witness-stall alert open in the
    #                 records; lasts for the rest of the run (no resolve action in v1)
    DIVERGED = 6    # re-derived result differs from its source: ks repro A B (determinism views, C6) or a
    #                 decisions replay (replay_mismatch, 1.5); not tampering
    USAGE = 64      # bad CLI arguments (incl. repro + --rogue, X7)


VERIFY_REASONS: dict[str, Exit] = {
    "ok": Exit.OK,
    "missing_file": Exit.IO, "unreadable": Exit.IO,
    "parse_error": Exit.TAMPER, "hash_mismatch": Exit.TAMPER, "seq_gap": Exit.TAMPER,
    "gw_sig_invalid": Exit.TAMPER, "agent_sig_mismatch": Exit.TAMPER, "side_entry_mismatch": Exit.TAMPER,
    "alert_mismatch": Exit.TAMPER, "epoch_regression": Exit.TAMPER, "expired_admitted": Exit.TAMPER,
    "window_violation": Exit.TAMPER, "reexec_invalid": Exit.TAMPER, "seed_invalid": Exit.TAMPER,
    "recovery_unbound": Exit.TAMPER,
    "witness_missing": Exit.WITNESS, "witness_sig_invalid": Exit.WITNESS, "witness_mismatch": Exit.WITNESS,
    "count_mismatch": Exit.WITNESS, "truncated": Exit.WITNESS, "head_mismatch": Exit.WITNESS,
    "keyring_mismatch": Exit.WITNESS, "config_mismatch": Exit.WITNESS,
    "reconcile_mismatch": Exit.RECONCILE, "no_state": Exit.RECONCILE,
    "frozen": Exit.FROZEN, "diverged": Exit.DIVERGED, "replay_mismatch": Exit.DIVERGED, "usage": Exit.USAGE,
}
"""K16 reason vocabulary (closed) and the exit each implies. Check order (F3): record, side, witness, reconcile.
Truncation (F4): ``truncated`` with ``first_bad = n + 1``; an anchor that disagrees: ``head_mismatch``,
``keyring_mismatch`` (RT8(h)) or ``config_mismatch``. v1.2 (F9): ``reexec_invalid`` -> TAMPER, a record with
``reexec_of`` that is not a valid unhold re-execution (no matching hold, released twice, or not released).
v1.3 (D-15): ``seed_invalid`` -> TAMPER, an admitted ``ks.seed`` record off seq 1/tick 0/ks.gateway/c-0, or whose
write_set differs from the scenario's ``seed_state``.
v1.5 (B3-47, kabir's B3-20 ruling): ``replay_mismatch`` -> DIVERGED, re-deriving the recorded decisions
(the ``ks.verify.decisions`` replay, or the ``RunConfig.decisions_from`` source run) gives a different result.
The record chain itself may be intact, so this is neither ``hash_mismatch`` nor a TAMPER exit: an honest but
divergent replay must not read as tampering. Also v1.5 (B3-30, G6/F5): ``recovery_unbound`` -> TAMPER, an
admitted ``ks.recover.<op>`` record with no prior matching ``ks.approve``, or whose plan file does not hash to the
approved ``plan_hash`` (edited), or a step applied twice.
Adding a reason is a minor version bump."""


class VerifyReport(Value):
    """Last stdout line of ``ks verify`` (canonical JSON)."""

    ok: bool
    """True iff exit code is Exit.OK."""
    exit: Annotated[int, Field(strict=True, ge=0, le=255)]
    """Numeric exit code (an ``Exit`` value)."""
    first_bad: Annotated[int, Field(strict=True, ge=1, le=canonical.MAX_SAFE_INT)] | None
    """seq (= 1-based line number) of the first bad record, or ``None``."""
    reason: Annotated[str, StringConstraints(strict=True, pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    """One of :data:`VERIFY_REASONS`; must match ``exit``."""
    last_witnessed_seq: NonNeg
    """Highest seq covered by a valid witness checkpoint (0 = none). Tamper-evident up to here."""
    anchored: bool
    """True iff verify ran with ``--head <RunAnchor>``, the anchor matched, and the run used fresh keys.
    The C1 claim (an insider cannot rewrite history undetected) holds **only when anchored** (F1)."""
    unanchored_reason: Literal["no_anchor", "repro_keys"] | None
    """Why not anchored: no ``--head`` given, or ``key_mode == repro`` (X7/R4). ``None`` iff ``anchored``."""
    isolation: Isolation | None = None
    """v1.2: echo of ``RunConfig.isolation``; ``None`` only when config.json could not be read. When
    ``degraded``, verify prints "per-agent attribution VOID" (SKEL-01 finding 4)."""

    @model_validator(mode="after")
    def _ok(self) -> VerifyReport:
        if self.ok != (self.exit == Exit.OK):
            raise ValueError("ok iff exit == 0")
        if self.reason not in VERIFY_REASONS:
            raise ValueError(f"unknown verify reason {self.reason!r}")
        if VERIFY_REASONS[self.reason] != self.exit:
            raise ValueError(f"reason {self.reason} implies exit {VERIFY_REASONS[self.reason].name}")
        if self.ok and self.first_bad is not None:
            raise ValueError("an OK report has no first_bad")
        if self.anchored != (self.unanchored_reason is None):
            raise ValueError("unanchored_reason is set iff not anchored")
        return self


class RunAnchor(Value):
    """F1/K1: the run's external anchor, one canonical line. The console prints ``keyring_hash`` and
    ``config_hash`` at start and the whole anchor at the end; ``ks verify --head <line>`` checks both hashes
    before any signature, then the chain against ``(seq, head, count)``. Swapping ``keys.json`` and re-signing
    everything (RT8(h)) gives ``keyring_mismatch`` -> WITNESS."""

    seq: Seq
    """Seq of the last witnessed record."""
    head: Hash
    """``Record.hash`` at ``seq``."""
    tick: Tick
    """Tick of the last checkpoint."""
    count: Seq
    """``WitnessCheckpoint.count`` of the last checkpoint (= number of witness lines, F2)."""
    keyring_hash: Hash
    """``Keyring.content_hash()`` of ``keys.json``."""
    config_hash: Hash
    """``RunConfig.content_hash()`` of ``config.json``."""

    @model_validator(mode="after")
    def _h(self) -> RunAnchor:
        if self.head == GENESIS_HASH:
            raise ValueError("an anchor head is a real record hash")
        return self

    @classmethod
    def of(cls, last: WitnessCheckpoint, keyring: Keyring, config: RunConfig) -> RunAnchor:
        return cls(seq=last.seq, head=last.head, tick=last.tick, count=last.count,
                   keyring_hash=keyring.content_hash(), config_hash=config.content_hash())

    def problems(self, keyring: Keyring, config: RunConfig) -> list[str]:
        """Hash checks run first by ``verify --head``: ``keyring_mismatch`` / ``config_mismatch``."""
        p = []
        if keyring.content_hash() != self.keyring_hash:
            p.append("keyring_mismatch")
        if config.content_hash() != self.config_hash:
            p.append("config_mismatch")
        return p

    def checkpoint_problems(self, last: WitnessCheckpoint | None) -> list[str]:
        """The last witness line must match the anchor: else ``truncated`` (fewer lines) or ``head_mismatch``."""
        if last is None or last.count < self.count:
            return ["truncated"]
        if (last.seq, last.head, last.tick, last.count) != (self.seq, self.head, self.tick, self.count):
            return ["head_mismatch"]
        return []


def anchor_status(anchor: RunAnchor | None, config: RunConfig) -> tuple[bool, str | None]:
    """``(anchored, unanchored_reason)`` for a VerifyReport whose hash/chain checks passed. Repro mode is never
    anchored (X7), whatever anchor is given."""
    if config.key_mode == "repro":
        return False, "repro_keys"
    if anchor is None:
        return False, "no_anchor"
    return True, None


def sidestore_relpath(h: str) -> str:
    """``sidestore/<h[:2]>/<h>.json``."""
    if not re.fullmatch(r"[0-9a-f]{64}", h):
        raise ValueError("not a hash")
    return f"{SIDESTORE_DIR}/{h[:2]}/{h}.json"


_JSONL_TYPES = {RECORD: Record, WITNESS: WitnessCheckpoint, ALERTS: Alert}
_PRIVATE = re.compile(rb"PRIVATE KEY|OPENSSH PRIVATE")
T = TypeVar("T", Record, WitnessCheckpoint, Alert)


class RunDir:
    """Create, append to, read and structurally validate a run dir. Crypto checks belong to ks.verify."""

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)

    DIR_MODE: ClassVar[int] = 0o711
    FILE_MODE: ClassVar[int] = 0o600
    SUBDIR_MODE: ClassVar[int] = 0o700
    RECORD_MODE: ClassVar[int] = 0o600  # gateway-only; the witness gets (seq, head, tick) pushed (ADR-00/02)

    @classmethod
    def create(cls, path: str | os.PathLike[str], config: RunConfig, keyring: Keyring, *,
               witness_uid: int | None = None, witness_gid: int | None = None) -> RunDir:
        """Create the layout with explicit modes (F1). With ``witness_uid``/``witness_gid`` (gateway runs as
        root), ``witness.jsonl`` and ``witness-heads/`` are chowned to the witness and ``record.jsonl`` gets
        the record stays gateway-only (0600): the witness never reads it, the gateway pushes (seq, head, tick)."""
        problems = keyring.problems(config)
        if problems:
            raise ValueError(f"incomplete keyring: {problems}")
        rd = cls(path)
        rd.path.mkdir(parents=True, exist_ok=False)
        os.chmod(rd.path, cls.DIR_MODE)
        rd._write(CONFIG, config.to_canonical())
        rd._write(KEYS, keyring.to_canonical())
        rd._write(RECORD, b"", mode=cls.RECORD_MODE)
        rd._write(WITNESS, b"")
        rd._write(ALERTS, b"")
        for d in (PLANS_DIR, SIDESTORE_DIR, ORACLE_DIR, BASELINES_DIR, WORKSPACE_DIR, WITNESS_HEADS_DIR):
            (rd.path / d).mkdir()
            os.chmod(rd.path / d, cls.SUBDIR_MODE)
        if witness_uid is not None or witness_gid is not None:
            u = -1 if witness_uid is None else witness_uid
            g = -1 if witness_gid is None else witness_gid
            os.chown(rd.path / WITNESS, u, g)
            os.chown(rd.path / WITNESS_HEADS_DIR, u, g)
        return rd

    def _write(self, rel: str, data: bytes, *, mode: int | None = None, append: bool = False) -> Path:
        p = self.path / rel
        flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC)
        fd = os.open(p, flags, self.FILE_MODE if mode is None else mode)
        try:
            if not append:
                os.fchmod(fd, self.FILE_MODE if mode is None else mode)
            os.write(fd, data)
        finally:
            os.close(fd)
        return p

    def write(self, relpath: str, data: bytes) -> Path:
        """Write a run-dir file (``effects.jsonl``, ``score.json``, ``oracle/...``) at 0600, parents 0700."""
        p = self.path / relpath
        if p.resolve().parent != self.path.resolve() and self.path.resolve() not in p.resolve().parents:
            raise ValueError("path escapes the run dir")
        self._mkdirs(p.parent)
        return self._write(str(p.relative_to(self.path)), data)

    def _mkdirs(self, d: Path) -> None:
        if d.is_dir():
            return
        self._mkdirs(d.parent)
        d.mkdir()
        os.chmod(d, self.SUBDIR_MODE)

    def config(self) -> RunConfig:
        return RunConfig.from_canonical((self.path / CONFIG).read_bytes())

    def keyring(self) -> Keyring:
        return Keyring.from_canonical((self.path / KEYS).read_bytes())

    def append(self, doc: Record | WitnessCheckpoint | Alert) -> None:
        name = next(f for f, t in _JSONL_TYPES.items() if isinstance(doc, t))
        self._write(name, doc.to_canonical() + b"\n", append=True,
                    mode=self.RECORD_MODE if name == RECORD else None)

    def _iter(self, name: str, typ: type[T]) -> Iterator[T]:
        with open(self.path / name, "rb") as fh:
            for line in fh:
                yield typ.from_canonical(line[:-1] if line.endswith(b"\n") else line)

    def records(self) -> Iterator[Record]:
        return self._iter(RECORD, Record)

    def witness(self) -> Iterator[WitnessCheckpoint]:
        return self._iter(WITNESS, WitnessCheckpoint)

    def alerts(self) -> Iterator[Alert]:
        return self._iter(ALERTS, Alert)

    def write_plan(self, plan: RecoveryPlan) -> Path:
        return self.write(f"{PLANS_DIR}/{plan.plan_id}.json", plan.to_canonical())

    def write_side(self, entry: SideEntry) -> Path:
        return self.write(sidestore_relpath(entry.hash), entry.to_canonical())

    def determinism_files(self) -> dict[str, bytes]:
        """C4/C5: relpath -> bytes to compare across runs of the same seed. Record and witness lines are
        replaced by the canonical bytes of their :func:`determinism_view`; every other deterministic file is
        read as is. Missing optional files are simply absent from the mapping."""
        out: dict[str, bytes] = {}
        for pat in DETERMINISTIC_FILES:
            if pat.endswith("/**"):
                base = self.path / pat[:-3]
                if base.is_dir():
                    for p in sorted(base.rglob("*")):
                        if p.is_file():
                            out[str(p.relative_to(self.path))] = p.read_bytes()
            elif (self.path / pat).is_file():
                if pat in PROJECTED_FILES:
                    docs = self.records() if pat == RECORD else self.witness()
                    out[pat] = b"".join(canonical.dumps_line(determinism_view(d)) for d in docs)
                else:
                    out[pat] = (self.path / pat).read_bytes()
        return out

    def perm_problems(self) -> list[str]:
        """F1: anything an agent uid could read. The run dir must not be group/other readable or writable, and
        no file or subdirectory below it may grant other-uids access (``record.jsonl`` may be group-read)."""
        probs: list[str] = []
        m = stat.S_IMODE(self.path.stat().st_mode)
        if m & 0o066:
            probs.append(f"run dir mode {m:o}")
        for p in sorted(self.path.rglob("*")):
            m = stat.S_IMODE(p.lstat().st_mode)
            rel = str(p.relative_to(self.path))
            allowed_group = 0o040 if rel == RECORD else 0
            if m & 0o007 or m & 0o070 & ~allowed_group:
                probs.append(f"{rel}: mode {m:o}")
        return probs

    def validate(self) -> list[str]:
        """Structural problems (empty list = valid): required files, canonical parse of every
        document and line, seq = 1..n, no private key material anywhere."""
        probs: list[str] = []
        for f in (CONFIG, KEYS, RECORD, WITNESS, ALERTS):
            if not (self.path / f).is_file():
                probs.append(f"missing {f}")
        for d in (PLANS_DIR, SIDESTORE_DIR):
            if not (self.path / d).is_dir():
                probs.append(f"missing {d}/")
        if probs:
            return probs
        docs = {}
        for name, typ in ((CONFIG, RunConfig), (KEYS, Keyring)):
            try:
                docs[name] = typ.from_canonical((self.path / name).read_bytes())
            except ValueError as e:
                probs.append(f"{name}: {e.__class__.__name__}")
        if len(docs) == 2:
            probs += [f"{KEYS}: {p}" for p in docs[KEYS].problems(docs[CONFIG])]
        for name, typ in _JSONL_TYPES.items():
            data = (self.path / name).read_bytes()
            if data and not data.endswith(b"\n"):
                probs.append(f"{name}: last line not LF-terminated")
            for i, line in enumerate(data.splitlines(), start=1):
                try:
                    doc = typ.from_canonical(line)
                except ValueError as e:
                    probs.append(f"{name}:{i}: {e.__class__.__name__}")
                    continue
                if name == RECORD and doc.seq != i:
                    probs.append(f"{name}:{i}: seq {doc.seq} != line {i}")
        for p in sorted((self.path / PLANS_DIR).glob("*.json")):
            try:
                RecoveryPlan.from_canonical(p.read_bytes())
            except ValueError as e:
                probs.append(f"{PLANS_DIR}/{p.name}: {e.__class__.__name__}")
        for p in sorted(self.path.rglob("*")):
            if not p.is_file() or p.relative_to(self.path).parts[0] == WORKSPACE_DIR:
                continue
            if p.suffix in (".key", ".pem") or _PRIVATE.search(p.read_bytes()[:1 << 20]):
                probs.append(f"private key material: {p.relative_to(self.path)}")
        return probs
