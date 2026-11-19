"""C6 Run directory: the only thing the scorer, ``ks verify`` and the jury read.

Layout (constants below)::

    <run>/
      config.json        RunConfig (seed, scenario, hold window, sensitive fields, agents)  [canonical]
      keys.json          Keyring: PUBLIC keys only (agents, gateway, witness, console, ...)  [canonical]
      record.jsonl       C2 Records, one canonical line each, seq 1..n                       [gateway only]
      witness.jsonl      C2 WitnessCheckpoints, one per tick                                 [witness only]
      alerts.jsonl       C4 Alerts                                                           [monitor]
      plans/             C5 RecoveryPlans, ``<plan_id>.json``
      sidestore/         C3 SideEntries, ``<hash[:2]>/<hash>.json`` (redactable)
      oracle/            S* artefacts (ks.oracle, ADR-06)
      effects.jsonl      world effect ledger (schema: ADR-06, tara)
      score.json         ks.score output (keys: ADR-06, tara)
      timing.jsonl       wall-clock measurements: the ONLY non-deterministic file
      workspace/         gateway-private (state.db); 0700, never read by the scorer

Private keys never touch the run dir (THREAT-MODEL v2: generated in memory). ``validate`` flags
any file that looks like private key material.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from enum import IntEnum
from pathlib import Path
from typing import Annotated, ClassVar, Literal, TypeVar

from pydantic import Field, StringConstraints, field_validator, model_validator

from . import canonical
from ._base import Document, Value
from .control import Alert
from .hashing import Domain
from .ids import AgentId, NonNeg, PrincipalId, PubKey
from .recovery import RecoveryPlan
from .record import Record, WitnessCheckpoint
from .state import SideEntry

__all__ = [
    "CONFIG", "KEYS", "RECORD", "WITNESS", "ALERTS", "PLANS_DIR", "SIDESTORE_DIR", "ORACLE_DIR", "EFFECTS",
    "SCORE", "TIMING", "WORKSPACE_DIR", "STATE_DB", "DETERMINISTIC_FILES", "SensitiveField", "RunConfig",
    "KeyEntry", "Keyring", "Exit", "VerifyReport", "RunDir", "sidestore_relpath",
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

DETERMINISTIC_FILES = (CONFIG, KEYS, RECORD, WITNESS, ALERTS)
"""Same seed => these files are byte-identical (plus plans/ and sidestore/). timing.jsonl is excluded."""

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
    fault: Annotated[str, StringConstraints(strict=True, pattern=r"^F[0-9]+\+?$")] | None
    """Injected fault id, e.g. ``F2+``; ``None`` for a clean (oracle) run."""
    culprit: AgentId | None
    """Agent the fault is injected into (ground truth for the scorer only; never read by ks.monitor)."""
    ticks: NonNeg
    """Number of ticks to run."""
    tick_us: Annotated[int, Field(strict=True, ge=1, le=canonical.MAX_SAFE_INT)]
    """Logical microseconds per tick; ``Record.ts_us = start_ts_us + tick*tick_us + slot``."""
    start_ts_us: NonNeg
    """Logical time of tick 0."""
    hold_window_ticks: NonNeg
    """Hold window: ticks a new outbox item waits before release. 0 = no hold (demo toggle)."""
    sensitive_fields: tuple[SensitiveField, ...]
    """Fields whose change triggers an early hold of dependent outbox items, sorted."""
    agents: tuple[AgentId, ...]
    """Agents in tick-barrier order (agent_id order), sorted."""

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
        return self


class KeyEntry(Value):
    """One public key."""

    principal: PrincipalId
    """Agent id or ``ks.*`` principal."""
    alg: Literal["ed25519"] = "ed25519"
    """Signature algorithm."""
    pub: PubKey
    """Raw 32-byte Ed25519 public key, hex."""


class Keyring(Document):
    """``keys.json``: public keys ``verify`` checks signatures against. Never private keys."""

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
        return v

    def pub(self, principal: str) -> str | None:
        return next((k.pub for k in self.keys if k.principal == principal), None)


class Exit(IntEnum):
    """Exit codes of ``ks verify`` / ``ks recover`` (ks.verify re-exports as ``ks.verify.Exit``). Use names, not numbers."""

    OK = 0
    IO = 1          # missing/unreadable/non-canonical run dir files
    TAMPER = 2      # chain, hash or signature mismatch, or seq gap
    WITNESS = 3     # record disagrees with a witness checkpoint (incl. full rewrite)
    RECONCILE = 4   # fold(record) != live state
    FROZEN = 5      # ks recover refused: unresolved tamper alert
    USAGE = 64      # bad CLI arguments


class VerifyReport(Value):
    """Last stdout line of ``ks verify`` (canonical JSON)."""

    ok: bool
    """True iff exit code is Exit.OK."""
    exit: Annotated[int, Field(strict=True, ge=0, le=255)]
    """Numeric exit code (an ``Exit`` value)."""
    first_bad: Annotated[int, Field(strict=True, ge=1, le=canonical.MAX_SAFE_INT)] | None
    """seq (= 1-based line number) of the first bad record, or ``None``."""
    reason: Annotated[str, StringConstraints(strict=True, pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    """Short code, e.g. ``ok``, ``hash_mismatch``, ``gw_sig_invalid``, ``seq_gap``, ``witness_mismatch``."""
    last_witnessed_seq: NonNeg
    """Highest seq covered by a valid witness checkpoint (0 = none). Tamper-evident up to here."""

    @model_validator(mode="after")
    def _ok(self) -> VerifyReport:
        if self.ok != (self.exit == Exit.OK):
            raise ValueError("ok iff exit == 0")
        return self


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

    @classmethod
    def create(cls, path: str | os.PathLike[str], config: RunConfig, keyring: Keyring) -> RunDir:
        rd = cls(path)
        rd.path.mkdir(parents=True, exist_ok=False)
        (rd.path / CONFIG).write_bytes(config.to_canonical())
        (rd.path / KEYS).write_bytes(keyring.to_canonical())
        for f in (RECORD, WITNESS, ALERTS):
            (rd.path / f).write_bytes(b"")
        for d in (PLANS_DIR, SIDESTORE_DIR, ORACLE_DIR):
            (rd.path / d).mkdir()
        (rd.path / WORKSPACE_DIR).mkdir(mode=0o700)
        return rd

    def config(self) -> RunConfig:
        return RunConfig.from_canonical((self.path / CONFIG).read_bytes())

    def keyring(self) -> Keyring:
        return Keyring.from_canonical((self.path / KEYS).read_bytes())

    def append(self, doc: Record | WitnessCheckpoint | Alert) -> None:
        name = next(f for f, t in _JSONL_TYPES.items() if isinstance(doc, t))
        with open(self.path / name, "ab") as fh:
            fh.write(doc.to_canonical() + b"\n")

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
        p = self.path / PLANS_DIR / f"{plan.plan_id}.json"
        p.write_bytes(plan.to_canonical())
        return p

    def write_side(self, entry: SideEntry) -> Path:
        p = self.path / sidestore_relpath(entry.hash)
        p.parent.mkdir(exist_ok=True)
        p.write_bytes(entry.to_canonical())
        return p

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
        for name, typ in ((CONFIG, RunConfig), (KEYS, Keyring)):
            try:
                typ.from_canonical((self.path / name).read_bytes())
            except ValueError as e:
                probs.append(f"{name}: {e.__class__.__name__}")
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
            if not p.is_file() or WORKSPACE_DIR in p.relative_to(self.path).parts:
                continue
            if p.suffix in (".key", ".pem") or _PRIVATE.search(p.read_bytes()[:1 << 20]):
                probs.append(f"private key material: {p.relative_to(self.path)}")
        return probs
