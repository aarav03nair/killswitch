"""``ks verify RUN [--head ANCHOR]`` (ADR-02 §6), stopping at the first failure:

IO (config, keys, record) -> anchor hashes (keyring/config, before any signature) -> keyring complete ->
record pass (parse, seq, prev_hash, hash, gw_sig, agent sig vs sig_ok, D-15 seed rule) -> witness pass (sig, count chain,
truncation, heads) -> anchor vs last checkpoint.

SKEL-01 scope: no side-store, dispatch-window, epoch or reconcile pass yet (Sprint 3, arjun).
"""

from __future__ import annotations

import sys
from pathlib import Path

from ks.contracts import (GENESIS_HASH, RECOVER_TOOL_PREFIX, SEED_TOOL, SYSTEM_CONN, SYSTEM_PRINCIPALS, VERIFY_REASONS,
                          CanonicalError, Decision, EpochFold, Keyring, Record, RunAnchor, RunConfig, VerifyReport,
                          WitnessCheckpoint, anchor_status, args_hash, witness_chain_problems)
from ks.contracts.rundir import CONFIG, KEYS, RECORD, STATE_DB, WITNESS
from ks.identity import verify_hex

__all__ = ["verify"]


class _Fail(Exception):
    def __init__(self, reason: str, first_bad: int | None = None, detail: str = ""):
        super().__init__(reason)
        self.reason, self.first_bad, self.detail = reason, first_bad, detail


def _lines(data: bytes) -> list[bytes]:
    """Record/witness lines; a missing final LF leaves a last line that will not parse."""
    parts = data.split(b"\n")
    if parts and parts[-1] == b"":
        parts.pop()
    elif parts:
        parts[-1] += b"\x00"  # not LF-terminated: force a parse error on that line
    return parts


def verify(run: str | Path, anchor: RunAnchor | None = None, *, log=lambda s: print(s, file=sys.stderr)) -> VerifyReport:
    run = Path(run)
    state = {"lws": 0, "config": None}

    def report(reason: str, first_bad: int | None = None) -> VerifyReport:
        cfg: RunConfig | None = state["config"]
        if reason == "ok":
            anchored, why = anchor_status(anchor, cfg)
        else:
            anchored, why = False, ("repro_keys" if cfg is not None and cfg.key_mode == "repro" else "no_anchor")
        code = VERIFY_REASONS[reason]
        return VerifyReport(ok=code == 0, exit=int(code), first_bad=first_bad, reason=reason,
                            last_witnessed_seq=state["lws"], anchored=anchored, unanchored_reason=why,
                            isolation=cfg.isolation if cfg is not None else None)

    try:
        config, keyring, record_bytes = _load(run)
        state["config"] = config
        if config.isolation == "degraded":
            log("verify: isolation degraded: per-agent attribution VOID for this run")
        if anchor is not None:
            probs = anchor.problems(keyring, config)
            if probs:
                raise _Fail(probs[0], None, "anchor hash differs from the files")
        if keyring.problems(config):
            raise _Fail("unreadable", None, f"keys.json incomplete: {keyring.problems(config)}")
        writes: list = []
        hashes = _record_pass(record_bytes, keyring, writes, config)
        last = _witness_pass(run, hashes, keyring, state)
        if anchor is not None:
            probs = anchor.checkpoint_problems(last)
            if probs:
                n = len(hashes)
                raise _Fail(probs[0], n + 1 if probs[0] == "truncated" else min(anchor.seq, n) + 1)
        if config.scenario == "skeleton" and (run / STATE_DB).exists():
            raise _Fail("no_state", None, "a skeleton (stateless) run must not have a state.db")
        _reconcile_pass(run, writes)
    except _Fail as f:
        if f.detail:
            log(f"verify: {f.reason}: {f.detail}")
        return report(f.reason, f.first_bad)
    return report("ok")


def _load(run: Path) -> tuple[RunConfig, Keyring, bytes]:
    raw = {}
    for name in (CONFIG, KEYS, RECORD):
        p = run / name
        if not p.is_file():
            raise _Fail("missing_file", None, name)
        try:
            raw[name] = p.read_bytes()
        except OSError as e:
            raise _Fail("unreadable", None, f"{name}: {e}") from None
    try:
        config = RunConfig.from_canonical(raw[CONFIG])
        keyring = Keyring.from_canonical(raw[KEYS])
    except CanonicalError as e:
        raise _Fail("unreadable", None, f"config/keys do not parse: {e}") from None
    return config, keyring, raw[RECORD]


def _needs_seed(config: RunConfig) -> bool:
    """A contracts >= 1.3 run with a state store has a ks.seed record at seq 1 (D-SEQ1). The ``skeleton``
    scenario is stateless (no store, no seed record by construction); everything else is seeded."""
    try:
        minor = tuple(int(x) for x in config.contracts_version.split(".")[:2])
    except ValueError:
        return False
    return minor >= (1, 3) and config.scenario != "skeleton"


def _record_pass(data: bytes, keyring: Keyring, writes: list, config: RunConfig) -> list[str]:
    """Per line: parse, seq == line, prev_hash, hash, gw_sig, agent signature consistent with sig_ok, then the
    per-record rules (ADR-02 section 6): seed, system tools only by system principals on c-0, epoch fold,
    ts_us formula, agents named by the config. Record validators already refuse expired admissions at parse."""
    gw_pub = keyring.pub("ks.gateway") or ""
    hashes: list[str] = []
    prev = GENESIS_HASH
    epochs = EpochFold(config.agents)
    last_slot: dict[int, int] = {}  # tick -> last slot seen (strictly increasing within a tick)
    seed_args = args_hash({"seed": config.scenario})
    need_seed = _needs_seed(config)
    stateless = config.scenario == "skeleton"
    for i, line in enumerate(_lines(data), start=1):
        try:
            rec = Record.from_canonical(line)
        except CanonicalError as e:
            raise _Fail("parse_error", i, str(e)[:200]) from None
        if rec.seq != i:
            raise _Fail("seq_gap", i, f"line {i} has seq {rec.seq}")
        if rec.prev_hash != prev:
            raise _Fail("hash_mismatch", i, "prev_hash does not chain")
        probs = rec.integrity_problems()
        if any(p != "unsigned record" for p in probs):
            raise _Fail("hash_mismatch", i, ", ".join(probs))
        if rec.gw_sig is None or not verify_hex(gw_pub, rec.gw_sig, rec.signing_bytes()):
            raise _Fail("gw_sig_invalid", i)
        slot = rec.ts_us - config.start_ts_us - rec.tick * config.tick_us
        if not 0 <= slot < config.tick_us or slot <= last_slot.get(rec.tick, -1):
            raise _Fail("hash_mismatch", i, f"ts_us {rec.ts_us} does not follow start_ts_us + tick*tick_us + slot")
        last_slot[rec.tick] = slot
        env = rec.envelope
        if stateless and rec.write_set:  # the label must not buy an exemption: a skeleton run writes no state
            raise _Fail("seed_invalid", i, "a skeleton (stateless) run has a record with state writes")
        if i == 1 and need_seed and (env is None or env.tool != SEED_TOOL or rec.decision == Decision.DENY):
            raise _Fail("seed_invalid", 1, "record 1 of a 1.3 run must be an admitted ks.seed")
        if env is not None:
            pub = keyring.pub(env.agent_id)
            checkable = (env.sig is not None and pub is not None
                         and not (env.agent_id in SYSTEM_PRINCIPALS and rec.conn_id != SYSTEM_CONN))
            if (checkable and verify_hex(pub, env.sig, env.signing_bytes())) != rec.sig_ok:
                raise _Fail("agent_sig_mismatch", i)
            if env.tool == SEED_TOOL and rec.decision.value != "deny":
                probs = rec.seed_problems()
                if not probs and env.args_hash != seed_args:
                    probs = ["seed args differ from the run's scenario"]
                if not probs and rec.write_set != expected_seed_writes():
                    probs = ["write_set differs from seed_state"]
                if probs:
                    raise _Fail("seed_invalid", i, "; ".join(probs))
            if rec.sig_ok and env.agent_id not in SYSTEM_PRINCIPALS and env.agent_id not in config.agents:
                raise _Fail("agent_sig_mismatch", i, f"{env.agent_id} is not an agent of this run")
            if rec.decision == Decision.EXEC and (env.tool == "ks.control" or env.tool.startswith(RECOVER_TOOL_PREFIX)):
                if (env.agent_id not in SYSTEM_PRINCIPALS or rec.conn_id != SYSTEM_CONN or not rec.sig_ok
                        or (rec.control is not None and rec.control.issued_by != env.agent_id)):
                    raise _Fail("agent_sig_mismatch", i, f"{env.tool} executed outside a verified system principal on c-0")
            if rec.control is not None and rec.decision == Decision.EXEC:
                try:
                    epochs.apply(rec.control)
                except ValueError as e:
                    raise _Fail("epoch_regression", i, str(e)[:200]) from None
        writes.extend(rec.write_set)
        hashes.append(rec.hash)
        prev = rec.hash
    return hashes


def expected_seed_writes() -> tuple:
    """D-15: the write set ``ks.world.scenario.seed_state`` produces at seq 1 on an empty store (the seed is a
    pure function of the code, not of the run), sorted by obj like ``Record.write_set``."""
    import sqlite3

    from ks.contracts import VersionRef, WriteEntry
    from ks.state import Store
    from ks.world.scenario import FIELDS, seed_state

    store = Store(sqlite3.connect(":memory:", isolation_level=None), fields=FIELDS)
    try:
        with store.txn():
            seed_state(store, seq=1)
        rows = store.conn.execute("SELECT obj, ver, hash FROM versions WHERE seq = 1 ORDER BY obj").fetchall()
        out = []
        for obj, ver, h in rows:
            prev = store.conn.execute("SELECT hash FROM versions WHERE obj = ? AND ver = ?", (obj, ver - 1)).fetchone()
            out.append(WriteEntry(obj=obj, before=None if prev is None else VersionRef(ver=ver - 1, hash=prev[0]),
                                  after=VersionRef(ver=ver, hash=h)))
        return tuple(out)
    finally:
        store.close()


def _witness_pass(run: Path, hashes: list[str], keyring: Keyring, state: dict) -> WitnessCheckpoint | None:
    """Checkpoint signatures, count chain, truncation, heads vs records. Returns the last checkpoint."""
    n = len(hashes)
    p = run / WITNESS
    data = p.read_bytes() if p.is_file() else b""
    if not data:
        if n:
            raise _Fail("witness_missing", 1)
        return None
    w_pub = keyring.pub("ks.witness") or ""
    cps: list[WitnessCheckpoint] = []
    for line in _lines(data):
        try:
            cp = WitnessCheckpoint.from_canonical(line)
        except CanonicalError as e:
            raise _Fail("witness_sig_invalid", None, f"bad witness line: {str(e)[:200]}") from None
        cps.append(cp)
    chain = {int(s.split(":")[0]): s.split(": ")[1] for s in reversed(witness_chain_problems(cps))}
    for i, cp in enumerate(cps, start=1):
        if cp.sig is None or not verify_hex(w_pub, cp.sig, cp.signing_bytes()):
            raise _Fail("witness_sig_invalid", cp.seq if cp.seq <= n else None)
        if i in chain:
            raise _Fail(chain[i], min(cp.seq, n + 1))
        if cp.seq > n:
            raise _Fail("truncated", n + 1, f"checkpoint {i} witnessed seq {cp.seq}, record has {n}")
        if hashes[cp.seq - 1] != cp.head:
            raise _Fail("witness_mismatch", cp.seq)
        state["lws"] = cp.seq
    return cps[-1]


def _reconcile_pass(run: Path, writes: list) -> None:
    """``state_digest(fold(record))`` against ``workspace/state.db`` (ADR-02 §6; last pass). No state file: fine
    if the record has no state writes, else ``no_state``. A crash between state commit and record append, or an
    unmediated write, shows here as ``reconcile_mismatch``. Never silent (B3-09)."""
    from ks.contracts import state_digest
    from ks.state import FoldError, Store, fold

    try:
        folded = fold(writes)
    except FoldError as e:
        raise _Fail("reconcile_mismatch", None, f"record write sets do not chain: {e}") from None
    db = run / STATE_DB
    if not db.is_file():
        if folded:
            raise _Fail("no_state", None, "the record has state writes but there is no state.db")
        return
    import sqlite3
    try:
        conn = sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True, isolation_level=None)
        try:
            live = Store(conn).state_digest()
            bad = _value_problems(conn)
        finally:
            conn.close()
    except Exception as e:  # unreadable or foreign database: the state cannot be reconciled
        raise _Fail("reconcile_mismatch", None, f"state.db unreadable: {type(e).__name__}: {e}") from None
    if live != state_digest(folded):
        raise _Fail("reconcile_mismatch", None, "state.db differs from fold(record)")
    if bad:
        raise _Fail("reconcile_mismatch", None, f"state.db value differs from its hash: {bad}")


def _value_problems(conn) -> str | None:
    """Value-vs-hash: the digest covers only (obj, ver, hash), so an edited value would pass it. Every head value
    and every non-redacted side value must hash to what the record committed (B3-15)."""
    from ks.contracts import SideDomain, SideEntry, value_hash
    from ks.state.store import _value

    for obj, ver, h, text, redacted in conn.execute(
            "SELECT obj, head_ver, head_hash, head_value, head_redacted FROM objects ORDER BY obj").fetchall():
        row = conn.execute("SELECT hash FROM versions WHERE obj = ? AND ver = ?", (obj, ver)).fetchone()
        if row is None or row[0] != h:
            return f"{obj} head hash differs from versions"
        if redacted:
            if text is not None:
                return f"{obj} redacted head still has a value"
        elif text is None:
            if h != value_hash(None):
                return f"{obj} head has no value"
        elif value_hash(_value(text)) != h:
            return f"{obj} head value does not hash to {h[:16]}"
    for h, domain, text, redacted in conn.execute("SELECT hash, domain, value, redacted FROM side").fetchall():
        if redacted:
            continue
        if text is None:
            return f"side value {h[:16]} missing"
        entry = SideEntry.model_construct(hash=h, domain=SideDomain(domain), value=_value(text), redacted=False)
        if entry.expected_hash() != h:
            return f"side value {h[:16]} does not hash to its key"
    return None
