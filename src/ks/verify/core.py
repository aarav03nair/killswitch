"""``ks verify RUN [--head ANCHOR]`` (ADR-02 §6), stopping at the first failure:

IO (config, keys, record) -> anchor hashes (keyring/config, before any signature) -> keyring complete ->
record pass (parse, seq, prev_hash, hash, gw_sig, agent sig vs sig_ok, D-15 seed rule) -> witness pass (sig, count chain,
truncation, heads) -> anchor vs last checkpoint.

After the record pass: dispatch window (F4), alerts.jsonl cross-check (F6), side-store check (B3-31), recovery
binding (B3-30, ``recovery_unbound``), resolutions (S4-13, ``resolution_invalid``).
"""

from __future__ import annotations

import sys
from pathlib import Path

from ks.contracts import (GENESIS_HASH, NO_LINEAGE_HOLD_BANNER, SEED_TOOL, SYSTEM_CONN, SYSTEM_PRINCIPALS, VERIFY_REASONS,
                          CanonicalError, Decision, EpochFold, Keyring, Record, RunAnchor, RunConfig, VerifyReport,
                          WitnessCheckpoint, anchor_status, args_hash, system_tool_signers, witness_chain_problems)
from ks.contracts.rundir import CONFIG, KEYS, RECORD, STATE_DB, WITNESS
from ks.identity import verify_hex

from .recovery import recovery_pass, resolution_pass
from .reexec import reexec_pass
from .window import Violation, alerts_pass, side_pass, window_pass

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
            anchored, why = False, "verify_failed"  # S4-32: a failing run makes no anchoring claim, with or without --head
        code = VERIFY_REASONS[reason]
        if reason != "ok" and not state["lws"] and state.get("keyring") is not None:
            state["lws"] = _signed_witness_seq(run, state["keyring"])  # S4-32: the real figure, not "stopped early"
        return VerifyReport(ok=code == 0, exit=int(code), first_bad=first_bad, reason=reason,
                            last_witnessed_seq=state["lws"], anchored=anchored, unanchored_reason=why,
                            isolation=cfg.isolation if cfg is not None else None,
                            lineage_hold=cfg.lineage_hold if cfg is not None else True)

    try:
        config, keyring, record_bytes = _load(run)
        state["config"] = config
        state["keyring"] = keyring
        if config.isolation == "degraded":
            log("verify: isolation degraded: per-agent attribution VOID for this run")
        if not config.lineage_hold:
            log(f"verify: {NO_LINEAGE_HOLD_BANNER}")
        if anchor is not None:
            probs = anchor.problems(keyring, config)
            if probs:
                raise _Fail(probs[0], None, "anchor hash differs from the files")
        if keyring.problems(config):
            raise _Fail("unreadable", None, f"keys.json incomplete: {keyring.problems(config)}")
        writes: list = []
        recs: list = []
        hashes = _record_pass(record_bytes, keyring, writes, config, recs)
        try:
            reexec_pass(recs)  # B3-25 (F9)
            window_pass(run, recs, config)
            alerts_pass(run, recs)
            side_pass(run, recs)
            recovery_pass(run, recs)  # B3-30: ks.recover.* bound to a ks.approve and the plan file
            resolution_pass(run, recs)  # S4-13 (D-18, ADR-05a §6): resolutions the rule supports
        except Violation as v:
            raise _Fail(v.reason, v.first_bad, v.detail) from None
        last = _witness_pass(run, hashes, keyring, state)
        if anchor is not None:
            probs = anchor.checkpoint_problems(last)
            if probs:
                n = len(hashes)
                raise _Fail(probs[0], n + 1 if probs[0] == "truncated" else min(anchor.seq, n) + 1)
        if config.scenario == "skeleton" and (run / STATE_DB).exists():
            raise _Fail("no_state", None, "a skeleton (stateless) run must not have a state.db")
        _reconcile_pass(run, writes, recs)
    except _Fail as f:
        if f.detail:
            log(f"verify: {f.reason}: {f.detail}")
        return report(f.reason, f.first_bad)
    return report("ok")


def _signed_witness_seq(run: Path, keyring: Keyring) -> int:
    """Best effort, failure path only: highest seq of a checkpoint whose signature verifies (heads are not compared
    to the record here; the failure reason already says what is wrong). 0 if none or unreadable."""
    try:
        w_pub = keyring.pub("ks.witness") or ""
        best = 0
        for line in _lines((run / WITNESS).read_bytes()):
            cp = WitnessCheckpoint.from_canonical(line)
            if cp.sig is not None and verify_hex(w_pub, cp.sig, cp.signing_bytes()):
                best = max(best, cp.seq)
        return best
    except Exception:  # noqa: BLE001
        return 0


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


def _record_pass(data: bytes, keyring: Keyring, writes: list, config: RunConfig, recs: list | None = None) -> list[str]:
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
        if stateless and (rec.write_set or rec.read_set or rec.outbox_ids):  # the label must not buy an exemption
            raise _Fail("seed_invalid", i, "a skeleton (stateless) run has a record with state reads/writes/outbox")
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
            if rec.decision == Decision.EXEC and env.tool.startswith("ks."):
                # B3-13 / K13: every reserved tool (ks.control, ks.alert, ks.approve, ks.dispatch, ks.seed,
                # ks.recover.<op>) executes only for a principal allowed to sign it, verified, on c-0; an unknown
                # ks.* tool has no signer at all
                if (env.agent_id not in system_tool_signers(env.tool) or rec.conn_id != SYSTEM_CONN or not rec.sig_ok
                        or (rec.control is not None and rec.control.issued_by != env.agent_id)):
                    raise _Fail("agent_sig_mismatch", i, f"{env.tool} executed outside a verified system principal on c-0")
            if (rec.decision in (Decision.EXEC, Decision.HOLD) and env.agent_id in config.agents
                    and env.agent_id not in SYSTEM_PRINCIPALS):
                # B3-49: epoch fence. An admitted agent record (re-executions included) carries the agent's current
                # epoch folded from earlier executed Controls; none while suspended/revoked. B3-35 (kabir's B3-49
                # follow-ups): a HOLD is fenced too (the gateway denies at steps 8-9, before policy can hold), and
                # no act_chain ancestor may be suspended/revoked at admission (step 9, revoked_ancestor).
                cur = epochs.epoch(env.agent_id)
                if cur is None or env.epoch != cur:
                    raise _Fail("epoch_regression", i, f"{env.agent_id} admitted ({rec.decision.value}) at epoch "
                                f"{env.epoch} while the fold says {'suspended/revoked' if cur is None else cur}")
                dead = [l.principal for l in env.act_chain if l.principal in config.agents
                        and epochs.epoch(l.principal) is None]
                if dead:
                    raise _Fail("epoch_regression", i, f"{env.agent_id} admitted ({rec.decision.value}) with "
                                f"suspended/revoked act_chain ancestor {dead[0]}")
            if rec.control is not None and rec.decision == Decision.EXEC:
                try:
                    epochs.apply(rec.control)
                except ValueError as e:
                    raise _Fail("epoch_regression", i, str(e)[:200]) from None
        writes.extend(rec.write_set)
        if recs is not None:
            recs.append(rec)
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


def _reconcile_pass(run: Path, writes: list, recs: list | None = None) -> None:
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
        conn = sqlite3.connect(f"{db.resolve().as_uri()}?mode=ro", uri=True, isolation_level=None)
        try:
            live = Store(conn).state_digest()
            bad = _value_problems(conn)
            hist = _history_problems(conn, recs, run) if recs is not None else None
        finally:
            conn.close()
    except Exception as e:  # unreadable or foreign database: the state cannot be reconciled
        raise _Fail("reconcile_mismatch", None, f"state.db unreadable: {type(e).__name__}: {e}") from None
    if live != state_digest(folded):
        raise _Fail("reconcile_mismatch", None, "state.db differs from fold(record)")
    if hist:
        raise _Fail("reconcile_mismatch", None, f"state.db version history differs from the record: {hist}")
    if bad:
        raise _Fail("reconcile_mismatch", None, f"state.db value differs from its hash: {bad}")


def _history_problems(conn, recs: list, run: Path) -> str | None:
    """S4-33: the digest covers only head (obj, ver, hash), but ``ks score`` reads every version's author. Every
    ``versions`` row (obj, ver, hash, seq, author, action_id) must be backed by a write in the record at that seq,
    and every recorded write must have its row: no extra, missing or re-attributed version. A ``ks.recover.*``
    record re-runs under the original agent/action ids (B3-27), so its writes keep any author of the run."""
    expected: dict[tuple[str, int], tuple[str, int, set, str]] = {}
    for rec in recs:
        env = rec.envelope
        recover = env is not None and env.tool.startswith("ks.recover.")
        for w in rec.write_set:
            expected[(w.obj, w.after.ver)] = (w.after.hash, rec.seq, recover, env)
    pairs: dict[int, tuple[str, str]] = {r.seq: (r.envelope.agent_id, r.envelope.action_id)
                                         for r in recs if r.envelope is not None}

    pairs_all = set(pairs.values())
    recs_by_seq = {r.seq: r for r in recs}
    rows = conn.execute("SELECT obj, ver, hash, author, seq, action_id FROM versions").fetchall()
    seen = set()
    for obj, ver, h, author, seq, action in rows:
        seen.add((obj, ver))
        exp = expected.get((obj, ver))
        if exp is None:
            return f"{obj} v{ver} (seq {seq}, {author}) has no record write"
        eh, eseq, recover, env = exp
        if (eh, eseq) != (h, seq):
            return f"{obj} v{ver} is (hash, seq) ({h[:12]}, {seq}) but the record says ({eh[:12]}, {eseq})"
        if env is None:
            return f"{obj} v{ver} is backed by a record at seq {seq} with no envelope"
        if env.tool == "ks.recover.rerun":
            # S4-33: a repair row is authored by the plan step's own action (the approved, bound plan step carried in
            # the record's RecoverArgs), not by any earlier agent
            want = _rerun_action(run, recs_by_seq[seq])
            if want is None or (author, action) != want or want not in pairs_all:
                return f"{obj} v{ver} is authored {author}/{action} but the plan step at seq {seq} re-runs {want}"
            continue
        if author != env.agent_id:
            return f"{obj} v{ver} is authored {author} but the record at seq {seq} is {env.agent_id}"
        if author == env.agent_id and action != env.action_id and not (
                env.tool == SEED_TOOL and action.startswith("seed-")):
            return f"{obj} v{ver} action_id {action} differs from the record's {env.action_id}"
    missing = sorted(set(expected) - seen)
    if missing:
        return f"{missing[0][0]} v{missing[0][1]} is in the record but not in state.db"
    return None


def _rerun_action(run: Path, rec) -> tuple[str, str] | None:
    """(agent_id, action_id) of the ActionRef in the RecoverArgs step of a ``ks.recover.rerun`` record, or None."""
    from ks.contracts import RecoverArgs, canonical

    from .window import _side_value
    try:
        a = RecoverArgs.model_validate_json(canonical.dumps(_side_value(run, rec.envelope.args_hash)))
        return (a.step.action.agent_id, a.step.action.action_id)
    except Exception:  # noqa: BLE001
        return None


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
