"""``ks verify RUN [--head ANCHOR]`` (ADR-02 §6), stopping at the first failure:

IO (config, keys, record) -> anchor hashes (keyring/config, before any signature) -> keyring complete ->
record pass (parse, seq, prev_hash, hash, gw_sig, agent sig vs sig_ok) -> witness pass (sig, count chain,
truncation, heads) -> anchor vs last checkpoint.

SKEL-01 scope: no side-store, dispatch-window, epoch or reconcile pass yet (Sprint 3, arjun).
"""

from __future__ import annotations

import sys
from pathlib import Path

from ks.contracts import (GENESIS_HASH, SYSTEM_CONN, SYSTEM_PRINCIPALS, VERIFY_REASONS, CanonicalError, Keyring,
                          Record, RunAnchor, RunConfig, VerifyReport, WitnessCheckpoint, anchor_status,
                          witness_chain_problems)
from ks.contracts.rundir import CONFIG, KEYS, RECORD, WITNESS
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
                            last_witnessed_seq=state["lws"], anchored=anchored, unanchored_reason=why)

    try:
        config, keyring, record_bytes = _load(run)
        state["config"] = config
        if anchor is not None:
            probs = anchor.problems(keyring, config)
            if probs:
                raise _Fail(probs[0], None, "anchor hash differs from the files")
        if keyring.problems(config):
            raise _Fail("unreadable", None, f"keys.json incomplete: {keyring.problems(config)}")
        hashes = _record_pass(record_bytes, keyring)
        last = _witness_pass(run, hashes, keyring, state)
        if anchor is not None:
            probs = anchor.checkpoint_problems(last)
            if probs:
                n = len(hashes)
                raise _Fail(probs[0], n + 1 if probs[0] == "truncated" else min(anchor.seq, n) + 1)
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


def _record_pass(data: bytes, keyring: Keyring) -> list[str]:
    """Per line: parse, seq == line, prev_hash, hash, gw_sig, agent signature consistent with sig_ok."""
    gw_pub = keyring.pub("ks.gateway") or ""
    hashes: list[str] = []
    prev = GENESIS_HASH
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
        env = rec.envelope
        if env is not None:
            pub = keyring.pub(env.agent_id)
            checkable = (env.sig is not None and pub is not None
                         and not (env.agent_id in SYSTEM_PRINCIPALS and rec.conn_id != SYSTEM_CONN))
            if (checkable and verify_hex(pub, env.sig, env.signing_bytes())) != rec.sig_ok:
                raise _Fail("agent_sig_mismatch", i)
        hashes.append(rec.hash)
        prev = rec.hash
    return hashes


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
