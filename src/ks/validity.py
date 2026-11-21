"""Run validity (S4-22): may this run be presented as the headline?

A run is the headline only if all three hold:

* ``config.json`` says ``isolation = per_agent_uid`` (otherwise per-agent attribution is VOID, RT3b),
* ``key_mode = fresh`` (repro keys are never anchored: not a security run),
* ``timing.jsonl`` exists and no connection missed a tick deadline. Panel S4-26: under heavy host load agents miss
  deadlines, no-op, and the hero scores C 3/144 instead of 0/265. Such a run is DEGRADED, never the headline.

Verdict: ``VOID`` (isolation or keys), else ``DEGRADED`` (deadline misses, or no timing.jsonl), else ``OK``.
Reads only ``config.json`` and ``timing.jsonl`` (the deadline-miss *count*, never a wall-clock value), so the console
model stays the same for the same run dir. ``python -m ks.validity RUN`` prints one canonical JSON line and a
banner; exit 0 only for ``OK`` (used by ``scripts/finale.sh``).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from ks.contracts import canonical
from ks.contracts.rundir import CONFIG, TIMING

__all__ = ["VALIDITY_KEY", "run_validity", "score_entry", "validity_line"]

VALIDITY_KEY = "run_validity"
"""score.json key, present only when the verdict is not ``OK``, so every headline-eligible score.json is
byte-identical to before S4-22 (same pattern as ``lineage_hold`` and the resolver keys)."""


def _misses(run: Path) -> tuple[int | None, list[int]]:
    p = run / TIMING
    if not p.is_file():
        return None, []
    n, ticks = 0, []
    try:
        for line in p.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            missed = row["missed"]
            if not isinstance(missed, list) or not isinstance(row["tick"], int):
                return None, []
            if missed:
                n += len(missed)
                ticks.append(row["tick"])
    except (OSError, ValueError, KeyError, TypeError):
        return None, []
    return n, ticks


def run_validity(run: str | Path) -> dict[str, Any] | None:
    """Verdict for a run dir, or ``None`` if it has no readable ``config.json`` (synthetic dirs: nothing claimed)."""
    run = Path(run)
    try:
        cfg = json.loads((run / CONFIG).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(cfg, dict):
        return None
    iso, km = cfg.get("isolation", "degraded"), cfg.get("key_mode")
    n, ticks = _misses(run)
    reasons = []
    if iso != "per_agent_uid":
        reasons.append("isolation_degraded")
    if km != "fresh":
        reasons.append("repro_keys" if km == "repro" else "key_mode_unknown")
    void = bool(reasons)
    if n is None:
        reasons.append("no_timing")
    elif n:
        reasons.append("deadline_missed")
    verdict = "VOID" if void else ("DEGRADED" if reasons else "OK")
    return {"verdict": verdict, "headline": verdict == "OK", "reasons": reasons, "isolation": iso, "key_mode": km,
            "deadline_misses": n, "missed_ticks": ticks}


def score_entry(run: str | Path) -> dict[str, Any] | None:
    """The ``run_validity`` value for score.json, or ``None`` (key omitted) for an OK run or a dir without config."""
    v = run_validity(run)
    if v is None or v["verdict"] == "OK":
        return None
    return {k: v[k] for k in ("verdict", "reasons", "isolation", "key_mode", "deadline_misses", "missed_ticks")}


def validity_line(v: dict[str, Any] | None) -> str | None:
    """One line for the console and the finale script; ``None`` without config."""
    if v is None:
        return None
    n = v["deadline_misses"]
    miss = "deadline misses: unknown (no timing.jsonl)" if n is None else f"deadline misses: {n}"
    if n:
        miss += f" (ticks {', '.join(map(str, v['missed_ticks'][:8]))}{', ...' if len(v['missed_ticks']) > 8 else ''})"
    head = (f"isolation={v['isolation']}, key_mode={v['key_mode']}, {miss}")
    if v["verdict"] == "OK":
        return f"run validity: OK (headline-eligible): {head}"
    what = ("per-agent attribution is VOID" if "isolation_degraded" in v["reasons"]
            else "not a security run" if v["verdict"] == "VOID" else "agents missed tick deadlines")
    return f"run validity: {v['verdict']}, NOT THE HEADLINE ({what}): {head}"


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m ks.validity RUN", file=sys.stderr)
        return 2
    v = run_validity(argv[0])
    if v is None:
        print(f"validity: no readable config.json in {argv[0]}", file=sys.stderr)
        return 2
    line = validity_line(v)
    print(("!! " if v["verdict"] != "OK" else "") + line)
    print(canonical.dumps(v).decode())
    return 0 if v["verdict"] == "OK" else 1


if __name__ == "__main__":
    raise SystemExit(main())
