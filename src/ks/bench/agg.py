"""Aggregation (ADR-06-metrics §4): integers only, no means. Sort ascending, ratios as rationals by
cross-multiplication, ``null`` = +inf; median = nearest-rank lower (10th of 20), p95 = 19th of 20, max last.
A statistic whose rank lands on ``null`` is ``null``. Reported with k/N non-null."""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from fractions import Fraction
from typing import Any

__all__ = ["METRICS", "flatten", "aggregate", "render_table", "rank"]

METRICS = ("tti_detect", "tti_attribute", "ttc", "post_alert_tainted_effects", "irreversible_tainted_released", "R", "C",
           "c_culprit_window", "reemitted", "false_accusations", "fp_cost.honest_suspensions", "fp_cost.stall_ticks",
           "fp_cost.held_honest_actions", "fp_cost.operator_unholds.total", "fp_cost.operator_unholds.honest",
           "fp_cost.operator_unholds.tainted", "damage_in_window", "exposure", "collateral_stall",
           "kept_without_redo", "revert_precision", "revert_recall")


def _val(x: Any) -> Fraction | None:
    """int -> itself; {"n","d"} -> n/d (d=0 -> 0); null / {"unavailable"} / anything else -> None."""
    if isinstance(x, bool) or x is None:
        return None
    if isinstance(x, int):
        return Fraction(x)
    if isinstance(x, Mapping) and "n" in x and "d" in x:
        return Fraction(x["n"], x["d"]) if x["d"] else Fraction(0)
    return None


def flatten(score: Mapping[str, Any]) -> dict[str, Fraction | None]:
    out: dict[str, Fraction | None] = {}
    for m in METRICS:
        cur: Any = score
        for part in m.split("."):
            cur = cur.get(part) if isinstance(cur, Mapping) else None
        out[m] = _val(cur)
    return out


def rank(n: int, which: str) -> int:
    """0-based index into the ascending sort: median = (n-1)//2 (10th of 20), p95 = ceil(0.95 n)-1 (19th of 20)."""
    return {"median": (n - 1) // 2, "p95": math.ceil(n * 95 / 100) - 1, "max": n - 1, "min": 0}[which]


def _stat(vals: Sequence[Fraction | None], which: str) -> Fraction | None:
    if not vals:
        return None
    inf = sorted(vals, key=lambda v: (v is None, v if v is not None else 0))
    return inf[rank(len(vals), which)]


def _fmt(v: Fraction | None) -> str:
    if v is None:
        return "null"
    return str(v.numerator) if v.denominator == 1 else f"{v.numerator}/{v.denominator}"


def aggregate(scores: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, str | int]]:
    """metric -> {min, median, p95, max, k, n} (strings for values: exact rationals, no floats)."""
    rows = [flatten(s) for s in scores]
    out: dict[str, dict[str, str | int]] = {}
    for m in METRICS:
        vals = [r[m] for r in rows]
        out[m] = {"min": _fmt(_stat(vals, "min")), "median": _fmt(_stat(vals, "median")),
                  "p95": _fmt(_stat(vals, "p95")), "max": _fmt(_stat(vals, "max")),
                  "k": sum(v is not None for v in vals), "n": len(vals)}
    return out


def render_table(title: str, cells: Mapping[str, Sequence[Mapping[str, Any]]], metrics: Sequence[str] = METRICS) -> str:
    """One table: a row per metric; per baseline two columns, ``median [min..max] k/n`` and ``p95`` (19th of 20)."""
    aggs = {b: aggregate(s) for b, s in cells.items()}
    # B3-53: a contrast cell (any score.json with lineage_hold == false) is marked in its column header
    labels = [b + (" [CONTRAST: NO-LINEAGE-HOLD]" if any(x.get("lineage_hold") is False for x in cells[b]) else "")
              for b in cells]
    names = list(cells)
    head = " | ".join(f"{lab} | {lab} p95" for lab in labels)
    lines = [f"### {title}", "", "| metric | " + head + " |", "|---|" + "---|---|" * len(names)]
    for m in metrics:
        cols = []
        for b in names:
            a = aggs[b][m]
            cols += [f"{a['median']} [{a['min']}..{a['max']}] {a['k']}/{a['n']}", str(a["p95"])]
        lines.append(f"| {m} | " + " | ".join(cols) + " |")
    return "\n".join(lines) + "\n"
