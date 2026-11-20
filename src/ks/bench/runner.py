"""ks bench runner: one cell = (fault, seed, H, baseline) on the real command path (CALL-02 B2, ADR-06-metrics §4).

``ks run --scenario world --fault F --pause-on-alert`` as a subprocess; at the operator beat (the pause after the
monitor's suspend) the bench approver acts, then the run resumes to T and the scorer runs on the run dir alone.

* ``system``: ``ks recover --dry-run``, ``--apply``, unhold exactly the items the apply lists (X4), resume.
* ``revert_culprit_only`` / ``snapshot``: the baseline plan (oracle-assisted: culprit and t_inject from the spec) goes
  through the same dry-run and the same apply path; nothing is unheld (outbox untouched / cancelled).
* ``no_op``: resume with no recovery.
Same run, same alert, same suspend, same t_rec. S* is cached per (fault, seed, H, T, suspend_tick): identical across
baselines. Deterministic: scores contain no wall clock; timings go to timings.json only."""

from __future__ import annotations

import contextlib
import io
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from ks.contracts import canonical
from ks.inject import make_spec, world_fault

from .agg import render_table

__all__ = ["BASELINES", "run_cell", "bench", "DEFAULT_FAULTS"]

BASELINES = ("system", "snapshot", "revert_culprit_only", "no_op")
DEFAULT_FAULTS = ("F1", "F2", "F2+", "F2+c", "F2+x", "F3", "F4", "F7")
WORLD_FAULTS = DEFAULT_FAULTS  # F5 (forged envelope) and F6 (tamper) are scored by ks verify, not this table


def _cli(*argv: str) -> tuple[int, str]:
    from ks.cli import main
    buf, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
        rc = main(list(argv))
    return rc, buf.getvalue() + err.getvalue()


def _baseline_plan(run: Path, spec, baseline: str) -> str:
    from ks.contracts import RunDir
    from ks.contracts.rundir import STATE_DB
    from ks.contracts import OutboxItem, OutboxStatus
    from ks.recovery import ToolRerunner, args_from_sidestore, dry_run, revert_culprit_only, write_plan
    from ks.world.scenario import open_world_store
    from ks.world.tools import WorldDispatcher
    from .baselines import snapshot_plan
    rd = RunDir(run)
    records = list(rd.records())
    st = open_world_store(run / STATE_DB)
    try:
        if baseline == "revert_culprit_only":
            planned = revert_culprit_only(records, culprit=spec.culprit, t_inject=spec.t_inject).planned
        else:
            held = []
            for obj in st.heads():
                if obj.startswith("outbox:"):
                    v = st.get(obj)
                    if v is not None and v.value is not None and OutboxItem.from_obj(v.value).status == OutboxStatus.HELD:
                        held.append(obj[len("outbox:"):])
            planned = snapshot_plan(records, held, t_inject=spec.t_inject, culprit=spec.culprit)
        dr = dry_run(st, planned, rerunner=ToolRerunner(WorldDispatcher(), args_from_sidestore(run)), on_stale="halt")
    finally:
        st.close()
    write_plan(dr.plan, rd)
    return dr.plan.plan_id


def run_cell(fault: str, seed: int, hold: int, baseline: str, ticks: int, out: Path, *,
             star_cache: dict | None = None, timeout: float = 900, notes_out: list[str] | None = None,
             no_lineage_hold: bool = False) -> dict[str, Any]:
    """Run and score one cell in ``out`` (must not exist). Returns score.json's dict plus nothing else.
    ``notes_out`` receives labels for anything that ran differently from the plan (``no_plan``: the system cell got no
    recovery plan, so it is scored as the pause-only run). ``no_lineage_hold`` (B3-53) runs the D10 contrast cell
    (needs hold 0); its score.json carries ``lineage_hold: false`` and is never aggregated with system cells."""
    from ks.contracts import RunDir
    from ks.runtime.operator import operator_request
    from ks.score import score_run, suspend_tick_of, write_score
    if baseline not in BASELINES:
        raise ValueError(f"unknown baseline {baseline!r}")
    spec = make_spec(world_fault(fault), seed, ticks=ticks)
    p = subprocess.Popen([sys.executable, "-m", "ks", "run", "--scenario", "world", "--fault", fault, "--seed", str(seed),
                          "--ticks", str(ticks), "--hold", str(hold), "--pause-on-alert", "--out", str(out),
                          *(["--no-lineage-hold"] if no_lineage_hold else [])],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True)
    try:
        lines: list[str] = []
        end = time.monotonic() + timeout
        paused = False
        while time.monotonic() < end:
            line = p.stdout.readline()
            if not line:
                break
            lines.append(line)
            if "paused before tick" in line:
                paused = True
                break
        notes: list[str] = []
        if paused:
            unholds: list[str] = []
            applied = False
            if baseline == "system":
                rc, txt = _cli("recover", str(out), "--dry-run")
                m = re.search(r"--apply (p-\d+)", txt)
                if rc != 0 or not m:
                    notes.append("no_plan")  # surfaced below: this cell is scored as pause-only, not as a recovery
                else:
                    rc, txt = _cli("recover", str(out), "--apply", m.group(1))
                    applied = rc == 0
                    if rc != 0:
                        notes.append("apply_failed")
                    unholds = re.findall(r"ks contain unhold outbox:(ob-\d+)", txt)
            elif baseline != "no_op":
                from ks.runtime import recover as R
                try:
                    R.cli_apply(out, _baseline_plan(out, spec, baseline))
                    applied = True
                except Exception as e:  # noqa: BLE001 - recorded, not hidden
                    notes.append(f"baseline_failed:{type(e).__name__}:{e}")
            if applied:  # the apply wakes the run; it pauses again (pacing beat) before the unhold/resume
                while time.monotonic() < end:
                    line = p.stdout.readline()
                    if not line or "paused before tick" in line:
                        break
            for oid in unholds:  # X4: the bench approver releases exactly what the apply listed, before T
                _cli("contain", "unhold", f"outbox:{oid}", str(out))
            if p.poll() is None:
                operator_request(out, {"op": "resume"})
        rest, err = p.communicate(timeout=timeout)
        if notes_out is not None:
            notes_out.extend(n for n in notes if n == "no_plan")
        bad = [n for n in notes if n.startswith(("baseline_failed", "apply_failed"))]
        if bad:  # a baseline that did not run must not be scored as if it had
            raise RuntimeError("; ".join(bad))
        if p.returncode != 0:
            raise RuntimeError(f"ks run exited {p.returncode}: {err[-500:]}")
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
    cfg = RunDir(out).config()
    if cfg.lineage_hold == no_lineage_hold:  # B3-53: contrast cells only on request, system cells never contrast
        raise RuntimeError(f"lineage_hold={cfg.lineage_hold} but no_lineage_hold={no_lineage_hold}")
    stick = suspend_tick_of(out, spec.culprit)
    key = (fault, seed, hold, ticks, stick)
    if star_cache is not None and key in star_cache:
        star = star_cache[key]
    else:
        star = _star(spec, out, stick, hold)
        if star_cache is not None:
            star_cache[key] = star
    s = score_run(out, spec, star, hold=cfg.hold_window_ticks, baseline=baseline)
    write_score(out, s)
    return s


def _star(spec, out: Path, stick, hold):
    from ks.oracle import run_s_star
    return run_s_star(spec, out / "oracle" / "s-star", suspend_tick=stick, hold=hold).effects


def bench(seeds: list[int], faults: list[str], holds: list[int], baselines: list[str], ticks: int, out: Path, *,
          keep_runs: bool = False, log=print, contrast_faults: list[str] | tuple[str, ...] = (),
          contrast_baselines: tuple[str, ...] = ("system", "no_op")) -> dict[str, Any]:
    """Run the whole matrix; per-seed ``score.json`` under ``out/<fault>/h<H>/<baseline>/s<seed>/``, ``bench.json``
    (deterministic summary), ``bench.md`` (tables), ``timings.json`` (wall clock per seed, ms).
    ``contrast_faults``: per fault, one extra ``system`` column at H=0 with ``--no-lineage-hold`` (D10), reported in its
    own ``CONTRAST`` table and under ``contrast_cells`` in bench.json; never mixed into ``cells``."""
    from .agg import aggregate
    out.mkdir(parents=True, exist_ok=True)
    scratch = out / "_runs"
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir()
    cache: dict = {}
    results: dict[tuple[str, int, str], dict[int, dict]] = {}
    timings: dict[str, int] = {}
    failures: list[str] = []
    notes: list[str] = []
    contrast: dict[tuple[str, str], dict[int, dict]] = {}
    for f, cb, seed in [(f, cb, s) for f in contrast_faults for cb in contrast_baselines for s in seeds]:
        if True:
            name = f"{f}/h0/{cb}-contrast-no-lineage-hold/s{seed}"
            t = time.monotonic()
            d = scratch / f"{world_fault(f)}-h0-{cb}-contrast-s{seed}"
            cn: list[str] = []
            try:
                s = run_cell(f, seed, 0, cb, ticks, d, star_cache=cache, notes_out=cn, no_lineage_hold=True)
            except Exception as e:  # noqa: BLE001
                failures.append(f"{name}: {type(e).__name__}: {e}")
                log(f"FAIL {name}: {e}")
                continue
            notes += [f"{name}: {n}" for n in cn]
            timings[name] = int((time.monotonic() - t) * 1000)
            dst = out / "contrast" / f.replace("+", "p") / "h0" / f"{cb}_no_lineage_hold" / f"s{seed}"
            dst.mkdir(parents=True, exist_ok=True)
            shutil.copy(d / "score.json", dst / "score.json")
            if not keep_runs:
                shutil.rmtree(d, ignore_errors=True)
            contrast.setdefault((f, cb), {})[seed] = s
            log(f"ok   {name} {timings[name]} ms")
    for f in faults:
        for h in holds:
            for seed in seeds:
                for b in baselines:
                    name = f"{f}/h{h}/{b}/s{seed}"
                    t = time.monotonic()
                    d = scratch / f"{world_fault(f)}-h{h}-{b}-s{seed}"
                    cn = []
                    try:
                        s = run_cell(f, seed, h, b, ticks, d, star_cache=cache, notes_out=cn)
                    except Exception as e:  # noqa: BLE001 - listed in the summary, never dropped silently
                        failures.append(f"{name}: {type(e).__name__}: {e}")
                        log(f"FAIL {name}: {e}")
                        continue
                    notes += [f"{name}: {n}" for n in cn]
                    ms = int((time.monotonic() - t) * 1000)
                    timings[name] = ms
                    dst = out / f.replace("+", "p") / f"h{h}" / b / f"s{seed}"
                    dst.mkdir(parents=True, exist_ok=True)
                    shutil.copy(d / "score.json", dst / "score.json")
                    if not keep_runs:
                        shutil.rmtree(d, ignore_errors=True)
                    results.setdefault((f, h, b), {})[seed] = s
                    log(f"ok   {name} {ms} ms")
    summary: dict[str, Any] = {"contract": "ks.bench/1", "ticks": ticks, "seeds": seeds, "failures": failures,
                               "notes": notes, "cells": {}, "contrast_cells": {}}
    md = [f"# ks bench: T={ticks} (ADR-06-metrics A4), seeds {seeds[0]}..{seeds[-1]} (n={len(seeds)})\n",
          f"Every number here is at **T={ticks}**; do not compare ratio metrics with T=120. Cells are `median [min..max] k/n` "
          "(k = seeds with a non-null value), next to a p95 column (nearest-rank, 19th of 20; null = never = +inf).\n",
          "- `system`: the product path; its recovery is not told the culprit or t_inject.",
          "- `snapshot` and `revert_culprit_only` are **oracle-assisted**: they are given t_inject and the culprit from the "
          "inject spec, which the system is not. They are upper-bound-style baselines, not products.",
          "- `no_op`: pause (suspend) only, no recovery.",
          "- `collateral_stall` is a **proxy**, basis `s_star` (A3): non-culprit keys outside B whose final_T differs from "
          "S*_T. Real runs have no unmirrored S0.",
          "- `tti_*`/`ttc` for a denied or held bad action (F3: scope alert on a denied pii egress) follow ADR-06-metrics A5: "
          "first alert naming the culprit, measured from the bad action.\n"]
    for f in faults:
        for h in holds:
            cells = {b: [results[(f, h, b)][s] for s in sorted(results.get((f, h, b), {}))] for b in baselines
                     if (f, h, b) in results}
            if not cells:
                continue
            summary["cells"][f"{f}/h{h}"] = {b: aggregate(v) for b, v in cells.items()}
            md.append(render_table(f"{f}, H={h}, T={ticks}", cells))
    for f in contrast_faults:
        c = {f"{cb} (CONTRAST: no lineage hold)": [contrast[(f, cb)][s] for s in sorted(contrast[(f, cb)])]
             for cb in contrast_baselines if (f, cb) in contrast}
        if c:
            summary["contrast_cells"][f"{f}/h0"] = {k: aggregate(v) for k, v in c.items()}
            md.append(render_table(f"CONTRAST (D10, not a security result), {f}, H=0, T={ticks}", c))
    if notes:
        md.append("## notes (cells scored as run, not as planned)\n\n" + "\n".join(f"- {x}" for x in notes) + "\n")
    if failures:
        md.append("## failures\n\n" + "\n".join(f"- {x}" for x in failures) + "\n")
    (out / "bench.json").write_bytes(canonical.dumps_line(summary))
    (out / "bench.md").write_text("\n".join(md))
    (out / "timings.json").write_bytes(canonical.dumps_line({"ms": timings, "total_ms": sum(timings.values())}))
    shutil.rmtree(scratch, ignore_errors=True)
    return summary
