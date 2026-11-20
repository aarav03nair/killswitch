"""``ks console RUN --live [--once] [--pace]``: read-only terminal view that tails the run dir (ADR-07 §4).

``--pace`` stops at each beat boundary (break, identify, contain, recover, audit) until a keypress (Enter).
Pacing of the *run* itself is ``ks run --pause-at/--step`` (ks.runtime.RunOptions); this view never writes.
"""
from __future__ import annotations

import sys
import time

from .model import BEAT_SECONDS, BEATS, build_model

__all__ = ["frame", "beat_frame", "run_live", "beat_ticks"]


def _banners(m: dict) -> list[str]:
    v = m["verify"]
    out = ["!! " + b["text"] for b in m["banners"]]
    out.append(f"verify: {'OK' if v['ok'] else 'FAILED ' + v['reason']}; tamper-evident up to the last witnessed head "
               f"(seq {v['last_witnessed_seq']}); {'anchored' if v['anchored'] else 'not anchored'}")
    return out


def frame(run) -> str:
    m = build_model(run)
    recs = m["records"]
    L = _banners(m) + [f"run {m['run_id']}  records {len(recs)}  ticks {len(m['ticks'])}  (read-only)", "agents:"]
    suspended = {r["control"]["target"].split(":", 1)[1] for r in m["controls"] if r["control"]["op"] == "suspend"}
    last: dict = {}
    for r in recs:
        if r["agent"] and not r["agent"].startswith("ks."):
            last[r["agent"]] = r
    for a in sorted(last):
        r = last[a]
        L.append(f"  {a:<11} {'SUSPENDED' if a in suspended else 'running':<9} tick {r['tick']:>3} {r['tool']} [{r['decision']}]")
    L.append("alerts: " + (", ".join(f"{a['alert_id']} {a['detector']}" for a in m["alerts"]) or "none"))
    L.append(f"held items: {len(m['held'])}" + "".join(f"\n  seq {h['seq']} {h['agent']} {h['tool']} ({h['reason']})" for h in m["held"][-5:]))
    L.append("recent records:")
    L += [f"  {r['seq']:>4} t{r['tick']:<3} {r['agent']} {r['tool']} {r['decision']}/{r['reason']}" for r in recs[-6:]]
    return "\n".join(L)


def beat_frame(m: dict, i: int) -> str:
    b, (_, title, sub) = m["beats"][i], BEATS[i]
    head = f"== Beat {i + 1}/5 {title.upper()} ({BEAT_SECONDS[i]}s) [{b['status'].upper()}] =="
    body = ["  " + x for x in b["lines"]]
    if b.get("plan"):
        body += ["  plan steps:"] + [f"    {s['n']}. {s['text']}" + (f" [{s['reason']}]" if s.get("reason") else "") for s in b["plan"]["steps"]]
        body += ["  dry-run diff (hashes only):"] + [f"    {d['obj']}: now v{d['current']} -> {d['planned_hash']}" for d in b["plan"]["diff"]]
    if b["id"] == "recover":
        body += ["  " + x for x in scorecard_lines(m)]
    if b["id"] == "audit" and b.get("first_bad") is not None:
        body.append(f"  first bad index: {b['first_bad']} ({b['reason']})")
    return "\n".join([head] + body)


def scorecard_lines(m: dict) -> list[str]:
    sc = m.get("scorecard")
    if not sc:
        return ["scorecard: not run (no score.json; ks score RUN)"]
    out = ["scorecard (" + " | ".join(sc["columns"]) + "):"]
    out += [f"  {r['label']}: " + " | ".join(r["cells"]) for r in sc["rows"]]
    if sc["hold_note"]:
        out.append(sc["hold_note"])
    return out


def beat_ticks(run) -> list[int | None]:
    """Tick of each beat in this run (None where the run has no data yet): feed these to ``ks run --pause-at``."""
    return [b["tick"] for b in build_model(run)["beats"]]


def run_live(run, *, once: bool = False, pace: bool = False, out=None, wait=None, interval: float = 1.0) -> int:
    out = out or sys.stdout
    wait = wait or (lambda prompt: input(prompt))
    if pace:
        m = build_model(run)
        print("\n".join(_banners(m)), file=out)
        for i in range(len(BEATS)):
            print(beat_frame(m, i), file=out)
            if i < len(BEATS) - 1:
                try:
                    wait(f"-- Enter for beat {i + 2} ({BEATS[i + 1][1]}) --")
                except EOFError:
                    break
        return 0
    print(frame(run), file=out)
    while not once:
        time.sleep(interval)
        print("\n" + frame(run), file=out)
    return 0
