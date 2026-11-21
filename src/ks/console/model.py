"""Console model (ADR-07 §4, B3-28): everything the page and the live terminal view show, read from a run dir.

Read-only: opens record, witness, alerts, plans, score, baselines, config and timing.jsonl (S4-22: the
deadline-miss count only); never imports gateway or signer
code and never opens the operator socket. Build-time ``verify`` result is embedded; no wall-clock time, so the
same run dir gives the same model. Owner: ishaan.
"""
from __future__ import annotations

import json
from pathlib import Path

from ks.contracts.rundir import NO_LINEAGE_HOLD_BANNER, resolver_label
from ks.validity import run_validity, validity_line

__all__ = ["BEATS", "BEAT_SECONDS", "HERO_FIXTURE", "LABELS", "build_model", "label"]

# (id, title, TERMS-wording subtitle). Order is the finale script (zoya §4, ADR-07 §4).
BEATS = (("break", "Break", "crm changed a supplier's bank account"),
         ("identify", "Identify", "alert and ranked root candidates"),
         ("contain", "Contain", "crm suspended; payment and email held"),
         ("recover", "Recover", "dry-run diff, four lanes"),
         ("audit", "Audit", "verify; tamper-evident up to the last witnessed head"))
BEAT_SECONDS = (40, 60, 60, 100, 40)  # sums to 300 s: the 5-minute finale on the hero seed

# One banking-label table (ADR-07 §4). Suffix or full object id -> label.
LABELS = {".iban": "bank account (IBAN)", ".price": "price", ".risk_note": "risk note"}
HERO_LINE = "triage edited the same supplier; we kept its edit and restored only the bank account"

# Shaped like the contracts (Alert C4, Control C4, RecoveryPlan C5). Shown only as "pending", never as run data.
HERO_FIXTURE = {
    "alert": {"alert_id": "a-000001", "detector": "inv.iban_checksum", "kind": "invariant", "hard": True,
              "tick": 0, "seq": 0, "evidence_seqs": [], "root_candidates": ["crm"]},
    "control": {"op": "suspend", "target": "agent:crm", "auto": True, "issued_by": "ks.monitor"},
    "held": ["payments.send (lineage hold)", "comms.send_email (lineage hold)"],
    "lanes": {"restore": ["suppliers:S-17.iban", "suppliers:S-22"],
              "rerun": ["billing", "payments", "comms"],
              "kept": ["triage: suppliers risk note"],
              "independent": ["inventory", "docs"]},
}


def label(obj: str) -> str:
    for suf, name in LABELS.items():
        if obj.endswith(suf):
            return f"{name} of {obj[:-len(suf)].split(':')[-1]}"
    return obj


def fmt_metric(v) -> str:
    """One score.json value as text. ``{"unavailable": why}`` is shown as unavailable, never 0 (ADR-06 §3);
    ``None`` means it never happened; ``{"n","d"}`` is a ratio."""
    if isinstance(v, dict):
        if "unavailable" in v:
            return f"unavailable ({v['unavailable']})"
        if set(v) == {"n", "d"}:
            return f"{v['n']}/{v['d']}"
        return ", ".join(f"{k} {fmt_metric(x)}" for k, x in v.items())
    if v is None:
        return "never happened"
    if isinstance(v, bool):
        return "yes" if v else "no"
    return str(v)


SCORE_ROWS = (("tti_detect", "time to identify: detect (ticks)"), ("tti_attribute", "time to identify: attribute (ticks)"),
              ("ttc", "time to contain (ticks)"), ("R", "residual damage R"), ("C", "collateral loss C"),
              ("irreversible_tainted_released", "irreversible tainted effects released"), ("clean", "clean recovery"))
BASELINE_COLUMNS = ("snapshot", "revert_culprit_only")


def _scorecard(score, base: dict, lineage_hold: bool = True):
    """TTI/TTC/R/C of this run next to each baseline, straight from score.json files (nothing computed here).
    A missing file is "not run"; a metric key a file lacks is "unavailable (not in score.json)"."""
    if not isinstance(score, dict):
        return None
    cols = [("system", score)] + [(n, base.get(n)) for n in BASELINE_COLUMNS] + \
           [(n, b) for n, b in base.items() if n not in BASELINE_COLUMNS]
    rows = []
    for k, name in SCORE_ROWS:
        rows.append({"key": k, "label": name, "cells": [
            "not run" if c is None else (fmt_metric(c[k]) if k in c else "unavailable (not in score.json)") for _, c in cols]})
    hold = score.get("hold")
    irr, r = score.get("irreversible_tainted_released"), score.get("R")
    note = None
    if hold == 0:
        # "no lineage hold" only when the run config turned the lineage hold off (D10 contrast); else H=0 is the window.
        why = "H=0 (no lineage hold)" if lineage_hold is False else "H=0 (hold window 0 ticks; lineage hold on)"
        if isinstance(irr, int) and not isinstance(irr, bool) and irr > 0:
            note = f"{why}: {irr} tainted irreversible effect(s) escaped, counted as residual damage R = {fmt_metric(r)}"
        else:
            note = f"{why}: residual damage R = {fmt_metric(r)}; irreversible tainted effects released = {fmt_metric(irr)}"
    fp = score.get("fp_cost")
    un = fp.get("operator_unholds") if isinstance(fp, dict) else None
    ha = fp.get("held_honest_actions") if isinstance(fp, dict) else None
    if isinstance(un, dict) and all(k in un for k in ("total", "honest", "tainted")):
        # D-17: every R = 0 is stated together with what the operator released; tainted = recovery re-holds, clean payloads
        releases = (f"operator released {un['total']} held item(s): {un['honest']} honest, {un['tainted']} tainted "
                    f"(recovery re-holds); honest actions held: {fmt_metric(ha) if ha is not None else 'unavailable (not in score.json)'}")
    else:
        releases = "operator releases: unavailable (no fp_cost.operator_unholds in score.json)"
    return {"columns": [n for n, _ in cols], "rows": rows, "hold": hold, "hold_note": note, "releases": releases,
            "operator_unholds": un, "held_honest_actions": ha,
            "oracle_assisted": [n for n, c in cols if isinstance(c, dict) and c.get("baseline_oracle_assisted")]}



def _plan_view(plan: dict, recs: list[dict]) -> dict:
    """Plan file as the dry-run wrote it: one line per step (restore/rerun/cancel/flag/replan), the hash-only diff,
    t0 and its delta, and how many ks.recover.<op> records the run holds for it (0 = nothing applied)."""
    steps = []
    for s in plan.get("steps") or []:
        op, a = s["op"], s.get("action") or {}
        if op == "restore":
            txt = f"restore {label(s['obj'])} ({s['obj']}) to " + ("deleted (tombstone)" if s.get("to") is None else f"v{s['to']['ver']}")
        elif op in ("rerun", "replan"):
            txt = f"{op} {a.get('agent_id')} action {a.get('action_id')} (seq {a.get('seq')})"
        elif op == "cancel_outbox":
            txt = f"cancel outbox {s['outbox_id']}"
        elif op == "flag":
            txt = "flag for a person: " + (s.get("obj") or (f"action {a.get('action_id')}" if a else "?"))
        elif op == "resolve":  # S4-13 (D-18, ADR-05a §7)
            rb = s.get("rebased") or {}
            txt = (f"resolve {label(s['obj'])} ({s['obj']}, {s.get('rule')}/{s.get('rule_version')}): "
                   f"v{s['culprit_ver']['ver']} reverted, {rb.get('agent_id')} edit rebased on v{s['to']['ver']} -> "
                   f"{str(s.get('rebased_hash'))[:8]}; unblocked {', '.join(s.get('unblocked') or []) or '-'}; "
                   f"checks {','.join(s.get('rationale') or [])}; undo: ks recover RUN --unresolve "
                   f"{plan.get('plan_id')}.{s['n']}")
        elif op == "unresolve":
            r0 = (s.get("reverts") or [{}])[0]
            txt = (f"unresolve {(s.get('resolution') or {}).get('action_id')}: {r0.get('obj')} back to "
                   f"v{(r0.get('to') or {}).get('ver')}, flag raised again; re-held "
                   f"{', '.join(s.get('reheld') or []) or '-'}")
        else:
            txt = f"{op} {a.get('action_id', '')}".strip()
        steps.append({"n": s["n"], "op": op, "reason": s.get("reason"), "text": txt})
    diff = [{"obj": d["obj"], "label": label(d["obj"]), "current": (d.get("current") or {}).get("ver"),
             "planned_hash": str(d.get("planned_hash"))[:16]} for d in plan.get("diff") or []]
    lit, t0 = plan.get("t0_seq_est_literal"), plan.get("t0_seq_est")
    applied = sum(1 for r in recs if (r["tool"] or "").startswith("ks.recover.") and r["decision"] == "exec")
    return {"plan_id": plan.get("plan_id"), "steps": steps, "diff": diff, "t0": t0, "t0_literal": lit,
            "t0_delta": None if lit is None or t0 is None else t0 - lit, "applied_records": applied}


def _jl(p: Path) -> list[dict]:
    if not p.is_file():
        return []
    out = []
    try:
        lines = p.read_text(errors="replace").splitlines()
    except OSError:
        return []
    for x in lines:  # malformed lines are skipped: verify names the first bad one, the page shows the rest
        try:
            o = json.loads(x) if x.strip() else None
        except ValueError:
            continue
        if isinstance(o, dict):
            out.append(o)
    return out


def _jf(p: Path):
    """Parsed JSON file, or None if absent or malformed (rendered as not run / pending, never a crash)."""
    try:
        return json.loads(p.read_text()) if p.is_file() else None
    except (ValueError, OSError):
        return None


def _verify(run: Path) -> dict:
    from ks.verify import verify
    try:
        rep = verify(run, None, log=lambda s: None)
        return json.loads(rep.to_canonical())
    except Exception as e:  # noqa: BLE001 - verify must never take the page down
        return {"ok": False, "reason": "parse_error", "first_bad": None, "last_witnessed_seq": None,
                "anchored": False, "unanchored_reason": "verify_crashed", "detail": str(e)[:200]}


def _side(run: Path, env: dict):
    """Body of a record's args from the side store, checked against its args_hash (None if unreadable/forged)."""
    from ks.contracts.hashing import args_hash
    from ks.contracts.rundir import sidestore_relpath
    try:
        p = run / sidestore_relpath(env["args_hash"])
        entry = json.loads(p.read_text())
        body = entry.get("value")
        if entry.get("redacted") or not isinstance(body, dict) or args_hash(body) != env["args_hash"]:
            return None
        return body
    except Exception:  # noqa: BLE001 - unreadable is skipped, never guessed
        return None


def _chained_alerts(run: Path, raw: list[dict]) -> list[dict]:
    """Executed ks.alert records signed by ks.monitor (sig_ok): body from the side store, parsed with C4 Alert.
    alerts.jsonl is never read (unauthenticated copy), as ks.score."""
    from ks.contracts.control import Alert
    out = []
    for r in raw:
        env = r.get("envelope")
        if not env or env.get("tool") != "ks.alert" or r["decision"] != "exec":
            continue
        if not r.get("sig_ok") or env.get("agent_id") != "ks.monitor":
            continue
        body = _side(run, env)
        if body is None:
            continue
        try:
            a = Alert.from_obj(body).to_obj()
        except Exception:  # noqa: BLE001
            continue
        out.append({**a, "record_seq": r["seq"], "record_tick": r["tick"]})
    return out


def _approvals(run: Path, raw: list[dict]) -> list[dict]:
    out = []
    for r in raw:
        env = r.get("envelope")
        if not env or env.get("tool") != "ks.approve" or r["decision"] != "exec" or not r.get("sig_ok"):
            continue
        if env.get("agent_id") != "ks.operator":
            continue
        body = _side(run, env)
        if body and body.get("plan_hash"):
            out.append({"seq": r["seq"], "plan_id": body.get("plan_id"), "plan_hash": body["plan_hash"]})
    return out


def _plan_hash(plan: dict):
    try:
        from ks.contracts.recovery import RecoveryPlan
        return RecoveryPlan.from_obj(plan).content_hash()
    except Exception:  # noqa: BLE001
        return None


def _rec(r: dict) -> dict:
    env = r.get("envelope") or {}
    ctl = r.get("control")
    return {"seq": r["seq"], "reads": [w["obj"] for w in r.get("read_set") or []],
            "sig_ok": bool(r.get("sig_ok")), "tick": r["tick"], "agent": env.get("agent_id"), "tool": env.get("tool"),
            "decision": r["decision"], "reason": r["reason"], "cls": r["action_class"],
            "writes": [w["obj"] for w in r.get("write_set") or []],
            "outbox": list(r.get("outbox_ids") or []), "rule": r.get("policy_rule"),
            "control": None if not ctl else {k: ctl.get(k) for k in ("op", "target", "auto", "issued_by", "alert_id", "reason")}}


def _holds(recs: list[dict]) -> list[dict]:
    """Holds as the gateway records them (B3-23): executed ks.control op=hold on target outbox:<id> (reason
    lineage_hold | sensitive_field); the item's tool and agent come from the record that created the outbox id."""
    made = {}
    for r in recs:
        for o in r["outbox"]:
            made.setdefault(o, r)
    out = []
    for r in recs:
        c = r["control"]
        if c and c["op"] == "hold" and r["decision"] == "exec" and str(c["target"]).startswith("outbox:"):
            oid = c["target"].split(":", 1)[1]
            src = made.get(oid)
            out.append({"seq": r["seq"], "tick": r["tick"], "outbox": oid, "reason": c.get("reason") or r["reason"],
                        "agent": src["agent"] if src else None, "tool": src["tool"] if src else None,
                        "created_seq": src["seq"] if src else None, "unwitnessed": r.get("unwitnessed", False)})
    return out


def _lanes(plan: dict, recs: list[dict]) -> dict:
    """Four lanes from a plan and the record: restore and re-run come from steps; kept = honest, untainted
    writes on a restored object's row after t0; independent = other untainted agents active after t0."""
    steps = plan.get("steps") or []
    restore = [s["obj"] for s in steps if s["op"] == "restore"]
    rerun = sorted({s["action"]["agent_id"] for s in steps if s["op"] == "rerun"})
    tainted = {a["seq"] for a in (plan.get("taint_set") or {}).get("actions", [])}
    rows = {o.split(".")[0] for o in restore}
    t0, culprit = plan.get("t0_seq_est", 0), plan.get("culprit")
    kept, indep_agents, kept_agents = [], set(), set()
    for r in recs:
        if r["seq"] <= t0 or r["seq"] in tainted or r["agent"] in (culprit, None) or r["agent"].startswith("ks."):
            continue
        hit = [w for w in r["writes"] if w.split(".")[0] in rows]
        if hit and r["decision"] == "exec":
            if "." in hit[0]:
                kept.append(f"{r['agent']}: {label(hit[0])}")
            else:  # row-level write: name the field from the tool (set_risk_note -> risk note)
                fld = (r["tool"] or "").split(".")[-1].removeprefix("set_").replace("_", " ")
                kept.append(f"{r['agent']}: {fld} of {hit[0].split(':')[-1]}")
            kept_agents.add(r["agent"])
        else:
            indep_agents.add(r["agent"])
    indep = sorted(indep_agents - kept_agents - set(rerun))
    return {"restore": [label(o) + f" ({o})" for o in restore], "rerun": rerun,
            "kept": sorted(set(kept)), "independent": indep,
            "flags": sum(1 for s in steps if s["op"] == "flag"),
            "replan": [s["n"] for s in steps if s["op"] == "replan"],
            "cancel": [s["outbox_id"] for s in steps if s["op"] == "cancel_outbox"]}


def build_model(run) -> dict:
    run = Path(run)
    cfg = _jf(run / "config.json") or {}
    verify = _verify(run)
    raw = _jl(run / "record.jsonl")
    recs = []
    for r in raw:
        try:
            recs.append(_rec(r))
        except Exception:  # noqa: BLE001 - record missing required fields: skipped, verify reports it
            continue
    raw = [r for r in raw if isinstance(r.get("seq"), int)]
    lw = verify.get("last_witnessed_seq")
    for r in recs:
        # a failed verify stops at first_bad: last_witnessed_seq is then where verify stopped, not what the witness signed
        r["unwitnessed"] = bool(verify.get("ok")) and (lw is None or r["seq"] > lw)
    alerts = _chained_alerts(run, raw)
    appr = _approvals(run, raw)
    plans = [_jf(p) for p in sorted((run / "plans").glob("*.json"))] if (run / "plans").is_dir() else []
    plans = [p for p in plans if isinstance(p, dict)]
    for p in plans:
        h = _plan_hash(p)
        p["_plan_hash"] = h
        p["_approved"] = bool(h) and any(a["plan_hash"] == h for a in appr)
    score = _jf(run / "score.json")
    base = {}
    if (run / "baselines").is_dir():
        for d in sorted((run / "baselines").iterdir()):
            if (d / "score.json").is_file():
                base[d.name] = _jf(d / "score.json")
    controls = [r for r in recs if r["control"]]
    suspends = [r for r in controls if r["control"]["op"] == "suspend" and r["control"]["target"].startswith("agent:")]
    held = _holds(recs)
    ticks = {}
    for r in recs:
        t = ticks.setdefault(r["tick"], {"tick": r["tick"], "n": 0, "agents": {}})
        t["n"] += 1
        if r["agent"]:
            t["agents"][r["agent"]] = t["agents"].get(r["agent"], 0) + 1
    banners = []
    if "degraded" in (cfg.get("isolation"), verify.get("isolation")):
        banners.append({"kind": "isolation", "text": "DEGRADED ISOLATION: per-agent attribution is VOID for this run"})
    if cfg.get("key_mode") == "repro":
        banners.append({"kind": "repro", "text": "NOT A SECURITY RUN: repro keys are never anchored; determinism check only"})
    if cfg.get("lineage_hold", True) is False or verify.get("lineage_hold", True) is False:  # contracts 1.6, B3-51
        banners.append({"kind": "contrast", "text": NO_LINEAGE_HOLD_BANNER})
    validity = run_validity(run)  # S4-22: deadline-miss count from timing.jsonl (a count, never a wall-clock value)
    if validity is not None and validity["deadline_misses"] != 0:
        n = validity["deadline_misses"]
        banners.append({"kind": "deadline", "text": "DEGRADED RUN: " + (
            "no timing.jsonl, deadline misses unknown" if n is None else f"{n} tick deadline misses (timing.jsonl)")
            + "; agents no-op'd, so this run is not the headline"})
    if not verify["ok"]:
        banners.append({"kind": "verify", "text": f"VERIFY FAILED: {verify['reason']}"
                        + (f" at seq {verify['first_bad']}" if verify.get("first_bad") is not None else "")})
    m = {"run_id": cfg.get("run_id"), "config": {**{k: cfg.get(k) for k in (
            "run_id", "scenario", "seed", "ticks", "fault", "culprit", "fault_tick", "hold_window_ticks",
            "isolation", "key_mode", "agents", "contracts_version")}, "lineage_hold": cfg.get("lineage_hold", True)},
         "verify": verify, "banners": banners, "records": recs, "alerts": alerts, "plans": plans,
         "approvals": [a["seq"] for a in appr], "score": score, "baselines": base,
         "ticks": [ticks[k] for k in sorted(ticks)], "held": held, "controls": controls,
         "scorecard": _scorecard(score, base, cfg.get("lineage_hold", True)),
         "beat_seconds": list(BEAT_SECONDS), "hero_line": HERO_LINE, "fixture": HERO_FIXTURE,
         "resolver_label": resolver_label(cfg.get("resolver", "off")),
         "validity": validity, "validity_line": validity_line(validity)}  # S4-13 (ADR-05a §7): always shown
    m["beats"] = _beats(m, suspends, held)
    return m


def _beats(m: dict, suspends: list[dict], held: list[dict]) -> list[dict]:
    recs, alerts, plans, v = m["records"], m["alerts"], m["plans"], m["verify"]
    live = "live" if v["ok"] else "unverified"  # on a failed verify no data beat is LIVE: record is not trusted
    sens = [r for r in recs if any(w.endswith(".iban") for w in r["writes"]) and r["agent"] and not r["agent"].startswith("ks.")]
    pend = "PENDING in this run: fixture shaped like the contracts, not run data"
    out = []
    # 1 break
    ev = {q for a in alerts for q in a["evidence_seqs"]}
    sens = [r for r in sens if r["seq"] in ev] + [r for r in sens if r["seq"] not in ev] if ev else sens
    if (m["config"].get("fault") or alerts) and sens:
        r = sens[0]
        rows = {w.split(".")[0] for w in r["writes"] if w.endswith(".iban")}
        readers = sorted({x["agent"] for x in recs if x["seq"] > r["seq"] and x["agent"] and x["agent"] != r["agent"]
                          and not x["agent"].startswith("ks.") and any(o.split(".")[0] in rows for o in x["reads"])})
        out.append({"id": "break", "status": live, "tick": r["tick"], "seq": r["seq"],
                    "lines": [f"{r['agent']} changed {label(w)} (seq {r['seq']}, tick {r['tick']})" for w in r["writes"] if w.endswith(".iban")]
                    + ["read afterwards by: " + (", ".join(readers) or "no other agent")]})
    else:
        out.append({"id": "break", "status": "pending", "tick": None, "seq": None,
                    "lines": [pend, "crm changed a supplier's bank account (suppliers:S-17.iban)",
                              "billing, payments and comms read it; inventory and docs are independent"]})
    # 2 identify
    if alerts:
        a = alerts[0]
        out.append({"id": "identify", "status": live, "tick": a["tick"], "seq": a["record_seq"],
                    "lines": [f"alert {a['alert_id']}: {a['detector']} ({'hard' if a['hard'] else 'soft'}) at tick {a['tick']}"
                              f" (chained ks.alert, record seq {a['record_seq']})",
                              "root candidates: " + (", ".join(a["root_candidates"]) or "none named"),
                              f"first bad action: seq {a['evidence_seqs'][0]}" if a["evidence_seqs"] else "no evidence seq"]})
    else:
        f = HERO_FIXTURE["alert"]
        out.append({"id": "identify", "status": "pending", "tick": None, "seq": None,
                    "lines": [pend, f"alert {f['alert_id']}: {f['detector']} (hard)",
                              "root candidates: " + ", ".join(f["root_candidates"]) + " (crm first)"]})
    # 3 contain
    if suspends:
        s = suspends[0]
        tgt = s["control"]["target"].split(":", 1)[1]
        after = [r for r in recs if r["agent"] == tgt and r["seq"] > s["seq"] and r["decision"] == "exec"]
        lines = [f"{tgt} suspended at seq {s['seq']} ({'auto' if s['control']['auto'] else 'operator'}, by {s['control']['issued_by']})",
                 f"held items: {len(held)}" + "".join(f"; {h['outbox']} {h['tool'] or ''} ({h['reason']})" for h in held[:4]),
                 f"{tgt} writes after suspend: {sum(1 for r in after if r['writes'])} (target 0)",
                 "agents still running: " + ", ".join(sorted({r['agent'] for r in recs if r['seq'] > s['seq'] and r['agent'] and r['agent'] != tgt and not r['agent'].startswith('ks.')}))]
        out.append({"id": "contain", "status": live, "tick": s["tick"], "seq": s["seq"], "lines": lines})
    else:
        f = HERO_FIXTURE
        out.append({"id": "contain", "status": "pending", "tick": None, "seq": None,
                    "lines": [pend, "crm suspended (auto, hard alert)"] + ["held: " + h for h in f["held"]]
                    + ["independent agents still running; crm writes after suspend: 0 (target)"]})
    # 4 recover
    if plans:
        p = plans[-1]
        ln = _lanes(p, recs)
        appr = p.get("_approved")
        src = ("approved: ks.approve matches plan_hash" if appr else "dry-run file, not in the record (no matching ks.approve)")
        if p.get("_plan_hash") is None:
            src = "dry-run file, not in the record; plan_hash not recomputable"
        lines = [f"plan {p['plan_id']} for alert {p['alert_id']} (culprit {p['culprit']}); plan_hash "
                 + (p["_plan_hash"][:16] if p.get("_plan_hash") else "unknown") + ": " + src,
                 "restore: " + "; ".join(ln["restore"]), "re-run: " + ", ".join(ln["rerun"]),
                 "kept: " + ("; ".join(ln["kept"]) or "none"), "independent: " + ", ".join(ln["independent"]),
                 f"flag items: {ln['flags']}",
                 ("replan queue: approved" if appr else "replan queue: awaiting approval") if ln["replan"] else "replan queue: empty"]
        pv = _plan_view(p, recs)
        lines.append(f"t0 estimate: seq {pv['t0']}; literal walk: " + ("not set" if pv["t0_literal"] is None else f"seq {pv['t0_literal']}")
                     + ("" if not pv["t0_delta"] else f"; delta {pv['t0_delta']}: suspect writes reached only through view self-reads are not in the seed, widen it"))
        lines.append(f"applied: {pv['applied_records']} ks.recover record(s) in the record" if pv["applied_records"] else "applied: nothing yet")
        out.append({"id": "recover", "status": live, "tick": None, "seq": p["as_of_seq"], "lines": lines, "lanes": ln,
                    "plan": pv, "approved": bool(appr)})
    else:
        f = HERO_FIXTURE["lanes"]
        out.append({"id": "recover", "status": "pending", "tick": None, "seq": None,
                    "lines": [pend, "restore: " + ", ".join(f["restore"]), "re-run: " + ", ".join(f["rerun"]),
                              "kept: " + ", ".join(f["kept"]), "independent: " + ", ".join(f["independent"]),
                              "flag items: 0", HERO_LINE],
                    "lanes": {k: f[k] for k in ("restore", "rerun", "kept", "independent")} | {"flags": 0, "replan": [], "cancel": []}})
    if not v["ok"]:
        for b in out:
            if b["status"] == "unverified":
                b["lines"].insert(0, "UNTRUSTED: verify failed, this beat is read from a record that did not verify")
    # 5 audit
    lw = v["last_witnessed_seq"]
    if v["ok"]:
        head = f"verify OK; tamper-evident up to the last witnessed head (seq {lw})"
    else:
        fb = v.get("first_bad")
        head = (f"verify FAILED: {v['reason']}" + (f" at first bad seq {fb}" if fb is not None else "")
                + "; verify stopped there, later records were not checked (no witnessed-head claim is made)")
    lines = [head,
             "anchored: yes" if v["anchored"] else f"not anchored ({v['unanchored_reason']}); live proof: ks verify RUN --head ANCHOR",
             "build-time result: stale until the page is rebuilt"]
    n_unw = sum(1 for r in recs if r.get("unwitnessed"))
    if v["ok"] and n_unw:
        lines.append(f"{n_unw} record(s) after the last witnessed head (seq {lw}) are unwitnessed")
    out.append({"id": "audit", "status": "live" if v["ok"] else "fail", "tick": None, "seq": lw, "lines": lines,
                "first_bad": v.get("first_bad"), "reason": v.get("reason")})
    return out
