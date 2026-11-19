"""Console model (ADR-07 §4, B3-28): everything the page and the live terminal view show, read from a run dir.

Read-only: opens record, witness, alerts, plans, score, baselines and config; never imports gateway or signer
code and never opens the operator socket. Build-time ``verify`` result is embedded; no wall-clock time, so the
same run dir gives the same model. Owner: ishaan.
"""
from __future__ import annotations

import json
from pathlib import Path

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


def _jl(p: Path) -> list[dict]:
    if not p.is_file():
        return []
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()]


def _jf(p: Path):
    return json.loads(p.read_text()) if p.is_file() else None


def _verify(run: Path) -> dict:
    from ks.verify import verify
    rep = verify(run, None, log=lambda s: None)
    d = json.loads(rep.to_canonical())
    return d


def _rec(r: dict) -> dict:
    env = r.get("envelope") or {}
    ctl = r.get("control")
    return {"seq": r["seq"], "tick": r["tick"], "agent": env.get("agent_id"), "tool": env.get("tool"),
            "decision": r["decision"], "reason": r["reason"], "cls": r["action_class"],
            "writes": [w["obj"] for w in r.get("write_set") or []],
            "outbox": list(r.get("outbox_ids") or []), "rule": r.get("policy_rule"),
            "control": None if not ctl else {k: ctl.get(k) for k in ("op", "target", "auto", "issued_by", "alert_id", "reason")}}


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
            kept.append(f"{r['agent']}: {label(hit[0])}" if "." in hit[0] else f"{r['agent']}: {hit[0]}")
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
    recs = [_rec(r) for r in _jl(run / "record.jsonl")]
    alerts = _jl(run / "alerts.jsonl")
    plans = [_jf(p) for p in sorted((run / "plans").glob("*.json"))] if (run / "plans").is_dir() else []
    approvals = [r for r in recs if r["tool"] == "ks.approve"]
    score = _jf(run / "score.json")
    base = {}
    if (run / "baselines").is_dir():
        for d in sorted((run / "baselines").iterdir()):
            if (d / "score.json").is_file():
                base[d.name] = _jf(d / "score.json")
    controls = [r for r in recs if r["control"]]
    suspends = [r for r in controls if r["control"]["op"] == "suspend" and r["control"]["target"].startswith("agent:")]
    held = [r for r in recs if r["decision"] == "hold"]
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
    if not verify["ok"]:
        banners.append({"kind": "verify", "text": f"VERIFY FAILED: {verify['reason']}"
                        + (f" at seq {verify['first_bad']}" if verify.get("first_bad") else "")})
    m = {"run_id": cfg.get("run_id"), "config": {k: cfg.get(k) for k in (
            "run_id", "scenario", "seed", "ticks", "fault", "culprit", "fault_tick", "hold_window_ticks",
            "isolation", "key_mode", "agents", "contracts_version")},
         "verify": verify, "banners": banners, "records": recs, "alerts": alerts, "plans": plans,
         "approvals": [a["seq"] for a in approvals], "score": score, "baselines": base,
         "ticks": [ticks[k] for k in sorted(ticks)], "held": held, "controls": controls,
         "beat_seconds": list(BEAT_SECONDS), "hero_line": HERO_LINE, "fixture": HERO_FIXTURE}
    m["beats"] = _beats(m, suspends, held)
    return m


def _beats(m: dict, suspends: list[dict], held: list[dict]) -> list[dict]:
    recs, alerts, plans, v = m["records"], m["alerts"], m["plans"], m["verify"]
    sens = [r for r in recs if any(w.endswith(".iban") for w in r["writes"]) and r["agent"] and not r["agent"].startswith("ks.")]
    pend = "PENDING in this run: fixture shaped like the contracts, not run data"
    out = []
    # 1 break
    if m["config"].get("fault") and sens:
        r = sens[0]
        out.append({"id": "break", "status": "live", "tick": r["tick"], "seq": r["seq"],
                    "lines": [f"{r['agent']} changed {label(w)} (seq {r['seq']}, tick {r['tick']})" for w in r["writes"] if w.endswith(".iban")]
                    + ["billing, payments and comms read it; inventory and docs are independent"]})
    else:
        out.append({"id": "break", "status": "pending", "tick": None, "seq": None,
                    "lines": [pend, "crm changed a supplier's bank account (suppliers:S-17.iban)",
                              "billing, payments and comms read it; inventory and docs are independent"]})
    # 2 identify
    if alerts:
        a = alerts[0]
        out.append({"id": "identify", "status": "live", "tick": a["tick"], "seq": a["seq"],
                    "lines": [f"alert {a['alert_id']}: {a['detector']} ({'hard' if a['hard'] else 'soft'}) at tick {a['tick']}",
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
        after = [r for r in m["records"] if r["agent"] == tgt and r["seq"] > s["seq"] and r["decision"] == "exec"]
        lines = [f"{tgt} suspended at seq {s['seq']} ({'auto' if s['control']['auto'] else 'operator'}, by {s['control']['issued_by']})",
                 f"held items: {len(held)}" + "".join(f"; {h['tool']} ({h['reason']})" for h in held[:4]),
                 f"{tgt} writes after suspend: {sum(1 for r in after if r['writes'])} (target 0)",
                 "agents still running: " + ", ".join(sorted({r['agent'] for r in recs if r['seq'] > s['seq'] and r['agent'] and r['agent'] != tgt and not r['agent'].startswith('ks.')}))]
        out.append({"id": "contain", "status": "live", "tick": s["tick"], "seq": s["seq"], "lines": lines})
    else:
        f = HERO_FIXTURE
        out.append({"id": "contain", "status": "pending", "tick": None, "seq": None,
                    "lines": [pend, "crm suspended (auto, hard alert)"] + ["held: " + h for h in f["held"]]
                    + ["independent agents still running; crm writes after suspend: 0 (target)"]})
    # 4 recover
    if plans:
        p = plans[-1]
        ln = _lanes(p, recs)
        appr = bool(m["approvals"])
        lines = [f"plan {p['plan_id']} for alert {p['alert_id']} (culprit {p['culprit']})",
                 "restore: " + "; ".join(ln["restore"]), "re-run: " + ", ".join(ln["rerun"]),
                 "kept: " + ("; ".join(ln["kept"]) or "none"), "independent: " + ", ".join(ln["independent"]),
                 f"flag items: {ln['flags']}",
                 ("replan queue: approved" if appr else "replan queue: awaiting approval") if ln["replan"] else "replan queue: empty"]
        if ln["kept"]:
            lines.append(HERO_LINE)
        out.append({"id": "recover", "status": "live", "tick": None, "seq": p["as_of_seq"], "lines": lines, "lanes": ln})
    else:
        f = HERO_FIXTURE["lanes"]
        out.append({"id": "recover", "status": "pending", "tick": None, "seq": None,
                    "lines": [pend, "restore: " + ", ".join(f["restore"]), "re-run: " + ", ".join(f["rerun"]),
                              "kept: " + ", ".join(f["kept"]), "independent: " + ", ".join(f["independent"]),
                              "flag items: 0", HERO_LINE],
                    "lanes": {k: f[k] for k in ("restore", "rerun", "kept", "independent")} | {"flags": 0, "replan": [], "cancel": []}})
    # 5 audit
    lw = v["last_witnessed_seq"]
    lines = [("verify OK" if v["ok"] else f"verify FAILED: {v['reason']}" + (f" at first bad seq {v['first_bad']}" if v.get("first_bad") else ""))
             + f"; tamper-evident up to the last witnessed head (seq {lw})",
             "anchored: yes" if v["anchored"] else f"not anchored ({v['unanchored_reason']}); live proof: ks verify RUN --head ANCHOR",
             "build-time result: stale until the page is rebuilt"]
    out.append({"id": "audit", "status": "live" if v["ok"] else "fail", "tick": None, "seq": lw, "lines": lines})
    return out
