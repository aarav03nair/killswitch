#!/usr/bin/env python3
"""Team issue tracker CLI. Every agent uses this to create/update issues so the board stays consistent.

Examples:
  python3 org/issue.py create --id RES-01 --sprint 1 --track research --title "..." \
      --owner meera --reviewer anaya --model sonnet --by anaya \
      --outcome "one line" --accept "criterion 1" --accept "criterion 2" --deliverable research/RES-01.md
  python3 org/issue.py status RES-01 in_progress --who meera --msg "started"
  python3 org/issue.py summary RES-01 --who meera --text "3-6 line result summary"
  python3 org/issue.py review RES-01 --who anaya --verdict done --text "review notes"   # verdict: done|changes
  python3 org/issue.py log RES-01 --who meera --msg "note"
  python3 org/issue.py list [--sprint 1]
Statuses: todo, in_progress, in_review, changes, done, blocked
Team ids: aarav maya anaya kabir zoya panel meera rohan leela sameer arjun nisha vikram tara ishaan
"""
import argparse, json, os, sys, datetime, fcntl
from zoneinfo import ZoneInfo

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDIR = os.path.join(ROOT, "org", "issues")
BOARD = os.path.join(ROOT, "org", "board.json")
STAT = {"todo", "in_progress", "in_review", "changes", "done", "blocked"}
TEAM = {"pmo", "aarav", "maya", "anaya", "kabir", "zoya", "panel", "meera", "rohan", "leela", "sameer",
        "arjun", "nisha", "vikram", "tara", "ishaan"}


def now():
    return datetime.datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%d %b %H:%M")


def path(i):
    return os.path.join(IDIR, f"{i}.json")


def load(i):
    p = path(i)
    if not os.path.exists(p):
        sys.exit(f"no such issue {i}")
    with open(p) as f:
        return json.load(f)


def save(d):
    tmp = path(d["id"]) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path(d["id"]))


def activity(who, msg):
    with open(BOARD, "r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        b = json.load(f)
        b.setdefault("activity", []).append({"t": now(), "who": who, "msg": msg})
        b["activity"] = b["activity"][-200:]
        f.seek(0); f.truncate(); json.dump(b, f, indent=2, ensure_ascii=False)
        fcntl.flock(f, fcntl.LOCK_UN)


def chk(who):
    if who not in TEAM:
        sys.exit(f"unknown team id {who}; use one of {sorted(TEAM)}")


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    c = sp.add_parser("create")
    for k in ["id", "title", "track", "owner", "reviewer", "model", "by", "outcome", "deliverable"]:
        c.add_argument("--" + k, required=k not in {"deliverable", "reviewer"})
    c.add_argument("--sprint", type=int, required=True)
    c.add_argument("--accept", action="append", default=[])
    c.add_argument("--depends", action="append", default=[])
    s = sp.add_parser("status"); s.add_argument("id"); s.add_argument("status"); s.add_argument("--who", required=True); s.add_argument("--msg", default="")
    m = sp.add_parser("summary"); m.add_argument("id"); m.add_argument("--who", required=True); m.add_argument("--text", required=True)
    r = sp.add_parser("review"); r.add_argument("id"); r.add_argument("--who", required=True); r.add_argument("--verdict", choices=["done", "changes"], required=True); r.add_argument("--text", required=True)
    l = sp.add_parser("log"); l.add_argument("id"); l.add_argument("--who", required=True); l.add_argument("--msg", required=True)
    ls = sp.add_parser("list"); ls.add_argument("--sprint", type=int)
    a = ap.parse_args()

    if a.cmd == "create":
        chk(a.by); chk(a.owner)
        if a.reviewer: chk(a.reviewer)
        if os.path.exists(path(a.id)):
            sys.exit(f"{a.id} exists")
        d = dict(id=a.id, title=a.title, sprint=a.sprint, track=a.track, owner=a.owner, reviewer=a.reviewer,
                 model=a.model, created_by=a.by, status="todo", outcome=a.outcome, acceptance=a.accept,
                 depends=a.depends, deliverable=a.deliverable, summary="", review="",
                 log=[{"t": now(), "who": a.by, "msg": "opened"}])
        save(d); activity(a.by, f"opened {a.id} — {a.title}"); print("created", a.id)
    elif a.cmd == "list":
        for fn in sorted(os.listdir(IDIR)):
            if fn.endswith(".json"):
                d = json.load(open(os.path.join(IDIR, fn)))
                if a.sprint is None or d["sprint"] == a.sprint:
                    print(f"{d['id']:<10} S{d['sprint']} {d['status']:<12} {d['owner']:<8} {d['title']}")
    else:
        chk(a.who); d = load(a.id)
        if a.cmd == "status":
            if a.status not in STAT: sys.exit(f"bad status; use {STAT}")
            d["status"] = a.status
            d["log"].append({"t": now(), "who": a.who, "msg": f"→ {a.status}" + (f": {a.msg}" if a.msg else "")})
            activity(a.who, f"moved {a.id} to {a.status}")
        elif a.cmd == "summary":
            d["summary"] = a.text; d["log"].append({"t": now(), "who": a.who, "msg": "posted result summary"})
        elif a.cmd == "review":
            d["review"] = (d.get("review", "") + "\n\n" if d.get("review") else "") + f"[{a.who} · {a.verdict}] {a.text}"
            d["status"] = a.verdict
            d["log"].append({"t": now(), "who": a.who, "msg": f"review: {a.verdict}"})
            activity(a.who, f"reviewed {a.id}: {a.verdict}")
        elif a.cmd == "log":
            d["log"].append({"t": now(), "who": a.who, "msg": a.msg})
        save(d); print("ok", a.id, d["status"])


if __name__ == "__main__":
    main()
