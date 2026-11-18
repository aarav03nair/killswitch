"""Render org/board.json + org/issues/*.json into board/index.html."""
import json, glob, os, datetime
from zoneinfo import ZoneInfo

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IST = ZoneInfo("Asia/Kolkata")


def load():
    with open(os.path.join(ROOT, "org", "board.json")) as f:
        d = json.load(f)
    issues = []
    for p in sorted(glob.glob(os.path.join(ROOT, "org", "issues", "*.json"))):
        try:
            with open(p) as f:
                issues.append(json.load(f))
        except Exception as e:  # a malformed issue file must not kill the board
            issues.append({"id": os.path.basename(p), "title": f"Unreadable issue file: {e}",
                           "sprint": 0, "status": "changes", "owner": "", "model": ""})
    issues.sort(key=lambda i: (i.get("sprint", 0), i.get("id", "")))
    d["issues"] = issues
    now = datetime.datetime.now(IST)
    d["project"]["updated"] = now.strftime("%d %b %Y, %H:%M IST")
    deadline = datetime.datetime(2026, 11, 22, 23, 59, tzinfo=IST)
    d["daysToAbstract"] = max(0, (deadline - now).days)
    return d


def main():
    d = load()
    with open(os.path.join(ROOT, "board", "template.html")) as f:
        tpl = f.read()
    blob = json.dumps(d, ensure_ascii=False).replace("</", "<\\/")
    out = tpl.replace("/*DATA*/", blob)
    with open(os.path.join(ROOT, "board", "index.html"), "w") as f:
        f.write(out)
    print(f"rendered {len(d['issues'])} issues")


if __name__ == "__main__":
    main()
