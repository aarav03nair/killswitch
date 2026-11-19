"""Render the Abstract Kit (abstract/*.md) into one tabbed, phone-friendly HTML page."""
import os, html, datetime
from zoneinfo import ZoneInfo
import markdown

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TABS = [
    ("start", "Start here", None),
    ("facts", "Fact card", "abstract/FACT-CARD.md"),
    ("skeleton", "Skeleton", "abstract/SKELETON.md"),
    ("guard", "Guardrails", "abstract/GUARDRAILS.md"),
    ("terms", "Terms", "abstract/TERMS.md"),
    ("jury", "Jury Q&A", "abstract/JURY-QA.md"),
]
START = """
<h1>Abstract Kit</h1>
<p class="lede">Everything you need to write the SEED abstract yourself: facts you may quote, how to phrase them safely, a notes-only skeleton, and the questions the jury will throw at you. Due <b>22 Nov 2026</b>, under 1,000 words, problem → fix → why it matters.</p>
<div class="note"><b>Why there is no draft here:</b> SEED requires the abstract to be written by you and checks for AI-written text. The team has deliberately given you notes, facts and rules, not sentences.</div>
<h2>How to use it (about 2 hours)</h2>
<ol>
<li><b>Skeleton</b>: read the budget table and the MUST bullets. Write the Fix section first, in your own words.</li>
<li><b>Fact card</b>: pull external numbers only from here, with the qualifier in the same row.</li>
<li><b>Terms</b>: use one name per concept (e.g. "suspend", not "quarantine"; "record", not "log").</li>
<li><b>Guardrails</b>: run the 12-point self-check in §4 on your draft.</li>
<li>Save your draft as <code>abstract/DRAFT-R1.md</code> (or paste it to me). The team reviews it with comments only, in two rounds, before 22 Nov.</li>
<li><b>Jury Q&amp;A</b>: not needed for the abstract. Read it before the finale.</li>
</ol>
<h2>The frame in one breath (notes)</h2>
<ul>
<li>Problem: the brief asks to undo one agent "without discarding" others' work; that is undefined once honest agents read the bad write.</li>
<li>Fix: every write has an author, every read a source; identify, contain and recover are three queries on one graph.</li>
<li>Payoff: selective undo of landed writes plus repair of their readers.</li>
<li>Why it matters: an agent's own log is testimony; we keep evidence the agent cannot forge, and score recovery against a no-fault run.</li>
</ul>
<p class="small">Related: the one-page <a href="https://claude.ai/artifact/38FVafjkHf2vXLTm2z6uBF">how-it-works diagram</a> and the <a href="https://claude.ai/artifact/HSWLtXFe9GYB36whkxwhwL">project board</a>.</p>
"""

CSS = """
:root{color-scheme:light dark;--bg:light-dark(#fff,#10191e);--ink:light-dark(#121212,#e9eef1);--mut:light-dark(#5b6670,#9fb0bb);--red:#e3120b;--sl:light-dark(#2e6f8e,#6fb3d3);--pan:light-dark(#e3ecf0,#18252c);--rule:light-dark(#cfd9de,#2a3a43)}
:root[data-theme=light]{color-scheme:light}:root[data-theme=dark]{color-scheme:dark}
*{box-sizing:border-box;min-width:0}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 Inter,system-ui,sans-serif;overflow-x:clip}
header{background:var(--pan);padding:14px max(5vw,16px) 0;position:sticky;top:0;z-index:2;border-bottom:1px solid var(--rule)}
.brand{font:600 15px Inter,sans-serif;margin-bottom:8px}.brand b{background:var(--red);color:#fff;padding:2px 7px;margin-right:6px;font-size:12px}
nav{display:flex;gap:2px;overflow-x:auto;scrollbar-width:none}nav::-webkit-scrollbar{display:none}
nav button{flex:none;font:500 14px Inter,sans-serif;min-height:44px;padding:8px 14px;border:0;background:none;color:var(--mut);cursor:pointer;border-bottom:3px solid transparent}
nav button[aria-selected=true]{color:var(--ink);border-bottom-color:var(--red)}
:focus-visible{outline:3px solid var(--sl);outline-offset:2px}
main{max-width:900px;margin:0 auto;padding:20px max(5vw,16px) 60px}
section[hidden]{display:none}
h1,h2,h3{font-family:"Source Serif 4",Georgia,serif;font-weight:600;line-height:1.15;text-wrap:balance}
h1{font-size:clamp(28px,5vw,40px);margin:.2em 0 .4em}h2{font-size:24px;margin:1.6em 0 .5em}h3{font-size:19px;margin:1.3em 0 .4em}
.lede{font-size:17px}.small{font-size:13px;color:var(--mut)}
.note{background:var(--pan);border-left:4px solid var(--red);padding:12px 14px;margin:16px 0}
table{border-collapse:collapse;width:100%;font-size:14px;display:block;overflow-x:auto}
th,td{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--rule)}th{color:var(--mut);font-weight:600;font-size:13px}
td{min-width:8em}td:first-child,th:first-child{min-width:2.2em}
section{scroll-margin-top:120px}
code{font-size:.9em;background:var(--pan);padding:1px 4px;overflow-wrap:anywhere}pre{overflow-x:auto;background:var(--pan);padding:10px}
a{color:var(--sl)}blockquote{margin:0;padding-left:12px;border-left:3px solid var(--rule);color:var(--mut)}
"""


def main():
    secs, btns = [], []
    for i, (tid, label, path) in enumerate(TABS):
        btns.append(f'<button role="tab" id="t-{tid}" aria-controls="{tid}" aria-selected="{"true" if i == 0 else "false"}">{html.escape(label)}</button>')
        if path:
            with open(os.path.join(ROOT, path)) as f:
                body = markdown.markdown(f.read(), extensions=["tables", "fenced_code", "sane_lists"])
        else:
            body = START
        secs.append(f'<section id="{tid}" role="tabpanel" {"" if i == 0 else "hidden"}>{body}</section>')
    stamp = datetime.datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%d %b %Y, %H:%M IST")
    page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Abstract Kit</title><link href="https://fonts.googleapis.com/css2?family=Source+Serif+4:opsz,wght@8..60,600&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>{CSS}</style></head><body>
<header><div class="brand"><b>Kill Switch</b>Abstract Kit · updated {stamp}</div><nav role="tablist">{''.join(btns)}</nav></header>
<main>{''.join(secs)}</main>
<script>{{const bs=[...document.querySelectorAll('nav button')];
function show(id,push){{bs.forEach(b=>{{const on=b.getAttribute('aria-controls')===id;b.setAttribute('aria-selected',on);document.getElementById(b.getAttribute('aria-controls')).hidden=!on}});if(push)history.replaceState(null,'','#'+id);window.scrollTo(0,0)}}
bs.forEach(b=>b.addEventListener('click',()=>show(b.getAttribute('aria-controls'),true)));
const h=location.hash.slice(1);if(bs.some(b=>b.getAttribute('aria-controls')===h)){{show(h,false);setTimeout(()=>scrollTo(0,0),0)}}
addEventListener('hashchange',()=>{{const k=location.hash.slice(1);if(bs.some(b=>b.getAttribute('aria-controls')===k))show(k,false)}})}}</script>
</body></html>"""
    with open(os.path.join(ROOT, "board", "kit.html"), "w") as f:
        f.write(page)
    print("kit rendered")


if __name__ == "__main__":
    main()
