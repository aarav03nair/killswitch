"""``ks console RUN --html OUT``: one static HTML file, inline CSS and JS, data embedded as JSON, no network."""
from __future__ import annotations

from ks.contracts import canonical

from .model import build_model

__all__ = ["render_html", "write_html"]

_CSS = """
:root{--bg:#10141a;--pan:#1a212b;--ink:#e6e9ee;--mut:#8b96a5;--ok:#3fb27f;--red:#e5484d;--amb:#e0a030;--rule:#2b3542}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:16px}h1{font-size:20px;margin:0 0 4px}
.banner{padding:8px 12px;margin:6px 0;font-weight:700;border-left:6px solid var(--red);background:#3a1a1d}
.banner.ok{border-color:var(--ok);background:#12301f;font-weight:400}.banner.warn{border-color:var(--amb);background:#3a2e12}
.beats{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:6px;margin:12px 0}
.beat{background:var(--pan);border-top:4px solid var(--rule);padding:8px}.beat.live{border-top-color:var(--ok)}
.beat.pending{border-top-color:var(--amb)}.beat.fail,.beat.unverified{border-top-color:var(--red)}
.beat b{display:block}.beat span{color:var(--mut);font-size:12px}
section{background:var(--pan);padding:12px;margin:10px 0}h2{font-size:16px;margin:0 0 6px}
.tag{font-size:11px;padding:1px 6px;background:var(--rule);margin-left:6px}.tag.pending{background:var(--amb);color:#000}.tag.unverified,.tag.fail{background:var(--red)}
tr.unw td{opacity:.6;font-style:italic}
.lanes{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.lane{border:1px solid var(--rule);padding:8px}
.lane h3{margin:0 0 4px;font-size:13px}.lane.kept{border-color:var(--ok)}ul{margin:4px 0;padding-left:18px}
table{border-collapse:collapse;width:100%;font-size:12px}td,th{border-bottom:1px solid var(--rule);padding:2px 6px;text-align:left}
tr.hold td{color:var(--amb)}tr.ctl td{color:var(--red)}.mono{font-family:ui-monospace,monospace}
.tl{display:flex;gap:2px;align-items:flex-end;height:60px}.tl i{flex:1;background:var(--ok);min-width:2px}
.scroll{max-height:320px;overflow:auto}
@media(max-width:700px){.beats,.lanes{grid-template-columns:minmax(0,1fr)}}
"""

_JS = r"""
const M=JSON.parse(document.getElementById('m').textContent);
function E(t,c,x){const e=document.createElement(t);if(c)e.className=c;if(x!==undefined)e.textContent=x;return e}
const root=document.getElementById('root');
root.append(E('h1','','Incident console: '+M.run_id));
M.banners.forEach(b=>root.append(E('div','banner '+b.kind,b.text)));
const v=M.verify;
root.append(E('div','banner '+(v.ok?'ok':''),'verify (build time): '+(v.ok?'OK':'FAILED '+v.reason)+'; tamper-evident up to the last witnessed head (seq '+v.last_witnessed_seq+'); '+(v.anchored?'anchored':'not anchored ('+v.unanchored_reason+')')+'. Stale until rebuilt.'));
const st=E('div','beats');M.beats.forEach((b,i)=>{const d=E('div','beat '+b.status);d.append(E('b','',(i+1)+'. '+B[i][1]),E('span','',b.status==='pending'?'PENDING (fixture)':b.status==='unverified'?'UNVERIFIED':B[i][2]),E('span','',' '+M.beat_seconds[i]+'s'));st.append(d)});root.append(st);
M.beats.forEach((b,i)=>{const s=E('section','');const h=E('h2','',(i+1)+'. '+B[i][1]);h.append(E('span','tag '+b.status,b.status));s.append(h);
 const u=E('ul');b.lines.forEach(l=>u.append(E('li','',l)));s.append(u);
 if(b.lanes){const g=E('div','lanes');[['restore','Restore'],['rerun','Re-run'],['kept','Kept'],['independent','Independent']].forEach(k=>{const l=E('div','lane '+k[0]);l.append(E('h3','',k[1]));const q=E('ul');(b.lanes[k[0]]||[]).forEach(x=>q.append(E('li','',x)));l.append(q);g.append(l)});s.append(g)}
 if(b.id==='recover'){s.append(E('p','','Residual damage R and collateral loss C: '+(M.score?JSON.stringify(M.score):'not run')));
  const bn=Object.keys(M.baselines);s.append(E('p','','Baselines: '+(bn.length?bn.map(n=>n+' '+JSON.stringify(M.baselines[n])).join('; '):'not run')))}
 root.append(s)});
const tl=E('section');tl.append(E('h2','','Timeline: records per tick'));const bars=E('div','tl');const mx=Math.max(1,...M.ticks.map(t=>t.n));
M.ticks.forEach(t=>{const i=E('i');i.style.height=(100*t.n/mx)+'%';i.title='tick '+t.tick+': '+t.n+' records '+JSON.stringify(t.agents);bars.append(i)});tl.append(bars);
const sc=E('div','scroll');const tb=E('table');const hr=E('tr');hr.append(...['seq','tick','agent','tool','decision','reason','note'].map(x=>E('th','',x)));tb.append(hr);
M.records.forEach(r=>{if(r.tool==='ks.seed')return;const tr=E('tr',(r.control?'ctl':r.decision==='hold'?'hold':'')+(r.unwitnessed?' unw':''));
 [r.seq,r.tick,r.agent,r.tool,r.decision,r.reason,(r.control?(r.control.op+' '+r.control.target):(r.outbox.length?'outbox '+r.outbox.join(','):''))+(r.unwitnessed?' [unwitnessed]':'')].forEach(x=>tr.append(E('td','mono',x===null?'':String(x))));tb.append(tr)});
sc.append(tb);tl.append(sc);root.append(tl);
"""


def _nofloat(o):
    if isinstance(o, float):
        return repr(o)  # canonical JSON has no floats; score values shown as text
    if isinstance(o, dict):
        return {k: _nofloat(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_nofloat(v) for v in o]
    return o


def _embed(m: dict) -> str:
    return canonical.dumps(_nofloat(m)).decode().replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render_html(run) -> str:
    m = build_model(run)
    from .model import BEATS
    beats = canonical.dumps([list(b) for b in BEATS]).decode()
    return (f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Incident console {m['run_id']}</title>"
            f"<style>{_CSS}</style></head><body><main id=\"root\"></main>"
            f"<script type=\"application/json\" id=\"m\">{_embed(m)}</script>"
            f"<script>const B={beats};{_JS}</script></body></html>\n")


def write_html(run, out) -> None:
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(render_html(run))
