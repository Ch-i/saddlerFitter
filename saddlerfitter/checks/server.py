"""Checks viewer server — serves the run + the GitHub-Actions-style page.

GET /            -> the checks page
GET /api/run     -> the latest run (grill --json output: passes per family)
GET /api/log     -> the run's terminal stream
POST /api/fix    -> trigger a saddler fix for one flag   (queued stub for now)
POST /api/grill  -> ask a question of one flag's panel    (stub for now)
"""
from __future__ import annotations

import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RUNS = Path(__file__).resolve().parents[1] / "state" / "runs"


def _latest_run() -> Path | None:
    demo = RUNS / "demo.json"
    if demo.exists():
        return demo
    js = sorted(RUNS.glob("*.json"))
    return js[-1] if js else None


def run(port=8199, host="127.0.0.1"):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _body(self, body: bytes, ctype: str, code=200):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            p = urllib.parse.urlparse(self.path).path
            if p == "/api/run":
                f = _latest_run()
                self._body((f.read_bytes() if f else b"{}"), "application/json")
            elif p == "/api/log":
                lf = RUNS / "demo.log"
                txt = lf.read_text(errors="replace") if lf.exists() else ""
                self._body(txt.encode(), "text/plain; charset=utf-8")
            elif p in ("/", "/index", "/index.html"):
                self._body(PAGE.encode(), "text/html; charset=utf-8")
            else:
                self._body(b"not found", "text/plain", 404)

        def do_POST(self):
            p = urllib.parse.urlparse(self.path).path
            n = int(self.headers.get("Content-Length", 0) or 0)
            try:
                data = json.loads(self.rfile.read(n).decode() or "{}")
            except Exception:
                data = {}
            if p == "/api/fix":
                resp = {"ok": True, "status": "queued",
                        "message": f"saddler queued a fix for {data.get('id', '?')} — "
                                   "it will localise, propose a minimal diff, re-grill "
                                   "cross-family, and surface it for /approve."}
                self._body(json.dumps(resp).encode(), "application/json")
            elif p == "/api/grill":
                resp = {"ok": True,
                        "answer": "(grill session stub) the arbiter + verifiers would "
                                  f"re-defend or revise flag {data.get('id', '?')} here, "
                                  f"given your question: “{data.get('q', '')}”"}
                self._body(json.dumps(resp).encode(), "application/json")
            else:
                self._body(b"not found", "text/plain", 404)

    ThreadingHTTPServer((host, port), Handler).serve_forever()


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>saddler — checks</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root{
    --bg:#FAFAFA; --surface:#FFFFFF; --ink:#18181A; --dim:#8A8A8E; --faint:#B4B4B8;
    --line:#EAEAEA; --line2:#F2F2F2; --ok:#2E7D32; --warn:#C2632B; --crit:#B23B3B; --mid:#A07B2E;
    --sans:-apple-system,BlinkMacSystemFont,"Helvetica Neue","Inter",Arial,sans-serif;
    --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,monospace;
  }
  *{box-sizing:border-box} html,body{margin:0;height:100%}
  body{background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:13px;line-height:1.55;
       -webkit-font-smoothing:antialiased;font-feature-settings:"tnum" 1}
  .lbl{font-size:10.5px;text-transform:uppercase;letter-spacing:.14em;color:var(--dim);font-weight:600}
  .mono{font-family:var(--mono)}
  header{display:flex;align-items:center;gap:18px;height:54px;padding:0 26px;border-bottom:1px solid var(--line);background:var(--surface)}
  header .brand{font-weight:600;letter-spacing:.16em;font-size:12px} header .brand b{font-weight:700} header .brand span{color:var(--faint)}
  header .target{color:var(--dim);font-size:12px} header .target b{color:var(--ink);font-weight:600}
  .pill{margin-left:6px;font-size:11px;font-weight:700;letter-spacing:.06em;padding:3px 10px;border-radius:12px}
  .pill.pass{color:#1d5e2a;background:#e7f1e8} .pill.block{color:#7e2a2a;background:#f3e3e3}
  .right{margin-left:auto;display:flex;gap:16px;align-items:center;color:var(--dim);font-size:12px}

  .wrap{display:grid;grid-template-columns:392px 1fr;height:calc(100vh - 54px)}
  .flags{border-right:1px solid var(--line);overflow:auto}
  .flags .hd{padding:16px 22px 8px}
  .chk{display:flex;gap:11px;align-items:flex-start;padding:12px 22px;border-bottom:1px solid var(--line2);cursor:pointer}
  .chk:hover{background:#fff} .chk.sel{background:#fff;box-shadow:inset 3px 0 0 var(--ink)}
  .chk .ic{flex:none;width:16px;height:16px;border-radius:50%;margin-top:1px;display:grid;place-items:center;font-size:10px;color:#fff}
  .ic.keep{background:var(--ink)} .ic.esc{background:var(--mid)} .ic.info{background:var(--faint)}
  .chk .ttl{font-weight:600;font-size:13px}
  .chk .meta{color:var(--dim);font-size:11.5px;margin-top:2px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  .sev{font-size:10px;font-weight:700;letter-spacing:.05em;padding:1px 6px;border-radius:4px;text-transform:uppercase}
  .sev.critical{color:#fff;background:var(--crit)} .sev.high{color:#fff;background:var(--warn)}
  .sev.medium{color:#5b4a1e;background:#f0e6cd} .sev.low,.sev.info{color:var(--dim);background:#eee}
  .fam{font-size:10px;font-weight:700;letter-spacing:.05em;padding:1px 6px;border-radius:4px;border:1px solid var(--line);color:var(--dim)}
  .fam.claude{color:#6a4ea8;border-color:#e0d6f0} .fam.codex{color:#1f6f6a;border-color:#cfe8e6}

  .detail{overflow:auto;padding:24px 30px 60px}
  .detail .dh .ttl{font-size:18px;font-weight:700;line-height:1.3}
  .detail .dh .sub{color:var(--dim);font-size:12px;margin-top:6px;display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  .actions{display:flex;gap:10px;margin:16px 0 6px}
  .btn{font-family:var(--sans);font-size:12.5px;font-weight:600;border:1px solid var(--line);background:var(--surface);
       color:var(--ink);padding:7px 14px;border-radius:7px;cursor:pointer}
  .btn:hover{border-color:var(--ink)} .btn.primary{background:var(--ink);color:#fff;border-color:var(--ink)}
  .toast{margin-top:8px;font-size:12px;color:var(--ok);background:#eef5ef;border:1px solid #d9e9da;padding:8px 11px;border-radius:7px;display:none}

  .sec{margin-top:26px} .sec>.lbl{margin-bottom:10px}
  .path{position:relative;margin-left:7px;padding-left:22px;border-left:2px solid var(--line)}
  .step{position:relative;padding:0 0 16px}
  .step .node{position:absolute;left:-30px;top:1px;width:15px;height:15px;border-radius:50%;background:#fff;border:2px solid var(--ink);display:grid;place-items:center}
  .step .node.ok{background:var(--ink)} .step .node.no{border-color:var(--crit)}
  .step .nm{font-weight:600;font-size:12.5px}
  .step .dt{color:var(--dim);font-size:12px;margin-top:1px}
  .aspect{display:flex;gap:8px;align-items:baseline;font-size:12px;margin-top:5px}
  .aspect .v{font-weight:700} .aspect .v.y{color:var(--ok)} .aspect .v.n{color:var(--crit)} .aspect .v.u{color:var(--mid)}
  .aspect .why{color:var(--dim)}
  .think{background:var(--surface);border:1px solid var(--line);border-radius:9px;padding:13px 15px;font-size:12.5px;color:#333}
  .think .q{color:var(--faint);font-size:11px}
  .fix{font-family:var(--mono);font-size:12px;white-space:pre-wrap;background:#f3f4f3;border:1px solid var(--line);border-radius:7px;padding:11px 13px}
  .tabs{display:flex;gap:18px;border-bottom:1px solid var(--line);margin-bottom:10px}
  .tab{cursor:pointer;color:var(--dim);font-size:12px;font-weight:600;padding-bottom:7px;border-bottom:2px solid transparent}
  .tab.on{color:var(--ink);border-bottom-color:var(--ink)}
  .log{font-family:var(--mono);font-size:11.5px;white-space:pre-wrap;color:#3a3a3a;background:#fbfbfb;border:1px solid var(--line);
       border-radius:7px;padding:12px 13px;max-height:340px;overflow:auto}
  .empty{color:var(--faint);padding:60px 20px;text-align:center}
  .grillbox{margin-top:10px;display:none;gap:8px}
  .grillbox input{flex:1;font-family:var(--sans);font-size:12.5px;padding:7px 11px;border:1px solid var(--line);border-radius:7px}
</style></head>
<body>
<header>
  <div class="brand"><b>SADDLER</b> <span>/</span> CHECKS</div>
  <div class="target" id="target">—</div>
  <span class="pill" id="verdict"></span>
  <div class="right"><span id="fam"></span><span id="count"></span></div>
</header>
<div class="wrap">
  <div class="flags"><div class="hd"><span class="lbl" id="flagslbl">flags</span></div><div id="flags"></div></div>
  <div class="detail" id="detail"><div class="empty">select a flag to open its action path</div></div>
</div>
<script>
const SEVR={critical:4,high:3,medium:2,low:1,info:0,unknown:0};
const esc=s=>(s||"").replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let FLAGS=[], SEL=-1, LOG="", TAB="thought";

function vmark(v){return v==="confirmed"?["y","✓"]:(v==="refuted"?["n","✗"]:["u","?"]);}

function list(){
  document.getElementById("flags").innerHTML = FLAGS.map((f,i)=>{
    const st = f.status==="confirmed"?["keep","✓"]:(f.status==="needs_human"?["esc","⚑"]:["info","·"]);
    return `<div class="chk ${i===SEL?'sel':''}" data-i="${i}">
      <span class="ic ${st[0]}">${st[1]}</span>
      <div><div class="ttl">${esc(f.title)}</div>
      <div class="meta"><span class="sev ${f.severity}">${esc(f.severity)}</span>
        <span class="fam ${f.family}">${esc(f.family)}</span>
        <span>${esc((f.file||'').split('/').pop())}${f.line?':'+f.line:''}</span></div></div></div>`;
  }).join("") || '<div class="empty">no flags</div>';
  document.querySelectorAll(".chk").forEach(el=>el.onclick=()=>{SEL=+el.dataset.i;list();detail();});
}

function detail(){
  const f=FLAGS[SEL]; if(!f){return;}
  const aspects=(f.verifier_verdicts||[]).map(v=>{const m=vmark(v.verdict);
    return `<div class="aspect"><span class="v ${m[0]}">${m[1]}</span><b>${esc(v.aspect)}</b>
      <span class="why">${esc(v.reason)} <i>(${(v.confidence||0).toFixed(2)})</i></span></div>`;}).join("");
  const ev=(f.evidence||[]).map(d=>`${esc(d.source)}:${esc(d.code)}@${d.line}`).join(", ");
  const nC=f.verifier_verdicts? f.verifier_verdicts.filter(v=>v.verdict==="confirmed").length:0;
  const nT=f.verifier_verdicts? f.verifier_verdicts.length:0;
  const arb=f.status==="confirmed"?["ok","kept"]:(f.status==="needs_human"?["","escalated to human"]:["no","dropped"]);
  const think = [
    f.rationale?`<div class="q">why it's a defect</div>${esc(f.rationale)}`:"",
    (f.verifier_verdicts||[]).map(v=>`<div class="q" style="margin-top:8px">${esc(v.aspect)} — ${esc(v.verdict)}</div>${esc(v.reason)}`).join(""),
    f.arbiter_summary?`<div class="q" style="margin-top:8px">arbiter</div>${esc(f.arbiter_summary)}`:"",
  ].join("");

  document.getElementById("detail").innerHTML = `
    <div class="dh"><div class="ttl">${esc(f.title)}</div>
      <div class="sub"><span class="sev ${f.severity}">${esc(f.severity)}</span>
        <span class="fam ${f.family}">${esc(f.family)} family</span>
        <span class="mono">${esc(f.file)}${f.line?':'+f.line:''}</span>
        <span>conf ${(f.confidence||0).toFixed(2)}</span>
        <span>${f.execution_anchored?'⚓ tool-anchored':'~ hypothesis'}</span></div></div>

    <div class="actions">
      <button class="btn primary" onclick="fix()">▶ Fix with saddler</button>
      <button class="btn" onclick="toggleGrill()">💬 Grill this flag</button></div>
    <div class="toast" id="toast"></div>
    <div class="grillbox" id="grillbox" style="display:none">
      <input id="grillq" placeholder="ask this flag's panel… e.g. is this reachable in production?">
      <button class="btn" onclick="grill()">ask</button></div>

    <div class="sec"><div class="lbl">action path</div>
      <div class="path">
        <div class="step"><div class="node ok"></div><div class="nm">propose</div>
          <div class="dt">raised by lens: ${esc((f.proposers||[]).join(', '))}</div></div>
        <div class="step"><div class="node ${ev?'ok':''}"></div><div class="nm">evidence anchor</div>
          <div class="dt">${ev?('⚓ '+esc(ev)):'no non-LLM corroboration — hypothesis'}</div></div>
        <div class="step"><div class="node ${nC>=nT/2?'ok':'no'}"></div><div class="nm">verify · ${nC}/${nT} aspects confirm</div>
          ${aspects}</div>
        <div class="step"><div class="node ${arb[0]}"></div><div class="nm">arbitrate · ${arb[1]} [${esc(f.severity)}]</div>
          <div class="dt">${esc(f.arbiter_summary||'')}</div></div>
      </div></div>

    ${f.suggested_fix?`<div class="sec"><div class="lbl">suggested fix</div><div class="fix">${esc(f.suggested_fix)}</div></div>`:""}

    <div class="sec"><div class="lbl">streams</div>
      <div class="tabs">
        <span class="tab ${TAB==='thought'?'on':''}" data-t="thought">thought</span>
        <span class="tab ${TAB==='terminal'?'on':''}" data-t="terminal">terminal</span>
        <span class="tab ${TAB==='irc'?'on':''}" data-t="irc">raw irc</span></div>
      <div id="stream"></div></div>`;

  document.querySelectorAll(".tab").forEach(el=>el.onclick=()=>{TAB=el.dataset.t;detail();});
  const s=document.getElementById("stream");
  if(TAB==="thought") s.innerHTML=`<div class="think">${think||'—'}</div>`;
  else if(TAB==="terminal") s.innerHTML=`<div class="log">${esc(LOG)||'—'}</div>`;
  else s.innerHTML=`<div class="log">raw IRC stream — connect the hub (#saddler-debate / #findings) to mirror agent debate here.</div>`;
}

function toggleGrill(){const g=document.getElementById("grillbox");g.style.display=g.style.display==="flex"?"none":"flex";}
async function fix(){const f=FLAGS[SEL];const t=document.getElementById("toast");
  const r=await (await fetch("/api/fix",{method:"POST",headers:{'Content-Type':'application/json'},body:JSON.stringify({id:f.fid||f.title})})).json();
  t.style.display="block"; t.textContent="▶ "+r.message;}
async function grill(){const f=FLAGS[SEL];const q=document.getElementById("grillq").value;const t=document.getElementById("toast");
  const r=await (await fetch("/api/grill",{method:"POST",headers:{'Content-Type':'application/json'},body:JSON.stringify({id:f.fid||f.title,q})})).json();
  t.style.display="block"; t.style.color="#18181A"; t.style.background="#f3f4f3"; t.style.borderColor="#eaeaea"; t.textContent="💬 "+r.answer;}

async function load(){
  let run={passes:{}}; try{run=await (await fetch("/api/run")).json();}catch(e){}
  try{LOG=await (await fetch("/api/log")).text();}catch(e){}
  FLAGS=[];
  for(const fam of Object.keys(run.passes||{}))
    for(const f of run.passes[fam]) FLAGS.push(Object.assign({family:fam},f));
  FLAGS.sort((a,b)=>(SEVR[b.severity]||0)-(SEVR[a.severity]||0));
  const cl=(run.passes&&run.passes.claude||[]).length, co=(run.passes&&run.passes.codex||[]).length;
  document.getElementById("target").innerHTML="cross-family double-grill · <b>"+esc((run.passes&&Object.keys(run.passes).length)?'sample':'—')+"</b>";
  const v=document.getElementById("verdict");
  if(run.blocked!==undefined){v.className="pill "+(run.blocked?'block':'pass');v.textContent=run.blocked?('⛔ blocked ≥ '+esc(run.block_at||'high')):'✓ pass';}
  document.getElementById("fam").innerHTML=`<span class="fam claude">claude ${cl}</span> <span class="fam codex">codex ${co}</span>`;
  document.getElementById("count").textContent=FLAGS.length+" flags";
  document.getElementById("flagslbl").textContent="flags · "+FLAGS.length;
  if(SEL<0&&FLAGS.length) SEL=0;
  list(); detail();
}
load();
</script>
</body></html>
"""


if __name__ == "__main__":
    run(port=int(os.environ.get("SADDLER_CHECKS_PORT", "8199")),
        host=os.environ.get("SADDLER_CHECKS_BIND", "127.0.0.1"))
