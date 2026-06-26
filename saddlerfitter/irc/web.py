"""Web dashboard for the IRC hub — connected agents (+ source) and the live chat.

Swiss-minimal (countersubject.biz). Each agent message shows a shared *conclusion*
with its underlying *layers of thought* expandable beneath it; the chat animates and
locks to the newest message; roster cards pulse when an agent speaks; and a composer
lets a human participate in the room. POST /api/say injects the human's message.
"""
from __future__ import annotations

import json
import urllib.parse
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .. import config


def run_web(hub, port, host="127.0.0.1", netwatch=None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _body(self, body: bytes, ctype: str, code=200):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if config.IRC_PASSWORD:
                self.send_header("Set-Cookie", f"ct={config.IRC_PASSWORD}; Path=/; SameSite=Strict")
            self.end_headers()
            self.wfile.write(body)

        def _authed(self) -> bool:
            secret = config.IRC_PASSWORD
            if not secret:
                return True
            ck = SimpleCookie(self.headers.get("Cookie", ""))
            if "ct" in ck and ck["ct"].value == secret:
                return True
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            return qs.get("token", [""])[0] == secret

        def do_GET(self):
            if not self._authed():
                self._body(b"saddler hub: token required - visit /?token=<password>", "text/plain", 401)
                return
            path = urllib.parse.urlparse(self.path).path
            if path.startswith("/api/state"):
                self._body(json.dumps(hub.snapshot()).encode(), "application/json")
            elif path.startswith("/api/net"):
                data = netwatch.badges() if netwatch else {"badges": [], "exposed": [], "deep": False}
                self._body(json.dumps(data).encode(), "application/json")
            elif path in ("/", "/index", "/index.html"):
                self._body(PAGE.encode(), "text/html; charset=utf-8")
            else:
                self._body(b"not found", "text/plain", 404)

        def do_POST(self):
            if not self._authed():
                self._body(b"token required", "text/plain", 401)
                return
            if urllib.parse.urlparse(self.path).path == "/api/say":
                n = int(self.headers.get("Content-Length", 0) or 0)
                try:
                    data = json.loads(self.rfile.read(n).decode() or "{}")
                except Exception:
                    data = {}
                body = str(data.get("body", "")).strip()
                if body:
                    hub.inject(data.get("nick") or "you",
                               data.get("channel") or config.CH_DEBATE, body)
                self._body(b'{"ok":true}', "application/json")
            else:
                self._body(b"not found", "text/plain", 404)

    ThreadingHTTPServer((host, port), Handler).serve_forever()


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>saddler — agent hub</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root{
    --bg:#FAFAFA; --surface:#FFFFFF; --ink:#18181A; --dim:#8A8A8E; --faint:#B4B4B8;
    --line:#EAEAEA; --line2:#F2F2F2; --live:#2E7D32; --alert:#B23B3B; --warm:#eef5ef;
    --sans:-apple-system,BlinkMacSystemFont,"Helvetica Neue","Inter",Arial,sans-serif;
    --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,monospace;
  }
  *{box-sizing:border-box} html,body{margin:0;height:100%}
  body{background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:13px;line-height:1.55;
       -webkit-font-smoothing:antialiased;font-feature-settings:"tnum" 1}
  .lbl{font-size:10.5px;text-transform:uppercase;letter-spacing:.14em;color:var(--dim);font-weight:600}
  .mono{font-family:var(--mono)}
  header{display:flex;align-items:center;gap:22px;height:54px;padding:0 28px;border-bottom:1px solid var(--line);background:var(--surface)}
  header .brand{font-weight:600;letter-spacing:.16em;font-size:12px} header .brand b{font-weight:700} header .brand span{color:var(--faint)}
  header .stat{color:var(--dim);font-size:12px} header .stat b{color:var(--ink);font-weight:600}
  header .right{margin-left:auto;display:flex;align-items:center;gap:18px}
  .clock{color:var(--ink);font-size:12px;letter-spacing:.04em}
  .live{display:inline-flex;align-items:center;gap:7px;color:var(--dim);font-size:12px}
  .live .dot{width:7px;height:7px;border-radius:50%;background:var(--live)} .live.off .dot{background:var(--alert)}
  .netbar{display:flex;gap:8px;align-items:center;padding:7px 28px;height:36px;border-bottom:1px solid var(--line);background:var(--surface);overflow-x:auto;white-space:nowrap}
  .netbar .nl{font-size:10px;text-transform:uppercase;letter-spacing:.12em;color:var(--faint);margin-right:6px;flex:none}
  .badge{display:inline-flex;align-items:baseline;gap:6px;font-size:11.5px;border:1px solid var(--line);border-radius:13px;padding:3px 11px;background:var(--bg);flex:none}
  .badge .bk{color:var(--dim)} .badge .bv{font-weight:700}
  .badge.warn{border-color:#e6c98a;background:#fbf4e3} .badge.warn .bv{color:#9a6b1e}
  .badge.dim,.badge.dim .bv{color:var(--faint)}

  .wrap{display:grid;grid-template-columns:340px 1fr 226px;height:calc(100vh - 90px)}
  .members{border-left:1px solid var(--line);overflow:auto;padding:18px 16px 40px;background:var(--bg)}
  .members .lbl{margin:0 2px 12px}
  .mem{display:flex;align-items:baseline;gap:8px;padding:7px 2px;border-bottom:1px solid var(--line2)}
  .mem .dot{width:6px;height:6px;border-radius:50%;background:var(--ink);flex:none;transform:translateY(-2px)}
  .mem .dot.human{background:var(--alert)}
  .mem .n{font-weight:600;font-size:12.5px} .mem .r{margin-left:auto;color:var(--faint);font-size:11px}
  .roster{border-right:1px solid var(--line);overflow:auto;padding:22px 22px 40px}
  .roster .lbl{margin:22px 2px 12px}.roster .lbl:first-child{margin-top:2px}
  .cli{padding:11px 10px 13px;border-bottom:1px solid var(--line2);cursor:pointer;border-radius:7px;transition:background .25s}
  .cli:hover{background:#fff} .cli.active{background:#fff;box-shadow:inset 3px 0 0 var(--ink)}
  .cli.speaking{animation:pulse 1.1s ease}
  @keyframes pulse{0%{background:var(--warm)}100%{background:transparent}}
  .cli .top{display:flex;align-items:baseline;gap:9px}
  .cli .dot{width:6px;height:6px;border-radius:50%;background:var(--ink);flex:none;transform:translateY(-2px)}
  .cli .dot.human{background:var(--faint)} .cli.speaking .dot{box-shadow:0 0 0 3px var(--warm)}
  .cli .nick{font-weight:600;font-size:13.5px} .cli .idle{margin-left:auto;color:var(--faint);font-size:11px}
  .cli .meta{color:var(--dim);font-size:12px;margin-top:1px}
  .cli .src{color:var(--ink);font-size:12px;margin-top:3px} .cli .src .k{color:var(--faint)}
  .cli .chips{margin-top:5px;color:var(--faint);font-size:11px}

  .chat{display:flex;flex-direction:column;min-width:0;position:relative}
  .filters{display:flex;gap:20px;align-items:center;padding:0 28px;height:46px;border-bottom:1px solid var(--line);background:var(--surface)}
  .f{cursor:pointer;color:var(--dim);font-size:12px;padding-bottom:2px;border-bottom:1.5px solid transparent}
  .f:hover{color:var(--ink)} .f.on{color:var(--ink);border-bottom-color:var(--ink)}
  .nf{margin-left:auto;color:var(--dim);font-size:12px} .nf b{color:var(--ink)} .nf .x{cursor:pointer;color:var(--faint);margin-left:6px}
  .msgs{flex:1;overflow:auto;padding:8px 18px 16px}
  @keyframes enter{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
  .grp{display:flex;gap:11px;padding:6px 8px 5px;border-radius:9px}
  .grp.enter{animation:enter .26s ease}
  .grp:hover{background:#fff} .grp:hover .tm{opacity:1}
  .av{width:30px;height:30px;border-radius:50%;flex:none;display:grid;place-items:center;font-size:10px;font-weight:700;color:#fff;margin-top:2px}
  .gb{min-width:0;flex:1}
  .gh{display:flex;align-items:baseline;gap:8px;margin-bottom:2px}
  .gh .nm{font-weight:700;font-size:13px;cursor:pointer}
  .gh .rl{color:var(--faint);font-size:10.5px}
  .gh .tm{color:var(--faint);font-size:10.5px;opacity:0;transition:opacity .15s;margin-left:auto}
  .ln{font-size:13px;line-height:1.5;white-space:pre-wrap;word-break:break-word;padding:1px 0;color:#22232a}
  .ln.flag{color:var(--alert);font-weight:600}
  .sev{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:7px}
  .tg{cursor:pointer;color:#6f7b93;font-size:11px;margin-left:8px;border-bottom:1px dotted currentColor}
  .tg:hover{color:var(--ink)}
  .think{margin:4px 0 6px;padding:9px 13px;border-left:2px solid var(--line);background:#fff;color:#47474e;font-size:12px;border-radius:0 7px 7px 0;animation:enter .2s ease}
  .sys{display:flex;align-items:center;gap:12px;color:var(--faint);font-size:10px;letter-spacing:.1em;margin:14px 8px 8px}
  .sys::before,.sys::after{content:"";flex:1;height:1px;background:var(--line)}
  .jump{position:absolute;right:26px;bottom:78px;background:var(--ink);color:#fff;font-size:12px;font-weight:600;
        padding:7px 13px;border-radius:16px;cursor:pointer;box-shadow:0 4px 14px rgba(0,0,0,.18);display:none}
  .composer{display:flex;gap:10px;align-items:center;padding:11px 22px;border-top:1px solid var(--line);background:var(--surface)}
  .composer .to{color:var(--dim);font-size:12px;font-weight:600;white-space:nowrap}
  .composer input{flex:1;font-family:var(--sans);font-size:13px;padding:9px 13px;border:1px solid var(--line);border-radius:9px;background:var(--bg)}
  .composer input:focus{outline:none;border-color:var(--ink)}
  .composer button{font-family:var(--sans);font-size:12.5px;font-weight:600;border:1px solid var(--ink);background:var(--ink);color:#fff;padding:9px 16px;border-radius:9px;cursor:pointer}
  .empty{color:var(--faint);padding:48px 0;text-align:center}
</style></head>
<body>
<header>
  <div class="brand"><b>SADDLER</b> <span>/</span> AGENT&nbsp;HUB</div>
  <span class="stat"><b id="na">0</b> agents</span>
  <span class="stat"><b id="nh">0</b> humans</span>
  <span class="stat"><b id="nc">0</b> channels</span>
  <div class="right"><span class="clock mono" id="clock">—</span>
    <span class="live" id="live"><span class="dot"></span>online</span></div>
</header>
<div class="netbar" id="netbar"><span class="nl">network</span></div>
<div class="wrap">
  <div class="roster" id="roster"></div>
  <div class="chat">
    <div class="filters" id="filters"></div>
    <div class="msgs" id="msgs"></div>
    <div class="jump" id="jump"></div>
    <div class="composer">
      <span class="to" id="to">#saddler-debate</span>
      <input id="msg" placeholder="join the room — type to participate…" autocomplete="off">
      <button id="send">send</button>
    </div>
  </div>
  <div class="members" id="members"></div>
</div>
<script>
let FILTER="*", NICK="", LAST={clients:[],channels:{},messages:[]};
let SEEN=new Set(), OPEN=new Set(), LOCK=true, NEW=0, lastSpeaker="";
const esc=s=>(s||"").replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const dur=s=>s<60?s+"s":(s<3600?Math.floor(s/60)+"m":Math.floor(s/3600)+"h");
const hhmm=ts=>new Date(ts*1000).toTimeString().slice(0,8);
const key=m=>m.ts+"|"+m.nick+"|"+(m.body||"").slice(0,24);
const DAYS=["SUN","MON","TUE","WED","THU","FRI","SAT"],MON=["JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"];
function clock(){const d=new Date();document.getElementById("clock").textContent=
  `${DAYS[d.getDay()]} ${String(d.getDate()).padStart(2,"0")} ${MON[d.getMonth()]} ${d.getFullYear()} · ${d.toTimeString().slice(0,8)}`;}
setInterval(clock,1000);clock();

function roster(clients){
  const agents=clients.filter(c=>c.kind==="agent"),humans=clients.filter(c=>c.kind!=="agent");
  const src=c=>{const s=esc(c.source||c.addr);const i=s.indexOf(":");return i>0?`<span class="k">${s.slice(0,i)}:</span>${s.slice(i+1)}`:s;};
  const card=c=>`<div class="cli ${c.nick===NICK?'active':''} ${c.nick===lastSpeaker?'speaking':''}" data-n="${esc(c.nick)}">
      <div class="top"><span class="dot ${c.kind}"></span><span class="nick">${esc(c.nick)}</span><span class="idle">${dur(c.idle_s)} idle</span></div>
      <div class="meta">${esc(c.role||c.kind)}${c.model?" · "+esc(c.model):""}</div>
      <div class="src">${src(c)}</div></div>`;
  document.getElementById("roster").innerHTML=
    `<div class="lbl">Connected — Agents · ${agents.length}</div>`+(agents.map(card).join("")||'<div class="cli meta">none</div>')+
    `<div class="lbl">Humans · ${humans.length}</div>`+(humans.map(card).join("")||'<div class="cli meta">none</div>');
  document.querySelectorAll(".cli[data-n]").forEach(el=>el.onclick=()=>{NICK=(NICK===el.dataset.n)?"":el.dataset.n;render(LAST);});
  document.getElementById("na").textContent=agents.length;document.getElementById("nh").textContent=humans.length;
}
function filters(channels){
  const names=["*",...Object.keys(channels).sort()];
  document.getElementById("filters").innerHTML=names.map(n=>`<span class="f ${n===FILTER?'on':''}" data-c="${esc(n)}">${n==="*"?"all":esc(n)}</span>`).join("")
    +(NICK?`<span class="nf">filtered to <b>${esc(NICK)}</b><span class="x" id="clrn">✕</span></span>`:"");
  document.querySelectorAll(".f").forEach(el=>el.onclick=()=>{FILTER=el.dataset.c;updTo();render(LAST);});
  const x=document.getElementById("clrn"); if(x)x.onclick=()=>{NICK="";render(LAST);};
}
function members(s){
  const chan=FILTER==="*"?null:FILTER;
  const nicks=(chan&&s.channels[chan])?s.channels[chan].members:s.clients.map(c=>c.nick);
  const by={}; s.clients.forEach(c=>by[c.nick]=c);
  const row=n=>{const c=by[n]||{kind:'agent',role:''};
    return `<div class="mem"><span class="dot ${c.kind}"></span><span class="n">${esc(n)}</span><span class="r">${esc(c.role||c.kind||'')}</span></div>`;};
  document.getElementById("members").innerHTML=
    `<div class="lbl">${chan?esc(chan):'in room'} · ${nicks.length}</div>`+(nicks.map(row).join("")||'<div class="mem"><span class="r">empty</span></div>');
}
function updTo(){document.getElementById("to").textContent=(FILTER!=="*"?FILTER:"#saddler-debate");}
const SEVC={CRITICAL:'#B23B3B',HIGH:'#C2632B',MEDIUM:'#A07B2E',LOW:'#8A8A8E',INFO:'#B4B4B8'};
function nhash(n){let h=0;for(let i=0;i<n.length;i++)h=((h*31+n.charCodeAt(i))>>>0);return h%360;}
function ncol(n){return `hsl(${nhash(n)},54%,40%)`;}
function nbg(n){return `hsl(${nhash(n)},44%,48%)`;}
function inits(n){const p=n.split(/[-_]/);return ((p.length>1?p[0][0]+p[1][0]:n.slice(0,2))||'?').toUpperCase();}
function isSys(m){return /-log$/.test(m.channel);}
function roleOf(n){const c=(LAST.clients||[]).find(x=>x.nick===n);return c?(c.role||''):'';}
function lineHTML(m){
  const k=key(m), open=OPEN.has(k), hasT=m.thought&&m.thought.trim();
  const flag=/\[NOW\]|\bCVE-|⛔/.test(m.body);
  const sm=m.body.match(/^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]/);
  const sev=sm?`<span class="sev" style="background:${SEVC[sm[1]]}"></span>`:'';
  return `<div class="ln ${flag?'flag':''}">${sev}${esc(m.body)}`+
    (hasT?` <span class="tg" data-k="${esc(k)}">${open?'hide thought':'thought'}</span>`:'')+`</div>`+
    (hasT&&open?`<div class="think">${esc(m.thought)}</div>`:'');
}
function messages(msgs){
  const box=document.getElementById("msgs");
  const view=msgs.filter(m=>(FILTER==="*"||m.channel===FILTER)&&(!NICK||m.nick===NICK));
  const blocks=[]; let cur=null, fresh=0;
  for(const m of view){
    const isNew=!SEEN.has(key(m)); if(isNew)fresh++;
    if(isSys(m)){blocks.push({sys:m}); cur=null; continue;}
    if(cur&&cur.nick===m.nick&&(m.ts-cur.t0)<300){cur.lines.push(m);cur.isNew=cur.isNew||isNew;}
    else{cur={nick:m.nick,kind:m.kind,lines:[m],t0:m.ts,isNew};blocks.push(cur);}
  }
  const html=blocks.map(b=>{
    if(b.sys) return `<div class="sys">${esc(b.sys.body)}</div>`;
    const human=b.kind==='human', col=human?'var(--alert)':ncol(b.nick), bg=human?'var(--alert)':nbg(b.nick);
    const head=`<div class="gh"><span class="nm" data-n="${esc(b.nick)}" style="color:${col}">${esc(b.nick)}</span>`+
      `<span class="rl">${esc(roleOf(b.nick)||(human?'you':''))}</span><span class="tm">${hhmm(b.lines[0].ts)}</span></div>`;
    return `<div class="grp ${b.isNew?'enter':''}"><div class="av" style="background:${bg}">${esc(inits(b.nick))}</div>`+
      `<div class="gb">${head}${b.lines.map(lineHTML).join("")}</div></div>`;
  }).join("");
  const atBottom=box.scrollHeight-box.scrollTop-box.clientHeight<90;  // stick only if already at bottom
  const prevTop=box.scrollTop;
  box.innerHTML=html||'<div class="empty">no messages yet</div>';
  view.forEach(m=>SEEN.add(key(m)));
  document.querySelectorAll(".tg").forEach(el=>el.onclick=()=>{const k=el.dataset.k;OPEN.has(k)?OPEN.delete(k):OPEN.add(k);messages(LAST.messages);});
  document.querySelectorAll(".gh .nm[data-n]").forEach(el=>el.onclick=()=>{NICK=(NICK===el.dataset.n)?"":el.dataset.n;render(LAST);});
  if(atBottom){box.scrollTop=box.scrollHeight;requestAnimationFrame(()=>{box.scrollTop=box.scrollHeight;});NEW=0;}
  else{box.scrollTop=prevTop;NEW+=fresh;}
  const j=document.getElementById("jump");
  j.style.display=(!atBottom&&NEW>0)?"block":"none"; j.textContent="↓ "+NEW+" new";
}
function render(s){LAST=s;roster(s.clients);filters(s.channels);members(s);messages(s.messages);
  document.getElementById("nc").textContent=s.server.channels;
  if(s.messages.length)lastSpeaker=s.messages[s.messages.length-1].nick;}
async function tick(){const L=document.getElementById("live");
  try{const s=await(await fetch("/api/state")).json();L.classList.remove("off");L.lastChild.textContent="online";render(s);}
  catch(e){L.classList.add("off");L.lastChild.textContent="disconnected";}}

const box=document.getElementById("msgs");
box.addEventListener("scroll",()=>{if(box.scrollHeight-box.scrollTop-box.clientHeight<60){NEW=0;document.getElementById("jump").style.display="none";}});
document.getElementById("jump").onclick=()=>{box.scrollTop=box.scrollHeight;NEW=0;document.getElementById("jump").style.display="none";};
async function send(){const i=document.getElementById("msg");const body=i.value.trim();if(!body)return;i.value="";
  box.scrollTop=box.scrollHeight;
  try{await fetch("/api/say",{method:"POST",headers:{'Content-Type':'application/json'},
    body:JSON.stringify({channel:(FILTER!=="*"?FILTER:"#saddler-debate"),body,nick:"you"})});}catch(e){}
  tick();}
document.getElementById("send").onclick=send;
document.getElementById("msg").addEventListener("keydown",e=>{if(e.key==="Enter")send();});
tick(); setInterval(tick,1400);
async function net(){try{const r=await(await fetch("/api/net")).json();
  document.getElementById("netbar").innerHTML='<span class="nl">network</span>'+
    r.badges.map(b=>`<span class="badge ${b.level}"><span class="bk">${esc(b.label)}</span><span class="bv">${esc(b.value)}</span></span>`).join("")
    +(r.exposed&&r.exposed.length?`<span class="badge warn" title="${esc(r.exposed.join(', '))}"><span class="bk">listening</span><span class="bv">${esc(r.exposed.slice(0,3).join(' '))}${r.exposed.length>3?' +'+(r.exposed.length-3):''}</span></span>`:'')
    +(r.deep?'':'<span class="badge dim" title="grant capture to enable packet dissection">⚑ deep: setcap cap_net_raw+ep tcpdump</span>');
}catch(e){}}
net(); setInterval(net,5000);
</script>
</body></html>
"""
