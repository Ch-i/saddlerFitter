"""Stream a consensus run's live deliberation into the IRC hub.

Connects one bot per agent role (orchestrator, a proposer per lens, a verifier per
aspect, an arbiter) and translates the engine's on_event stream into channel posts —
so the hub shows the agents actually reasoning and arguing in real time, and a human
in the channels can interject. The reasoning text comes from the propose/verify/
arbitrate detail events emitted by consensus.run_audit.
"""
from __future__ import annotations

import threading
import time

from .. import config
from ..llm import run_agent
from .bus import Bot

SEP = " ⟪think⟫ "  # splits a shared conclusion from its underlying layers of thought

# Keyword → the verifier the orchestrator routes a human question to (else the arbiter).
ROUTE = [("already", "verf-alrea"), ("handled", "verf-alrea"), ("mitigat", "verf-alrea"),
         ("reach", "verf-reach"), ("exploit", "verf-reach"), ("trigger", "verf-reach"),
         ("impact", "verf-impac"), ("sever", "verf-impac"), ("risk", "verf-impac"),
         ("reproduc", "verf-repro"), ("test", "verf-repro"), ("repro", "verf-repro")]
ROLE_DESC = {"verf-reach": "the reachability/exploitability verifier",
             "verf-alrea": "the already-handled verifier",
             "verf-impac": "the impact/severity verifier",
             "verf-repro": "the reproducibility verifier",
             "arbiter": "the arbiter"}


def _pnick(lens: str) -> str:
    return "prop-" + lens[:4]


def _vnick(aspect: str) -> str:
    return "verf-" + aspect[:5]


class IRCSink:
    def __init__(self, host=None, port=None, password=None):
        self.host = host or config.IRC_HOST
        self.port = port or config.IRC_PORT
        self.password = config.IRC_PASSWORD if password is None else password
        self.bots: dict[str, Bot] = {}
        self.family = ""
        self.findings = []   # accumulated confirmed findings → context for replies
        self.target = ""     # what was audited

    def _spawn(self, nick, role, source):
        # Only the orchestrator answers humans — otherwise every bot that receives
        # the broadcast replies, flooding the channel with identical acks.
        b = Bot(nick, host=self.host, port=self.port, role=role, source=source,
                password=self.password,
                on_privmsg=self._on_msg if nick == "orchestrator" else None).connect()
        b.join(config.CH_FINDINGS, config.CH_DEBATE, config.CH_APPROVALS, config.CH_LOG)
        self.bots[nick] = b
        return b

    def connect(self):
        self._spawn("orchestrator", "orchestrator", "host:local")
        for lens in config.LENSES:
            self._spawn(_pnick(lens), "proposer", f"lens:{lens}")
        for aspect in config.VERIFY_ASPECTS:
            self._spawn(_vnick(aspect), "verifier", f"aspect:{aspect}")
        self._spawn("arbiter", "arbiter", "host:local")
        time.sleep(0.5)
        return self

    def _say(self, nick, chan, msg):
        b = self.bots.get(nick) or self.bots.get("orchestrator")
        if b:
            b.say(chan, msg)

    def _on_msg(self, nick, target, msg):
        if nick in self.bots:  # ignore our own agents
            return
        m = msg.strip()
        if not m:
            return
        if target == config.CH_APPROVALS and m.startswith(("/approve", "/reject")):
            self._say("orchestrator", config.CH_APPROVALS, f"{nick}: recorded — {m}")
            return
        # Route the human's message to a real agent and relay a substantive answer.
        threading.Thread(target=self._reply, args=(nick, target, m), daemon=True).start()

    def _route(self, q):
        ql = q.lower()
        for key, nick in ROUTE:
            if key in ql and nick in self.bots:
                return nick
        return "arbiter"

    def _reply(self, human, chan, question):
        nick = self._route(question)
        self._say("orchestrator", chan, f"{human}: → routing to {nick}")
        fsum = "; ".join(f"[{x['severity']}] {x['title']}" for x in self.findings[-8:]) \
            or "no confirmed findings yet"
        prompt = (f"You are {ROLE_DESC.get(nick, 'the arbiter')} in a multi-agent code-audit "
                  f"panel that reviewed {self.target or 'the code'}. Confirmed findings so far: "
                  f"{fsum}. A human operator ({human}) asks in the channel: \"{question}\". "
                  "Reply concisely (1-3 sentences), substantively, grounded in the audit. "
                  "Plain prose, no preamble, no markdown.")
        ans = ""
        for _ in range(3):  # the reply can collide with the grill's burst of claude calls
            try:
                ans = run_agent(prompt, model=config.CRITIC_MODEL, timeout=70)
                if ans and ans.strip():
                    break
            except Exception as e:
                ans = f"(model error: {e})"
            time.sleep(2)
        ans = " ".join((ans or "").split())[:500]
        self._say(nick, chan, f"{human}: {ans}")

    def event(self, kind, **kw):
        try:
            if kind == "grill_pass":
                self.family = kw.get("family", "")
                self._say("orchestrator", config.CH_LOG, f"── grill pass · {self.family} ──")
            elif kind == "phase":
                self._say("orchestrator", config.CH_LOG, f"layer · {kw.get('phase')}")
            elif kind == "propose_detail":
                for it in kw.get("items", []):
                    self._say(_pnick(kw["lens"]), config.CH_DEBATE,
                              f"candidate: {it['title']}{SEP}{it.get('rationale', '')}")
            elif kind == "evidence":
                self._say("orchestrator", config.CH_DEBATE,
                          f"⚓ non-LLM anchor: {kw.get('anchored', 0)} candidate(s) corroborated")
            elif kind == "verify_detail":
                mark = {"confirmed": "✓", "refuted": "✗"}.get(kw["verdict"], "?")
                self._say(_vnick(kw["aspect"]), config.CH_DEBATE,
                          f"[{kw['fid']}] {kw['aspect']} {mark}{SEP}{kw.get('reason') or ''}")
            elif kind == "arbitrate_detail":
                if kw["status"] == "confirmed":
                    self.findings.append({"severity": str(kw.get("severity", "")).upper(),
                                          "title": kw.get("title", "")})
                    self._say("arbiter", config.CH_FINDINGS,
                              f"[{str(kw['severity']).upper()}] {kw['title']}{SEP}{kw.get('summary') or ''}")
                elif kw["status"] == "needs_human":
                    self._say("arbiter", config.CH_APPROVALS,
                              f"[{kw['fid']}] needs review: {kw['title']} — reply /approve {kw['fid']}")
            elif kind == "done":
                self._say("orchestrator", config.CH_LOG,
                          f"= {kw.get('confirmed', 0)} confirmed · {kw.get('escalated', 0)} escalated")
        except Exception:
            pass

    def close(self):
        for b in self.bots.values():
            try:
                b.quit()
            except Exception:
                pass
