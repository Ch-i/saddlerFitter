"""Minimal asyncio IRC server with an introspectable roster.

Speaks enough of the protocol for real clients (NICK/USER/CAP/JOIN/PART/PRIVMSG/
NOTICE/PING/NAMES/WHO/QUIT) and for the saddler bus client. Agents declare their
source in the USER realname as `saddler kind=agent role=… model=… source=…`, which
the hub parses into the roster the dashboard renders.
"""
from __future__ import annotations

import threading
import time
from collections import deque

from .. import config

SERVER = "saddler.hub"
THOUGHT_SEP = " ⟪think⟫ "  # conclusion ⟪think⟫ layers-of-thought (parsed for the dashboard)


class Client:
    def __init__(self, reader, writer, addr):
        self.reader = reader
        self.writer = writer
        self.addr = addr
        self.nick = None
        self.user = None
        self.realname = ""
        self.passwd = None
        self.registered = False
        self.channels: set[str] = set()
        self.connected_at = time.time()
        self.last = time.time()
        self.kind = "human"
        self.role = ""
        self.model = ""
        self.source = ""

    def parse_meta(self):
        rn = self.realname or ""
        kv = {}
        for tok in rn.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                kv[k] = v.replace("_", " ")
        if kv.get("role") or kv.get("kind") == "agent" or rn.lower().startswith("saddler"):
            self.kind = "agent"
        self.role = kv.get("role", self.role)
        self.model = kv.get("model", self.model)
        self.source = kv.get("source") or kv.get("host") or self.source
        if self.kind == "human" and not self.source:
            self.source = rn

    def host(self):
        return self.addr[0] if self.addr else "local"

    def prefix(self):
        return f"{self.nick}!{self.user or self.nick}@{self.host()}"


class Hub:
    def __init__(self, ledger=None, on_message=None):
        self.clients: dict[str, Client] = {}
        self.channels: dict[str, set[str]] = {}
        self.topics: dict[str, str] = {}
        self.messages = deque(maxlen=500)
        self.lock = threading.Lock()
        self.ledger = ledger
        self.on_message = on_message
        self.started_at = time.time()

    # ---- connection lifecycle ----
    async def on_connect(self, reader, writer):
        c = Client(reader, writer, writer.get_extra_info("peername"))
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                line = data.decode("utf-8", "replace").rstrip("\r\n")
                c.last = time.time()
                if line:
                    await self.dispatch(c, line)
                    try:
                        await writer.drain()
                    except Exception:
                        pass
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception:
            pass
        finally:
            self.cleanup(c)

    def send(self, c, line):
        try:
            c.writer.write((line + "\r\n").encode())
        except Exception:
            pass

    async def dispatch(self, c, line):
        if " :" in line:
            pre, trail = line.split(" :", 1)
            args = pre.split() + [trail]
        else:
            args = line.split()
        if not args:
            return
        cmd = args[0].upper()
        params = args[1:]
        handler = getattr(self, "cmd_" + cmd.lower(), None)
        if handler:
            handler(c, params)

    # ---- commands ----
    def cmd_pass(self, c, params):
        if params:
            c.passwd = params[0]

    def cmd_cap(self, c, params):
        if params and params[0].upper() == "LS":
            self.send(c, f":{SERVER} CAP * LS :")

    def cmd_nick(self, c, params):
        if not params:
            return
        new = params[0].replace("\r", "").replace("\n", "")
        if not new:
            return
        with self.lock:
            if new in self.clients and self.clients[new] is not c:
                self.send(c, f":{SERVER} 433 * {new} :Nickname is already in use")
                return
            old = c.nick
            c.nick = new
            if old and old in self.clients and self.clients[old] is c:
                del self.clients[old]
            if c.registered:
                self.clients[new] = c
                # keep channel membership in sync with the new nick — otherwise the
                # channel sets reference a nick that no longer routes to this client.
                for chan in c.channels:
                    members = self.channels.get(chan)
                    if members is not None and old in members:
                        members.discard(old)
                        members.add(new)
        self._maybe_register(c)

    def cmd_user(self, c, params):
        if params:
            c.user = params[0]
        c.realname = params[-1] if len(params) >= 4 else (params[-1] if params else "")
        c.parse_meta()
        self._maybe_register(c)

    def _maybe_register(self, c):
        if c.registered or not c.nick or c.user is None:
            return
        if config.IRC_PASSWORD and c.passwd != config.IRC_PASSWORD:
            self.send(c, f":{SERVER} 464 {c.nick} :Password incorrect")
            try:
                c.writer.close()
            except Exception:
                pass
            return
        with self.lock:
            self.clients[c.nick] = c
        c.registered = True
        self.send(c, f":{SERVER} 001 {c.nick} :Welcome to the saddler hub, {c.nick}")
        self.send(c, f":{SERVER} 002 {c.nick} :Your host is {SERVER}")
        self.send(c, f":{SERVER} 003 {c.nick} :This is the saddler agent bus")
        self.send(c, f":{SERVER} 004 {c.nick} {SERVER} saddler-0.1 o o")
        self.send(c, f":{SERVER} 375 {c.nick} :- {SERVER} message of the day -")
        self.send(c, f":{SERVER} 372 {c.nick} :- humans and agents co-inhabit; reads open, writes human-gated")
        self.send(c, f":{SERVER} 376 {c.nick} :End of MOTD")
        if self.ledger:
            self.ledger.agent_connected(c.nick, c.kind, c.role, c.model, c.source)

    def cmd_join(self, c, params):
        if not c.registered or not params:
            return
        for chan in params[0].split(","):
            chan = chan.strip()
            if not chan:
                continue
            with self.lock:
                self.channels.setdefault(chan, set()).add(c.nick)
                c.channels.add(chan)
                members = sorted(self.channels[chan])
            self._broadcast(chan, f":{c.prefix()} JOIN {chan}")
            topic = self.topics.get(chan)
            if topic:
                self.send(c, f":{SERVER} 332 {c.nick} {chan} :{topic}")
            self.send(c, f":{SERVER} 353 {c.nick} = {chan} :{' '.join(members)}")
            self.send(c, f":{SERVER} 366 {c.nick} {chan} :End of NAMES")

    def cmd_part(self, c, params):
        if not params:
            return
        chan = params[0]
        self._broadcast(chan, f":{c.prefix()} PART {chan}")
        with self.lock:
            self.channels.get(chan, set()).discard(c.nick)
            c.channels.discard(chan)

    def cmd_privmsg(self, c, params, kind="PRIVMSG"):
        if len(params) < 2 or not c.registered:
            return
        target, body = params[0], params[1]
        self._record(target, c.nick, c.kind, body)
        line = f":{c.prefix()} {kind} {target} :{body}"
        if target.startswith(("#", "&")):
            self._broadcast(target, line, exclude=c.nick)
        else:
            with self.lock:
                dest = self.clients.get(target)
            if dest:
                self.send(dest, line)
        if self.on_message:
            try:
                self.on_message(c.nick, target, body)
            except Exception:
                pass

    def cmd_notice(self, c, params):
        self.cmd_privmsg(c, params, kind="NOTICE")

    def cmd_ping(self, c, params):
        token = params[0] if params else SERVER
        self.send(c, f":{SERVER} PONG {SERVER} :{token}")

    def cmd_pong(self, c, params):
        pass

    def cmd_names(self, c, params):
        chan = params[0] if params else ""
        with self.lock:
            members = sorted(self.channels.get(chan, set()))
        self.send(c, f":{SERVER} 353 {c.nick} = {chan} :{' '.join(members)}")
        self.send(c, f":{SERVER} 366 {c.nick} {chan} :End of NAMES")

    def cmd_who(self, c, params):
        chan = params[0] if params else ""
        with self.lock:
            members = list(self.channels.get(chan, set()))
            clients = dict(self.clients)
        for nick in members:
            cl = clients.get(nick)
            if cl:
                self.send(c, f":{SERVER} 352 {c.nick} {chan} {cl.user} {cl.host()} "
                             f"{SERVER} {nick} H :0 {cl.realname}")
        self.send(c, f":{SERVER} 315 {c.nick} {chan} :End of WHO")

    def cmd_topic(self, c, params):
        if len(params) >= 2:
            chan, topic = params[0], params[1]
            self.topics[chan] = topic
            self._broadcast(chan, f":{c.prefix()} TOPIC {chan} :{topic}")

    def cmd_mode(self, c, params):
        pass

    def cmd_quit(self, c, params):
        self.cleanup(c, announce=params[0] if params else "Client quit")

    # ---- helpers ----
    def _broadcast(self, chan, line, exclude=None):
        with self.lock:
            members = list(self.channels.get(chan, set()))
            clients = dict(self.clients)
        for nick in members:
            if nick == exclude:
                continue
            cl = clients.get(nick)
            if cl:
                self.send(cl, line)

    def _record(self, channel, nick, kind, body):
        thought = ""
        if THOUGHT_SEP in body:
            body, thought = body.split(THOUGHT_SEP, 1)
        m = {"ts": time.time(), "channel": channel, "nick": nick, "kind": kind,
             "body": body, "thought": thought}
        with self.lock:
            self.messages.append(m)
        if self.ledger:
            self.ledger.record_message(channel, nick, kind, body, m["ts"])

    def inject(self, nick, channel, body):
        """Inject a human message from the dashboard into a channel (and to agents)."""
        nick = (nick or "you").replace(" ", "_")[:24]
        body = (body or "")[:400]
        self._record(channel, nick, "human", body)
        self._broadcast(channel, f":{nick}!web@dashboard PRIVMSG {channel} :{body}")

    def cleanup(self, c, announce="Connection closed"):
        if not c.nick:
            return
        for chan in list(c.channels):
            self._broadcast(chan, f":{c.prefix()} QUIT :{announce}", exclude=c.nick)
            with self.lock:
                self.channels.get(chan, set()).discard(c.nick)
        with self.lock:
            if self.clients.get(c.nick) is c:
                del self.clients[c.nick]
        if c.registered and self.ledger:
            self.ledger.agent_disconnected(c.nick)
        c.registered = False
        try:
            c.writer.close()
        except Exception:
            pass

    def snapshot(self):
        now = time.time()
        with self.lock:
            clients = []
            for c in set(self.clients.values()):
                clients.append({
                    "nick": c.nick,
                    "kind": c.kind,
                    "role": c.role,
                    "model": c.model,
                    "source": c.source or c.host(),
                    "realname": c.realname,
                    "addr": c.host(),
                    "channels": sorted(c.channels),
                    "connected_s": round(now - c.connected_at),
                    "idle_s": round(now - c.last),
                })
            channels = {
                n: {"members": sorted(m), "topic": self.topics.get(n, "")}
                for n, m in self.channels.items()
            }
            messages = list(self.messages)
        return {
            "server": {
                "name": SERVER,
                "uptime_s": round(now - self.started_at),
                "clients": len(clients),
                "channels": len(channels),
            },
            "clients": sorted(clients, key=lambda x: (x["kind"] != "agent", x["nick"])),
            "channels": channels,
            "messages": messages,
        }
