"""Synchronous IRC client for agent bots.

Usable from the orchestrator's plain (thread-pool) code: connect, declare source,
join, say. A background reader thread answers PINGs and dispatches inbound PRIVMSGs
to an optional callback (used later for human /approve parsing in #approvals).
"""
from __future__ import annotations

import socket
import threading
import time


class Bot:
    def __init__(self, nick, host="127.0.0.1", port=6667, *, role="", model="",
                 source="", kind="agent", password="", on_privmsg=None):
        self.nick = nick
        self.host = host
        self.port = port
        self.role = role
        self.model = model
        self.source = source
        self.kind = kind
        self.password = password
        self.on_privmsg = on_privmsg
        self.sock = None
        self._buf = b""
        self._stop = False
        self._slock = threading.Lock()

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=10)
        self.sock.settimeout(None)  # blocking reads after connect; don't drop idle bots
        # strip CRLF from every field so no value can inject a second IRC command
        clean = lambda s: str(s).replace("\r", "").replace("\n", "")
        rn = f"saddler kind={clean(self.kind)}"
        if self.role:
            rn += f" role={clean(self.role)}"
        if self.model:
            rn += f" model={clean(self.model)}"
        if self.source:
            rn += f" source={clean(self.source).replace(' ', '_')}"
        if self.password:
            self._send(f"PASS {clean(self.password)}")
        self._send(f"NICK {clean(self.nick)}")
        self._send(f"USER {clean(self.nick)} 0 * :{rn}")
        threading.Thread(target=self._loop, daemon=True).start()
        time.sleep(0.3)
        return self

    def _send(self, line):
        with self._slock:  # serialize concurrent posts from the consensus threads
            try:
                self.sock.sendall((line + "\r\n").encode())
            except Exception:
                pass

    @staticmethod
    def _san(s):
        return str(s).replace("\r", "").replace("\n", "")

    def join(self, *channels):
        for ch in channels:
            self._send(f"JOIN {self._san(ch)}")
        time.sleep(0.1)

    def say(self, channel, msg):
        ch = self._san(channel)
        for ln in str(msg).split("\n"):
            if ln.strip():
                self._send(f"PRIVMSG {ch} :{self._san(ln)}")
                time.sleep(0.02)

    def _loop(self):
        while not self._stop:
            try:
                data = self.sock.recv(4096)
            except Exception:
                break
            if not data:
                break
            self._buf += data
            while b"\r\n" in self._buf:
                raw, self._buf = self._buf.split(b"\r\n", 1)
                self._handle(raw.decode("utf-8", "replace"))

    def _handle(self, line):
        if line.startswith("PING"):
            self._send("PONG " + line[5:])
            return
        if " PRIVMSG " in line and self.on_privmsg:
            try:
                prefix, rest = line[1:].split(" PRIVMSG ", 1)
                nick = prefix.split("!", 1)[0]
                target, msg = rest.split(" :", 1)
                self.on_privmsg(nick, target.strip(), msg)
            except Exception:
                pass

    def quit(self):
        self._stop = True
        self._send("QUIT :bye")
        try:
            self.sock.close()
        except Exception:
            pass
