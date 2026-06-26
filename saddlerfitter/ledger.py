"""SQLite ledger — the saddler's source of truth. IRC mirrors it, never replaces it.

Self-contained at saddler/state/saddler.sqlite so the harness owns its own
operational state (findings, advisories, the human accept-queue, the agent roster,
and the chat log) independently of the reports DB.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

_DEFAULT = Path(__file__).resolve().parent / "state" / "saddler.sqlite"

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, channel TEXT, nick TEXT, kind TEXT, body TEXT
);
CREATE TABLE IF NOT EXISTS agents(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nick TEXT, kind TEXT, role TEXT, model TEXT, source TEXT,
  connected_at REAL, disconnected_at REAL
);
CREATE TABLE IF NOT EXISTS findings(
  fid TEXT, run_id TEXT, target TEXT, severity TEXT, title TEXT,
  status TEXT, confidence REAL, rationale TEXT, fix TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS advisories(
  id TEXT, package TEXT, version TEXT, ecosystem TEXT, urgency TEXT,
  severity TEXT, summary TEXT, status TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS accept_queue(
  item_id TEXT PRIMARY KEY, kind TEXT, summary TEXT, status TEXT,
  decided_by TEXT, decided_at REAL, created_at REAL
);
CREATE TABLE IF NOT EXISTS constraints(
  id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT, rationale TEXT,
  source TEXT, active INTEGER, created_at REAL
);
"""


class Ledger:
    def __init__(self, path=None):
        self.path = str(path or _DEFAULT)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.executescript(SCHEMA)
        self.db.commit()

    def _w(self, sql, args=()):
        with self._lock:
            self.db.execute(sql, args)
            self.db.commit()

    # --- chat + roster (written by the IRC hub) ---
    def record_message(self, channel, nick, kind, body, ts=None):
        self._w(
            "INSERT INTO messages(ts,channel,nick,kind,body) VALUES(?,?,?,?,?)",
            (ts or time.time(), channel, nick, kind, body),
        )

    def agent_connected(self, nick, kind, role, model, source, ts=None):
        self._w(
            "INSERT INTO agents(nick,kind,role,model,source,connected_at) VALUES(?,?,?,?,?,?)",
            (nick, kind, role, model, source, ts or time.time()),
        )

    def agent_disconnected(self, nick, ts=None):
        self._w(
            "UPDATE agents SET disconnected_at=? WHERE nick=? AND disconnected_at IS NULL",
            (ts or time.time(), nick),
        )

    # --- findings / advisories / approvals (written by audit + cve, gated by humans) ---
    def record_finding(self, f: dict, run_id: str, target: str):
        self._w(
            "INSERT INTO findings(fid,run_id,target,severity,title,status,confidence,"
            "rationale,fix,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (f.get("fid"), run_id, target, f.get("severity"), f.get("title"),
             f.get("status"), f.get("confidence"), f.get("rationale"),
             f.get("suggested_fix"), time.time()),
        )

    def record_advisory(self, a: dict):
        c = a.get("component", {}) or {}
        self._w(
            "INSERT INTO advisories(id,package,version,ecosystem,urgency,severity,"
            "summary,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (a.get("id"), c.get("name"), c.get("version"), c.get("ecosystem"),
             a.get("urgency"), a.get("severity"), a.get("summary"), "pending", time.time()),
        )

    def enqueue(self, item_id, kind, summary):
        self._w(
            "INSERT OR REPLACE INTO accept_queue(item_id,kind,summary,status,created_at) "
            "VALUES(?,?,?,?,?)",
            (item_id, kind, summary, "pending", time.time()),
        )

    def decide(self, item_id, status, decided_by):
        self._w(
            "UPDATE accept_queue SET status=?,decided_by=?,decided_at=? WHERE item_id=?",
            (status, decided_by, time.time(), item_id),
        )

    # --- reads (for the cockpit / dashboard) ---
    def recent_messages(self, limit=200):
        with self._lock:
            cur = self.db.execute(
                "SELECT ts,channel,nick,kind,body FROM messages ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()
        return [
            {"ts": r[0], "channel": r[1], "nick": r[2], "kind": r[3], "body": r[4]}
            for r in reversed(rows)
        ]

    def pending_queue(self):
        with self._lock:
            cur = self.db.execute(
                "SELECT item_id,kind,summary,status FROM accept_queue WHERE status='pending'"
            )
            return [
                {"item_id": r[0], "kind": r[1], "summary": r[2], "status": r[3]}
                for r in cur.fetchall()
            ]
