"""The research ingest database — saddlerFitter's growing memory.

This is the store that lets the platform *learn over time*. Three concerns share one
sqlite file:

1. **Autoresearch ingest** — `sources` + `documents` + `candidate_rules`. Researched
   best-practice material is distilled into candidate rules that, once a human promotes
   them, are appended to `knowledge/rules.yaml`. The catalog grows under curation.
2. **Watch ledger** — `advisories_seen`. The scheduled CVE/disclosure watch records
   every advisory it has acted on, so a given advisory signals exactly once.
3. **Signals & tickets** — `signals` + `tickets`. A new relevant advisory raises a
   signal; the signal is triaged and becomes a ticket (locally and, optionally, a real
   GitHub issue), carrying the fix plan and a human-auditor recommendation when warranted.

Stdlib only. The DB path defaults to research/state/research.sqlite (gitignored) and is
overridable with SADDLER_RESEARCH_DB.
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(_HERE, "state", "research.sqlite")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY, url TEXT, title TEXT, kind TEXT,
  sha TEXT UNIQUE, fetched_at TEXT, status TEXT DEFAULT 'fetched'
);
CREATE TABLE IF NOT EXISTS documents (
  id INTEGER PRIMARY KEY, source_id INTEGER, chunk TEXT, distilled TEXT
);
CREATE TABLE IF NOT EXISTS candidate_rules (
  id INTEGER PRIMARY KEY, slug TEXT, title TEXT, lens TEXT, severity TEXT,
  cwe TEXT, owasp TEXT, uk TEXT, detect TEXT, recommendation TEXT,
  source_id INTEGER, rationale TEXT,
  status TEXT DEFAULT 'pending',   -- pending | approved | rejected | promoted
  created_at TEXT, decided_by TEXT
);
CREATE TABLE IF NOT EXISTS advisories_seen (
  advisory_id TEXT PRIMARY KEY, aliases TEXT, component TEXT, ecosystem TEXT,
  first_seen TEXT, last_seen TEXT, feed_severity TEXT, status TEXT DEFAULT 'seen'
);
CREATE TABLE IF NOT EXISTS signals (
  id INTEGER PRIMARY KEY, kind TEXT, ref TEXT, component TEXT, severity TEXT,
  summary TEXT, payload TEXT, created_at TEXT,
  status TEXT DEFAULT 'open',      -- open | triaged | ticketed | closed
  escalate_human INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tickets (
  id INTEGER PRIMARY KEY, signal_id INTEGER, title TEXT, body TEXT,
  severity TEXT, urgency TEXT, fix_plan TEXT,
  recommend_human_auditor INTEGER DEFAULT 0, human_auditor_reason TEXT,
  external_ref TEXT, status TEXT DEFAULT 'open', created_at TEXT
);
"""


class Store:
    def __init__(self, path: str | None = None):
        self.path = path or os.environ.get("SADDLER_RESEARCH_DB", DEFAULT_DB)
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with self._con() as c:
            c.executescript(_SCHEMA)

    @contextmanager
    def _con(self):
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()

    # --- watch dedup -----------------------------------------------------------
    def is_advisory_new(self, advisory_id: str) -> bool:
        with self._con() as c:
            return c.execute("SELECT 1 FROM advisories_seen WHERE advisory_id=?",
                             (advisory_id,)).fetchone() is None

    def record_advisory(self, advisory_id, aliases, component, ecosystem, feed_severity, now):
        with self._con() as c:
            c.execute(
                "INSERT INTO advisories_seen(advisory_id,aliases,component,ecosystem,"
                "first_seen,last_seen,feed_severity) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(advisory_id) DO UPDATE SET last_seen=excluded.last_seen",
                (advisory_id, json.dumps(aliases or []), component, ecosystem,
                 now, now, feed_severity),
            )

    # --- signals ---------------------------------------------------------------
    def add_signal(self, kind, ref, component, severity, summary, payload, now, escalate=False) -> int:
        with self._con() as c:
            cur = c.execute(
                "INSERT INTO signals(kind,ref,component,severity,summary,payload,created_at,escalate_human)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (kind, ref, component, severity, summary, json.dumps(payload), now, int(escalate)),
            )
            return cur.lastrowid

    def set_signal_status(self, signal_id, status):
        with self._con() as c:
            c.execute("UPDATE signals SET status=? WHERE id=?", (status, signal_id))

    def open_signals(self) -> list[dict]:
        with self._con() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM signals WHERE status!='closed' ORDER BY id DESC")]

    # --- tickets ---------------------------------------------------------------
    def add_ticket(self, signal_id, title, body, severity, urgency, fix_plan,
                   recommend_human, human_reason, external_ref, now) -> int:
        with self._con() as c:
            cur = c.execute(
                "INSERT INTO tickets(signal_id,title,body,severity,urgency,fix_plan,"
                "recommend_human_auditor,human_auditor_reason,external_ref,created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (signal_id, title, body, severity, urgency, json.dumps(fix_plan),
                 int(recommend_human), human_reason, external_ref, now),
            )
            return cur.lastrowid

    def tickets(self, status=None) -> list[dict]:
        q = "SELECT * FROM tickets" + (" WHERE status=?" if status else "") + " ORDER BY id DESC"
        with self._con() as c:
            return [dict(r) for r in (c.execute(q, (status,)) if status else c.execute(q))]

    # --- autoresearch ingest ---------------------------------------------------
    def add_source(self, url, title, kind, sha, now) -> int | None:
        with self._con() as c:
            try:
                cur = c.execute(
                    "INSERT INTO sources(url,title,kind,sha,fetched_at) VALUES (?,?,?,?,?)",
                    (url, title, kind, sha, now))
                return cur.lastrowid
            except sqlite3.IntegrityError:
                return None  # already ingested (sha unique)

    def add_candidate_rule(self, rule: dict, source_id, rationale, now) -> int:
        with self._con() as c:
            cur = c.execute(
                "INSERT INTO candidate_rules(slug,title,lens,severity,cwe,owasp,uk,detect,"
                "recommendation,source_id,rationale,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (rule.get("id"), rule.get("title"), rule.get("lens"), rule.get("severity"),
                 json.dumps(rule.get("cwe") or []), json.dumps(rule.get("owasp") or {}),
                 json.dumps(rule.get("uk") or {}), json.dumps(rule.get("detect") or []),
                 (rule.get("recommendation") or "").strip(), source_id, rationale, now))
            return cur.lastrowid

    def candidates(self, status="pending") -> list[dict]:
        with self._con() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM candidate_rules WHERE status=? ORDER BY id", (status,))]

    def get_candidate(self, cid) -> dict | None:
        with self._con() as c:
            r = c.execute("SELECT * FROM candidate_rules WHERE id=?", (cid,)).fetchone()
            return dict(r) if r else None

    def set_candidate_status(self, cid, status, decided_by=""):
        with self._con() as c:
            c.execute("UPDATE candidate_rules SET status=?, decided_by=? WHERE id=?",
                      (status, decided_by, cid))

    def counts(self) -> dict:
        with self._con() as c:
            out = {}
            for t in ("sources", "candidate_rules", "advisories_seen", "signals", "tickets"):
                out[t] = c.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
            return out
