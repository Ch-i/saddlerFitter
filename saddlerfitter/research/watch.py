"""The scheduled watch — saddlerFitter's standing sentry over new risk.

Run on a schedule (cron / systemd timer / n8n — see SCHEDULING.md). Each cycle:

    poll latest CVEs + vulnerability disclosures
        → dedup against what we've already acted on (advisories_seen)
        → SIGNAL on a genuinely new, relevant hit
        → research the fix (consensus triage, reusing the saddler harness)
        → open a TICKET (locally, and optionally a real GitHub issue)
        → recommend a professional human auditor when the risk warrants it

Two feeds:
- **CVEs against the dependency SBOM** (OSV.dev / NVD) — precise, version-filtered.
- **Vulnerability disclosures** (Atom/RSS advisory feeds) — broader; filtered to entries
  that mention a technology actually in your stack, so the watch stays on-topic.

The dependency-CVE path runs fully offline-of-LLM unless `do_triage=True`; triage and
ticket bodies are the only steps that call the model, and only on a *new* hit.
"""
from __future__ import annotations

import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from .. import config
from ..cve import inventory, sources, triage as cve_triage
from ..cve.watch import default_paths
from . import ticket
from .store import Store


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _emit(on_event, kind, **kw):
    if on_event:
        on_event(kind, **kw)


def run_watch(paths=None, *, do_triage=True, do_tickets=True, gh_repo=None,
              disclosure_feeds=None, store=None, on_event=None) -> dict:
    store = store or Store()
    paths = paths or default_paths()
    now = _now()

    # --- 1. dependency CVEs (OSV against the SBOM) ---------------------------------
    inv = inventory.build_inventory(paths)
    queryable = [c for c in inv if c["ecosystem"] in ("PyPI", "Go", "npm")]
    _emit(on_event, "watch_inventory", total=len(inv), queryable=len(queryable),
          sources=[p.split("/")[-1] for p in paths])

    hits = sources.osv_scan(queryable, on_event=None)
    advisories = _dedup_by_alias(hits)
    new_signals, tickets_made, escalations = [], [], 0

    for h in advisories:
        v, comp = h["vuln"], h["component"]
        aid = v.get("id")
        if not aid or not store.is_advisory_new(aid):
            continue
        store.record_advisory(aid, v.get("aliases"), comp.get("name"),
                              comp.get("ecosystem"), sources.vuln_severity(v), now)
        sev = sources.vuln_severity(v)
        sig_id = store.add_signal("cve", aid, comp.get("name"), sev,
                                  v.get("summary") or "", {"component": comp}, now)
        _emit(on_event, "signal", kind="cve", ref=aid, component=comp.get("name"), severity=sev)
        tri = {}
        if do_triage:
            tri = cve_triage.triage(comp, v)
            store.set_signal_status(sig_id, "triaged")
        if do_tickets:
            sig = {"id": sig_id, "ref": aid, "component": comp.get("name"), "severity": sev,
                   "summary": v.get("summary") or ""}
            res = ticket.open_ticket(store, sig, tri, now, gh_repo=gh_repo)
            tickets_made.append(res)
            escalations += 1 if res["recommend_human_auditor"] else 0
            _emit(on_event, "ticket", **res)
        new_signals.append(aid)

    # --- 2. vulnerability disclosures (Atom/RSS), filtered to our stack -----------
    feeds = disclosure_feeds if disclosure_feeds is not None else _configured_feeds()
    stack_terms = _stack_terms(inv)
    disclosures = 0
    for feed_url in feeds:
        for entry in _poll_feed(feed_url):
            ref = entry["id"]
            if not store.is_advisory_new(ref):
                continue
            text = (entry["title"] + " " + entry["summary"]).lower()
            matched = [t for t in stack_terms if t in text]
            if not matched:
                continue  # not about anything in this stack — skip the noise
            store.record_advisory(ref, [], matched[0], "disclosure", "unknown", now)
            store.add_signal("disclosure", ref, matched[0], "unknown",
                             entry["title"], {"link": entry["link"], "matched": matched}, now)
            _emit(on_event, "signal", kind="disclosure", ref=entry["title"][:80],
                  component=matched[0], severity="review")
            disclosures += 1

    summary = {"new_cve_signals": len(new_signals), "tickets": len(tickets_made),
               "human_auditor_escalations": escalations, "disclosure_signals": disclosures}
    _emit(on_event, "watch_done", **summary)
    return {**summary, "tickets_detail": tickets_made, "store_counts": store.counts()}


def _dedup_by_alias(hits: list[dict]) -> list[dict]:
    hits.sort(key=lambda h: sources.severity_rank(sources.vuln_severity(h["vuln"])), reverse=True)
    seen: set = set()
    out = []
    for h in hits:
        v = h["vuln"]
        ids = ({v.get("id")} | set(v.get("aliases") or [])) - {None}
        if ids & seen:
            continue
        seen |= ids
        out.append(h)
    return out


def _stack_terms(inv: list[dict]) -> set[str]:
    """Technology names from the SBOM, used to keep disclosure feeds on-topic."""
    terms = set()
    for c in inv:
        for key in ("component", "name"):
            v = (c.get(key) or "").lower().strip()
            if len(v) >= 4:
                terms.add(v)
    return terms


def _configured_feeds() -> list[str]:
    import os
    raw = os.environ.get("SADDLER_DISCLOSURE_FEEDS", "")
    return [u.strip() for u in raw.split(",") if u.strip()]


def _poll_feed(url: str) -> list[dict]:
    """Minimal Atom/RSS reader (stdlib). Returns [{id,title,link,summary}]."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "saddlerFitter-watch"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            root = ET.fromstring(resp.read())
    except Exception:
        return []
    out = []
    # Atom: <entry>; RSS: <item>
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag not in ("entry", "item"):
            continue
        get = lambda n: next((c.text for c in el if c.tag.rsplit("}", 1)[-1] == n and c.text), "")
        link = get("link") or next((c.get("href") for c in el
                                    if c.tag.rsplit("}", 1)[-1] == "link" and c.get("href")), "")
        out.append({"id": get("id") or get("guid") or link or get("title"),
                    "title": get("title"), "link": link,
                    "summary": get("summary") or get("description") or ""})
    return out
