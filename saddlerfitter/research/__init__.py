"""saddlerFitter research — the learning loop.

Two faces of one growing store (`store.py`):

- **Autoresearch ingest** (`ingest.py`) — distill best-practice sources into candidate
  rules; a human promotes them into `knowledge/rules.yaml`, so the catalog grows.
- **Scheduled watch** (`watch.py`) — poll the latest CVEs and vulnerability disclosures,
  signal on a new relevant hit, research the fix (`ticket.py` + the saddler triage),
  open a ticket, and recommend a professional human auditor when the risk warrants it.

See SCHEDULING.md for how to run the watch on a cron / systemd timer / n8n.
"""
