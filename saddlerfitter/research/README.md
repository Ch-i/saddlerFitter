# saddlerfitter.research — the learning loop

The part that makes saddlerFitter **grow over time**. One sqlite store
([`store.py`](./store.py)), two jobs.

## 1. Scheduled watch (`watch.py`) — standing sentry over new risk

```
saddler watch
```

```
poll latest CVEs (OSV/NVD vs your SBOM) + vulnerability disclosures (Atom/RSS)
   → dedup vs advisories_seen      (signal each advisory exactly once)
   → SIGNAL on a new, relevant hit
   → research the fix              (consensus triage, reusing the saddlerFitter harness)
   → open a TICKET                 (local; + a GitHub issue with --gh-repo)
   → recommend a professional human auditor when the risk warrants it
```

Run it on a timer — see [SCHEDULING.md](./SCHEDULING.md) (systemd / cron / n8n). It is
idempotent: a cycle with nothing new is essentially free and makes no model calls.

- `saddler watch --no-triage` — fast, model-free; just record new signals.
- `saddler watch --gh-repo owner/repo` — also file a real GitHub issue per ticket
  (escalations get a `needs-human-auditor` label).
- `saddler research signals` / `saddler research tickets` — review what the watch found.

### When it calls a human

saddlerFitter knows its limits. A ticket is flagged **recommend a professional human
auditor** when a serious (high/critical) advisory also has no clean fix, an unsafe/uncertain
fix, confirmed exploitability in your deployment, a high-blast-radius (unpinned) component,
or immediate urgency. The harness assists; it does not sign off on the hard cases alone.

## 2. Autoresearch ingest (`ingest.py`) — grow the rule catalog

```
saddler research ingest <url|file|-> --profile "python web api on k8s"
saddler research candidates
saddler research promote --id 7      # human-gated: appends to knowledge/rules.yaml
```

Distil a best-practice source (a new CWE, an OWASP/NCSC update, a hardening guide) into
**candidate rules** in the catalog's own schema, deduplicated against what's already
known, parameterised by your project profile so they stay relevant. A human **promotes**
a candidate, at which point it is appended to [`../knowledge/rules.yaml`](../knowledge/rules.yaml)
and every future audit has learned it. Machine-distilled rules never enter the catalog
unreviewed — that keeps the precision-first guarantee while still letting the platform
grow.

## The store

`research.sqlite` (gitignored): `sources` · `documents` · `candidate_rules` ·
`advisories_seen` · `signals` · `tickets`. Override the path with `SADDLER_RESEARCH_DB`.
