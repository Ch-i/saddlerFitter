# saddlerFitter — what it is, and what its role is

**saddlerFitter is a code-quality and security platform: a harness — a team of LLM agents
that audit code by cross-family consensus and gate commits — with two companion parts,
`knowledge` (a UK-best-practice rule catalog) and `research` (an autoresearch watch over
CVEs and disclosures that learns over time). Every finding is surfaced through a
human-in-the-loop IRC hub — gated so nothing lands without a human `/approve`.**

The name is literal: a saddler fits the saddle to horse and rider so the two move as one —
human + machine. The team of agents does the tireless, parallel, adversarial work; the
human stays in the loop and holds the authority. *The harness is the product* (the central
finding of the agent-harness literature it's built on; see `docs/RESEARCH_BRIEF.md`).

> Run it deliberately, not in an unbounded loop. Every audit/grill/reply makes real
> Claude **and** Codex CLI calls; a continuous loop will exhaust your model session
> quota (it did, during development). It's a tool you invoke, plus watches you
> schedule — never a thing left spinning.

---

## Its role, in one breath

Hold **code quality and security steady** alongside a human operator:
1. **Audit** changed code by consensus and gate commits on it.
2. **Watch** the stack — published CVEs against the SBOM, live network exposure.
3. **Surface** it all in a room where humans and agents co-inhabit, with the human
   approving any action.

---

## The pieces (all built, in this repo)

Paths are relative to the package root: the harness modules sit at the top level, the
catalog in `knowledge/`, the learning loop in `research/`.

| Part | Component | File(s) | Role |
|---|---|---|---|
| harness | **Consensus auditor** | `consensus.py` `agents.py` `evidence.py` | propose (per-lens) → non-LLM AST evidence anchor → blind aspect-diverse verifiers → arbiter (keep / drop / escalate-to-human) |
| harness | **Cross-family gate** | `grill.py` | audits a diff with **two model families** (Claude + Codex, both local-auth); blocks a push on a confirmed high/critical from *either*. Installs as a `pre-push` hook via `saddler init` |
| harness | **LLM backends** | `llm.py` | shells the local `claude -p` and `codex exec` CLIs — the "locally authenticated" seam (no API keys) |
| harness | **Network watch** | `netwatch.py` | privilege-free exposure badges from `ss` + `/proc`; opt-in tcpdump/Wireshark deep capture once `cap_net_raw` is granted |
| harness | **IRC hub + dashboard** | `irc/` | self-contained IRC server + dashboard; agents stream live deliberation, a human participates, the orchestrator **routes the message to the right agent for a real answer** |
| harness | **Checks viewer** | `checks/` | a GitHub-Actions-style surface: each flag is a check with an expandable action path, thought, logs, and per-flag `Fix` / `Grill` triggers |
| harness | **Ledger** | `ledger.py` | sqlite source of truth (findings · advisories · roster · chat). IRC mirrors it |
| knowledge | **Rule catalog** | `knowledge/rules.yaml` `__init__.py` | CWE/OWASP/UK-framework rules that drive detection + phrase recommendations; builds a queryable SQLite DB |
| research | **Watch → ticket** | `research/watch.py` `ticket.py` | poll CVEs + disclosures → signal → consensus triage → ticket → human-auditor escalation |
| research | **Autoresearch ingest** | `research/ingest.py` `store.py` | distil best-practice sources into candidate rules; a human promotes them so the catalog **grows over time** |

## How you run it

```bash
saddler audit <file|--diff REF>     # consensus audit, one target
saddler grill <file> [--irc]        # cross-family double-grill (stream to the hub)
saddler knowledge show              # the best-practice rule catalog
saddler watch                       # poll CVEs + disclosures → signal → triage → ticket
saddler research ingest <url|file|-> # grow the catalog from a best-practice source
saddler hub                         # IRC server + dashboard (:6667 / :8198)
saddler init                        # embed the pre-push gate into the current repo
```

`SADDLER_*` env vars override everything (models, lenses, aspects, gate severity,
bind host, IRC password, capture interface…). Defaults are safe: the hub binds
loopback and refuses to expose a writable IRC server without `SADDLER_IRC_PASSWORD`.

## Design principles (from the literature)

- **Generator → blind verifier, not debate** — debate drifts toward agreement, not
  truth. Verifiers are independent and **aspect-diverse**.
- **Decorrelate by model family** — a same-family panel carries few effective votes;
  the gate runs Claude *and* Codex.
- **Anchor in execution** — a finding a tool corroborates is high-precision; one it
  doesn't is a *hypothesis*.
- **Escalate on split, never silent-drop** a contested serious finding.
- **Precision over recall**; **one concern per change**; **human gate on anything
  irreversible** (reads open, writes gated).

## Security posture (and how it was earned)

The cross-family gate was run on **this harness's own code** during development and
**blocked it on real high-severity findings** — an arbitrate-phase crash, second-
order prompt injection, an unauthenticated IRC control channel, an unauthenticated
dashboard — all fixed before the core was committed. Current defaults:

- LLM auth is the **local CLIs only** — no API keys handled.
- The IRC server is **loopback by default**; exposing it requires a password
  (`PASS`), and the dashboard then requires a token. Fail-closed.
- The curator/redaction discipline keeps hostnames/paths/tokens out of user-facing
  output.

## Roadmap / known TODOs

- **#4 approval-gate authorization** — channel-level write-authz on `#approvals`
  (only operators issue a valid `/approve`). *This is the remaining IRC security
  item the gate flagged; do it before exposing the hub beyond loopback.*
- **#5 revise → commit/push** — turn an approved finding into a minimal patch on a
  worker branch → re-grill → PR.
- **#7 Merge-Readiness Packs**, **#8 self-improvement** (learn from accept/reject),
  **#10 doc-drift detection**, **#11 self-maintenance**, **#12 scheduled watches**.

See `ARCHITECTURE.md` for the full design of record and `docs/RESEARCH_BRIEF.md` for
the cited agent-harness literature.
