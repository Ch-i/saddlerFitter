# saddlerFitter — Architecture (design of record)

saddlerFitter is a **harness** — the consensus audit engine, gate, and IRC hub described
below — with two companion parts: **`knowledge`** (the rule catalog) and **`research`**
(the autoresearch watch + ingest learning loop, §9). This document is the design of record
for the harness and how the parts compose.

Grounded in the agent-harness literature ([`docs/RESEARCH_BRIEF.md`](./docs/RESEARCH_BRIEF.md)).
The model is a swappable component; **the harness is the product** (SWE-agent roughly
doubled SWE-bench by redesigning the agent–computer interface, arXiv:2405.15793).

## 1. The harness, five parts

The literature decomposes a harness into **control loop · tool interface ·
memory/context · verification · environment** (arXiv:2603.25723, arXiv:2604.03515).
saddlerFitter's mapping:

| Part | saddlerFitter |
|---|---|
| Control loop | `consensus.run_audit` — propose → evidence → verify → arbitrate; a reactive pipeline, not tree search (Agentless arXiv:2407.01489) |
| Tool interface | `llm.run` over the local `claude -p` and `codex exec` CLIs — the "locally authenticated" seam (no API keys) |
| Knowledge | the [rule catalog](./knowledge/) (CWE/OWASP/UK frameworks) drives detection and recommendation; the sqlite **ledger** is the runtime source of truth |
| Verification | blind, aspect-diverse verifiers + a non-LLM evidence anchor; a confirmed finding is escalated, never silently dropped, when serious and contested |
| Environment | read-only audit by default; any code mutation goes to an isolated worker clone with a human gate before it lands |

## 2. The consensus engine (built)

```
            ┌─ propose[correctness] ─┐
target ────►├─ propose[security]    ─┤── dedup ──► candidates
            ├─ propose[performance] ─┤            (multi-lens provenance)
            └─ propose[maintainab.] ─┘                  │
                                                        ▼
                                      evidence anchor (AST + opt-in ruff/bandit)
                                                        │  ⚓ anchored / ~ hypothesis
                                                        ▼
                       ┌─ verify[reachability]   ─┐
              each ───►├─ verify[already_handled]─┤  BLIND, aspect-diverse
            candidate  ├─ verify[impact]         ─┤  (no cross-talk, no proposer conf)
                       └─ verify[reproducibility]─┘
                                                        │
                                                        ▼
                                   arbitrate → keep ✓ | drop ✗ | escalate ⚑
                                                        │
                              confirmed (F#) ───────────┴─────────── needs_human (H#)
```

The proposer lenses are seeded from the [rule catalog](./knowledge/rules.yaml), and a
confirmed finding carries its rule's framework citation + recommendation. See
[`knowledge/METHODOLOGY.md`](./knowledge/METHODOLOGY.md) for the full identify →
recommend flow. Design choices, each from the brief:

- **Generator → independent verifier, not debate.** Debate optimizes for agreement,
  not truth (arXiv:2305.14325). Discovery is the only place brainstorming belongs.
- **Blind + aspect-diverse verifiers** (BoN-MAV arXiv:2502.20379) so verifiers fail
  differently. Each answers one question; `confirmed` uniformly means "this aspect
  supports the finding."
- **Non-LLM evidence anchor.** Tool-corroborated findings are high-precision;
  uncorroborated ones are hypotheses (arXiv:2604.03196). `evidence.py`.
- **Escalate on split, never silent-drop a contested serious finding** — a confident
  lone dissenter on a security issue is signal (arXiv:2602.09341). Deterministic guard
  in `agents.arbitrate`.
- **Precision over recall.** Severity-floored; style findings suppressed by default.

## 3. Decorrelation by model family (built — the gate)

A same-family verifier panel carries fewer *effective* votes than its agent count
suggests — its members err together (arXiv:2605.29800). The commit gate (`grill.py`)
therefore runs the whole pipeline **twice, across two model families** (Claude and
Codex, both locally authenticated) and blocks a push on a confirmed high/critical from
**either**. Agreement across families is the strongest signal the harness produces.
Installs as a `pre-push` hook via `saddler init`.

## 4. IRC substrate (built)

A self-contained asyncio IRC server (`irc/server.py`) + a Swiss-minimal web dashboard
(`irc/web.py`), **loopback by default**. Agents stream their live deliberation; each
conclusion carries its expandable layers of thought (a ` ⟪think⟫ ` sentinel splits the
shared conclusion from its reasoning). A human participates from the composer, and the
orchestrator **routes the message to the right agent for a real answer** (`irc/sink.py`).
The **ledger is the source of truth; IRC mirrors it.**

| Channel | Role | Writers |
|---|---|---|
| `#findings` | one message per confirmed finding (span + anchor + citation) | orchestrator |
| `#debate` | discovery brainstorm + per-aspect verdicts | agents + human |
| `#approvals` | the human gate — bot posts summary + id; human commands | orchestrator + **human** |
| `#log` | append-only run telemetry | all |

A writable IRC server (it accepts control commands on `#approvals`) **must not** be
exposed beyond loopback without auth: the hub fails closed and refuses a non-loopback
bind unless `SADDLER_IRC_PASSWORD` is set, after which the dashboard also requires a
token. Channel-level authorization of `/approve` is the next hardening item (§7).

## 5. "Locally authenticated" — three concentric guarantees

1. **Human approval is the authority gate.** No irreversible action (a patch landing, a
   push) happens without a human `/approve` captured against a ledger row with
   provenance. **Reads open, writes gated.** Auto-approve only read-only/reversible
   actions (running the audit, opening a finding, writing the local ledger).
2. **Local identity, no remote trust.** The LLM backends are the local `claude` and
   `codex` CLIs using this machine's own sign-in — no API keys are handled or plumbed.
3. **No secret leakage.** Secrets stay in the gitignored `.env` family; the harness
   reads them from the environment and never echoes them; user-facing output is kept
   free of hostnames, paths, and tokens.

## 6. Commit/push path (safe-by-default)

- A confirmed finding is a **recommendation, not an action**. Turning it into a patch
  and landing that patch always passes through a human `/approve`.
- Code mutations run in an **isolated worker clone**, branch off the default branch,
  run the project's own checks, and at most **open a PR** — never force-push or merge
  unattended — until an integrator with objective test gates is proven.
- saddlerFitter's own code is gated by its own cross-family grill before it is committed.

## 7. Roadmap

The consensus engine, the cross-family gate, the CVE watch, the IRC hub + dashboard,
the checks viewer, the network watch, the ledger, and the knowledge base are **built**.
Remaining:

- **#4 Approval-gate authorization** — channel-level write-authz on `#approvals` (only
  operators issue a valid `/approve`). *Do before exposing the hub beyond loopback.*
- **#5 Revise → commit/push** — turn an approved finding into a minimal patch on a
  worker branch → re-grill → PR.
- **#7 Merge-Readiness Packs** + two-tier reviewer (objective gates auto-loop ≤3;
  judgment escalates to a human) + integrator.
- **#8 Self-improvement** — carry-forward learned constraints from rejections;
  calibrate/weight verifiers from real accept/dismiss feedback.
- **#10 Doc-drift detection**, **#11 self-maintenance**, **#12 scheduled watches**.

## 8. Continuous-custodian roles

saddlerFitter is not only an episodic auditor — it is a standing custodian of a project's
code, dependencies, and docs. Same consensus + human-gate spine, three trigger sources.

### 8a. CVE watch (built — `cve/`)

```
project manifests → inventory (lockfile SBOM + compose images)
        → OSV.dev batch (version-filtered) + NVD fallback
        → alias-dedup (one record per CVE across GHSA/GO/CVE ids)
        → consensus triage in the project's deployment context
             · exploitable_in_deployment?   · fix_safety?
        → arbiter: urgency {now·soon·watch·ignore} + remediation plan
        → reportable advisory = message + plan → #approvals (/approve gate)
```

The triage reasons about reachability *in the configured deployment* (supplied via
`SADDLER_DEPLOYMENT_CONTEXT` or `.deployment.md`), so a feed CVE becomes
"exploitable *here*?" rather than a raw severity number. Floating image tags (e.g.
`:latest`) are flagged as findings since their exposure can't be version-checked.
**Known limitation:** a lockfile is the build/index env; a container image pins its own
baked deps — scanning the actual container SBOMs (syft / `docker scout`) is a planned
enrichment. A single-family triage shows run-to-run verdict variance, which is exactly
why the human gate, not the model, is the final arbiter.

### 8b. Doc maintenance (#10)

Keep the docs true: diff the README / config / declared tech-map against the live
manifests (compose, lockfiles, running services). Drift is raised as findings through
the same consensus + human gate. Stale docs are blind spots in the CVE watch, so doc
accuracy is a *security* property here, not just hygiene.

### 8c. Self-maintenance (#11)

The harness audits and documents itself — its agent prompts, lens/aspect config,
evidence rules, the rule catalog, and the currency of this document. The dogfood loop
is already live: running the cross-family gate on saddlerFitter's own code blocked it on real
high-severity findings (an arbitrate crash, second-order prompt injection, an
unauthenticated IRC control channel, an unauthenticated dashboard) and they were fixed
before the core was committed.

## 9. research — the learning loop (`saddlerfitter.research`)

The harness audits a moment in time; the research part keeps saddlerFitter current and
makes it grow. One sqlite store (`research/store.py`), two jobs.

**Scheduled watch (`research/watch.py`).** Run on a timer (systemd / cron / n8n — see
`research/SCHEDULING.md`):

```
poll latest CVEs (OSV/NVD vs the SBOM) + vulnerability disclosures (Atom/RSS)
   → dedup vs advisories_seen        (signal each advisory exactly once)
   → SIGNAL on a new, relevant hit
   → research the fix                (reuses the saddlerFitter consensus triage)
   → open a TICKET                   (local; + a GitHub issue with --gh-repo)
   → recommend a professional human auditor when the risk warrants it
```

Disclosure feeds are filtered to entries that mention a technology actually in the SBOM,
so the watch stays on-topic. The watch is idempotent and makes model calls only on a *new*
advisory — a quiet cycle is essentially free.

**Knowing when to call a human.** A ticket carries an explicit *engage a professional
human auditor* recommendation when a serious advisory also has no clean fix, an
unsafe/uncertain fix, confirmed exploitability in the deployment, or a high-blast-radius
(unpinned) component. The harness assists; it does not sign off on the hard cases alone.

**Autoresearch ingest (`research/ingest.py`).** Distil a best-practice source (a new CWE,
an OWASP/NCSC update, a hardening guide) into candidate rules in the catalog's own schema,
deduplicated against what's known and parameterised by the project's profile so they stay
relevant. A human **promotes** a candidate, at which point it is appended to
`knowledge/rules.yaml` and every future audit has learned it. Machine-distilled rules
never enter the catalog unreviewed — the precision-first guarantee holds while the
platform still grows over time.
