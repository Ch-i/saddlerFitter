# Design Brief: saddlerFitter Code-Audit Harness (IRC + Multi-LLM Consensus, Locally Authenticated)

A worker/orchestrator/reviewer harness for code **audit → revision → improvement**, with a human co-pilot in the loop, grounded in 2023–2026 agent-harness literature. This brief is the *why* behind the design; [`../ARCHITECTURE.md`](../ARCHITECTURE.md) is the as-built design of record.

---

## 1. What a harness is, and the principles that matter for a code-audit saddlerFitter

The literature converges on a single definition: a harness is the engineered scaffolding that turns a next-token predictor into a goal-directed agent, decomposed into **five owned parts — control loop, tool interface, memory/context, verification, environment/sandbox** (Natural-Language Agent Harnesses, arXiv:2603.25723; the six-dimension source-code taxonomy in *Inside the Scaffold*, arXiv:2604.03515). The central empirical claim is that **the harness, not the base model, dominates outcomes** — SWE-agent roughly doubled SWE-bench resolution with the same model purely by redesigning the agent-computer interface (arXiv:2405.15793). Treat the model as a swappable component; the harness is the product.

The principles most load-bearing for an *audit* saddlerFitter (vs. a generic coder):

1. **Design tools for the agent's failure modes, not for a human.** Line-ranged file views, an edit command with built-in lint/syntax validation that *rejects* broken patches, compact structured feedback that fits the window (SWE-agent ACI, arXiv:2405.15793). For audit specifically, add first-class verbs: `open_finding`, `attach_repro`, `propose_minimal_diff`.

2. **Verification must be execution-grounded and two-sided.** Every revision passes `FAIL_TO_PASS` (the finding is actually fixed, ideally via an agent-generated reproduction test) **and** `PASS_TO_PASS` (no regressions), in a sandbox at the correct base commit — the SWE-bench harness contract (swebench.com; SWE-bench Verified, openai.com). **A finding without a reproducible failing test is a hypothesis, not a defect — label it as such.**

3. **Optimize for precision / signal-to-noise, not recall.** This is the defining tension of audit tools. Iterative "find more bugs" reflexion loops collapse SNR (CR-Bench: 2.89 → 0.91 on a small model, arXiv:2603.11078). Prefer single-pass / shallow iteration; gate every comment by severity and confidence; suppress subjective/style findings unless the project asks for them.

4. **Keep the control loop simple; lean Agentless for scoped fixes.** A deterministic localize → repair → validate pipeline (file → symbol → line, then patch-sample-and-test-select) is competitive with elaborate tool autonomy at a fraction of cost (Agentless, arXiv:2407.01489). Reserve open-ended tool loops for genuinely ambiguous tasks and *measure* whether the autonomy helped. A reactive ReAct while-loop, not tree search, is the right default (Claude Code dissection, arXiv:2604.14228).

5. **Externalize state; verify like a user.** One feature/finding per session; durable artifacts (a progress file, a JSON task list — models edit JSON less casually than Markdown — and git commits as memory/recovery); strongly-worded anti-tampering constraints so the agent never deletes or weakens tests to fake green (Anthropic long-running-agent guidance). A tree-sitter / PageRank-ranked **repo map** for navigation instead of dumping files (Aider, aider.chat/2023/10/22/repomap.html).

6. **Ship a Merge-Readiness Pack, not a diff.** Every revision travels with a structured evidence bundle — what changed and why, failing-then-passing tests, regression results, static-analysis deltas, lint/hygiene status, auditable rationale (Agentic SE pillars, arXiv:2509.06216). This *is* the saddlerFitter handoff artifact.

7. **Design the human interface for co-reasoning and trust calibration.** Expose reasoning, let the human accept/reject individual findings, surface per-finding confidence, route low-confidence items to the human as Consultation Requests. Human-in-the-loop is a measured multiplier (saddlerFitterEval: humans-only 18.9%, LLM-only 0.7%, collaboration 31.1%, arXiv:2512.04111); removing supervision cut precision ~4× (arXiv:2509.14745). Guard against over-trust by making uncertainty visible.

8. **Enforce small, single-concern changes.** One finding or one coherent fix per revision; never bundle unrelated edits; CI green before human review — the empirically-measured norm maintainers demand (Where Do AI Coding Agents Fail?, arXiv:2601.15195).

---

## 2. Consensus mechanism for confirming findings — precision-first

**Recommendation: a two-stage GENERATOR → INDEPENDENT-VERIFIER pipeline, not debate.** Debate is the wrong primitive for *confirming* findings: it optimizes for agreement not truth (accuracy can drop 5–12 pts over rounds; agents flip correct→incorrect more than the reverse, arXiv:2305.14325), collapses into sycophancy/conformity as rounds proceed (arXiv:2509.05396, arXiv:2509.23055), and same-family agents confabulate the same wrong answer so a 9-agent same-model panel carries only ~2 effective votes (Nine Judges, Two Effective Votes, arXiv:2605.29800).

The architecture:

- **Stage 1 — Discovery (optimize recall).** 2–3 heterogeneous proposer agents, *allowed* to brainstorm/discuss, emit **candidate findings only**. Each candidate carries exact `file:line` span, a concrete claim, and a falsifiable check. Debate's only legitimate role lives here — broadening bug-class coverage.
- **Stage 2 — Confirmation (optimize precision).** Each candidate is verified **independently and BLIND** — verifiers never see each other's votes or the proposers' confidence — which kills conformity and correct→incorrect flips (arXiv:2509.05396). Use **multi-aspect verification** (BoN-MAV, arXiv:2502.20379): decompose "is this real and report-worthy?" into independent aspect checks (is the path reachable? is the precondition satisfiable? is it already handled elsewhere? severity? exploitability?).

**False-positive control — three hard gates:**

1. **Conjunctive (AND-gate) reporting.** A finding surfaces only on a super-majority/unanimous bar of independent verifiers **plus at least one non-LLM evidence check.** This is the recall-for-precision trade you *want* in an auditor. (OR/union behavior is confined to discovery.)
2. **Decorrelate by model family, not agent count.** Use 2–3 genuinely different base models/providers for verifiers; prefer a different family for the verifier than the proposer (also defuses self-enhancement bias in LLM-as-judge, arXiv:2306.05685). Error decorrelation, not raw N, is what makes consensus trustworthy (arXiv:2402.05120; arXiv:2602.08003).
3. **Anchor in execution.** Add non-LLM verifiers — run a targeted repro, unit/property tests, type-checker, Semgrep/CodeQL — because test-based verification cuts false positives to ~8.6% vs ~35% for analyzer-style flagging (arXiv:2604.03196). LLM approvals are *evidence to reconcile* with these tools, never the final word.

**Split / minority-correct handling:** escalate to a human, don't auto-resolve. Plain majority vote scores ~0% on minority-correct cases; evidence-based auditing of the divergent span recovers ~65% (AgentAuditor, arXiv:2602.09341). A confident lone dissenter on a security finding is signal, not noise — route it to review rather than dropping it.

**Refinement:** apply Self-Refine/Reflexion (arXiv:2303.17651 / arXiv:2303.11366) **only after confirmation, only to the patch/wording, and only gated on an external signal** — never to let one model invent new findings via self-critique (shared blind spot).

**When consensus is WASTED vs ESSENTIAL:**
- **Wasted** (use a single cheap pass + tooling): deterministic, tool-checkable findings — lint, type errors, failing-test reproductions, static-analyzer hits with a clean repro. The tool *is* the verifier; a consensus panel adds cost and latency for nothing. Most verification gain lands in 1–2 rounds; deep MoA layering multiplies latency for marginal accuracy (arXiv:2406.04692).
- **Essential** (run the full heterogeneous panel + human escalation on splits): semantic/judgment findings with no clean executable oracle — logic bugs, concurrency/race claims, security reachability, API-contract violations, "is this actually a defect or intended?" These are exactly where single agents hit ~35% false-positive rates and where decorrelated conjunctive confirmation pays off.

**Cost discipline:** cheap-to-expensive cascade — one cheap proposer first; spend the multi-verifier panel + tool checks only on the candidate set, never on every line.

---

## 3. IRC substrate — why a chat bus

IRC is a deliberate fit: a durable, multi-party, human-and-bot-co-inhabitable text bus
where the **transcript is the log**, and which is trivially locally authenticated by
bind address + an operator password. Agents and the human share `#findings` /
`#debate` / `#approvals` / `#log` as equal participants — the human can interrupt
discovery, ask a verifier to justify a span, or answer a Consultation Request inline.
This realizes saddlerFitterEval co-reasoning (arXiv:2512.04111) without a bespoke UI.

The bus is the coordination *surface*; the **SQLite ledger is the source of truth** —
IRC messages mirror ledger state, they don't replace it. Stage-2 verifier votes are
written to the ledger *blind* (private to the orchestrator); only the aggregate verdict
echoes to `#debate`, preserving independence. Approval commands (`/approve`, `/reject`,
`/why`, `/hold`) are authenticated by IRC identity and written with provenance, so
accept/reject is auditable and replayable. saddlerFitter ships its own self-contained asyncio
server rather than a third-party daemon, so the dashboard can surface app-level agent
source/role/model that standard IRC does not carry.

---

## 4. Mapping onto the implementation

The literature above lands on concrete modules:

| Brief concept | Module |
|---|---|
| Generator → blind verifier → arbiter | `consensus.py`, `agents.py` |
| Non-LLM evidence anchor | `evidence.py` |
| Decorrelate by model family | `grill.py` (Claude + Codex), `llm.py` |
| What to look for + how to phrase it | `knowledge/` (rule catalog → CWE/OWASP/UK frameworks) |
| Durable state, source of truth | `ledger.py` (sqlite) |
| Human-and-bot bus | `irc/` (server, dashboard, sink, bus) |
| Continuous custodian | `cve/` (CVE watch), `netwatch.py` (exposure) |

---

## 5. The "locally authenticated" model — three concentric guarantees

1. **Human approval is the authority gate.** No irreversible action (a patch landing, a
   push) happens without a human `/approve` captured against a ledger row with
   provenance. **Reads open, writes gated.** Auto-approve only read-only/reversible
   actions; require human escalation for anything that mutates a repo or leaves the
   workspace — reversibility-weighted, deny-first defense-in-depth (Claude Code,
   arXiv:2604.14228; Codex sandbox × approval orthogonality).
2. **Local identity, no remote trust.** The LLM backends are the local `claude` and
   `codex` CLIs using this machine's own sign-in — **no API keys** are handled or
   plumbed. The IRC operator password authenticates *which human* approved.
3. **No secret leakage.** Credentials stay in the gitignored `.env` family; the harness
   reads them from the environment, never echoes them to a channel, and keeps
   hostnames/paths/tokens out of any user-facing output.

---

## 6. Roadmap and resolved design questions

The phased roadmap and the design decisions that resolved this brief's original open
questions (verifier providers, approval medium, PR-only vs direct-to-main, consensus
budget, severity floor) are recorded in [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §7.
The single biggest precision lever the literature identifies — **decorrelation by model
family** — is implemented in the commit gate (`grill.py`), which runs the pipeline
across Claude *and* Codex.
