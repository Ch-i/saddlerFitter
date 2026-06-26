# saddlerFitter

**A code-quality and security platform — consensus code audit, a UK-best-practice
knowledge base, and an autoresearch watch that learns over time. Human always in the loop.**

A saddler fits the saddle to both horse and rider — the interface that lets the two move
as one. saddlerFitter does the same for a codebase and its maintainers. It is a **harness**
— a team of LLM agents (a proposer per lens, a blind verifier per aspect, an arbiter, an
orchestrator) that audit code by cross-family consensus, gate commits, and surface findings
through a human-in-the-loop IRC hub (the *hands*). Two companion parts give it memory and
let it grow:

- **`knowledge`** — the **memory**. A versioned rule catalog (CWE/OWASP + the UK NCSC
  Secure Development principles and the 2025 Software Security Code of Practice) that
  drives detection *and* phrases every recommendation, so a finding is citable rather than
  an opinion.
- **`research`** — the **learning loop**. An ingest database fed by autoresearch, plus a
  scheduled watch over the latest CVEs and vulnerability disclosures that **signals** new
  risk, **researches the fix**, opens **tickets**, and **recommends a professional human
  auditor** when the risk exceeds what an automated triage should sign off on alone.

The model is a swappable component; **the harness is the product** — the central finding
of the agent-harness literature it is built on
([`saddlerfitter/docs/RESEARCH_BRIEF.md`](saddlerfitter/docs/RESEARCH_BRIEF.md);
SWE-agent arXiv:2405.15793).

> **Run it deliberately, not in an unbounded loop.** Audits, grills, triage, and ingest
> make real local LLM CLI calls. It's a tool you invoke plus a watch you schedule — never
> a thing left spinning.

## What's in it

| Part | Component | What it does |
|---|---|---|
| harness | Consensus auditor | propose (per-lens) → non-LLM AST evidence anchor → blind aspect-diverse verifiers → arbiter (keep / drop / escalate-to-human) |
| harness | Cross-family gate | `grill` audits a diff with two model families; blocks a push on a confirmed high/critical from *either*; installs as a pre-push hook |
| harness | IRC hub + dashboard | agents stream live deliberation; a human participates and the orchestrator routes questions to the right agent for a real answer |
| harness | Network watch | privilege-free exposure badges (`ss` + `/proc`); opt-in tcpdump/Wireshark deep capture |
| knowledge | Rule catalog | a versioned [catalog](saddlerfitter/knowledge/rules.yaml) (CWE/OWASP/UK frameworks); builds a queryable SQLite DB |
| research | Watch → ticket | poll CVEs + disclosures → signal → consensus triage → ticket → human-auditor escalation |
| research | Autoresearch ingest | distil best-practice sources into candidate rules; a human promotes them so the catalog **grows over time** |

## Install

Python 3.10+ and at least one local LLM CLI for the "locally authenticated" seam:

- [`claude`](https://claude.com/claude-code) (Claude Code) — the primary backend
- [`codex`](https://github.com/openai/codex) — the second family for the cross-family gate

Both use their own local sign-in; **no API keys are handled or plumbed.**

```bash
pip install -e .          # exposes the `saddler` console command
# or run straight from the tree:  python3 -m saddlerfitter.cli ...
```

## Quickstart

```bash
# audit one file / a diff
saddler audit path/to/file.py
saddler audit . --diff main

# the best-practice knowledge base
saddler knowledge build                 # rules.yaml -> knowledge.sqlite (+ json cache)
saddler knowledge show --lens security  # catalogued rules + their standards
saddler knowledge --id SEC-CMD-INJECTION

# cross-family double-grill (Claude + Codex); exit 1 if it would block a push
saddler grill --staged
saddler init                            # embed the gate as a pre-push hook in this repo

# the research watch: poll CVEs + disclosures -> signal -> triage -> ticket
saddler watch                           # one cycle; schedule it (see research/SCHEDULING.md)
saddler watch --gh-repo your-org/repo   # also file a GitHub issue per ticket
saddler research signals                # what the watch found
saddler research tickets                # tickets (⚠ marks human-auditor escalations)

# autoresearch: grow the catalog from a best-practice source (human-gated)
saddler research ingest https://example.com/advisory --profile "python web api"
saddler research candidates
saddler research promote --id 3         # append the approved rule into the catalog

# IRC hub + dashboard (loopback by default): agents + humans co-inhabit channels
saddler hub
```

## How it forms a recommendation

```
identify → dedup → anchor → verify → arbitrate → recommend
(catalog)        (non-LLM)  (blind,   (keep/drop/  (catalog recommendation
                            aspect-    escalate)    + framework citation)
                            diverse)
```

The full method is in
[`saddlerfitter/knowledge/METHODOLOGY.md`](saddlerfitter/knowledge/METHODOLOGY.md); the
frameworks and the rule→standard crosswalk are in
[`saddlerfitter/knowledge/FRAMEWORKS.md`](saddlerfitter/knowledge/FRAMEWORKS.md); the
watch and learning loop are in [`saddlerfitter/research/`](saddlerfitter/research/).

## When it calls a human

saddlerFitter knows its limits. A vulnerability ticket is flagged **recommend a
professional human security auditor** when a serious (high/critical) advisory also has no
clean fix, an unsafe or uncertain fix, confirmed exploitability in your deployment, or a
high-blast-radius (unpinned) component. The platform assists; it does not sign off on the
hard cases alone.

## Security posture

- LLM auth is the **local CLIs only** — no API keys handled.
- The IRC hub is **loopback by default** and fails closed: exposing it needs a password,
  and the dashboard then needs a token.
- Machine-distilled rules **never** enter the catalog unreviewed — a human promotes them.
- The cross-family gate was run on this platform's own code during development and blocked
  it on real high-severity findings before they were committed.

## See also

- [`saddlerfitter/ROLE.md`](saddlerfitter/ROLE.md) — what saddlerFitter is and its role.
- [`saddlerfitter/ARCHITECTURE.md`](saddlerfitter/ARCHITECTURE.md) — design of record + roadmap.
- [`saddlerfitter/knowledge/`](saddlerfitter/knowledge/) — the rule catalog, methodology, frameworks.
- [`saddlerfitter/research/`](saddlerfitter/research/) — the watch + autoresearch learning loop.

## License

[MIT](./LICENSE).
