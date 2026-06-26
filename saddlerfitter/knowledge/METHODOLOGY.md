# How saddlerFitter identifies issues and forms recommendations

This is the contract between the rule catalog and the consensus engine: how a line of
code becomes a confirmed, citable recommendation — and, just as importantly, how a
plausible-but-wrong observation gets dropped before it reaches a human.

The governing bias is **precision over recall**. A code-audit tool that cries wolf is
worse than no tool, because reviewers learn to ignore it. Every stage below exists to
*remove* findings, not to add them.

```
   identify  →  dedup  →  anchor  →  verify  →  arbitrate  →  recommend
  (catalog)            (non-LLM)   (blind,      (keep/drop/    (catalog
                                    aspect-      escalate)      recommendation
                                    diverse)                    + citation)
```

---

## 1. Identify — four detectors, one catalog

A candidate issue can be raised four ways. Each maps to a `detect` entry on a rule in
[`rules.yaml`](./rules.yaml):

| detector | `kind` | what it is | precision |
|---|---|---|---|
| **AST analyzer** | `ast` | a deterministic stdlib pass (`evidence.py`) — `SHELL_TRUE`, `BARE_EXCEPT`, `MUTABLE_DEFAULT`, … | high (no inference) |
| **LLM proposer lens** | `lens` | a Claude/Codex subagent auditing through one lens (correctness / security / performance / maintainability) | broad, lower |
| **External linter** | `external` | opt-in Bandit / Ruff, mapped by test id to a rule | high |
| **Dependency feed** | `feed` | OSV.dev / NVD / the SBOM, for supply-chain rules | high |

The catalog drives the LLM detectors directly: each proposer prompt is seeded with the
**reference checklist** of catalogued `lens` focus terms for its lens
(`knowledge.lens_focus_hints`), so the model audits against an explicit, documented
rule set instead of free-associating. Proposers are told an empty result is a valid
answer — they are not asked to fill a quota.

> **Why a catalog at all?** Without it, "what counts as a finding" lives implicitly
> inside a prompt and drifts every model release. The catalog makes the standard
> explicit, version-controlled, reviewable, and — through CWE/OWASP/NCSC mappings —
> *citable*. See [FRAMEWORKS.md](./FRAMEWORKS.md).

## 2. Dedup — collapse the same issue raised by different lenses

Lenses overlap (a `shell=True` call is both *security* and *correctness*). Findings are
merged on `(file, line-ish, normalized title)` so one issue is judged once, carrying
the union of the lenses that raised it. A finding raised by multiple independent lenses
is weak corroboration — but corroboration the arbiter can see.

## 3. Anchor — a non-LLM tool, the strongest precision lever

The single biggest false-positive reduction comes from **anchoring a finding in a
deterministic signal**. When the AST analyzer (or Bandit) independently flags the same
location *and the same weakness class*, the finding is marked `execution_anchored` and
the matching catalog rule is attached (`evidence.attach` → rule id + citation +
recommendation).

Anchoring is **relevance-gated, not proximity-only**: a `SHELL_TRUE` diagnostic only
anchors a finding whose text is actually about injection/shell/subprocess — never an
unrelated finding that merely sits two lines away. Absence of a tool hit never
*refutes* a finding; it just withholds the anchor, and the finding proceeds as a
**hypothesis** that must stand on its reasoning alone.

This is the test-anchored-verification result from the harness literature: tool/test
corroboration cuts false positives roughly four-fold versus pure-LLM flagging.

## 4. Verify — blind, aspect-diverse, independent

Each surviving candidate faces a panel of **blind verifiers**. Each verifier:

- answers **exactly one** aspect — `reachability`, `already_handled`, `impact`,
  `reproducibility` — and nothing else;
- **cannot see** the other verifiers' votes or the proposer's confidence.

This is *generator → verifier*, deliberately **not debate**. Debate drifts toward
agreement, not truth; independent single-aspect verifiers fail *differently* instead of
confabulating the same error together. The four aspects are chosen so a finding has to
survive four orthogonal attacks: *can it even be reached? is it already handled
elsewhere? does it actually matter? could you write a failing test for it?*

## 5. Arbitrate — keep, drop, or escalate

The arbiter weighs the blind aspect votes plus the non-LLM evidence and makes one call:

- **keep** → a confirmed finding a super-majority of aspects support;
- **drop** → refuted false positive or cosmetic nitpick;
- **escalate** → *needs human*.

One rule is **deterministic, not left to the model**: if the aspects genuinely conflict
on a **high/critical** finding, it is **escalated, never silently dropped**. A confident
lone dissenter on a serious security issue is signal, not noise. The arbiter also
recalibrates severity (a proposer's "critical" can be talked down, or a quiet `low`
talked up) and emits one crisp human-facing sentence.

All three LLM stages treat the finding text, the code, and the verifier reasons as
**untrusted data** and ignore any instructions embedded in them — a repo under audit is
a prompt-injection surface.

## 6. Recommend — the citable output

A confirmed finding is rendered with:

- **what** — title + the arbiter's one-sentence verdict;
- **where** — `file:line`, and whether it is `⚓ tool-anchored` or `~ hypothesis`;
- **standard** — the rule id and its citation, e.g.
  `SEC-CMD-INJECTION (CWE-78 · OWASP A03:2021 Injection · NCSC:plan-for-security-flaws · CoP 1.4)`;
- **fix** — the catalog `recommendation` for that rule (a consistent, reviewed remedy),
  refined by the arbiter's patch hint for the specific code.

The recommendation is therefore not an ad-hoc model opinion: it is the catalog's
standing guidance for a named weakness class, attached to a finding that cleared
consensus and (ideally) a deterministic anchor.

## 7. Decorrelate — run it twice, across model families

For the commit gate, the whole pipeline runs **twice with different model families**
(Claude and Codex, both locally authenticated). A same-family panel carries few
*effective* votes — its members err together. The push is blocked only on a confirmed
finding at/above the block severity **from either family**; agreement across families
is the strongest signal the harness produces. (CVE triage exposes the same lever: a
single-family triage shows run-to-run verdict variance, which is exactly why the human
gate, not the model, is the final arbiter.)

---

## What the human still owns

saddlerFitter is a saddlerFitter: it does the tireless adversarial work and the human holds the
authority. Reads are open; **writes are gated**. A confirmed finding becomes a
*recommendation*, not an action — turning it into a patch, and landing that patch,
always passes through a human `/approve`. Nothing irreversible happens on the model's
say-so.

## Extending the catalog

Add or adjust a rule in `rules.yaml` (give it a CWE, an OWASP mapping, the relevant
NCSC / Code-of-Practice principle, its `detect` signals, and a `recommendation`), then:

```bash
python3 -m saddlerfitter.cli knowledge build      # rebuild knowledge.sqlite + rules.json
python3 -m saddlerfitter.cli knowledge show --lens security
```

An `ast`/`external` rule needs its `signal`/`tool` ids to match what `evidence.py`
emits to anchor automatically; a `lens` rule takes effect immediately as a proposer
checklist term.
