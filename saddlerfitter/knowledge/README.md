# saddlerFitter knowledge base

The catalog of what saddlerFitter looks for and how it grounds a recommendation. This is the
"why a finding is trustworthy" layer — every rule is traced to an established standard.

| file | what it is |
|---|---|
| [`rules.yaml`](./rules.yaml) | **source of truth** — the rule catalog (human-editable, diff-friendly) |
| [`METHODOLOGY.md`](./METHODOLOGY.md) | how a finding flows identify → anchor → verify → arbitrate → **recommend** |
| [`FRAMEWORKS.md`](./FRAMEWORKS.md) | the UK/OWASP/CWE frameworks + the rule→framework crosswalk |
| `knowledge.sqlite` | **generated** queryable database (`knowledge build`); gitignored |
| `rules.json` | **generated** stdlib cache so runtime enrichment needs no PyYAML; gitignored |

```bash
python3 -m saddlerfitter.cli knowledge build              # rules.yaml -> knowledge.sqlite + rules.json
python3 -m saddlerfitter.cli knowledge show               # list the catalog
python3 -m saddlerfitter.cli knowledge show --lens security
python3 -m saddlerfitter.cli knowledge --id SEC-CMD-INJECTION   # full detail for one rule
```

Query the database directly:

```sql
-- rules and their weakness classes, grouped by lens
SELECT lens, id, cwes, owasp_top10, ncsc_principle FROM rule_full ORDER BY lens;
```

The catalog is wired into the engine: proposer lenses are seeded with the catalogued
focus terms, the AST analyzer's diagnostics anchor to the matching rule, and a
confirmed finding is rendered with its rule id + citation + recommendation.
