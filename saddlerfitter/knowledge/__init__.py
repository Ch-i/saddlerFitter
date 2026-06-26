"""The best-practice knowledge base: the catalog of what saddlerFitter looks for and how
it grounds a recommendation.

`rules.yaml` is the human-editable source of truth. This module loads it, indexes it
for the harness (by AST signal, by lens), and builds a queryable SQLite database
(`knowledge.sqlite`) plus a stdlib-only JSON cache (`rules.json`) so runtime
enrichment works even where PyYAML is not installed.

Design: the catalog is *data*, not code. The harness identifies a candidate
(`detect`), and when a finding is confirmed it cites the rule's frameworks and emits
the rule's `recommendation`. Every report line is therefore traceable to CWE / OWASP /
the UK NCSC principles rather than being an unanchored opinion. See METHODOLOGY.md.
"""
from __future__ import annotations

import json
import os
import sqlite3
from functools import lru_cache

_HERE = os.path.dirname(os.path.abspath(__file__))
RULES_YAML = os.path.join(_HERE, "rules.yaml")
RULES_JSON = os.path.join(_HERE, "rules.json")  # generated stdlib cache
DB_PATH = os.path.join(_HERE, "knowledge.sqlite")  # generated, gitignored


@lru_cache(maxsize=1)
def load_catalog() -> dict:
    """Load the catalog from YAML (source of truth) or the generated JSON cache.

    Falls back gracefully: a missing PyYAML or unbuilt cache yields an empty catalog
    so the rest of the harness keeps working (enrichment simply withholds citations).
    """
    try:
        import yaml  # optional dependency — only the knowledge base needs it

        with open(RULES_YAML, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except ImportError:
        if os.path.exists(RULES_JSON):
            with open(RULES_JSON, "r", encoding="utf-8") as fh:
                return json.load(fh)
        return {"version": 0, "rules": []}
    except FileNotFoundError:
        return {"version": 0, "rules": []}


def rules() -> list[dict]:
    return list(load_catalog().get("rules", []))


@lru_cache(maxsize=1)
def by_id() -> dict:
    return {r["id"]: r for r in rules()}


@lru_cache(maxsize=1)
def by_ast_signal() -> dict:
    """AST diagnostic code (evidence.py) -> the rule it corroborates."""
    out: dict[str, dict] = {}
    for r in rules():
        for d in r.get("detect", []):
            if d.get("kind") == "ast" and d.get("signal"):
                out[d["signal"]] = r
    return out


def rules_for_lens(lens: str) -> list[dict]:
    return [r for r in rules() if r.get("lens") == lens]


def citation(rule: dict) -> str:
    """One-line provenance string for a confirmed finding."""
    bits: list[str] = []
    for c in rule.get("cwe", []) or []:
        bits.append(c)
    ow = rule.get("owasp") or {}
    if ow.get("top10"):
        bits.append("OWASP " + ow["top10"])
    uk = rule.get("uk") or {}
    if uk.get("ncsc"):
        bits.append("NCSC:" + uk["ncsc"])
    if uk.get("code_of_practice"):
        bits.append("CoP " + str(uk["code_of_practice"]).split(" ", 1)[0])
    return " · ".join(bits)


def lens_focus_hints(lens: str) -> str:
    """Catalog-derived focus terms for a proposer lens — keeps prompts anchored to the
    documented rule set rather than the model's free association."""
    terms = []
    for r in rules_for_lens(lens):
        for d in r.get("detect", []):
            if d.get("kind") == "lens" and d.get("focus"):
                terms.append(d["focus"])
    return "; ".join(terms)


# --- database build -------------------------------------------------------------

_SCHEMA = """
CREATE TABLE rule (
    id TEXT PRIMARY KEY, title TEXT, lens TEXT, severity TEXT,
    owasp_top10 TEXT, owasp_asvs TEXT,
    ncsc_principle TEXT, code_of_practice TEXT,
    recommendation TEXT
);
CREATE TABLE rule_cwe (rule_id TEXT, cwe TEXT);
CREATE TABLE rule_detect (rule_id TEXT, kind TEXT, detail TEXT);
CREATE TABLE rule_reference (rule_id TEXT, url TEXT);
CREATE VIEW rule_full AS
  SELECT r.id, r.lens, r.severity, r.title,
         group_concat(DISTINCT c.cwe) AS cwes,
         r.owasp_top10, r.ncsc_principle, r.code_of_practice
  FROM rule r LEFT JOIN rule_cwe c ON c.rule_id = r.id
  GROUP BY r.id;
"""


def build_db(db_path: str | None = None) -> tuple[str, int]:
    """YAML -> knowledge.sqlite (+ rules.json cache). Returns (db_path, rule_count)."""
    cat = _load_yaml_strict()  # build requires the real source, not the cache
    rs = cat.get("rules", [])
    path = db_path or DB_PATH
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    try:
        con.executescript(_SCHEMA)
        for r in rs:
            ow = r.get("owasp") or {}
            uk = r.get("uk") or {}
            con.execute(
                "INSERT INTO rule VALUES (?,?,?,?,?,?,?,?,?)",
                (r["id"], r.get("title", ""), r.get("lens", ""), r.get("severity", ""),
                 ow.get("top10"), ow.get("asvs"), uk.get("ncsc"),
                 str(uk.get("code_of_practice") or ""), (r.get("recommendation") or "").strip()),
            )
            for c in r.get("cwe", []) or []:
                con.execute("INSERT INTO rule_cwe VALUES (?,?)", (r["id"], c))
            for d in r.get("detect", []) or []:
                con.execute("INSERT INTO rule_detect VALUES (?,?,?)",
                            (r["id"], d.get("kind", ""), json.dumps(d)))
            for u in r.get("references", []) or []:
                con.execute("INSERT INTO rule_reference VALUES (?,?)", (r["id"], u))
        con.commit()
    finally:
        con.close()
    # stdlib cache so runtime enrichment needs no PyYAML
    with open(RULES_JSON, "w", encoding="utf-8") as fh:
        json.dump(cat, fh, indent=2)
    load_catalog.cache_clear(); by_id.cache_clear(); by_ast_signal.cache_clear()
    return path, len(rs)


def _load_yaml_strict() -> dict:
    import yaml  # raises ImportError with a clear message if absent

    with open(RULES_YAML, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}
