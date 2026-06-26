"""Non-LLM evidence anchor.

The brief's strongest false-positive lever: a finding corroborated by a
deterministic tool is *execution/tool-anchored*; one that is not is a
*hypothesis* (test-based verification cuts FP to ~8.6% vs ~35% for pure LLM
flagging — arXiv:2604.03196). The stdlib AST linter below always runs (zero
deps, offline); `uvx ruff`/`bandit` add a richer layer when SADDLER_EXTERNAL_LINT
is set. Absence of a tool hit never *refutes* a finding — it only withholds the
anchor, leaving the LLM reasoning to stand on its own as a hypothesis.
"""
from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess

from . import config


def ast_lint(content: str, path: str = "<target>") -> list[dict]:
    """A curated, high-signal stdlib AST linter — every rule maps to a real bug
    class, so a hit is meaningful corroboration rather than style noise."""
    try:
        tree = ast.parse(content)
    except SyntaxError as e:
        return [
            {
                "line": e.lineno or 0,
                "code": "SYNTAX",
                "message": f"SyntaxError: {e.msg}",
                "source": "ast",
            }
        ]
    diags: list[dict] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                diags.append(_d(node, "BARE_EXCEPT",
                                 "bare 'except:' catches BaseException (SystemExit/KeyboardInterrupt)"))
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                diags.append(_d(node, "EXCEPT_PASS", "exception silently swallowed (except: pass)"))
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    diags.append(_d(node, "SHELL_TRUE", "call with shell=True (command-injection risk)"))
            if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                diags.append(_d(node, "EVAL_EXEC", f"use of {node.func.id}() executes arbitrary code"))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for default in node.args.defaults + node.args.kw_defaults:
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    diags.append(_d(node, "MUTABLE_DEFAULT", "mutable default argument"))
        if isinstance(node, ast.Compare):
            for op, comp in zip(node.ops, node.comparators):
                if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(comp, ast.Constant) and comp.value is None:
                    diags.append(_d(node, "COMPARE_NONE", "comparison to None should use 'is' / 'is not'"))
    return diags


def _d(node, code, message) -> dict:
    return {"line": getattr(node, "lineno", 0), "code": code, "message": message, "source": "ast"}


def external_lint(path: str) -> list[dict]:
    """Opt-in richer layer via `uvx` (ephemeral, no persistent install)."""
    if not config.EXTERNAL_LINT or not shutil.which("uv"):
        return []
    diags: list[dict] = []
    try:
        r = subprocess.run(
            ["uv", "tool", "run", "ruff", "check", "--output-format", "json", path],
            capture_output=True, text=True, timeout=180,
        )
        for d in json.loads(r.stdout or "[]"):
            loc = d.get("location") or {}
            diags.append({"line": loc.get("row", 0), "code": d.get("code", "RUFF"),
                          "message": d.get("message", ""), "source": "ruff"})
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["uv", "tool", "run", "bandit", "-q", "-f", "json", path],
            capture_output=True, text=True, timeout=180,
        )
        for d in json.loads(r.stdout or "{}").get("results", []):
            diags.append({"line": d.get("line_number", 0), "code": d.get("test_id", "BANDIT"),
                          "message": d.get("issue_text", ""), "source": "bandit"})
    except Exception:
        pass
    return diags


def gather_evidence(target: dict) -> list[dict]:
    """Collect deterministic diagnostics for a target (Python files only for now)."""
    if target.get("kind") != "file":
        return []
    path = target.get("path", "")
    if not path.endswith(".py"):
        return []
    diags = ast_lint(target.get("content", ""), path)
    if os.path.exists(path):
        diags += external_lint(path)
    seen, out = set(), []
    for d in diags:
        key = (d["line"], d["code"])
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


# Each diagnostic only corroborates a finding that is actually ABOUT that bug
# class — proximity alone produced false anchors (a shell=True hit "confirming" an
# unrelated dedup finding two lines away). Relevance gates first, then proximity.
CODE_KEYWORDS = {
    "SHELL_TRUE": ("shell", "inject", "subprocess", "command"),
    "EVAL_EXEC": ("eval", "exec", "arbitrary"),
    "BARE_EXCEPT": ("except", "exception", "bare", "swallow", "baseexception"),
    "EXCEPT_PASS": ("except", "exception", "swallow", "silenc", "pass"),
    "MUTABLE_DEFAULT": ("default", "mutable"),
    "COMPARE_NONE": ("none", "comparison", "identity"),
}


def _relevant(finding, diag: dict) -> bool:
    if diag.get("code") == "SYNTAX":
        return True
    kws = CODE_KEYWORDS.get(diag.get("code", ""))
    if not kws:
        return False
    text = f"{finding.title} {finding.rationale}".lower()
    return any(k in text for k in kws)


def attach(findings, diags: list[dict], window: int = 3) -> None:
    """Anchor a finding to a diagnostic only when they describe the same bug class
    (relevance) AND are co-located — or the diagnostic is the file's only one of its
    code, which absorbs LLM line-number drift without inviting false matches.

    Anchored diagnostics are enriched in place with the matching catalog rule (id,
    framework citation, recommendation) so the provenance flows through to the arbiter
    and the report — the finding is then traceable to CWE/OWASP/NCSC, not just to an
    LLM opinion. See knowledge/."""
    from collections import Counter

    from . import knowledge

    sig_rule = knowledge.by_ast_signal()
    code_counts = Counter(d.get("code") for d in diags)
    for f in findings:
        hits = []
        for d in diags:
            if not _relevant(f, d):
                continue
            near = f.line is not None and abs((d.get("line") or -999) - f.line) <= window
            unique = code_counts[d.get("code")] == 1
            if near or unique:
                rule = sig_rule.get(d.get("code"))
                if rule and "rule" not in d:
                    d["rule"] = rule["id"]
                    d["citation"] = knowledge.citation(rule)
                    d["recommendation"] = (rule.get("recommendation") or "").strip()
                hits.append(d)
        if hits:
            f.evidence = hits
            f.execution_anchored = True
