"""Pipeline: propose -> dedup -> evidence -> verify (aspects) -> arbitrate.

Layers run concurrently within a layer but are sequenced across layers — a finding
cannot be arbitrated before it is verified. The `on_event` hook narrates each layer
in real time, which is how a human "addresses layers" of the hierarchy. Confirmed
findings are reported; verifier-split serious findings are escalated (needs_human),
never silently dropped.
"""
from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import agents, config, evidence
from .schema import Finding

_STOP = {
    "the", "a", "an", "of", "in", "to", "is", "and", "or", "for", "on", "with",
    "this", "that", "missing", "unhandled", "potential", "possible",
}


def _keywords(title: str) -> set[str]:
    words = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]+", title.lower())
    return {w for w in words if w not in _STOP and len(w) > 2}


def _merge_key(f: Finding):
    # Use the full reported path (not basename) so same-named files in different
    # directories don't merge. Single-file audits pin file to the target path, so the
    # earlier abs-vs-relative mismatch can't recur. A finding without a line gets a
    # unique key so only same-line findings cluster.
    if not isinstance(f.line, int):
        return (f.file, f"noline-{id(f)}")
    return (f.file, f.line // 5)


def _sev_rank(s: str) -> int:
    try:
        return config.SEVERITY_ORDER.index(s)
    except ValueError:
        return 1


def dedup(findings: list[Finding]) -> list[Finding]:
    """Cluster near-duplicate findings from different lenses into one candidate
    carrying multi-lens provenance (agreement signal for the arbiter)."""
    clusters: list[tuple[Finding, set[str]]] = []
    for f in findings:
        fk = _keywords(f.title)
        placed = False
        for rep, kw in clusters:
            if _merge_key(rep) == _merge_key(f) and (fk & kw or f.category == rep.category):
                for p in f.proposers:
                    if p not in rep.proposers:
                        rep.proposers.append(p)
                if _sev_rank(f.severity) > _sev_rank(rep.severity):
                    rep.severity = f.severity
                if len(f.rationale) > len(rep.rationale):
                    rep.rationale = f.rationale
                if len(f.suggested_fix) > len(rep.suggested_fix):
                    rep.suggested_fix = f.suggested_fix
                kw |= fk
                placed = True
                break
        if not placed:
            clusters.append((f, fk))
    return [rep for rep, _ in clusters]


def run_audit(target, lenses=None, aspects=None, on_event=None, backend=None) -> list[Finding]:
    lenses = lenses or config.LENSES
    aspects = aspects or config.VERIFY_ASPECTS
    backend = backend or {
        "family": "claude", "proposer": config.PROPOSER_MODEL,
        "critic": config.CRITIC_MODEL, "arbiter": config.ARBITER_MODEL,
    }
    emit = on_event or (lambda *a, **k: None)

    # --- layer 1: propose (one auditor per lens, in parallel) ---
    emit("phase", phase="propose", lenses=lenses)
    proposed: list[Finding] = []
    with ThreadPoolExecutor(max_workers=config.MAX_CONCURRENCY) as ex:
        futs = {ex.submit(agents.propose, target, lens, backend): lens for lens in lenses}
        for fut in as_completed(futs):
            lens = futs[fut]
            try:
                fs = fut.result()
            except Exception as e:
                emit("error", layer="propose", lens=lens, error=str(e))
                fs = []
            emit("proposed", lens=lens, count=len(fs))
            emit("propose_detail", lens=lens,
                 items=[{"title": f.title, "rationale": f.rationale} for f in fs])
            proposed.extend(fs)

    candidates = dedup(proposed)
    for i, f in enumerate(candidates, 1):
        f.fid = f"C{i}"
    emit("deduped", raw=len(proposed), candidates=len(candidates))
    if not candidates:
        emit("done", confirmed=0, escalated=0, dropped=0)
        return []

    # --- evidence anchor (non-LLM, local, cheap) ---
    emit("phase", phase="evidence")
    diags = evidence.gather_evidence(target)
    evidence.attach(candidates, diags, window=config.EVIDENCE_WINDOW)
    anchored = sum(1 for f in candidates if f.execution_anchored)
    emit("evidence", diagnostics=len(diags), anchored=anchored)

    # --- layer 2: verify (blind, aspect-diverse, per candidate) ---
    emit("phase", phase="verify", aspects=aspects)

    def _verify_one(f: Finding) -> Finding:
        verds = []
        with ThreadPoolExecutor(max_workers=max(1, len(aspects))) as ex:
            futs = {ex.submit(agents.verify, target, f, a, backend): a for a in aspects}
            for fut in as_completed(futs):
                try:
                    v = fut.result()
                except Exception as e:
                    v = {"aspect": futs[fut], "verdict": "uncertain",
                         "confidence": 0.0, "reason": f"error: {e}"}
                verds.append(v)
                emit("verify_detail", fid=f.fid, aspect=v["aspect"],
                     verdict=v["verdict"], reason=v.get("reason", ""))
        f.verifier_verdicts = verds
        return f

    with ThreadPoolExecutor(max_workers=config.MAX_CONCURRENCY) as ex:
        futs = [ex.submit(_verify_one, f) for f in candidates]
        for fut in as_completed(futs):
            f = fut.result()
            conf = sum(1 for v in f.verifier_verdicts if v["verdict"] == "confirmed")
            emit("verified", fid=f.fid, confirmed=conf, total=len(f.verifier_verdicts),
                 anchored=f.execution_anchored)

    # --- layer 3: arbitrate (keep | drop | escalate) ---
    emit("phase", phase="arbitrate", candidates=len(candidates))
    final: list[Finding] = []
    with ThreadPoolExecutor(max_workers=config.MAX_CONCURRENCY) as ex:
        futs = {ex.submit(agents.arbitrate, target, f, backend): f for f in candidates}
        for fut in as_completed(futs):
            try:
                f = fut.result()
            except Exception as e:
                # An arbiter LLM/transport error must not sink the whole run — escalate
                # the finding to a human rather than crash or silently drop it.
                f = futs[fut]
                f.status = "needs_human"
                f.arbiter_summary = f"arbiter error: {e}"
                emit("error", layer="arbitrate", error=str(e))
            emit("arbitrated", fid=f.fid, status=f.status, severity=f.severity)
            emit("arbitrate_detail", fid=f.fid, title=f.title, status=f.status,
                 severity=f.severity, summary=f.arbiter_summary)
            final.append(f)

    min_rank = _sev_rank(config.MIN_SEVERITY)
    confirmed = [
        f for f in final
        if f.status == "confirmed" and _sev_rank(f.severity) >= min_rank
    ]
    escalated = [f for f in final if f.status == "needs_human"]
    confirmed.sort(key=lambda f: (-_sev_rank(f.severity), -f.confidence))
    escalated.sort(key=lambda f: (-_sev_rank(f.severity), -f.confidence))
    for i, f in enumerate(confirmed, 1):
        f.fid = f"F{i}"
    for i, f in enumerate(escalated, 1):
        f.fid = f"H{i}"
    dropped = len(final) - len(confirmed) - len(escalated)
    emit("done", confirmed=len(confirmed), escalated=len(escalated), dropped=dropped)
    return confirmed + escalated
