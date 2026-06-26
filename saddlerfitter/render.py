"""Console rendering of consensus events + findings.

The same event vocabulary the IRC bus will speak, so a terminal run and an IRC
session narrate the audit identically.
"""
from __future__ import annotations

import sys

_C = {
    "critical": "\033[1;37;41m",
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
    "low": "\033[36m",
    "info": "\033[2m",
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}


def _color(s: str, sev: str) -> str:
    if not sys.stdout.isatty():
        return s
    return f"{_C.get(sev, '')}{s}{_C['reset']}"


def event_line(kind: str, **kw) -> str:
    if kind == "phase":
        extra = kw.get("lenses") or kw.get("aspects") or kw.get("candidates") or ""
        return f"  ┄ layer · {kw.get('phase')}  {extra}".rstrip()
    if kind == "proposed":
        return f"    · propose[{kw['lens']}]: {kw['count']} raised"
    if kind == "deduped":
        return f"  → {kw['candidates']} candidate(s) from {kw['raw']} raw findings"
    if kind == "evidence":
        return f"  ⚓ non-LLM anchor: {kw['diagnostics']} diagnostic(s), {kw['anchored']} candidate(s) corroborated"
    if kind == "verified":
        anchor = " ⚓" if kw.get("anchored") else ""
        return f"    · {kw['fid']}: {kw['confirmed']}/{kw['total']} aspects confirm{anchor}"
    if kind == "arbitrated":
        mark = {"confirmed": "keep ✓", "needs_human": "escalate ⚑", "refuted": "drop ✗"}
        return f"    · {kw['fid']}: {mark.get(kw['status'], kw['status'])}  [{kw['severity']}]"
    if kind == "done":
        esc = kw.get("escalated", 0)
        return (f"  = {kw['confirmed']} confirmed · {esc} escalated · "
                f"{kw['dropped']} dropped by consensus")
    if kind == "inventory":
        return (f"  ⊟ inventory: {kw['total']} components "
                f"({kw['queryable']} queryable, {kw['unpinned']} unpinned) "
                f"from {', '.join(kw.get('sources', []))}")
    if kind == "scanned":
        return f"  ⌕ OSV: {kw['advisories']} advisory match(es) across {kw['components']} components"
    if kind == "deferred":
        return f"  … {kw['count']} lower-severity advisor(ies) deferred from triage"
    if kind == "triaged":
        tag = " → report" if kw.get("report") else ""
        return f"    · {kw['id']}: {kw['urgency']}{tag}"
    if kind == "cve_done":
        return (f"  = {kw['triaged']} triaged · {kw['reportable']} reportable · "
                f"{kw['deferred']} deferred")
    if kind == "error":
        return f"    ! {kw.get('layer')} error ({kw.get('lens', '')}): {kw.get('error')}"
    return ""


def _block(f) -> list[str]:
    loc = f"{f.file}:{f.line}" if f.line else f.file
    anchor = "⚓ tool-anchored" if f.execution_anchored else "~ hypothesis (LLM-only)"
    tally = " ".join(
        f"{v['aspect']}:{'✓' if v['verdict'] == 'confirmed' else ('✗' if v['verdict'] == 'refuted' else '?')}"
        for v in f.verifier_verdicts
    )
    lines = ["", _color(f"[{f.severity.upper()}] {f.fid}  {f.title}", f.severity)]
    lines.append(f"   loc      {loc}")
    lines.append(f"   lenses   {', '.join(f.proposers)}   conf {f.confidence:.2f}   {anchor}")
    if tally:
        lines.append(f"   aspects  {tally}")
    if f.evidence:
        ev = "; ".join(f"{d['source']}:{d['code']}@{d['line']}" for d in f.evidence)
        lines.append(f"   evidence {ev}")
        cite = next((d.get("citation") for d in f.evidence if d.get("citation")), "")
        rule = next((d.get("rule") for d in f.evidence if d.get("rule")), "")
        if cite:
            lines.append(f"   standard {rule}  ({cite})")
    if f.arbiter_summary:
        lines.append(f"   verdict  {f.arbiter_summary}")
    if f.rationale:
        lines.append(f"   why      {f.rationale}")
    if f.suggested_fix:
        lines.append(f"   fix      {f.suggested_fix}")
    return lines


def render(findings, target) -> str:
    confirmed = [f for f in findings if f.status == "confirmed"]
    escalated = [f for f in findings if f.status == "needs_human"]
    head = f"\n══ saddlerFitter audit · {target.get('path')} ══"
    lines = [_C["bold"] + head + _C["reset"] if sys.stdout.isatty() else head]
    if not confirmed and not escalated:
        lines.append("  No findings cleared consensus (clean, or below threshold).")
        return "\n".join(lines)
    for f in confirmed:
        lines += _block(f)
    if escalated:
        lines.append("")
        banner = "── NEEDS HUMAN REVIEW · verifiers split on serious findings ──"
        lines.append(_C["bold"] + banner + _C["reset"] if sys.stdout.isatty() else banner)
        for f in escalated:
            lines += _block(f)
    lines.append("")
    return "\n".join(lines)
