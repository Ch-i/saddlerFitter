"""Cross-family double-grill — the commit/push gate.

Audit the target with two genuinely different model families (Claude Opus + Codex
gpt-5.4), each via its own LOCAL auth. Block on any confirmed finding at/above the
gate severity surviving EITHER family — one family's blind spots are not the other's
(a same-family panel carries far fewer effective votes, arXiv:2605.29800). This is
the in-between gate the pre-push hook invokes; it exits non-zero to refuse a push.
"""
from __future__ import annotations

from . import config, consensus
from .consensus import _sev_rank

CLAUDE_BACKEND = {
    "family": "claude", "proposer": config.PROPOSER_MODEL,
    "critic": config.CRITIC_MODEL, "arbiter": config.ARBITER_MODEL,
}
CODEX_BACKEND = {
    "family": "codex",
    "proposer": config.CODEX_MODEL or None,
    "critic": config.CODEX_MODEL or None,
    "arbiter": config.CODEX_MODEL or None,
}


def double_grill(target, on_event=None, backends=None) -> dict:
    backends = backends or [("claude", CLAUDE_BACKEND), ("codex", CODEX_BACKEND)]
    emit = on_event or (lambda *a, **k: None)
    passes = []
    for label, backend in backends:
        emit("grill_pass", family=label)
        findings = consensus.run_audit(target, backend=backend, on_event=on_event)
        passes.append((label, findings))
        emit("grill_pass_done", family=label,
             confirmed=sum(1 for f in findings if f.status == "confirmed"),
             escalated=sum(1 for f in findings if f.status == "needs_human"))
    block_rank = _sev_rank(config.GATE_BLOCK_SEVERITY)
    blockers = [
        (label, f)
        for label, fs in passes
        for f in fs
        if f.status == "confirmed" and _sev_rank(f.severity) >= block_rank
    ]
    return {
        "passes": passes,
        "blockers": blockers,
        "blocked": bool(blockers),
        "block_at": config.GATE_BLOCK_SEVERITY,
    }


def format_result(result: dict, target: dict) -> str:
    lines = [f"\n══ Cross-family double-grill · {target.get('path')} ══"]
    for label, fs in result["passes"]:
        conf = [f for f in fs if f.status == "confirmed"]
        esc = [f for f in fs if f.status == "needs_human"]
        lines.append(f"  [{label:6}] {len(conf)} confirmed · {len(esc)} escalated")
        for f in conf:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            lines.append(f"      {f.severity.upper():8} {f.title}  ({loc})")
    if result["blocked"]:
        lines.append(f"\n  ⛔ BLOCKED — {len(result['blockers'])} finding(s) ≥ "
                     f"{result['block_at']} across families:")
        for label, f in result["blockers"]:
            lines.append(f"      [{label}] {f.severity.upper()} {f.title}")
        lines.append("  push refused. Resolve, or `git push --no-verify` / lower "
                     "SADDLER_GATE_BLOCK to override.")
    else:
        lines.append(f"\n  ✓ PASS — no findings ≥ {result['block_at']} from either "
                     "family. Clear to commit/push.")
    return "\n".join(lines)
