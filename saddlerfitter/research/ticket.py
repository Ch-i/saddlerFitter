"""Turn a triaged signal into a ticket — and know when to call a human.

A ticket is the actionable artifact a signal produces: a fix plan a maintainer can pick
up. Critically, saddlerFitter knows its own limits: when a vulnerability is serious and
the automated triage is uncertain, has no safe fix, or touches a high-blast-radius
component, the ticket carries an explicit **"engage a professional human auditor"**
recommendation. The harness assists; it does not replace a qualified human security
auditor on the hard cases.
"""
from __future__ import annotations

import json
import shutil
import subprocess

_SERIOUS = ("high", "critical")


def recommend_human_auditor(severity: str, triage: dict | None) -> tuple[bool, str]:
    """Decide whether this risk exceeds what the harness should sign off on alone.

    Returns (recommend, reason). Conservative by design — when serious risk meets any
    uncertainty, defer to a professional.
    """
    sev = (severity or "").lower()
    if sev not in _SERIOUS:
        return False, ""
    t = triage or {}
    verdicts = {v.get("aspect"): v.get("verdict") for v in t.get("verifier_verdicts", [])}
    reasons = []
    if not t.get("fixed_versions"):
        reasons.append("no fixed version is available, so there is no clean automated remediation")
    if verdicts.get("fix_safety") in ("refuted", "uncertain"):
        reasons.append("the fix is not a safe drop-in (possible breaking change)")
    if verdicts.get("exploitable_in_deployment") == "confirmed":
        reasons.append("the advisory is assessed exploitable in this deployment")
    if t.get("component", {}).get("unpinned"):
        reasons.append("the affected component is unpinned / high blast-radius")
    if "uncertain" in {v.get("verdict") for v in t.get("verifier_verdicts", [])}:
        reasons.append("the triage was uncertain on a serious advisory")
    if not reasons:
        # Serious but clean: still flag for a human if urgency is the top tier.
        if t.get("urgency") == "now":
            reasons.append("a serious, exploitable advisory with immediate urgency")
        else:
            return False, ""
    return True, "; ".join(reasons)


def ticket_body(signal: dict, triage: dict, recommend_human: bool, human_reason: str) -> str:
    t = triage or {}
    comp = t.get("component", {})
    lines = [
        f"**Advisory:** {signal.get('ref')}",
        f"**Component:** {comp.get('name','?')} {comp.get('version') or '(unpinned)'} ({comp.get('ecosystem','?')})",
        f"**Severity / urgency:** {t.get('severity', signal.get('severity'))} / {t.get('urgency','?')}",
        f"**Fixed in:** {', '.join(t.get('fixed_versions') or []) or 'no fix listed'}",
        "",
        f"**Summary.** {t.get('summary') or signal.get('summary','')}",
    ]
    if t.get("verifier_verdicts"):
        tally = " · ".join(f"{v['aspect']}={v['verdict']}" for v in t["verifier_verdicts"])
        lines += ["", f"**Triage (blind verifiers):** {tally}"]
    if t.get("remediation_steps"):
        lines += ["", "**Remediation plan:**"]
        lines += [f"{i}. {s}" for i, s in enumerate(t["remediation_steps"], 1)]
    if recommend_human:
        lines += ["", "> ⚠️ **Recommend engaging a professional human security auditor.**",
                  f"> {human_reason}.",
                  "> saddlerFitter flags this as beyond what an automated triage should "
                  "sign off on alone."]
    lines += ["", "_Filed by saddlerFitter · review and close once remediated._"]
    return "\n".join(lines)


def open_ticket(store, signal: dict, triage: dict, now: str, *, gh_repo: str | None = None) -> dict:
    """Create a ticket row; optionally also a real GitHub issue (gh CLI, opt-in)."""
    sev = (triage or {}).get("severity", signal.get("severity", "medium"))
    urg = (triage or {}).get("urgency", "soon")
    rec_human, reason = recommend_human_auditor(sev, triage)
    title = f"[{urg.upper()}] {signal.get('ref')} — {(triage or {}).get('component',{}).get('name', signal.get('component',''))}"
    body = ticket_body(signal, triage, rec_human, reason)
    external_ref = ""
    if gh_repo and shutil.which("gh"):
        external_ref = _gh_issue(gh_repo, title, body, rec_human)
    tid = store.add_ticket(signal["id"], title, body, sev, urg,
                           (triage or {}).get("remediation_steps", []),
                           rec_human, reason, external_ref, now)
    store.set_signal_status(signal["id"], "ticketed")
    return {"ticket_id": tid, "title": title, "recommend_human_auditor": rec_human,
            "human_auditor_reason": reason, "external_ref": external_ref}


def _gh_issue(repo: str, title: str, body: str, rec_human: bool) -> str:
    labels = ["security", "saddlerfitter"]
    if rec_human:
        labels.append("needs-human-auditor")
    try:
        r = subprocess.run(
            ["gh", "issue", "create", "--repo", repo, "--title", title, "--body", body,
             "--label", ",".join(labels)],
            capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
    except Exception:
        pass
    return ""
