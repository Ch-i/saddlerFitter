"""Consensus triage of a CVE hit, in the deployment's own context.

OSV already version-filters, so the LLM panel answers the questions a feed can't:
is the vulnerable component actually *reachable* in OUR deployment, and is the fix
a *safe* bump? Same generator -> blind-verifier -> arbiter shape as the code auditor,
producing a human-gated remediation plan rather than a code finding.
"""
from __future__ import annotations

from .. import config
from ..llm import run_agent
from ..schema import extract_json
from . import sources

# How the software under watch is deployed — the context the panel needs to judge
# whether a CVE is reachable HERE. Supplied by the operator via
# SADDLER_DEPLOYMENT_CONTEXT or a .saddler/deployment.md in the audited repo; absent
# that, a neutral default triages on general reachability.
_NEUTRAL_CONTEXT = (
    "No deployment context was provided. Triage on general reachability: treat a "
    "component as reachable if it is a runtime dependency of the service, assume a "
    "typical internet-facing or internal deployment, and weigh whether the vulnerable "
    "code path is plausibly exercised. When unsure, prefer reporting over dismissing."
)


def _deployment_context() -> str:
    if config.DEPLOYMENT_CONTEXT.strip():
        return config.DEPLOYMENT_CONTEXT.strip()
    for name in (".saddler/deployment.md", ".saddler/deployment.txt"):
        try:
            with open(name, encoding="utf-8") as fh:
                txt = fh.read().strip()
            if txt:
                return txt
        except OSError:
            continue
    return _NEUTRAL_CONTEXT


DEPLOYMENT_CONTEXT = _deployment_context()

ASPECT_Q = {
    "exploitable_in_deployment": "Given the deployment context, can this advisory "
    "actually be exploited here — is the vulnerable component/feature reachable via "
    "an exposed endpoint or a realistic actor, with this configuration? confirmed = "
    "realistically exploitable/relevant here; refuted = not reachable or not our usage.",
    "fix_safety": "Is moving to the fixed version a safe, low-risk change for our "
    "pinned version (no major-version break, drop-in)? confirmed = safe straightforward "
    "bump; refuted = risky/major break, or no fixed version is available yet.",
}


def _head(component: dict, vuln: dict) -> str:
    summary = vuln.get("summary") or (vuln.get("details", "") or "")[:500]
    fixed = sources.fixed_versions(vuln)
    aliases = ", ".join(vuln.get("aliases", []) or [])
    return (
        f"ADVISORY {vuln.get('id')}" + (f" ({aliases})" if aliases else "") + "\n"
        f"  package : {component['name']} ({component['ecosystem']})\n"
        f"  our ver : {component.get('version') or 'UNPINNED/floating'}\n"
        f"  fixed in: {', '.join(fixed) if fixed else 'no fix listed'}\n"
        f"  summary : {summary}"
    )


def _verify(head: str, context: str, aspect: str) -> dict:
    q = ASPECT_Q.get(aspect, f"Assess the {aspect}.")
    prompt = f"""You are one of several INDEPENDENT verifiers triaging a published \
vulnerability for a specific deployment. Assess EXACTLY ONE aspect; you cannot see \
the other verifiers.

DEPLOYMENT
{context}

{head}

ASPECT — {aspect}: {q}

If genuinely unsure, use "uncertain". Do not use tools.
Respond with ONLY a JSON object: \
{{"verdict": "confirmed|refuted|uncertain", "confidence": 0.0, "reason": str}}"""
    raw = run_agent(prompt, model=config.CRITIC_MODEL)
    data = extract_json(raw)
    if not isinstance(data, dict):
        data = {}
    return {
        "aspect": aspect,
        "verdict": str(data.get("verdict", "uncertain")).strip().lower(),
        "confidence": _f(data.get("confidence")),
        "reason": str(data.get("reason", "")).strip(),
    }


def _plan(head: str, context: str, verdicts: list[dict]) -> dict:
    import json as _json

    prompt = f"""You are the arbiter deciding how this deployment should respond to a \
published vulnerability, weighing independent verifier verdicts.

DEPLOYMENT
{context}

{head}

VERIFIER VERDICTS
{_json.dumps(verdicts, indent=2)}

Decide. `report=true` means a human operator should see this now. Set urgency: \
"now" (exploitable + fixed) / "soon" (relevant, plan the bump) / "watch" (low \
reachability or no fix yet) / "ignore" (not applicable here, with reason). \
Remediation steps should be concrete and specific to the component — e.g. the exact \
version/digest to pin, the manifest to edit, and any redeploy + post-deploy \
verification the operator must run. Do not use tools.

Respond with ONLY a JSON object:
{{"report": true, "urgency": "now|soon|watch|ignore", "severity": \
"critical|high|medium|low|info", "summary": str (one line for the operator), \
"remediation_steps": [str, ...]}}"""
    raw = run_agent(prompt, model=config.ARBITER_MODEL)
    data = extract_json(raw)
    if not isinstance(data, dict):
        data = {}
    return {
        "report": bool(data.get("report", True)),
        "urgency": str(data.get("urgency", "soon")).strip().lower(),
        "severity": str(data.get("severity", "medium")).strip().lower(),
        "summary": str(data.get("summary", "")).strip(),
        "remediation_steps": [str(s) for s in (data.get("remediation_steps") or [])],
    }


def triage(component: dict, vuln: dict, context: str = DEPLOYMENT_CONTEXT) -> dict:
    head = _head(component, vuln)
    verdicts = [_verify(head, context, a) for a in ASPECT_Q]
    plan = _plan(head, context, verdicts)
    return {
        "id": vuln.get("id"),
        "aliases": vuln.get("aliases", []) or [],
        "component": component,
        "fixed_versions": sources.fixed_versions(vuln),
        "feed_severity": sources.vuln_severity(vuln),
        "verifier_verdicts": verdicts,
        **plan,
    }


def _f(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default
