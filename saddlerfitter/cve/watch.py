"""Orchestrate the CVE watch: inventory -> OSV scan -> consensus triage -> report.

A confirmed, reportable hit is the "message + plan to remediate" the operator asked
for; in the full saddler it posts to #findings and queues a row in #approvals for a
human /approve before any image bump or dependency pin is applied.
"""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .. import config
from . import inventory, sources, triage

URGENCY_RANK = {"now": 4, "soon": 3, "watch": 2, "ignore": 1}

# Common dependency manifests, discovered relative to the repo root when no explicit
# SADDLER_SBOM_PATHS is set.
_MANIFEST_NAMES = [
    "uv.lock", "poetry.lock", "requirements.txt",
    "docker-compose.yml", "docker-compose.yaml",
    "docker/docker-compose.yml", "docker/docker-compose.yaml",
    "docker/docker-compose.override.yml",
]


def _repo_root() -> Path:
    import subprocess

    try:
        r = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return Path(r.stdout.strip())
    except Exception:
        pass
    return Path.cwd()


def default_paths() -> list[str]:
    """Explicit SADDLER_SBOM_PATHS wins; otherwise auto-discover manifests at the repo root."""
    if config.SBOM_PATHS:
        return [p for p in config.SBOM_PATHS if os.path.exists(p)]
    root = _repo_root()
    return [str(root / n) for n in _MANIFEST_NAMES if (root / n).exists()]


def run_cve_scan(paths=None, max_triage=6, on_event=None) -> dict:
    paths = paths or default_paths()
    emit = on_event or (lambda *a, **k: None)

    inv = inventory.build_inventory(paths)
    unpinned = [c for c in inv if c.get("unpinned")]
    queryable = [c for c in inv if c["ecosystem"] in ("PyPI", "Go", "npm")]
    emit("inventory", total=len(inv), queryable=len(queryable),
         unpinned=len(unpinned), sources=[os.path.basename(p) for p in paths])

    hits = sources.osv_scan(queryable, on_event=emit)
    # Sort by feed severity first so the kept representative of an alias group is the
    # richest/highest-severity record, then dedup by the UNION of ids+aliases. OSV
    # returns a separate GHSA-* and GO-*/CVE-* record for the SAME vulnerability;
    # without alias dedup they get triaged twice and can yield inconsistent verdicts.
    hits.sort(
        key=lambda h: sources.severity_rank(sources.vuln_severity(h["vuln"])),
        reverse=True,
    )
    seen_ids: set = set()
    advisories = []
    for h in hits:
        v = h["vuln"]
        ids = {v.get("id")} | set(v.get("aliases") or [])
        ids.discard(None)
        if ids & seen_ids:
            continue
        seen_ids |= ids
        advisories.append(h)
    # Triage ordering: floating/unpinned (e.g. the public ingress) first, then feed
    # severity. Feed severity alone is a weak gate — an in-context [NOW] finding can
    # carry a "low" feed label (CVE-2026-27585 on the sole ingress did) — so floating
    # high-stakes components are never deferred behind a cap.
    advisories.sort(
        key=lambda h: (
            1 if h["component"].get("unpinned") else 0,
            sources.severity_rank(sources.vuln_severity(h["vuln"])),
        ),
        reverse=True,
    )
    emit("scanned", components=len(queryable), advisories=len(advisories))

    if max_triage is None:
        to_triage = advisories
    elif max_triage <= 0:
        to_triage = []  # list-only
    else:
        to_triage = advisories[:max_triage]
    deferred = advisories[len(to_triage):]
    if deferred:
        emit("deferred", count=len(deferred))

    triaged = []
    if to_triage:
        with ThreadPoolExecutor(max_workers=config.MAX_CONCURRENCY) as ex:
            futs = {
                ex.submit(triage.triage, h["component"], h["vuln"]): h for h in to_triage
            }
            for fut in as_completed(futs):
                try:
                    t = fut.result()
                except Exception as e:
                    h = futs[fut]
                    t = {"id": h["vuln"].get("id"), "component": h["component"],
                         "report": True, "urgency": "soon", "severity": "unknown",
                         "summary": f"triage error: {e}", "remediation_steps": [],
                         "verifier_verdicts": [], "fixed_versions": [], "aliases": []}
                emit("triaged", id=t["id"], urgency=t["urgency"], report=t["report"])
                triaged.append(t)
    triaged.sort(key=lambda t: URGENCY_RANK.get(t["urgency"], 0), reverse=True)

    reportable = [t for t in triaged if t["report"] and t["urgency"] != "ignore"]
    emit("cve_done", triaged=len(triaged), reportable=len(reportable),
         deferred=len(deferred))
    return {
        "inventory": inv,
        "unpinned": unpinned,
        "advisories": advisories,
        "triaged": triaged,
        "reportable": reportable,
        "deferred": deferred,
    }


def format_report(result: dict) -> str:
    inv, unpinned = result["inventory"], result["unpinned"]
    L = [f"\n══ saddlerFitter CVE watch ══",
         f"  inventory: {len(inv)} components "
         f"({sum(1 for c in inv if c['ecosystem'] == 'PyPI')} PyPI, "
         f"{sum(1 for c in inv if c['ecosystem'] == 'Go')} Go, "
         f"{sum(1 for c in inv if c['ecosystem'] == 'OCI')} base-image)",
         f"  advisories: {len(result['advisories'])} matched · "
         f"{len(result['reportable'])} reportable · {len(result['deferred'])} deferred"]

    floats, seen_img = [], set()
    for c in unpinned:
        img = c.get("image")
        if img and img not in seen_img:
            seen_img.add(img)
            floats.append(c)
    if floats:
        L.append("\n  ⚠ unpinned/floating images (CVE exposure can't be version-checked):")
        for c in floats:
            L.append(f"      {c['image']}  — pin to an explicit version")

    if not result["reportable"]:
        L.append("\n  No reportable advisories at the pinned versions. ✓")
    for t in result["reportable"]:
        c = t["component"]
        ver = c.get("version") or "floating"
        fix = ", ".join(t["fixed_versions"]) if t["fixed_versions"] else "no fix listed"
        al = (" / " + ", ".join(t["aliases"])) if t["aliases"] else ""
        L.append("")
        L.append(f"  [{t['urgency'].upper()}] {t['id']}{al}  ({t['severity']})")
        L.append(f"     package  {c['name']} {ver}  →  fixed: {fix}")
        L.append(f"     summary  {t['summary']}")
        tally = " ".join(
            f"{v['aspect']}:{'✓' if v['verdict'] == 'confirmed' else ('✗' if v['verdict'] == 'refuted' else '?')}"
            for v in t["verifier_verdicts"]
        )
        if tally:
            L.append(f"     verify   {tally}")
        if t["remediation_steps"]:
            L.append("     remediation plan →")
            for i, s in enumerate(t["remediation_steps"], 1):
                L.append(f"        {i}. {s}")

    if result["deferred"]:
        L.append(f"\n  + {len(result['deferred'])} lower-severity advisor"
                 f"{'y' if len(result['deferred']) == 1 else 'ies'} detected, not triaged "
                 f"(raise --max-triage):")
        for h in result["deferred"][:12]:
            L.append(f"      {h['vuln'].get('id')}  {h['component']['name']} "
                     f"{h['component'].get('version') or ''}")
    L.append("\n  note: PyPI versions come from the lockfile (the build/index env); a "
             "container image pins its own baked deps independently — confirm "
             "in-container (pip show) before bumping a transitive package.")
    L.append("")
    return "\n".join(L)
