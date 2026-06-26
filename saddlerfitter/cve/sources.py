"""Advisory feed clients — OSV.dev (primary, version-filtered) + a thin NVD fallback.

Stdlib-only (urllib) so the watch has no extra deps. OSV's batch endpoint lets us
query the whole inventory in a couple of requests; details are fetched only for the
packages that actually have a hit.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
NVD_CVE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_SEV_RANK = {"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1, "unknown": 0}


def _post(url: str, payload: dict, timeout: int = 30) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _get(url: str, timeout: int = 30) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


def _query(component: dict) -> dict:
    pkg = {"name": component["name"], "ecosystem": component["ecosystem"]}
    q = {"package": pkg}
    if component.get("version"):
        q["version"] = component["version"]
    return q


def osv_scan(components: list[dict], on_event=None) -> list[dict]:
    """Return [{component, vuln}] for every advisory affecting the inventory.

    Components with a version are version-filtered by OSV; versionless ones return
    all advisories for the package (flagged version_unfiltered for the report).
    """
    emit = on_event or (lambda *a, **k: None)
    queryable = [c for c in components if c["ecosystem"] in ("PyPI", "Go", "npm")]
    results: list[dict] = []
    CHUNK = 200
    for i in range(0, len(queryable), CHUNK):
        batch = queryable[i : i + CHUNK]
        try:
            resp = _post(OSV_BATCH, {"queries": [_query(c) for c in batch]})
            got = resp.get("results", []) or []
        except Exception as e:  # network/transport — surface, never crash the watch
            emit("error", layer="osv", error=str(e))
            got = []
        # Keep results aligned 1:1 with the batch — a short/long response must never
        # shift advisories onto the wrong component.
        results.extend((got + [{}] * len(batch))[: len(batch)])

    detail: dict[str, dict] = {}
    hits: list[dict] = []
    for comp, res in zip(queryable, results):
        for v in (res or {}).get("vulns", []) or []:
            vid = v["id"]
            if vid not in detail:
                try:
                    detail[vid] = _get(OSV_VULN + vid)
                except Exception:
                    detail[vid] = {"id": vid}
            hits.append(
                {"component": comp, "vuln": detail[vid],
                 "version_unfiltered": not comp.get("version")}
            )
    return hits


def nvd_keyword(keyword: str, limit: int = 5, timeout: int = 30) -> list[dict]:
    """Thin NVD lookup for CPE-only products (e.g. PostgreSQL) not in OSV."""
    url = f"{NVD_CVE}?{urllib.parse.urlencode({'keywordSearch': keyword, 'resultsPerPage': limit})}"
    try:
        data = _get(url, timeout=timeout)
    except Exception:
        return []
    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        out.append({"id": cve.get("id"), "summary": _nvd_desc(cve), "source": "nvd"})
    return out


def _nvd_desc(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def vuln_severity(vuln: dict) -> str:
    """Best-effort severity label from OSV (GHSA database_specific or CVSS vector)."""
    spec = (vuln.get("database_specific") or {}).get("severity")
    if spec:
        return str(spec).lower()
    for aff in vuln.get("affected", []) or []:
        s = (aff.get("database_specific") or {}).get("severity")
        if s:
            return str(s).lower()
    for s in vuln.get("severity", []) or []:
        score = s.get("score", "")
        # CVSS vector -> coarse label by the area of the vector we can read cheaply
        if "CVSS:3" in score or "CVSS:4" in score:
            return "unknown"  # vector present but no cheap label; triage assesses severity
    return "unknown"


def severity_rank(label: str) -> int:
    return _SEV_RANK.get(label, 0)


def fixed_versions(vuln: dict) -> list[str]:
    out = set()
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    out.add(ev["fixed"])
    return sorted(out)
