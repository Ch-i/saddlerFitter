"""Build the technology inventory from the live manifests.

Doc-awareness bridge: the watch only knows what the manifests/docs declare, so
keeping these current is the doc-maintenance role. `uv.lock` covers the Python
tree precisely; IMAGE_MAP maps the deployed container images to the OSV/NVD
identity to query.
"""
from __future__ import annotations

import os
import re
import tomllib

# Container image (repo, tag is read separately) -> the upstream package(s) to query
# for CVEs. Some popular images ARE published packages, so we can query them by the
# image's pinned version. This is a starter map of common public images; extend it for
# your stack. Name variants cover OSV's PyPI normalization.
IMAGE_MAP = {
    "ghcr.io/stac-utils/pgstac": [{"name": "pypgstac", "ecosystem": "PyPI"}],
    "ghcr.io/stac-utils/stac-fastapi-pgstac": [
        {"name": "stac-fastapi-pgstac", "ecosystem": "PyPI"},
        {"name": "stac-fastapi.pgstac", "ecosystem": "PyPI"},
    ],
    "ghcr.io/stac-utils/titiler-pgstac": [
        {"name": "titiler-pgstac", "ecosystem": "PyPI"},
        {"name": "titiler.pgstac", "ecosystem": "PyPI"},
    ],
    "ghcr.io/developmentseed/titiler": [
        {"name": "titiler-core", "ecosystem": "PyPI"},
        {"name": "titiler", "ecosystem": "PyPI"},
    ],
    "caddy": [{"name": "github.com/caddyserver/caddy/v2", "ecosystem": "Go"}],
}


def _clean_ver(tag: str | None) -> str | None:
    """Image tag -> a version OSV can filter on, or None if it floats (e.g. latest,
    or a major-only tag like '2.8-alpine')."""
    if not tag:
        return None
    core = tag.split("-")[0].lstrip("v")
    # require a full-ish semver (x.y.z); float tags like '2.8' or 'latest' -> None
    return core if re.match(r"^\d+\.\d+\.\d+", core) else None


def from_uv_lock(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    out = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        if not name:
            continue
        out.append(
            {
                "name": name,
                "version": pkg.get("version"),
                "ecosystem": "PyPI",
                "component": name,
                "logical": f"{name} {pkg.get('version')}",
                "source": os.path.basename(path),
                "unpinned": pkg.get("version") is None,
            }
        )
    return out


_REQ_RE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:==\s*([0-9][^\s;#]*))?")


def from_requirements(path: str) -> list[dict]:
    """Parse a pip requirements.txt. A pinned `name==x.y.z` is queryable; anything
    looser (ranges, unpinned) is recorded as unpinned so it surfaces as a finding."""
    if not os.path.exists(path):
        return []
    out = []
    with open(path, errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith(("#", "-", "git+", "http")):
                continue
            m = _REQ_RE.match(line)
            if not m or not m.group(1):
                continue
            name, ver = m.group(1), m.group(2)
            out.append(
                {
                    "name": name,
                    "version": ver,
                    "ecosystem": "PyPI",
                    "component": name,
                    "logical": f"{name} {ver or '(unpinned)'}",
                    "source": os.path.basename(path),
                    "unpinned": ver is None,
                }
            )
    return out


def from_compose(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path, errors="replace") as fh:
        text = fh.read()
    out = []
    for m in re.finditer(r"image:\s*([^\s#]+)", text):
        ref = m.group(1).strip()
        # Split on the TAG colon only — a registry host may carry a :port (e.g.
        # registry:5000/img:1.2), so the tag is the colon in the last path segment.
        if ":" in ref.rsplit("/", 1)[-1]:
            repo, _, tag = ref.rpartition(":")
        else:
            repo, tag = ref, ""
        base = repo.split("/")[-1]
        version = _clean_ver(tag)
        mapped = IMAGE_MAP.get(repo) or IMAGE_MAP.get(base)
        if mapped:
            for pkg in mapped:
                out.append(
                    {
                        "name": pkg["name"],
                        "version": version,
                        "ecosystem": pkg["ecosystem"],
                        "component": base,
                        "logical": f"{base} (image {tag})",
                        "image": ref,
                        "source": os.path.basename(path),
                        "unpinned": version is None,
                    }
                )
        else:
            # Base image (e.g. a postgres layer) we can't OSV-query by package — record
            # for provenance so it isn't silently outside the watch.
            out.append(
                {
                    "name": base,
                    "version": tag,
                    "ecosystem": "OCI",
                    "component": base,
                    "logical": f"{base} (image {tag})",
                    "image": ref,
                    "source": os.path.basename(path),
                    "unpinned": version is None,
                }
            )
    return out


def build_inventory(paths: list[str]) -> list[dict]:
    """Merge manifests and dedup by (name, ecosystem, version)."""
    inv: list[dict] = []
    for p in paths:
        if p.endswith(".lock"):  # uv.lock / poetry.lock share the [[package]] shape
            inv += from_uv_lock(p)
        elif p.endswith(".txt"):
            inv += from_requirements(p)
        elif p.endswith((".yml", ".yaml")):
            inv += from_compose(p)
    seen, out = set(), []
    for c in inv:
        key = (c["name"], c["ecosystem"], c.get("version"))
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out
