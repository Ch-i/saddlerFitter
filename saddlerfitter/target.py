"""Load an audit target: a single file, or a git diff."""
from __future__ import annotations

import os
import subprocess

MAX_BYTES = 200_000


def from_file(path: str) -> dict:
    with open(path, "r", errors="replace") as fh:
        content = fh.read(MAX_BYTES + 1)
    return {
        "kind": "file",
        "path": os.path.abspath(path),
        "content": content[:MAX_BYTES],
        "truncated": len(content) > MAX_BYTES,
    }


def from_diff(repo: str, ref: str | None = None, excludes=None) -> dict:
    cmd = ["git", "-C", repo, "diff"]
    if ref:
        cmd.append(ref)
    if excludes:
        cmd += ["--", "."] + [f":(exclude){g}" for g in excludes]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"git diff failed: {out.stderr[:300]}")
    return {
        "kind": "diff",
        "path": os.path.abspath(repo),
        "ref": ref or "working tree",
        "content": out.stdout[:MAX_BYTES],
        "truncated": len(out.stdout) > MAX_BYTES,
    }
