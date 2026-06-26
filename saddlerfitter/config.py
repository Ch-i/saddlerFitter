"""saddlerFitter configuration — every value overridable via SADDLER_* env vars.

All settings are environment-overridable so the harness is portable across repos and
hosts without code edits and ships no machine-specific values.
"""
from __future__ import annotations

import os
import shutil


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


# --- LLM backend: the LOCAL Claude Code auth is the "locally authenticated" seam.
# Each auditor is a `claude -p` headless subagent using this box's own credentials;
# no API keys are plumbed and nothing leaves the local trust boundary for auth.
CLAUDE_BIN = _env("SADDLER_CLAUDE_BIN", shutil.which("claude") or "claude")
# Second family for the cross-family double-grill (decorrelation). Codex CLI uses
# its own local ChatGPT-login auth (~/.codex/auth.json) — no API keys, same "local
# auth" seam as claude. Low reasoning effort by default for gate speed.
import os as _os
CODEX_BIN = _env("SADDLER_CODEX_BIN", shutil.which("codex") or _os.path.expanduser("~/.npm-global/bin/codex"))
CODEX_MODEL = _env("SADDLER_CODEX_MODEL", "")  # empty = codex config default (gpt-5.4)
CODEX_REASONING = _env("SADDLER_CODEX_REASONING", "low")
PROPOSER_MODEL = _env("SADDLER_PROPOSER_MODEL", "sonnet")
CRITIC_MODEL = _env("SADDLER_CRITIC_MODEL", "sonnet")
ARBITER_MODEL = _env("SADDLER_ARBITER_MODEL", "opus")
FIXER_MODEL = _env("SADDLER_FIXER_MODEL", "opus")
DEFAULT_TIMEOUT = int(_env("SADDLER_LLM_TIMEOUT", "300"))

# --- consensus shape (the layered hierarchy) ---
LENSES = [
    s.strip()
    for s in _env(
        "SADDLER_LENSES", "correctness,security,performance,maintainability"
    ).split(",")
    if s.strip()
]
# Aspect-diverse blind verifiers (BoN-MAV, arXiv:2502.20379): each checks ONE
# independent question so they fail differently instead of confabulating together.
VERIFY_ASPECTS = [
    s.strip()
    for s in _env(
        "SADDLER_ASPECTS", "reachability,already_handled,impact,reproducibility"
    ).split(",")
    if s.strip()
]
MAX_CONCURRENCY = int(_env("SADDLER_MAX_CONCURRENCY", "5"))
MIN_SEVERITY = _env("SADDLER_MIN_SEVERITY", "low")
# The double-grill blocks a commit/push on a confirmed finding at/above this severity
# from EITHER model family.
GATE_BLOCK_SEVERITY = _env("SADDLER_GATE_BLOCK", "high")
# Paths the gate skips (intentional vuln fixtures, test data) — they would block
# every push forever otherwise.
GATE_EXCLUDE = _env(
    "SADDLER_GATE_EXCLUDE",
    "saddlerfitter/examples/*,*/examples/*,*/fixtures/*,*/_fixtures/*,*/testdata/*",
)

# Non-LLM evidence anchor: a stdlib AST linter always runs; uvx ruff/bandit are an
# opt-in richer layer (needs `uv`, may hit the network on first use).
EXTERNAL_LINT = _env("SADDLER_EXTERNAL_LINT", "0") not in ("0", "", "false", "no")
EVIDENCE_WINDOW = int(_env("SADDLER_EVIDENCE_WINDOW", "3"))

# --- IRC substrate (consumed by the daemon slice) ---
IRC_HOST = _env("SADDLER_IRC_HOST", "127.0.0.1")
IRC_PORT = int(_env("SADDLER_IRC_PORT", "6667"))
HUB_WEB_PORT = int(_env("SADDLER_HUB_WEB_PORT", "8198"))
# Bind for the hub server + dashboard. Default localhost-only: the IRC server
# accepts writes to control channels (#approvals), so exposing it on 0.0.0.0 without
# auth lets any Tailnet actor spoof an /approve. To expose safely, set
# SADDLER_IRC_PASSWORD (clients must then PASS) and SADDLER_HUB_BIND=0.0.0.0.
HUB_BIND = _env("SADDLER_HUB_BIND", "127.0.0.1")
IRC_PASSWORD = _env("SADDLER_IRC_PASSWORD", "")
IRC_NICK_PREFIX = _env("SADDLER_IRC_NICK_PREFIX", "saddler")
CH_FINDINGS = _env("SADDLER_CH_FINDINGS", "#saddler-findings")
CH_DEBATE = _env("SADDLER_CH_DEBATE", "#saddler-debate")
CH_APPROVALS = _env("SADDLER_CH_APPROVALS", "#saddler-approvals")
CH_LOG = _env("SADDLER_CH_LOG", "#saddler-log")

# --- auth / commit gate ---
# Who may approve a revision (IRC nicks). Empty list = any human in the channel.
APPROVERS = [s.strip() for s in _env("SADDLER_APPROVERS", "").split(",") if s.strip()]
COMMIT_IDENTITY = _env(
    "SADDLER_COMMIT_IDENTITY", "saddlerFitter <saddler@localhost>"
)

# --- CVE watch ---
# Dependency manifests to scan. Empty = auto-discover common manifests at the repo
# root (uv.lock, poetry.lock, requirements.txt, docker-compose.y*ml). Comma-separated.
SBOM_PATHS = [s.strip() for s in _env("SADDLER_SBOM_PATHS", "").split(",") if s.strip()]
# A plain-English description of how the software is deployed, used to triage whether a
# published CVE is actually reachable HERE. Set via env, or drop a .saddler/deployment.md
# in the audited repo. Empty falls back to a neutral, deployment-agnostic triage.
DEPLOYMENT_CONTEXT = _env("SADDLER_DEPLOYMENT_CONTEXT", "")

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
