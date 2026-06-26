"""Connect a set of agent bots to a running hub and post real-shaped chatter, so the
dashboard shows the roster (with source) and a live audit/CVE conversation.
"""
from __future__ import annotations

import time

from .. import config
from .bus import Bot

# (nick, role, model, source)
AGENTS = [
    ("orchestrator", "orchestrator", "opus", "host:local"),
    ("proposer-sec", "proposer", "sonnet", "lens:security"),
    ("proposer-corr", "proposer", "sonnet", "lens:correctness"),
    ("verifier-reach", "verifier", "sonnet", "aspect:reachability"),
    ("verifier-fix", "verifier", "sonnet", "aspect:fix_safety"),
    ("arbiter", "arbiter", "opus", "host:local"),
    ("cve-watch", "cve-triage", "opus", "feed:osv.dev+nvd"),
]

SCRIPT = [
    ("orchestrator", config.CH_LOG, "cve-scan started · target project SBOM (69 components)"),
    ("cve-watch", config.CH_DEBATE, "candidate: caddy:2.8-alpine is the sole public ingress, unpinned + outdated"),
    ("proposer-sec", config.CH_DEBATE, "candidate: CVE-2026-27585 glob-bypass → path traversal on /assets"),
    ("verifier-reach", config.CH_DEBATE, "reachability: /assets is served by Caddy on :8088 — reachable. confirmed"),
    ("verifier-fix", config.CH_DEBATE, "fix_safety: 2.8 → 2.11.1 is a drop-in within v2. confirmed"),
    ("arbiter", config.CH_FINDINGS, "[NOW] CVE-2026-27585 caddy:2.8-alpine — path traversal + token-gate bypass (conf 0.86)"),
    ("cve-watch", config.CH_FINDINGS, "+ starlette 1.2.0 → 1.3.0 (CVE-2026-54282, [SOON]); 13 Caddy CVEs [WATCH] not reachable"),
    ("orchestrator", config.CH_APPROVALS, "A1: pin caddy:2.8-alpine → 2.11.1 + docker compose up -d caddy — reply '/approve A1'"),
]


def run():
    bots = {}
    for nick, role, model, source in AGENTS:
        b = Bot(nick, host=config.IRC_HOST, port=config.IRC_PORT,
                role=role, model=model, source=source,
                password=config.IRC_PASSWORD).connect()
        b.join(config.CH_FINDINGS, config.CH_DEBATE, config.CH_APPROVALS, config.CH_LOG)
        bots[nick] = b
    time.sleep(0.6)
    for nick, chan, msg in SCRIPT:
        bots[nick].say(chan, msg)
        time.sleep(0.4)
    return bots


def run_blocking():
    bots = run()
    print(f"demo: {len(bots)} agent bots connected and posted. "
          f"dashboard http://{config.IRC_HOST}:{config.HUB_WEB_PORT}  (Ctrl-C to disconnect)",
          flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        for b in bots.values():
            b.quit()
