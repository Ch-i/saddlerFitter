"""saddler — the saddlerFitter CLI.

Drives the saddler audit harness, the knowledge catalog, and the research watch:

    saddler audit path/to/file.py
    saddler grill --staged              # cross-family gate
    saddler knowledge show --lens security
    saddler watch                       # poll CVEs + disclosures -> signal -> ticket
    saddler research ingest <url|file|-> --profile "python web api"
"""
from __future__ import annotations

import argparse
import json
import sys

from . import config, render
from . import target as targetmod
from .consensus import run_audit


def _cve_scan(args) -> int:
    from .cve import watch

    def on_event(kind, **kw):
        if getattr(args, "json", False):
            return
        line = render.event_line(kind, **kw)
        if line:
            print(line, file=sys.stderr, flush=True)

    result = watch.run_cve_scan(max_triage=args.max_triage, on_event=on_event)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(watch.format_report(result))
    return 0


def _knowledge(args) -> int:
    from . import knowledge

    if args.action == "build":
        try:
            path, n = knowledge.build_db()
        except ImportError:
            print("saddler knowledge build: needs PyYAML (pip install pyyaml)", file=sys.stderr)
            return 1
        print(f"built {path}  ({n} rules)")
        print(f"cache {knowledge.RULES_JSON}")
        return 0

    rs = knowledge.rules()
    if getattr(args, "lens", None):
        rs = [r for r in rs if r.get("lens") == args.lens]
    if getattr(args, "id", None):
        rs = [r for r in rs if r["id"] == args.id]
    if not rs:
        print("no matching rules", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(rs, indent=2))
        return 0
    for r in rs:
        print(f"\n{r['id']}  [{r.get('severity','')}] {r.get('lens','')}")
        print(f"  {r.get('title','')}")
        print(f"  standard  {knowledge.citation(r)}")
        det = ", ".join(
            d.get("signal") or d.get("tool") or d.get("source") or d.get("kind", "")
            for d in r.get("detect", [])
        )
        print(f"  detect    {det}")
        if args.id:  # full detail for a single rule
            print(f"  fix       {(r.get('recommendation') or '').strip()}")
    print(f"\n{len(rs)} rule(s).  Source: knowledge/rules.yaml")
    return 0


def _grill(args) -> int:
    import os
    from . import grill, render
    from . import target as targetmod

    cwd = os.getcwd()
    excl = [g.strip() for g in config.GATE_EXCLUDE.split(",") if g.strip()]
    if args.staged:
        tgt = targetmod.from_diff(cwd, "--cached", excludes=excl)
    elif args.diff is not None:
        tgt = targetmod.from_diff(cwd, args.diff or None, excludes=excl)
    elif args.path:
        tgt = targetmod.from_file(args.path)
    else:
        tgt = targetmod.from_diff(cwd, None)
    if not (tgt.get("content") or "").strip():
        print("saddler grill: nothing to audit (empty diff/target)", file=sys.stderr)
        return 0

    sink = None
    if getattr(args, "irc", False):
        from .irc.sink import IRCSink
        sink = IRCSink().connect()
        sink.target = tgt.get("path", "")

    def on_event(kind, **kw):
        if sink:
            sink.event(kind, **kw)
        if kind == "grill_pass":
            print(f"\n━━ grill pass · {kw['family']} ━━", file=sys.stderr, flush=True)
            return
        if kind == "grill_pass_done":
            return
        line = render.event_line(kind, **kw)
        if line:
            print(line, file=sys.stderr, flush=True)

    result = grill.double_grill(tgt, on_event=on_event)
    if args.json:
        print(json.dumps(
            {"blocked": result["blocked"], "block_at": result["block_at"],
             "passes": {label: [f.to_dict() for f in fs] for label, fs in result["passes"]}},
            indent=2, default=str))
    else:
        print(grill.format_result(result, tgt))
    if sink:
        import time
        print("saddler: deliberation streamed to the hub; agents staying connected "
              "(Ctrl-C to disconnect).", file=sys.stderr, flush=True)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            sink.close()
    return 1 if result["blocked"] else 0


PRE_PUSH_HOOK = '''#!/usr/bin/env bash
# saddler helping-hands gate — cross-family double-grill before push.
# Bypass once with:  git push --no-verify
set -euo pipefail
REF="${SADDLER_GATE_REF:-origin/main}"
echo "saddler: double-grilling outgoing diff vs ${REF} ..." >&2
exec python3 -m saddlerfitter.cli grill --diff "${REF}"
'''

DEFAULT_SADDLER_CONFIG = '''# saddler helping-hands config (SADDLER_* env vars still win)
[gate]
block_severity = "high"      # block push on findings at/above this, either family
families = ["claude", "codex"]

[watch]
# CVE + threat-model + doc-drift run out-of-band (scheduled), not in the gate
'''


def _init(args) -> int:
    import os
    import stat
    import subprocess

    r = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True)
    root = r.stdout.strip()
    if r.returncode != 0 or not root:
        print("saddler init: not inside a git repo", file=sys.stderr)
        return 1
    hookdir = os.path.join(root, ".git", "hooks")
    os.makedirs(hookdir, exist_ok=True)
    hook = os.path.join(hookdir, "pre-push")
    with open(hook, "w") as fh:
        fh.write(PRE_PUSH_HOOK)
    os.chmod(hook, os.stat(hook).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    cdir = os.path.join(root, ".saddler")
    os.makedirs(cdir, exist_ok=True)
    cfg = os.path.join(cdir, "config.toml")
    if not os.path.exists(cfg):
        with open(cfg, "w") as fh:
            fh.write(DEFAULT_SADDLER_CONFIG)
    print(f"saddler embedded in {root}")
    print(f"  pre-push gate  → {hook}")
    print(f"  config         → {cfg}")
    print("  every `git push` now runs the cross-family double-grill on the outgoing diff.")
    print("  (requires the `saddler` package importable here, or pip-installed.)")
    return 0


def _watch(args) -> int:
    from .research import watch as rwatch

    def on_event(kind, **kw):
        if getattr(args, "json", False):
            return
        line = _watch_line(kind, **kw)
        if line:
            print(line, file=sys.stderr, flush=True)

    result = rwatch.run_watch(do_triage=not args.no_triage, do_tickets=not args.no_tickets,
                              gh_repo=args.gh_repo, on_event=on_event)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        esc = result["human_auditor_escalations"]
        print(f"\n══ saddlerFitter watch ══\n  {result['new_cve_signals']} new CVE signal(s) · "
              f"{result['disclosure_signals']} disclosure(s) · {result['tickets']} ticket(s) · "
              f"{esc} flagged for a human auditor")
        for t in result.get("tickets_detail", []):
            flag = "  ⚠ RECOMMEND HUMAN AUDITOR" if t["recommend_human_auditor"] else ""
            print(f"   • {t['title']}{flag}")
            if t["recommend_human_auditor"]:
                print(f"       reason: {t['human_auditor_reason']}")
    return 0


def _watch_line(kind, **kw) -> str:
    if kind == "watch_inventory":
        return f"  ⊟ {kw['queryable']} queryable component(s) from {', '.join(kw.get('sources', []))}"
    if kind == "signal":
        return f"  ⚡ signal[{kw['kind']}] {kw['ref']} · {kw.get('component','')} ({kw['severity']})"
    if kind == "ticket":
        flag = " ⚠HUMAN-AUDITOR" if kw.get("recommend_human_auditor") else ""
        return f"    → ticket: {kw['title']}{flag}"
    return ""


def _research(args) -> int:
    from .research import ingest as ring
    from .research.store import Store

    store = Store()
    if args.action == "ingest":
        if not args.source:
            print("saddler research ingest: need a URL, file path, or - (stdin)", file=sys.stderr)
            return 1
        text, url = _read_source(args.source)
        res = ring.ingest_text(text, url=url, title=args.title or (url or "(stdin)"),
                               profile=args.profile or "a general-purpose software project",
                               store=store)
        print(json.dumps(res, indent=2))
        return 0
    if args.action == "candidates":
        cs = store.candidates(args.status)
        for c in cs:
            print(f"  #{c['id']} [{c['status']}] {c['slug']}  ({c['lens']}/{c['severity']})  {c['title']}")
        print(f"  {len(cs)} {args.status} candidate rule(s). promote with: saddler research promote --id N")
        return 0
    if args.action in ("promote", "reject"):
        if not args.id:
            print(f"saddler research {args.action}: need --id N", file=sys.stderr)
            return 1
        fn = ring.promote if args.action == "promote" else ring.reject
        print(json.dumps(fn(int(args.id), store=store), indent=2))
        return 0
    if args.action == "signals":
        for s in store.open_signals():
            print(f"  #{s['id']} [{s['status']}] {s['kind']} {s['ref']} ({s['severity']}) {s['summary'][:70]}")
        return 0
    if args.action == "tickets":
        for t in store.tickets():
            flag = " ⚠HUMAN-AUDITOR" if t["recommend_human_auditor"] else ""
            print(f"  #{t['id']} [{t['urgency']}] {t['title']}{flag}  {t['external_ref']}")
        return 0
    return 1


def _read_source(src: str) -> tuple[str, str]:
    if src == "-":
        return sys.stdin.read(), ""
    if src.startswith(("http://", "https://")):
        import urllib.request
        req = urllib.request.Request(src, headers={"User-Agent": "saddlerFitter"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode("utf-8", "replace"), src
    with open(src, encoding="utf-8", errors="replace") as fh:
        return fh.read(), src


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="saddler", description="saddlerFitter — consensus code auditor + research watch"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="run a consensus audit over a file or diff")
    a.add_argument("path", help="file to audit, or repo path when using --diff")
    a.add_argument(
        "--diff",
        nargs="?",
        const="",
        default=None,
        help="audit `git diff [REF]` in the repo at PATH instead of a file",
    )
    a.add_argument(
        "--lenses",
        default=None,
        help="proposer lenses, comma list (default: %s)" % ",".join(config.LENSES),
    )
    a.add_argument(
        "--aspects",
        default=None,
        help="verifier aspects, comma list (default: %s)" % ",".join(config.VERIFY_ASPECTS),
    )
    a.add_argument("--json", action="store_true", help="emit findings as JSON")

    kn = sub.add_parser("knowledge", help="the best-practice rule catalog (build DB / show rules)")
    kn.add_argument("action", nargs="?", default="show", choices=["show", "build"],
                    help="show the catalog (default) or build the queryable SQLite DB")
    kn.add_argument("--lens", default=None, help="filter to one lens")
    kn.add_argument("--id", default=None, help="show full detail for one rule id")
    kn.add_argument("--json", action="store_true", help="emit the catalog as JSON")

    cv = sub.add_parser("cve-scan", help="scan the project dependency SBOM against CVE feeds")
    cv.add_argument(
        "--max-triage", type=int, default=None,
        help="cap advisories triaged by consensus, highest-priority first "
             "(default: triage all; 0 = list only)",
    )
    cv.add_argument("--json", action="store_true", help="emit the scan result as JSON")

    hb = sub.add_parser("hub", help="run the IRC hub (server + web dashboard)")
    hb.add_argument("--port", type=int, default=None, help="IRC port (default 6667)")
    hb.add_argument("--web-port", type=int, default=None, help="dashboard port (default 8198)")

    sub.add_parser("irc-demo", help="connect demo agent bots to a running hub")

    g = sub.add_parser("grill", help="cross-family double-grill (claude+codex); exit 1 if blocked")
    g.add_argument("path", nargs="?", help="file to grill (omit to use --diff/--staged)")
    g.add_argument("--diff", nargs="?", const="", default=None,
                   help="grill `git diff [REF]` in the cwd repo")
    g.add_argument("--staged", action="store_true", help="grill the staged diff")
    g.add_argument("--irc", action="store_true",
                   help="stream the live deliberation into the IRC hub")
    g.add_argument("--json", action="store_true")

    sub.add_parser("init", help="embed the saddler gate into the current repo (pre-push hook)")

    w = sub.add_parser("watch", help="poll latest CVEs + disclosures -> signal -> triage -> ticket")
    w.add_argument("--no-triage", action="store_true",
                   help="skip consensus triage (offline, no model calls)")
    w.add_argument("--no-tickets", action="store_true", help="signal only; don't open tickets")
    w.add_argument("--gh-repo", default=None, metavar="OWNER/REPO",
                   help="also open a GitHub issue per ticket (needs the gh CLI)")
    w.add_argument("--json", action="store_true")

    rs = sub.add_parser("research", help="autoresearch: grow the rule catalog (human-gated)")
    rs.add_argument("action",
                    choices=["ingest", "candidates", "promote", "reject", "signals", "tickets"])
    rs.add_argument("source", nargs="?", help="for ingest: a URL, a file path, or - for stdin")
    rs.add_argument("--id", default=None, help="candidate id for promote/reject")
    rs.add_argument("--title", default=None, help="source title (ingest)")
    rs.add_argument("--profile", default=None,
                    help="project profile so research stays relevant (ingest)")
    rs.add_argument("--status", default="pending", help="filter for `candidates`")

    args = p.parse_args(argv)

    if args.cmd == "watch":
        return _watch(args)
    if args.cmd == "research":
        return _research(args)
    if args.cmd == "knowledge":
        return _knowledge(args)
    if args.cmd == "cve-scan":
        return _cve_scan(args)
    if args.cmd == "hub":
        try:
            from .irc import hub as hubmod
        except ImportError:
            print("saddler: the IRC hub is not present in this build", file=sys.stderr)
            return 1
        hubmod.run(port=args.port, web_port=args.web_port)
        return 0
    if args.cmd == "irc-demo":
        try:
            from .irc import demo
        except ImportError:
            print("saddler: the IRC hub is not present in this build", file=sys.stderr)
            return 1
        demo.run_blocking()
        return 0
    if args.cmd == "grill":
        return _grill(args)
    if args.cmd == "init":
        return _init(args)

    if args.diff is not None:
        tgt = targetmod.from_diff(args.path, args.diff or None)
    else:
        tgt = targetmod.from_file(args.path)
    lenses = [s.strip() for s in args.lenses.split(",")] if args.lenses else None
    aspects = [s.strip() for s in args.aspects.split(",")] if args.aspects else None

    def on_event(kind, **kw):
        if args.json:
            return
        line = render.event_line(kind, **kw)
        if line:
            print(line, file=sys.stderr, flush=True)

    findings = run_audit(tgt, lenses=lenses, aspects=aspects, on_event=on_event)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        print(render.render(findings, tgt))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
