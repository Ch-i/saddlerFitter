# Scheduling the watch

`saddler watch` is a single idempotent cycle: it polls CVE + disclosure feeds, dedups
against what it has already acted on, and only signals/tickets *new* hits. So you simply
run it on a timer. Three ways, in order of recommendation.

## Recommended: a systemd timer (single host, robust)

Most reliable for a server you control — survives reboots, logs to the journal, no extra
service to run.

`/etc/systemd/system/saddler-watch.service`
```ini
[Unit]
Description=saddlerFitter vulnerability watch
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/srv/your-project          # the repo whose SBOM to scan
ExecStart=/usr/bin/saddler watch --gh-repo your-org/your-repo
# secrets via the service environment, never on the command line:
Environment=SADDLER_DISCLOSURE_FEEDS=https://example.com/security/atom.xml
```

`/etc/systemd/system/saddler-watch.timer`
```ini
[Unit]
Description=Run saddlerFitter watch every 6 hours

[Timer]
OnCalendar=*-*-* 00,06,12,18:00:00
Persistent=true            # catch up a missed run after downtime

[Install]
WantedBy=timers.target
```
```bash
systemctl enable --now saddler-watch.timer
journalctl -u saddler-watch.service -f
```

## Simplest: cron

```cron
# every 6 hours; triage + open tickets, log to a file
0 */6 * * *  cd /srv/your-project && SADDLER_DISCLOSURE_FEEDS=https://example.com/security/atom.xml \
             /usr/bin/saddler watch --gh-repo your-org/your-repo >> /var/log/saddler-watch.log 2>&1
```

## Visual / multi-step / team routing: n8n

Reach for n8n when you want a **visual workflow that fans a signal out** — open a Jira
ticket *and* post to Slack *and* page on-call — or to chain saddlerFitter with other
tools. Two integration shapes:

- **Execute Command node** runs `saddler watch --json`; a Function node parses the JSON
  (`tickets_detail`, `human_auditor_escalations`) and routes each ticket — escalations
  (`recommend_human_auditor: true`) to a "page a human auditor" branch, the rest to a
  normal ticket branch.
- **Schedule Trigger** (n8n's cron) every 6h drives the above, so n8n owns the cadence
  instead of system cron.

```
[Schedule Trigger 6h] → [Execute: saddler watch --json] → [Function: split tickets]
                                                              ├─ human_auditor → [Slack #security + PagerDuty]
                                                              └─ normal        → [Jira: create issue]
```

## Pacing & cost

- `saddler watch` makes model calls **only on a new advisory** (consensus triage + ticket
  body). A quiet cycle with nothing new is essentially free.
- Use `--no-triage` for a fast, model-free pass that just signals new advisories (triage
  them later in a separate, rate-limited run).
- Do **not** run it on a tight loop — every few hours is plenty; advisories don't land by
  the minute, and each new hit costs real LLM calls.

## What feeds it

- **Dependency CVEs** — OSV.dev + NVD against your SBOM (auto-discovered, or
  `SADDLER_SBOM_PATHS`). Always on.
- **Vulnerability disclosures** — Atom/RSS advisory feeds in `SADDLER_DISCLOSURE_FEEDS`
  (comma-separated). Entries are filtered to ones that mention a technology in *your*
  stack, so the watch stays on-topic. Point it at the advisory feeds for the frameworks
  you actually run.
