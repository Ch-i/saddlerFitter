"""CVE watch: monitor advisory feeds for the technologies a project actually ships,
triage hits by consensus in the project's deployment context, and draft a
human-gated remediation plan.

The inventory is built from the project's dependency manifests (lockfiles +
compose images) — so keeping those manifests accurate IS what scopes the watch.
"""
