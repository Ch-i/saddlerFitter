"""Claude subagent adapter — shells out to the local `claude -p` CLI.

This is deliberately the only place that touches the model backend, so swapping
in a local Ollama model (or another vendor) later is a single-file change. Using
the local Claude Code CLI means the harness inherits this machine's own auth:
"locally authenticated", no API key handling.
"""
from __future__ import annotations

import json
import subprocess

from . import config


class LLMError(RuntimeError):
    pass


def run_agent(
    prompt: str,
    *,
    model: str,
    allowed_tools: list[str] | None = None,
    add_dirs: list[str] | None = None,
    max_turns: int = 1,
    timeout: int | None = None,
    cwd: str | None = None,
) -> str:
    """Run one headless Claude turn over `prompt`; return the result text.

    The prompt is fed on stdin to avoid arg-length and shell-quoting limits.
    `max_turns=1` keeps reasoning agents single-shot (no tool loop); pass
    `allowed_tools` + `add_dirs` for the fixer slice that edits files.
    """
    cmd = [
        config.CLAUDE_BIN,
        "-p",
        "--output-format",
        "json",
        "--model",
        model,
        "--max-turns",
        str(max_turns),
    ]
    if allowed_tools:
        cmd += ["--allowedTools", ",".join(allowed_tools)]
    for d in add_dirs or []:
        cmd += ["--add-dir", d]

    try:
        proc = subprocess.run(
            cmd,
            input=prompt,
            text=True,
            capture_output=True,
            timeout=timeout or config.DEFAULT_TIMEOUT,
            cwd=cwd,
        )
    except subprocess.TimeoutExpired as exc:
        raise LLMError(
            f"claude timed out after {timeout or config.DEFAULT_TIMEOUT}s"
        ) from exc

    if proc.returncode != 0:
        raise LLMError(f"claude exited {proc.returncode}: {(proc.stderr or proc.stdout or '')[:400]}")

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        # Non-JSON (shouldn't happen with --output-format json) — return raw.
        return proc.stdout.strip()

    if isinstance(payload, dict):
        if payload.get("is_error"):
            raise LLMError(f"claude reported error: {str(payload)[:300]}")
        return payload.get("result", "")
    return str(payload)


def run_codex(prompt: str, *, model: str | None = None, reasoning: str | None = None,
              timeout: int | None = None, cwd: str | None = None) -> str:
    """Run one headless Codex turn — the second model family for cross-family grilling.

    Uses `codex exec` with a read-only sandbox and writes the final message to a temp
    file (`--output-last-message`) so we parse only the answer, not the agent preamble.
    Auth is Codex's own local ChatGPT login (~/.codex/auth.json) — no API keys.
    """
    import os
    import tempfile

    fd, out_path = tempfile.mkstemp(prefix="saddler-codex-", suffix=".txt")
    os.close(fd)
    cmd = [config.CODEX_BIN, "exec", "-s", "read-only", "--color", "never",
           "-o", out_path,
           "-c", f"model_reasoning_effort={reasoning or config.CODEX_REASONING}"]
    if model or config.CODEX_MODEL:
        cmd += ["-m", model or config.CODEX_MODEL]
    try:
        proc = subprocess.run(
            cmd, input=prompt, text=True, capture_output=True,
            timeout=timeout or config.DEFAULT_TIMEOUT, cwd=cwd,
        )
        try:
            with open(out_path) as fh:
                msg = fh.read().strip()
        except OSError:
            msg = ""
    except subprocess.TimeoutExpired as exc:
        raise LLMError(f"codex timed out after {timeout or config.DEFAULT_TIMEOUT}s") from exc
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass
    if not msg and proc.returncode != 0:
        raise LLMError(f"codex exited {proc.returncode}: {proc.stderr[:400]}")
    return msg


def run(prompt: str, *, family: str = "claude", model: str | None = None,
        timeout: int | None = None, cwd: str | None = None, reasoning: str | None = None) -> str:
    """Family-routed entry point for the consensus layers (claude | codex)."""
    if family == "codex":
        return run_codex(prompt, model=model, reasoning=reasoning, timeout=timeout, cwd=cwd)
    return run_agent(prompt, model=model or config.PROPOSER_MODEL, timeout=timeout, cwd=cwd)
