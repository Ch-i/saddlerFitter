"""Finding model + tolerant JSON extraction from LLM output."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field


@dataclass
class Finding:
    fid: str = ""
    title: str = ""
    category: str = ""
    severity: str = "low"
    file: str = ""
    line: int | None = None
    rationale: str = ""
    suggested_fix: str = ""
    proposers: list[str] = field(default_factory=list)  # lenses that raised it
    verifier_verdicts: list[dict] = field(default_factory=list)  # blind aspect votes
    evidence: list[dict] = field(default_factory=list)  # non-LLM tool corroboration
    execution_anchored: bool = False
    status: str = "candidate"  # candidate -> confirmed | refuted | needs_human
    arbiter_summary: str = ""
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


def extract_json(text: str | None):
    """Pull the first JSON array/object out of an LLM response.

    Tolerant of ``` fences and surrounding prose. Returns the parsed value or
    None — never trusts the response to be pure JSON.
    """
    if not text:
        return None
    t = text.strip()
    if "```" in t:
        for seg in t.split("```")[1::2]:  # fenced segments
            seg = seg.strip()
            if seg.lower().startswith("json"):
                seg = seg[4:].strip()
            cand = _try_balanced(seg)
            if cand is not None:
                return cand
    return _try_balanced(t)


def _try_balanced(s: str):
    try:
        return json.loads(s)
    except Exception:
        pass
    for opener, closer in (("[", "]"), ("{", "}")):
        start = s.find(opener)
        if start == -1:
            continue
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(s)):
            c = s[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
                continue
            if c == '"':
                in_str = True
            elif c == opener:
                depth += 1
            elif c == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(s[start : i + 1])
                    except Exception:
                        break
    return None
