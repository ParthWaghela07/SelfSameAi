"""Injection tracing: spot instruction-like text in content an agent reads.

This is a lightweight rule-based detector. Its job is not to be a perfect filter
(that is a losing game) but to remember WHAT the agent read just before its behaviour
changed, so an alert can say "this started after reading <file>".
"""
from __future__ import annotations
import re

_PATTERNS = [
    (r"ignore (all )?(previous|prior|above) instructions", 0.5, "tells the agent to ignore its instructions"),
    (r"(do not|don't) (mention|tell|reveal)", 0.3, "asks the agent to hide something"),
    (r"(upload|send|forward|post|exfiltrate).{0,80}(https?://|\.io\b|\.net\b|\.com\b)", 0.4, "asks for data to be sent to an outside address"),
    (r"maintenance mode|system prompt|you are now", 0.3, "tries to change the agent's mode or role"),
    (r"<!--.*?-->|​", 0.2, "contains hidden text"),
    (r"\b(hr|finance)/\S+", 0.2, "points at sensitive internal files"),
]


def injection_score(text: str) -> tuple[float, list[str]]:
    hits: list[str] = []
    score = 0.0
    for pat, weight, label in _PATTERNS:
        if re.search(pat, text, flags=re.I | re.S):
            score += weight
            hits.append(label)
    return min(1.0, round(score, 2)), hits


def extract_instruction(text: str) -> tuple[str | None, str | None]:
    """What a *vulnerable* agent would do after reading the text: (file to open, domain to send to)."""
    path = re.search(r"\b((?:hr|finance)/[\w./-]+)", text)
    dom = re.search(r"https?://([\w.-]+)", text)
    return (path.group(1) if path else None, dom.group(1) if dom else None)
