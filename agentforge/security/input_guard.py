"""Input sanitization helpers (CLAUDE.md §8.4 Input Guard).

Used by routers and agents to scrub user-controlled fields before they hit
the DB or downstream services. WAF handles obvious malicious patterns;
input_guard handles subtler hygiene (control chars, length caps, SSRF-safe
URL checks) at the field level.
"""

from __future__ import annotations

import re
from typing import Any

from agentforge.security.waf import _ssrf_check

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_PROMPT_INJECTION_HINTS = re.compile(
    r"(?i)(ignore (all )?previous (instructions|prompts)|disregard prior|jailbreak|do anything now|system override|"
    r"sudo (mode|prompt))"
)


def strip_control_chars(value: str) -> str:
    """Remove ASCII control characters except whitespace."""
    return _CONTROL_CHARS.sub("", value)


def clip(value: str, max_len: int = 4000) -> str:
    return value if len(value) <= max_len else value[:max_len]


def sanitize_string(value: str, *, max_len: int = 4000) -> str:
    """Generic sanitizer for user-supplied strings going into the DB or LLM."""
    return clip(strip_control_chars(value), max_len)


def is_safe_url(url: str | None) -> bool:
    """Return True if the URL is safe to follow (no SSRF, allowed schemes)."""
    if not url:
        return False
    if "://" not in url:
        return False
    scheme = url.split("://", 1)[0].lower()
    if scheme not in {"http", "https"}:
        return False
    return not _ssrf_check(url)


def detect_prompt_injection(value: str) -> bool:
    """Heuristic match for known injection phrases in *operator-supplied* fields.

    Note: AgentForge expects operators to supply config like target URLs, NOT
    raw attack prompts (those come from the seed library). So when this fires
    on an operator field it usually means a misconfiguration or a tampering
    attempt.
    """
    return bool(_PROMPT_INJECTION_HINTS.search(value))


def validate_operator_field(value: Any, *, field_name: str) -> str:
    """Strict validator for operator-supplied string fields (campaign notes,
    target overrides, etc). Returns the sanitized value; raises ValueError on
    suspicious content.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field_name}: expected string, got {type(value).__name__}")
    cleaned = sanitize_string(value)
    if detect_prompt_injection(cleaned):
        raise ValueError(f"{field_name}: contains prompt-injection patterns; reject for safety")
    return cleaned
