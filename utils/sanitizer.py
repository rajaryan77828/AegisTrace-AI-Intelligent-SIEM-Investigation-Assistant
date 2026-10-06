"""
AegisTrace AI — Input Sanitization Utilities
Prevents XSS and HTML injection from untrusted SIEM alert content
being rendered in the dashboard.
"""
from __future__ import annotations

import html
import re


# Tags and patterns that should never appear in rendered output
_DANGEROUS_TAGS = re.compile(
    r"<\s*/?\s*(script|iframe|object|embed|form|input|button|link|meta|base|svg|math|style)"
    r"[^>]*>",
    re.I,
)

_EVENT_HANDLERS = re.compile(r"\bon\w+\s*=", re.I)

_JAVASCRIPT_URI = re.compile(r"javascript\s*:", re.I)

_DATA_URI = re.compile(r"data\s*:\s*text/html", re.I)


def sanitize_html(text: str) -> str:
    """Escape a string for safe HTML rendering.

    This is the primary defense: every untrusted SIEM field value
    passes through here before being injected into any HTML template.
    """
    if not isinstance(text, str):
        text = str(text)
    return html.escape(text, quote=True)


def strip_dangerous_tags(text: str) -> str:
    """Remove known dangerous HTML tags from a string.

    Used as a secondary defense when sanitize_html is too aggressive
    (e.g., when we want to allow basic formatting but not scripts).
    """
    text = _DANGEROUS_TAGS.sub("", text)
    text = _EVENT_HANDLERS.sub("", text)
    text = _JAVASCRIPT_URI.sub("", text)
    text = _DATA_URI.sub("", text)
    return text


def sanitize_for_display(text: str, max_length: int = 500) -> str:
    """Full pipeline: escape, strip, and truncate for safe display."""
    if not isinstance(text, str):
        text = str(text)
    text = text[:max_length]
    return sanitize_html(text)


def sanitize_dict_values(data: dict) -> dict:
    """Sanitize all string values in a flat dictionary."""
    return {
        k: sanitize_html(v) if isinstance(v, str) else v
        for k, v in data.items()
    }
