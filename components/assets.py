"""Load bundled SVG artwork as data-URI <img> tags (no static file server needed)."""
from __future__ import annotations

import base64
from functools import lru_cache
from pathlib import Path

ASSET_DIR = Path(__file__).resolve().parent.parent / "assets"
_FALLBACK = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="none"/></svg>'


@lru_cache(maxsize=None)
def _read(name: str) -> bytes:
    path = ASSET_DIR / name
    try:
        return path.read_bytes()
    except OSError:
        return _FALLBACK.encode()


def svg_data_uri(svg: bytes | str) -> str:
    raw = svg.encode() if isinstance(svg, str) else svg
    return "data:image/svg+xml;base64," + base64.b64encode(raw).decode()


def asset_uri(name: str) -> str:
    return svg_data_uri(_read(name))


def img(name: str, alt: str = "", css_class: str = "", style: str = "") -> str:
    return (f'<img src="{asset_uri(name)}" alt="{alt}" class="{css_class}" style="{style}" '
            f'draggable="false"/>')
