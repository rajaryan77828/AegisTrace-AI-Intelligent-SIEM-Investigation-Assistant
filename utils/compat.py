"""Streamlit version compatibility (``use_container_width`` -> ``width``)."""
from __future__ import annotations

import streamlit as st


def _version() -> tuple[int, ...]:
    parts = []
    for p in st.__version__.split(".")[:3]:
        digits = "".join(ch for ch in p if ch.isdigit())
        parts.append(int(digits or 0))
    return tuple(parts)


STRETCH: dict = {"width": "stretch"} if _version() >= (1, 50) else {"use_container_width": True}
