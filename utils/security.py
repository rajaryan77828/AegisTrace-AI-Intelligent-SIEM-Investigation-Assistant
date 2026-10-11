"""Network-safety helpers for user-supplied API endpoints (SSRF defence)."""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

_ALWAYS_BLOCKED = [
    ipaddress.ip_network(n)
    for n in ("169.254.0.0/16", "fe80::/10", "0.0.0.0/8", "224.0.0.0/4", "::/128")
]


class EndpointError(ValueError):
    """Raised when an API endpoint URL is rejected."""


def allow_private_endpoints() -> bool:
    return os.getenv("AEGIS_ALLOW_PRIVATE_ENDPOINTS", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def validate_endpoint(url: str, *, allow_private: bool | None = None) -> str:
    """Validate ``url`` and return it normalised (no trailing slash).

    * only http/https, no embedded credentials
    * link-local / metadata ranges (169.254.0.0/16 ...) are always refused
    * loopback / private ranges are refused unless explicitly allowed
    """
    if allow_private is None:
        allow_private = allow_private_endpoints()
    url = (url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise EndpointError("Endpoint must be a full http(s) URL, e.g. https://api.example.com/v1")
    if parsed.username or parsed.password:
        raise EndpointError("Do not embed credentials in the URL; use the API key field.")

    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise EndpointError(f"Could not resolve host '{parsed.hostname}'.") from exc

    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if any(addr in net for net in _ALWAYS_BLOCKED):
            raise EndpointError("Link-local / metadata addresses are never allowed.")
        if not allow_private and (
            addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_unspecified
        ):
            raise EndpointError(
                "Private and localhost endpoints are blocked on this deployment. "
                "Set AEGIS_ALLOW_PRIVATE_ENDPOINTS=1 when running locally (e.g. for Ollama)."
            )
    return url.rstrip("/")


def redact(text: str, *secrets: str) -> str:
    """Remove any secret substrings from ``text`` (for error messages)."""
    for secret in secrets:
        if secret and len(secret) >= 6:
            text = text.replace(secret, "••••")
    return text
