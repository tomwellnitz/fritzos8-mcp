"""Small validation helpers (ported from the author's own TypeScript mcp-fritzbox code)."""

from __future__ import annotations

import re
from typing import Any

from .errors import InvalidParameterError

MAX_HOSTNAME_LENGTH = 63
_MAC_HEX = re.compile(r"^[0-9a-fA-F]{12}$")


def normalize_mac(mac: str) -> str:
    """Accept AA:BB:CC:DD:EE:FF, aa-bb-cc-dd-ee-ff, aabb.ccdd.eeff or aabbccddeeff."""
    hex_ = re.sub(r"[:\-.]", "", (mac or "").strip())
    if not _MAC_HEX.match(hex_):
        raise InvalidParameterError(f'Ungültige MAC-Adresse: "{mac}"')
    hex_ = hex_.upper()
    return ":".join(hex_[i : i + 2] for i in range(0, 12, 2))


def safe_mac(mac: Any) -> str:
    try:
        return normalize_mac(str(mac or ""))
    except InvalidParameterError:
        return ""


def validate_hostname(name: str) -> str:
    """Trim and enforce the 1–63 character limit of the FRITZ!Box."""
    hostname = (name or "").strip()
    if not 1 <= len(hostname) <= MAX_HOSTNAME_LENGTH:
        raise InvalidParameterError(f"Name muss 1–{MAX_HOSTNAME_LENGTH} Zeichen lang sein, ist {len(hostname)}.")
    return hostname


def truthy(value: Any) -> bool:
    return str(value if value is not None else "").strip().lower() in {"1", "true", "on", "yes"}
