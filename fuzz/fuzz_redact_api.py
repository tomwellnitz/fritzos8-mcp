#!/usr/bin/env python3
"""Fuzz-Target: Schwärzung der /api/v0-Antworten (``redact_api``), die ``RestClient`` auf jede Antwort anwendet.

Baut aus den Fuzz-Daten eine JSON-artige Antwort und versteckt darin ein bekanntes Geheimnis an Stellen, die
immer geschwärzt sein müssen: unter geheimen Feldnamen (auch verschachtelt), in WireGuard-/IPSec-/PEM-Dokumenten,
als URL-Zugangsdaten, als SID in Query/Header und in Smart-Home-``httpRequest``-Objekten.

Invarianten: keine Exception, Ergebnis bleibt JSON-serialisierbar, das Geheimnis steht nirgends im Ergebnis.
"""

from __future__ import annotations

import json
from typing import Any

from fuzzhelp import data_provider, instrumented, pick, run

with instrumented():
    from fritzos8_mcp.redact import redact_api

SECRET = "geheim-fuzz-marker"  # Platzhalter-Geheimnis, kommt in zufälligem Füllmaterial nicht vor (wird geprüft)
HEX_SID = "5c0ffee15c0ffee1"  # Session-ID-artiger Hexwert
# Feldnamen, die laut AVM-Doku/Live-Mitschnitt Geheimnisse tragen (FRITZ!OS 8.2x, /api/v0, Smart-Home-REST).
SECRET_KEYS = (
    "wg_preshared_key",
    "wg_slave_config",
    "wg_master_config",
    "wg_mastered_slave_config",
    "wg_private_key",
    "access_psk",
    "xauth_password",
    "ipsec_user_name",
    "username",
    "password",
    "passphrase",
    "pskvalue",
    "secret",
    "private_key",
    "token",
    "dpw",
    "security_id",
    "latitude",
    "longitude",
    "geofencing",
    "recipient",
    "install_code",
    "pairing_code",
    "NewKeyPassphrase",
    "NewX_AVM-DE_URLParameters",
    "sid",
)
PLAIN_KEYS = ("name", "friendly_name", "ip", "mac", "UID", "state", "url", "comment", "value", "data", "")


def _filler(fdp: Any, limit: int = 40) -> str:
    return fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, limit))


def _url_safe(fdp: Any) -> str:
    # erlaubte Zeichen im userinfo-Teil einer URL (RFC 3986: unreserved, pct-encoded, sub-delims)
    raw = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 8))
    alphabet = "abcXYZ019-._~%!$&'()*+,;="
    return "".join(alphabet[b % len(alphabet)] for b in raw)


# Bewusst exakt verankerte Feldnamen (sonst zu viele Fehltreffer): keine Präfix-Variante.
_EXACT = frozenset({"latitude", "longitude", "recipient"})


def _case(fdp: Any, key: str) -> str:
    variants = [key, key.upper(), key.lower()]
    if key not in _EXACT:
        variants.append(f"x_{key}")
    return pick(fdp, variants)


def _hidden(fdp: Any) -> Any:
    """Ein Wert, der das Geheimnis enthält und an seiner Fundstelle geschwärzt werden muss."""
    kind = fdp.ConsumeIntInRange(0, 3)
    if kind == 0:
        return _filler(fdp) + SECRET + _filler(fdp)
    if kind == 1:
        return [SECRET, _filler(fdp)]
    if kind == 2:
        return {_filler(fdp, 8): SECRET}
    return 1234 if fdp.ConsumeBool() else SECRET


def _hidden_text(fdp: Any) -> str:
    """Ein Freitext-Wert (unter harmlosem Feldnamen), in dem das Geheimnis erkennbar geschwärzt werden muss."""
    kind = fdp.ConsumeIntInRange(0, 5)
    if kind == 0:
        return f"{_filler(fdp)}[Interface]\nPrivateKey = {SECRET}\n{_filler(fdp)}"
    if kind == 1:
        return f"{_filler(fdp)}[Peer]\nPresharedKey={SECRET}"
    if kind == 2:
        pem = "PRIVATE " + "KEY-----"  # zusammengesetzt, damit Secret-Scanner nicht anschlagen
        return f"-----BEGIN EC {pem}\n{SECRET}\n-----END EC {pem}"
    if kind == 3:
        return f"{_filler(fdp)} https://{_url_safe(fdp) or 'u'}:{_url_safe(fdp)}{SECRET}{_url_safe(fdp)}@box.example/"
    if kind == 4:
        return f"{_filler(fdp)}?sid={HEX_SID}&x={_filler(fdp)}"
    return f"AUTHORIZATION: AVM-SID {HEX_SID}"


def _build(fdp: Any, depth: int, planted: list[bool]) -> Any:
    kind = fdp.ConsumeIntInRange(0, 6 if depth < 4 else 2)
    if kind == 0:
        return _filler(fdp)
    if kind == 1:
        return pick(fdp, [None, True, False, 0, 1, -7, 2.5, ""])
    if kind == 2:
        planted[0] = True
        return _hidden_text(fdp)
    if kind == 3:
        return [_build(fdp, depth + 1, planted) for _ in range(fdp.ConsumeIntInRange(0, 4))]
    out: dict[str, Any] = {}
    for _ in range(fdp.ConsumeIntInRange(0, 5)):
        choice = fdp.ConsumeIntInRange(0, 3)
        if choice == 0:
            planted[0] = True
            out[_case(fdp, pick(fdp, SECRET_KEYS))] = _hidden(fdp)
        elif choice == 1:
            planted[0] = True
            method = pick(fdp, ["GET", "POST", ""])
            out[pick(fdp, ["httpRequest", "httpRequestInterface", "location"])] = {
                "method": method,
                pick(fdp, ["url", "headers", "body"]): _hidden(fdp),
            }
        else:
            key = pick(fdp, PLAIN_KEYS) if fdp.ConsumeBool() else _filler(fdp, 12)
            out[key] = _build(fdp, depth + 1, planted)
    return out


def _contains_marker(obj: Any) -> bool:
    text = json.dumps(obj, ensure_ascii=False)
    return SECRET in text or HEX_SID in text.lower()


def TestOneInput(data: bytes) -> None:
    fdp = data_provider(data)
    planted = [False]
    obj = _build(fdp, 0, planted)
    if not planted[0]:
        # Ohne gepflanztes Geheimnis: nur Robustheit (Füllmaterial kann zufällig wie ein Geheimnis aussehen).
        json.dumps(redact_api(obj))
        return
    out = redact_api(obj)
    assert not _contains_marker(out), json.dumps(out, ensure_ascii=False)[:2000]


if __name__ == "__main__":
    run(TestOneInput)
