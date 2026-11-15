#!/usr/bin/env python3
"""Fuzz-Target: zentrale Schwärzung (``redact``, ``redact_obj``, ``RedactingFilter``).

Invarianten:

* keine Exception, egal welcher Text, welche Struktur, welche Log-Argumente;
* ein bekanntes Geheimnis (≥ ``MIN_SECRET_LEN`` Zeichen) steht nie im Ergebnis – weder im Text noch in einem
  String-Wert einer Struktur noch in einem Log-Eintrag (auch nicht, wenn sich der Eintrag nicht formatieren lässt);
* Werte unter geheimen Feldnamen (``is_secret_field``) werden zu ``MASK``.

Ausgenommen sind Geheimnisse mit ``*``: die Maske ``***`` selbst kann zusammen mit dem Nachbartext eine solche
Zeichenfolge bilden, ohne dass etwas aus der Eingabe preisgegeben wird.
"""

from __future__ import annotations

import logging
from typing import Any

from fuzzhelp import data_provider, instrumented, pick, run

with instrumented():
    from fritzos8_mcp.redact import MASK, MIN_SECRET_LEN, RedactingFilter, is_secret_field, redact, redact_obj

_KEYS = ("NewKeyPassphrase", "NewX_AVM-DE_WPSAPPIN", "password", "sid", "name", "NewHostName", "url", "")


def _secrets(fdp: Any) -> list[str]:
    return [fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 24)) for _ in range(fdp.ConsumeIntInRange(0, 3))]


def _checked(secrets: list[str]) -> list[str]:
    return [s for s in secrets if len(s) >= MIN_SECRET_LEN and "*" not in s]


def _structure(fdp: Any, secrets: list[str], depth: int = 0) -> Any:
    kind = fdp.ConsumeIntInRange(0, 5 if depth < 3 else 2)
    if kind == 0:
        return fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 64))
    if kind == 1:
        return pick(fdp, [*secrets, ""]) if secrets else ""
    if kind == 2:
        return pick(fdp, [None, True, False, 0, 1234, -1, 1.5])
    if kind == 3:
        return [_structure(fdp, secrets, depth + 1) for _ in range(fdp.ConsumeIntInRange(0, 4))]
    if kind == 4:
        return tuple(_structure(fdp, secrets, depth + 1) for _ in range(fdp.ConsumeIntInRange(0, 3)))
    out: dict[str, Any] = {}
    for _ in range(fdp.ConsumeIntInRange(0, 4)):
        key = pick(fdp, _KEYS) if fdp.ConsumeBool() else fdp.ConsumeUnicodeNoSurrogates(12)
        out[key] = _structure(fdp, secrets, depth + 1)
    return out


def _strings(obj: Any) -> list[str]:
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _strings(v)]
    if isinstance(obj, list | tuple):
        return [s for v in obj for s in _strings(v)]
    return [obj] if isinstance(obj, str) else []


def _check_masked_fields(original: Any, redacted: Any) -> None:
    if isinstance(original, dict):
        for key, value in original.items():
            if is_secret_field(key) and value not in (None, "", False):
                assert redacted[key] == MASK, key
            else:
                _check_masked_fields(value, redacted[key])
    elif isinstance(original, list | tuple):
        for a, b in zip(original, redacted, strict=True):
            _check_masked_fields(a, b)


def TestOneInput(data: bytes) -> None:
    fdp = data_provider(data)
    secrets = _secrets(fdp)
    checked = _checked(secrets)
    mode = fdp.ConsumeIntInRange(0, 2)

    if mode == 0:
        out = redact(fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes()), secrets)
        for s in checked:
            assert s not in out, (s, out)
    elif mode == 1:
        obj = _structure(fdp, secrets)
        out_obj = redact_obj(obj, secrets)
        for text in _strings(out_obj):
            for s in checked:
                assert s not in text, (s, text)
        _check_masked_fields(obj, out_obj)
    else:
        msg = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 48))
        args = tuple(_structure(fdp, secrets, depth=2) for _ in range(fdp.ConsumeIntInRange(0, 3)))
        record = logging.LogRecord("fuzz", logging.INFO, __file__, 1, msg, args or None, None)
        assert RedactingFilter(secrets).filter(record)
        # Was ein Handler ausgibt – formatiert oder (bei kaputtem Format) als Rohdaten in handleError.
        try:
            shown = record.getMessage()
        except Exception:
            shown = f"{record.msg!s} {record.args!s}"
        for s in checked:
            assert s not in shown, (s, shown)


if __name__ == "__main__":
    run(TestOneInput)
