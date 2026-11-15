#!/usr/bin/env python3
"""Fuzz-Target: Anonymisierer für Community-Fixtures (``fritzos8-anonymize``: ``anonymize``, ``find_leftovers``).

Eingabe sind echte Box-Antworten beliebiger Art (TR-064-Ergebnis, /api/v0-JSON, AHA-/TR-064-XML, Log-Text).
Invarianten: keine Exception für Text, XML und jedes JSON; Ergebnis JSON-serialisierbar; ein Geheimnis unter einem
geheimen Feldnamen (Passwort, PSK, PIN, SID …) steht nie im Ergebnis.
"""

from __future__ import annotations

import json

from fuzzhelp import NOTHING, data_provider, instrumented, load_json, pick, run

with instrumented():
    from fritzos8_mcp.anonymize import anonymize, build_fixture, find_leftovers

SECRET = "geheim-fuzz-marker"
KINDS = ("auto", "tr064", "rest", "aha", "xml", "text")
SECRET_FIELDS = ("NewKeyPassphrase", "NewPreSharedKey", "NewX_AVM-DE_WPSClientPIN", "wg_preshared_key", "password")


def TestOneInput(data: bytes) -> None:
    fdp = data_provider(data)
    kind = pick(fdp, KINDS)
    plant = fdp.ConsumeIntInRange(0, len(SECRET_FIELDS))  # == len: nichts pflanzen
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    data_in: object = text
    if kind in ("auto", "tr064", "rest") and (parsed := load_json(text)) is not NOTHING:
        data_in = parsed
    planted = plant < len(SECRET_FIELDS) and isinstance(data_in, dict) and SECRET not in text
    if planted:
        assert isinstance(data_in, dict)
        data_in[SECRET_FIELDS[plant]] = SECRET
    result, _ = anonymize(data_in, kind)
    find_leftovers(result)
    fixture, _ = build_fixture(data_in, kind, model="FRITZ!Box 7590", fritzos="8.20", name="fuzz")
    dumped = json.dumps(fixture, ensure_ascii=False)
    if planted:
        assert SECRET not in dumped, dumped[:2000]


if __name__ == "__main__":
    run(TestOneInput)
