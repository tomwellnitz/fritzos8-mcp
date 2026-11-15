#!/usr/bin/env python3
"""Fuzz-Target: Auswertung des Mesh-JSON der Box (``parse_mesh``, Quelle ``X_AVM-DE_GetMeshListPath``).

``NetInfoClient`` stellt nur sicher, dass das Dokument gültiges JSON und ein Objekt ist – alles darunter kommt
ungeprüft von der Box (Felder können fehlen, ``null`` sein oder einen anderen Typ haben). Invarianten: keine
Exception für jedes JSON-Objekt, Ergebnis JSON-serialisierbar.
"""

from __future__ import annotations

import json

from fuzzhelp import header_and_text, instrumented, load_json, run

with instrumented():
    from fritzos8_mcp.netinfo import parse_mesh


def TestOneInput(data: bytes) -> None:
    head, text = header_and_text(data, 1)
    with_stations = bool(head[0] & 1)
    doc = load_json(text)
    if not isinstance(doc, dict):
        return  # weist NetInfoClient._mesh_document vorher ab
    stations = {"AA:BB:CC:00:00:01": {"signal_percent": 50, "signal_dbm_estimated": -70.0}} if with_stations else None
    json.dumps(parse_mesh(doc, stations))


if __name__ == "__main__":
    run(TestOneInput)
