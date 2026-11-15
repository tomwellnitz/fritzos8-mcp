#!/usr/bin/env python3
"""Fuzz-Target: Parser für XML-/Text-Antworten der Box (TR-064-Listen, AHA, Login, Ereignis-Log).

Das erste Byte wählt den Parser, der Rest (UTF-8) ist die Antwort der Box. Eine manipulierte oder kaputte Antwort darf
nur zu den dokumentierten Fehlern führen (``ET.ParseError``, ``FritzError``) oder – bei DTD-Entities/externen
Referenzen – zur Ablehnung durch defusedxml. Alles andere (``AttributeError``, ``TypeError`` …) ist ein Fund.
Zusätzlich muss jedes Ergebnis JSON-serialisierbar sein (Tool-Ausgaben sind JSON).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from fuzzhelp import header_and_text, instrumented, run

with instrumented():
    from defusedxml import DefusedXmlException
    from defusedxml.ElementTree import ParseError

    from fritzos8_mcp.auth import parse_session_info
    from fritzos8_mcp.diagnose import parse_log_text, parse_log_xml
    from fritzos8_mcp.errors import FritzError
    from fritzos8_mcp.line import parse_cell_list
    from fritzos8_mcp.netinfo import parse_wlan_device_list
    from fritzos8_mcp.parental import parse_profiles
    from fritzos8_mcp.phone import parse_phonebook
    from fritzos8_mcp.setupcheck import parse_rights_xml
    from fritzos8_mcp.smarthome import parse_device_list, parse_stats
    from fritzos8_mcp.tr064 import parse_host_list_xml


def _session(text: str) -> Any:
    info = parse_session_info(text)
    return {"sid": info.sid, "challenge": info.challenge, "block": info.block_time, "rights": info.rights}


PARSERS: tuple[Callable[[str], Any], ...] = (
    parse_log_text,
    parse_log_xml,
    parse_host_list_xml,
    parse_wlan_device_list,
    parse_cell_list,
    parse_phonebook,
    parse_profiles,
    _session,
    parse_rights_xml,
    parse_device_list,
    parse_stats,
)
EXPECTED = (ParseError, DefusedXmlException, FritzError)


def TestOneInput(data: bytes) -> None:
    head, text = header_and_text(data, 1)
    parser = PARSERS[head[0] % len(PARSERS)]
    try:
        result = parser(text)
    except EXPECTED:
        return
    json.dumps(result)


if __name__ == "__main__":
    run(TestOneInput)
