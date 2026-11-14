"""Stage 9.2 – tool reference generated from the registered tools (name, tier, right, description, input schema).

``scripts/gen_tool_reference.py`` writes ``docs/TOOLS.md``; ``tests/test_tool_reference.py`` fails when the file is
out of date, so the reference can never drift from the code.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from unittest.mock import MagicMock

from .rights import PARTIAL, RIGHT_LABELS, TOOL_RIGHTS
from .security import Gate

TIER_ORDER = ("read", "write", "critical", "secrets")
TIER_TEXT = {
    "read": "read – immer aktiv",
    "write": "write – `FRITZ_ALLOW_WRITE=1`",
    "critical": "critical – zusätzlich `FRITZ_ALLOW_CRITICAL=1`, nur Plan → Token → Execute",
    "secrets": "secrets – `FRITZ_ALLOW_SECRETS=1`",
}
_TIER = re.compile(r"^\[Stufe: (\w+)\]\s*")


def _type(schema: dict[str, Any]) -> str:
    if "anyOf" in schema:
        parts = [_type(s) for s in schema["anyOf"] if s.get("type") != "null"]
        return " | ".join(parts) + ("?" if any(s.get("type") == "null" for s in schema["anyOf"]) else "")
    if "enum" in schema:
        return " / ".join(str(v) for v in schema["enum"])
    if "const" in schema:
        return str(schema["const"])
    t = schema.get("type")
    if t == "array":
        return f"list[{_type(schema.get('items') or {})}]"
    if isinstance(t, str):
        return t
    if "$ref" in schema:
        return str(schema["$ref"]).rsplit("/", 1)[-1]
    return "any"


def _params(schema: dict[str, Any]) -> str:
    props: dict[str, Any] = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    out = []
    for name, p in props.items():
        if name == "box":
            continue
        mark = "" if name in required else "?"
        out.append(f"`{name}{mark}`: {_type(p)}")
    return ", ".join(out) or "–"


def _cell(text: str) -> str:
    return " ".join(text.split()).replace("|", "\\|")


async def _tools() -> list[Any]:
    from .server import build_server

    server = build_server(MagicMock(), Gate(True, True, True))
    return list(await server.list_tools())


def render() -> str:
    tools = asyncio.run(_tools())
    by_tier: dict[str, list[Any]] = {t: [] for t in TIER_ORDER}
    for tool in sorted(tools, key=lambda t: t.name):
        m = _TIER.match(tool.description or "")
        by_tier.setdefault(m.group(1) if m else "read", []).append(tool)
    lines = [
        "# Tool-Referenz",
        "",
        "<!-- generiert von scripts/gen_tool_reference.py – nicht von Hand bearbeiten -->",
        "",
        f"{len(tools)} Tools. Jedes Tool hat den optionalen Parameter `box` (Mehrbox-Betrieb, Namen in "
        "`server_status`); er ist unten nicht aufgeführt. `?` = optionaler Parameter. Spalte „Recht“: das nötige "
        "Recht des FRITZ!Box-Benutzers (System > FRITZ!Box-Benutzer); „FRITZ!Box Einstellungen“ schließt das App-Recht "
        "ein. `setup_check` zeigt, welche Rechte der eingerichtete Benutzer hat und welche Tools deshalb fehlen.",
        "",
        "Rechte: "
        + "; ".join(f"**{code}** = {label}" for code, label in RIGHT_LABELS.items() if code != "none")
        + "; **–** = kein Recht nötig.",
        "",
    ]
    for tier in TIER_ORDER:
        group = by_tier.get(tier) or []
        if not group:
            continue
        lines += [f"## {TIER_TEXT[tier]}", "", "| Tool | Recht | Parameter | Beschreibung |", "|---|---|---|---|"]
        for tool in group:
            desc = _TIER.sub("", tool.description or "")
            rights = TOOL_RIGHTS.get(tool.name, ())
            right = ", ".join(r for r in rights if r != "none") or "–"
            if tool.name in PARTIAL:
                right += f" (ohne: {PARTIAL[tool.name]})"
            schema_mark = (
                " · strukturierte Ausgabe" if (getattr(tool, "output_schema", None) or {}).get("properties") else ""
            )
            lines.append(
                f"| `{tool.name}` | {_cell(right)} | {_cell(_params(tool.input_schema or {}))} | "
                f"{_cell(desc)}{schema_mark} |"
            )
        lines.append("")
    return "\n".join(lines)
