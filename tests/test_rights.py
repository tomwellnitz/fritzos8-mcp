"""Stage 9.7 – every tool has a documented right (rights table complete and consistent)."""

from __future__ import annotations

from unittest.mock import MagicMock

from fritzos8_mcp.rights import PARTIAL, RIGHT_LABELS, TOOL_RIGHTS, affected_tools, satisfied
from fritzos8_mcp.security import Gate
from fritzos8_mcp.server import build_server


async def test_every_registered_tool_has_rights() -> None:
    names = {t.name for t in await build_server(MagicMock(), Gate(True, True, True)).list_tools()}
    assert names - set(TOOL_RIGHTS) == set(), "Rechte für neue Tools in rights.TOOL_RIGHTS eintragen"
    assert set(TOOL_RIGHTS) - names == set(), "rights.TOOL_RIGHTS enthält Tools, die es nicht gibt"
    assert set(PARTIAL) <= names


def test_rights_codes_are_known() -> None:
    for tool, needed in TOOL_RIGHTS.items():
        assert needed, tool
        assert set(needed) <= set(RIGHT_LABELS), tool


def test_settings_includes_app_and_affected_tools() -> None:
    assert satisfied(("app",), {"settings"})
    assert not satisfied(("phone",), {"settings"})
    assert satisfied(("none",), set())
    missing = affected_tools({"settings"})
    assert "call_list" in missing["phone"]
    assert "smarthome_overview" in missing["smarthome"]
    assert "settings" not in missing and "app" not in missing
    only_registered = affected_tools({"settings"}, registered={"call_list"})
    assert only_registered == {"phone": ["call_list"]}
