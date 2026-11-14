"""Stage 9.2 – docs/TOOLS.md must match the registered tools (regenerate with scripts/gen_tool_reference.py)."""

from __future__ import annotations

from pathlib import Path

from fritzos8_mcp.toolref import render

TOOLS_MD = Path(__file__).resolve().parent.parent / "docs" / "TOOLS.md"


def test_tool_reference_is_up_to_date() -> None:
    assert TOOLS_MD.read_text(encoding="utf-8") == render(), (
        "docs/TOOLS.md ist veraltet – uv run python scripts/gen_tool_reference.py"
    )


def test_tool_reference_lists_rights_and_tiers() -> None:
    text = render()
    assert "| `call_list` | phone |" in text
    assert "## critical" in text and "## secrets" in text
    assert "`box`" in text.split("\n\n")[2]
