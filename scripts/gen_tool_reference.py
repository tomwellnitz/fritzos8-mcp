"""Write docs/TOOLS.md from the registered tools.

uv run python scripts/gen_tool_reference.py          # regenerate
uv run python scripts/gen_tool_reference.py --check  # exit 1 if docs/TOOLS.md is out of date (pre-push, CI)
"""

from __future__ import annotations

import sys
from pathlib import Path

from fritzos8_mcp.toolref import render

target = Path(__file__).resolve().parent.parent / "docs" / "TOOLS.md"
content = render()
if "--check" in sys.argv[1:]:
    if target.read_text(encoding="utf-8") != content:
        print(f"{target} ist veraltet – 'uv run python scripts/gen_tool_reference.py' ausführen.")
        sys.exit(1)
    print(f"{target} ist aktuell")
else:
    target.write_text(content, encoding="utf-8")
    print(f"{target} geschrieben")
