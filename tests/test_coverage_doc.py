"""Stage 9.8 – every TR-064 action that curated code calls must be listed in docs/COVERAGE.md."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CALLS = {"call", "try_call", "call_first", "call_igd_first"}


def curated_actions() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in (ROOT / "src" / "fritzos8_mcp").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in CALLS):
                continue
            if len(node.args) < 2:
                continue
            arg = node.args[1]
            names: list[str] = []
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                names = [arg.value]
            elif isinstance(arg, ast.Tuple | ast.List):
                names = [e.value for e in arg.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            for name in names:
                found.setdefault(name, set()).add(path.name)
    return found


def test_found_a_plausible_number_of_actions() -> None:
    actions = curated_actions()
    assert len(actions) > 100
    assert "GetSpecificHostEntry" in actions or "X_AVM-DE_GetHostListPath" in actions


def test_every_curated_action_is_in_coverage() -> None:
    coverage = (ROOT / "docs" / "COVERAGE.md").read_text(encoding="utf-8")
    missing = {a: sorted(files) for a, files in curated_actions().items() if f"`{a}`" not in coverage}
    assert not missing, f"In docs/COVERAGE.md nachtragen: {missing}"


def test_coverage_counts_are_up_to_date() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("coverage_stats", ROOT / "scripts" / "coverage_stats.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    text = (ROOT / "docs" / "COVERAGE.md").read_text(encoding="utf-8")
    assert mod.recount(text) == text, "Zählung veraltet – uv run python scripts/coverage_stats.py"
