"""Recount the TR-064 statistics in docs/COVERAGE.md from the per-action rows (stage 9.8).

    uv run python scripts/coverage_stats.py          # rewrite the counts in place
    uv run python scripts/coverage_stats.py --check  # exit 1 if they are out of date (used by the tests)

Only the TR-064 part is recounted (per-service header lines, the "Je TR-064-Service" table and the three TR-064 rows
of the summary). AHA and Smart-Home-REST counts are maintained by hand.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PATH = Path(__file__).resolve().parent.parent / "docs" / "COVERAGE.md"
MARKS = ("✅", "🟡", "❌", "⛔")
ROW = re.compile(r"^\| `([^`]+)` \| ([RW]) \|.*\| (✅|🟡|❌|⛔)[^|]*\|\s*$")


def _pct(n: int, total: int) -> str:
    return f"{n / total * 100:.1f}".replace(".", ",") + " %" if total else "0 %"


def recount(text: str) -> str:
    start = text.index("## TR-064 – je Service und Action")
    end = text.index("\n## ", start + 10)
    part = text[start:end]
    services: dict[str, list[tuple[str, str]]] = {}
    current = None
    for line in part.splitlines():
        if line.startswith("### "):
            current = line[4:].strip()
            services[current] = []
        elif current and (m := ROW.match(line)):
            services[current].append((m.group(2), m.group(3)))
    for name, rows in services.items():
        c = {k: sum(1 for _, s in rows if s == k) for k in MARKS}
        header = f"{len(rows)} Actions · ✅ {c['✅']} · 🟡 {c['🟡']} · ❌ {c['❌']} · ⛔ {c['⛔']}"
        part = re.sub(
            rf"(### {re.escape(name)}\n\n)\d+ Actions · ✅ \d+ · 🟡 \d+ · ❌ \d+ · ⛔ \d+", rf"\g<1>{header}", part
        )
    text = text[:start] + part + text[end:]
    # per-service table
    for name, rows in services.items():
        c = {k: sum(1 for _, s in rows if s == k) for k in MARKS}
        reads = [s for rw, s in rows if rw == "R"]
        reach = sum(1 for s in reads if s in ("✅", "🟡"))
        pct = f"{round(reach / len(reads) * 100)} %" if reads else "–"
        line = f"| {name} | {len(rows)} | {c['✅']} | {c['🟡']} | {c['❌']} | {c['⛔']} | {pct} |"
        text = re.sub(rf"^\| {re.escape(name)} \| \d+ \|.*$", line, text, count=1, flags=re.M)
    # summary rows
    allrows = [r for rows in services.values() for r in rows]

    def summary(label: str, rows: list[tuple[str, str]], unit: str, write: bool) -> None:
        nonlocal text
        n = len(rows)
        c = {k: sum(1 for _, s in rows if s == k) for k in MARKS}
        gen = "–" if write else f"{c['🟡']} ({_pct(c['🟡'], n)})"
        missing = f"{c['❌']} ({_pct(c['❌'], n)})" if c["❌"] or write else "0"
        line = (
            f"| {label} | {n}{unit} | {c['✅']} ({_pct(c['✅'], n)}) | {gen} | {missing} | "
            f"{c['⛔']} ({_pct(c['⛔'], n)}) |"
        )
        text = re.sub(rf"^\| {re.escape(label)} \|.*$", line, text, count=1, flags=re.M)

    summary(f"TR-064 gesamt ({len(services)} Services)", allrows, " Actions", False)
    text = re.sub(
        r"^\| TR-064 gesamt \(\d+ Services\) \|", f"| TR-064 gesamt ({len(services)} Services) |", text, flags=re.M
    )
    summary("TR-064 lesend (Get*)", [r for r in allrows if r[0] == "R"], "", False)
    summary("TR-064 schreibend", [r for r in allrows if r[0] == "W"], "", True)
    return text


def main() -> int:
    text = PATH.read_text(encoding="utf-8")
    new = recount(text)
    if "--check" in sys.argv:
        if new != text:
            print("docs/COVERAGE.md: Zählung veraltet – uv run python scripts/coverage_stats.py")
            return 1
        return 0
    PATH.write_text(new, encoding="utf-8")
    print("docs/COVERAGE.md neu gezählt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
