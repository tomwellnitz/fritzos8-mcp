"""Scan files for private data of the maintainer (pre-commit hook and snapshot check).

    python3 scripts/check_private_data.py FILE...          # check the given files (pre-commit passes staged files)
    python3 scripts/check_private_data.py --all [--root R] # check every file below R (default: repository root)

Die Muster selbst stehen NIE in einer versionierten Datei. Sie werden zur Laufzeit gelesen aus
  1. `.private-patterns` (gitignored, eine feste Zeichenkette pro Zeile, `#` = Kommentar) und
  2. `CLAUDE.local.md` (gitignored) – daraus abgeleitet: IP-Adressen, AINs, Schlüsselbund-Namen, Home-Pfade,
     zitierte Geräte-/Raumnamen, Straßen-/Ortsnamen.
Fehlen beide Dateien (z. B. in einem frischen Klon eines Mitwirkenden), überspringt das Skript mit Hinweis (Exit 0).
Treffer werden ohne das Muster selbst gemeldet (Exit 1). Nur Standardbibliothek – läuft ohne venv.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PATTERN_FILE = ".private-patterns"
LOCAL_CONTEXT = "CLAUDE.local.md"

# Ableitungen aus CLAUDE.local.md (gleiche Logik wie früher in make_public_snapshot.sh)
DERIVE = [
    re.compile(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"),  # IP-Adressen
    re.compile(r"[0-9]{5} ?[0-9]{7}"),  # AINs
    re.compile(r"mcp-fritzbox-[A-Za-z0-9_-]+"),  # Schlüsselbund-Einträge
    re.compile(r"/Users/[A-Za-z0-9._-]+"),  # Home-Verzeichnisse
    re.compile(r"„([^“]{4,40})“"),  # zitierte Geräte-/Raumnamen
    re.compile(r'"([^"]{4,40})"'),
    re.compile(r"[A-ZÄÖÜ][a-zäöüß]+(?:straße|strasse|weg|allee|platz|gasse)"),  # Straßen/Orte
    re.compile(r"\(([A-ZÄÖÜ][a-zäöüß]+)\)"),  # einzelne Wörter in Klammern (Orte)
]
# Allgemeine Wörter bzw. Adressen, die keine privaten Daten sind
GENERIC = {"fritz!box", "fritz!os", "smart home", "box a", "box b", "wohnzimmer", "127.0.0.1", "0.0.0.0"}  # noqa: S104
GENERIC_RE = re.compile(r"^255\.255\.255\.[0-9]+$")
# Dateien, die nie geprüft werden (enthalten die Muster selbst bzw. sind binär/generiert)
SKIP_NAMES = {PATTERN_FILE, LOCAL_CONTEXT, "uv.lock"}
SKIP_DIRS = {".git", ".venv", ".mypy_cache", ".ruff_cache", ".pytest_cache", "__pycache__", "site", "node_modules"}


def load_patterns(root: Path) -> list[str] | None:
    """Return the private patterns, or None if neither source file exists."""
    sources = [root / PATTERN_FILE, root / LOCAL_CONTEXT]
    if not any(p.is_file() for p in sources):
        return None
    found: set[str] = set()
    if sources[0].is_file():
        for line in sources[0].read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.lstrip().startswith("#"):
                found.add(line.strip())
    if sources[1].is_file():
        text = sources[1].read_text(encoding="utf-8")
        for rx in DERIVE:
            for m in rx.finditer(text):
                found.add((m.group(1) if rx.groups else m.group(0)).strip())
    return sorted(p for p in found if p and p.lower() not in GENERIC and not GENERIC_RE.match(p))


def iter_all(root: Path) -> list[Path]:
    out = []
    for path in root.rglob("*"):
        if path.is_file() and not (set(path.relative_to(root).parts) & SKIP_DIRS):
            out.append(path)
    return out


def scan(files: list[Path], patterns: list[str], root: Path) -> list[str]:
    lowered = [p.lower() for p in patterns]
    hits = []
    for path in files:
        if path.name in SKIP_NAMES or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8").lower()
        except (UnicodeDecodeError, OSError):
            continue  # binär
        n = sum(1 for p in lowered if p in text)
        if n:
            try:
                rel = path.resolve().relative_to(root.resolve())
            except ValueError:
                rel = path
            hits.append(f"{rel}: {n} privates Muster (wird nicht ausgegeben)")
    return hits


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", type=Path)
    ap.add_argument("--all", action="store_true", help="alle Dateien unter --root prüfen")
    ap.add_argument("--root", type=Path, default=None, help="zu prüfendes Verzeichnis (Standard: Repository)")
    ap.add_argument("--patterns-from", type=Path, default=REPO, help="Ort der Musterdateien")
    args = ap.parse_args(argv)

    patterns = load_patterns(args.patterns_from)
    if patterns is None:
        print(f"Privatdaten-Prüfung übersprungen: weder {PATTERN_FILE} noch {LOCAL_CONTEXT} vorhanden.")
        return 0
    root = (args.root or REPO).resolve()
    if args.all:
        files = iter_all(root)
    elif args.files:
        files = args.files
    else:
        out = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True).stdout  # noqa: S607
        files = [root / f for f in out.splitlines()]
    hits = scan(files, patterns, root)
    for h in hits:
        print(f"  ✗ {h}")
    if hits:
        print(f"Private Daten gefunden ({len(patterns)} Muster aus {PATTERN_FILE}/{LOCAL_CONTEXT}). Bitte bereinigen.")
        return 1
    print(f"  ✓ keine privaten Daten ({len(patterns)} Muster, {len(files)} Dateien)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
