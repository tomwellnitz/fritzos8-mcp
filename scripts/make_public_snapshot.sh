#!/usr/bin/env bash
# Stage 9.1 – prepare a clean public repository LOCALLY: a fresh one-commit snapshot of the current HEAD without
# history, after checking that no private data is contained. Nothing is pushed, no remote is configured.
#
#   scripts/make_public_snapshot.sh [TARGET] [--force]
#
# TARGET defaults to ../fritzos8-mcp-public (outside this repository). --force replaces an existing TARGET.
#
# Checks (any hit aborts BEFORE the commit):
#   1. private patterns (scripts/check_private_data.py): taken at runtime from CLAUDE.local.md (IP addresses, AINs,
#      keychain entry names, quoted device/room names, street/location words, home directory paths) plus the untracked
#      .private-patterns file (one fixed string per line) – the patterns themselves never end up in a versioned file,
#   2. files that must never be public: CLAUDE.local.md, AVM documents (docs/vendor, *.pdf, SmarthomeRestApi*.html),
#      .env files, *.password, private keys,
#   3. token-like strings (GitHub, OpenAI/Anthropic, AWS, Slack, PEM private keys),
#   4. MAC addresses that are not invented test values (AA:BB:CC…, 00:…/FF:… or known test OUIs with 00:00:xx).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET=""
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    *) TARGET="$arg" ;;
  esac
done
TARGET="${TARGET:-$(dirname "$REPO")/fritzos8-mcp-public}"
case "$TARGET" in
  "$REPO"|"$REPO"/*) echo "Ziel darf nicht im Repository liegen: $TARGET" >&2; exit 2 ;;
esac

if [ -n "$(git -C "$REPO" status --porcelain)" ]; then
  echo "Arbeitsverzeichnis nicht sauber – erst committen (der Schnappschuss nimmt HEAD)." >&2
  exit 2
fi
if [ -e "$TARGET" ]; then
  if [ "$FORCE" -eq 1 ]; then rm -rf "$TARGET"; else echo "$TARGET existiert – mit --force ersetzen." >&2; exit 2; fi
fi

mkdir -p "$TARGET"
git -C "$REPO" archive --format=tar HEAD | tar -x -C "$TARGET"
HEAD_SHA="$(git -C "$REPO" rev-parse --short HEAD)"

fail=0
report() { echo "  ✗ $1"; fail=1; }

echo "Prüfe Schnappschuss von $HEAD_SHA in $TARGET …"

# ---------------------------------------------------------------- 1. private patterns
# Single source of the pattern logic: scripts/check_private_data.py (also the pre-commit hook).
if [ -f "$REPO/CLAUDE.local.md" ] || [ -f "$REPO/.private-patterns" ]; then
  # pipefail is set, so the exit code of the checker decides (sed only indents its output)
  if ! python3 "$REPO/scripts/check_private_data.py" --all --root "$TARGET" --patterns-from "$REPO" | sed "s|^|  |"; then
    report "privates Muster gefunden (Details oben, Muster werden nicht ausgegeben)"
  fi
else
  echo "  ! CLAUDE.local.md und .private-patterns fehlen – nur allgemeine Prüfungen"
fi

# ---------------------------------------------------------------- 2. forbidden files
forbidden="$(cd "$TARGET" && find . \( -name CLAUDE.local.md -o -path ./docs/vendor -o -name '*.pdf' \
  -o -name 'SmarthomeRestApi*' -o -name '.env' -o -name '.env.*' -o -name '*.password' -o -name '*.pem' \
  -o -name '*.key' -o -name '.private-patterns' \) -print)"
[ -n "$forbidden" ] && report "verbotene Dateien: $(echo "$forbidden" | tr '\n' ' ')"

# ---------------------------------------------------------------- 3. token-like strings
tokens="$(grep -rIlE 'gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|sk-(ant-)?[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16}|xox[abpr]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----' "$TARGET" || true)"
[ -n "$tokens" ] && report "token-ähnliche Zeichenketten in: $(echo "$tokens" | sed "s|$TARGET/||" | tr '\n' ' ')"

# ---------------------------------------------------------------- 4. MAC addresses
macs="$(grep -rIhoE '\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b' "$TARGET" | tr 'a-f-' 'A-F:' | sort -u \
  | grep -vE '^(AA:BB:CC|00:00:00|FF:FF:FF)' | grep -vE ':00:00:[0-9A-F]{2}$|:00:11:22$|:12:34:56$|:AB:CD:EF$|:AA:BB:CC$' || true)"
[ -n "$macs" ] && report "nicht erfundene MAC-Adressen: $(echo "$macs" | tr '\n' ' ')"

if [ "$fail" -ne 0 ]; then
  echo "Abbruch – nichts committet. Fundstellen bereinigen (im Original-Repo committen) und erneut ausführen."
  exit 1
fi
echo "  ✓ keine privaten Daten gefunden"

# ---------------------------------------------------------------- fresh one-commit repository
cd "$TARGET"
git init -q -b main
git add -A
# Conventional Commit. "feat" (not "chore"): release-please skips releases without user-facing commits. The
# Release-As footer pins the first release to exactly 0.1.0 (manifest starts at 0.0.0).
git -c commit.gpgsign=false commit -q -m "feat: initial public release" -m "Release-As: 0.1.0"
echo "Fertig: $TARGET ($(git rev-list --count HEAD) Commit, $(git ls-files | wc -l | tr -d ' ') Dateien, ohne Remote)."
echo "Veröffentlichen erst nach Freigabe: Repo auf GitHub anlegen, 'git remote add origin …', 'git push -u origin main'."
