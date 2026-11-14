#!/usr/bin/env bash
# One-time developer setup (also run by `make setup`). Safe to run again.
#   - checks git, uv and a suitable Python (>= 3.12, uv downloads one if missing)
#   - installs all dependencies from uv.lock (all extras, dev + docs groups)
#   - installs the pre-commit hooks for the stages pre-commit, commit-msg and pre-push
#   - creates a .private-patterns template (gitignored) for the private-data hook
# Never talks to a FRITZ!Box.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }
die()  { printf '  \033[31m✗\033[0m %s\n' "$1" >&2; exit 1; }

echo "fritzos8-mcp – developer setup"

command -v git >/dev/null 2>&1 || die "git not found – install git first."
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "not inside a git checkout (clone the repository with git)."
ok "git $(git --version | awk '{print $3}')"

command -v uv >/dev/null 2>&1 || die "uv not found – install it: https://docs.astral.sh/uv/getting-started/installation/"
ok "$(uv --version)"

PY_REQ="$(cat .python-version 2>/dev/null || echo 3.12)"
uv python find "$PY_REQ" >/dev/null 2>&1 || { warn "Python $PY_REQ not found – uv will download it"; uv python install "$PY_REQ"; }
ok "Python $(uv run --no-project --python "$PY_REQ" python -c 'import platform; print(platform.python_version())')"

uv sync --frozen --all-extras --all-groups
ok "dependencies installed from uv.lock (.venv)"

# core.hooksPath (set globally by some tools) would make pre-commit refuse to install
if [ -n "$(git config --local --get core.hooksPath || true)" ]; then
  warn "unsetting local core.hooksPath so pre-commit can install its hooks"
  git config --local --unset core.hooksPath
fi
uv run --frozen pre-commit install --install-hooks --hook-type pre-commit --hook-type commit-msg --hook-type pre-push
ok "git hooks installed (pre-commit, commit-msg, pre-push)"

if [ ! -f .private-patterns ]; then
  cat > .private-patterns <<'EOF'
# Private strings that must never be committed (one fixed string per line, case-insensitive).
# This file is gitignored; the pre-commit hook "private-data" and scripts/make_public_snapshot.sh read it.
# Examples (replace with your own): your public IP, your street, real device names, your e-mail address.
# 203.0.113.17
# Example Street
EOF
  ok ".private-patterns template created (gitignored) – add your own strings"
else
  ok ".private-patterns present"
fi

cat <<'EOF'

Next steps:
  make check        everything CI runs (lint, mypy, tests, docs, build)
  make help         all targets
  git switch -c feat/my-change   →   commit with Conventional Commits (e.g. "feat: add xyz tool")
  Live tests against your own box are opt-in: see CONTRIBUTING.md ("Live suite").
EOF
