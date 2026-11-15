#!/usr/bin/env bash
# Builds the Claude Desktop bundle dist/fritzos8-mcp-<version>.mcpb (MCP Bundle, server type "uv").
#
# The bundle carries the project itself (pyproject.toml, uv.lock, src/) – the host runs it with
# `uv run --frozen --no-dev`, so the dependencies resolve exactly as locked for this release.
# Only an explicit allowlist of git-tracked files is staged; nothing else (local notes, vendor documents,
# caches, .venv) can end up in the archive. The content is checked again after packing.
#
#   scripts/build_mcpb.sh    # validate + pack into dist/ (also used as the CI probe)
#   python3 scripts/mcpb_smoke.py dist/fritzos8-mcp-<version>.mcpb   # start it like the host and list the tools
#
# Needs: git, python3, npm (the mcpb CLI is pinned in mcpb/package-lock.json and installed with `npm ci`).
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

out_dir="$ROOT/dist"

version="$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"
manifest_version="$(python3 -c 'import json; print(json.load(open("mcpb/manifest.json"))["version"])')"
if [[ "$version" != "$manifest_version" ]]; then
  echo "error: mcpb/manifest.json version $manifest_version != pyproject version $version" >&2
  exit 1
fi

if [[ ! -x mcpb/node_modules/.bin/mcpb ]]; then
  npm ci --prefix mcpb --ignore-scripts --no-audit --no-fund
fi
MCPB="$ROOT/mcpb/node_modules/.bin/mcpb"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

# Bundle files from mcpb/, project files from git (tracked files only, working-tree content).
cp mcpb/manifest.json mcpb/icon.png mcpb/.mcpbignore "$stage/"
git ls-files -z -- pyproject.toml uv.lock README.md LICENSE NOTICE src/ | tar --null -T - -cf - | tar -xf - -C "$stage"

"$MCPB" validate "$stage/manifest.json"

mkdir -p "$out_dir"
bundle="$out_dir/fritzos8-mcp-$version.mcpb"
rm -f "$bundle"
"$MCPB" pack "$stage" "$bundle"

# Allowlist check on the packed archive.
python3 - "$bundle" <<'PY'
import re
import sys
import zipfile

allowed = re.compile(
    r"^(manifest\.json|icon\.png|\.mcpbignore|pyproject\.toml|uv\.lock|README\.md|LICENSE|NOTICE"
    r"|src/fritzos8_mcp/[\w/.-]+\.(py|typed|json|yaml|txt|csv))$"
)
names = [n for n in zipfile.ZipFile(sys.argv[1]).namelist() if not n.endswith("/")]
bad = [n for n in names if not allowed.match(n) or "__pycache__" in n]
if bad:
    sys.exit("unexpected files in bundle: " + ", ".join(bad))
if "manifest.json" not in names or "src/fritzos8_mcp/__init__.py" not in names:
    sys.exit("bundle is missing manifest.json or the package")
print(f"bundle content ok: {len(names)} files")
PY

echo "$bundle"
