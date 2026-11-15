#!/usr/bin/env bash
# Configure the public GitHub repository (settings, branch protection ruleset, labels, security features, PyPI
# environment). Idempotent – run it again after changing this file or .github/labels.yml.
#
#   scripts/github_setup.sh OWNER/REPO            # dry run (default): prints every API call, changes nothing
#   scripts/github_setup.sh OWNER/REPO --apply    # really apply (needs `gh auth login` with admin rights on REPO)
#
# What it sets:
#   - description, homepage, topics; issues + discussions on, wiki + projects off
#   - merge settings: squash merge only (PR title + body), auto-merge allowed, delete branch after merge
#   - repository ruleset "main": PR required (no review required – solo maintainer may merge own PRs), required
#     status checks (REQUIRED_CHECKS below), linear history, no force push, no deletion
#   - GITHUB_TOKEN default permission read-only, Actions may not approve PRs
#   - labels from .github/labels.yml
#   - private vulnerability reporting, secret scanning + push protection, Dependabot alerts + security updates
#   - environment "pypi" (deployments only from tags v* and main) for Trusted Publishing
# Not set here (manual go-live steps, see CONTRIBUTING.md): repository variable PUBLISH_PYPI, secret
# RELEASE_PLEASE_TOKEN, the PyPI Trusted Publisher.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPLY=0
SLUG=""
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --dry-run) APPLY=0 ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    */*) SLUG="$arg" ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done
[ -n "$SLUG" ] || { echo "usage: $0 OWNER/REPO [--dry-run|--apply]" >&2; exit 2; }

DESCRIPTION="MCP server for AVM FRITZ!Box routers with FRITZ!OS 8 – ~160 tools, read-only by default, every write read back, critical actions via plan → token → execute"
HOMEPAGE="https://github.com/$SLUG#readme"
TOPICS=(mcp mcp-server model-context-protocol fritzbox fritzos avm tr-064 router home-network smart-home python llm claude)
# Job names from .github/workflows/ci.yml, pr-title.yml and security.yml (keep in sync!)
REQUIRED_CHECKS=("lint" "typecheck" "test (py3.12)" "test (py3.13)" "docs" "package" "docker" "pr-title" "gitleaks" "mcpb")
GITHUB_ACTIONS_APP_ID=15368

command -v gh >/dev/null || { echo "gh (GitHub CLI) not found" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 not found" >&2; exit 1; }

if [ "$APPLY" -eq 1 ]; then
  echo "APPLY mode – changing $SLUG"
  gh api "repos/$SLUG" --jq '.full_name' >/dev/null || { echo "repository $SLUG not reachable with the current gh login" >&2; exit 1; }
else
  echo "DRY RUN – nothing is changed (use --apply). Target: $SLUG"
fi

# api METHOD PATH [JSON-BODY] – prints in dry-run mode, executes with --apply
api() {
  local method="$1" path="$2" body="${3:-}"
  if [ "$APPLY" -eq 0 ]; then
    echo "  → gh api -X $method $path"
    [ -n "$body" ] && echo "$body" | python3 -m json.tool | sed 's/^/      /'
    return 0
  fi
  if [ -n "$body" ]; then
    gh api -X "$method" "$path" -H "Accept: application/vnd.github+json" --input - <<<"$body" >/dev/null
  else
    gh api -X "$method" "$path" -H "Accept: application/vnd.github+json" >/dev/null
  fi
  echo "  ✓ $method $path"
}

json() { python3 -c "import json,sys; print(json.dumps($1, ensure_ascii=False))" "${@:2}"; }

echo "== Repository settings"
api PATCH "repos/$SLUG" "$(json '{
  "description": sys.argv[1], "homepage": sys.argv[2],
  "has_issues": True, "has_discussions": True, "has_wiki": False, "has_projects": False,
  "allow_squash_merge": True, "allow_merge_commit": False, "allow_rebase_merge": False,
  "squash_merge_commit_title": "PR_TITLE", "squash_merge_commit_message": "PR_BODY",
  "allow_auto_merge": True, "allow_update_branch": True, "delete_branch_on_merge": True,
  "web_commit_signoff_required": False,
  "security_and_analysis": {
    "secret_scanning": {"status": "enabled"},
    "secret_scanning_push_protection": {"status": "enabled"}
  }
}' "$DESCRIPTION" "$HOMEPAGE")"

echo "== Topics"
api PUT "repos/$SLUG/topics" "$(json '{"names": sys.argv[1:]}' "${TOPICS[@]}")"

echo "== Actions: read-only GITHUB_TOKEN by default"
api PUT "repos/$SLUG/actions/permissions/workflow" \
  '{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false}'

echo "== Security features"
api PUT "repos/$SLUG/private-vulnerability-reporting"
api PUT "repos/$SLUG/vulnerability-alerts"
api PUT "repos/$SLUG/automated-security-fixes"

echo "== Ruleset for main"
RULESET="$(json '{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
  "bypass_actors": [],
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "required_linear_history"},
    {"type": "pull_request", "parameters": {
      "required_approving_review_count": 0,
      "dismiss_stale_reviews_on_push": False,
      "require_code_owner_review": False,
      "require_last_push_approval": False,
      "required_review_thread_resolution": False,
      "allowed_merge_methods": ["squash"]}},
    {"type": "required_status_checks", "parameters": {
      "strict_required_status_checks_policy": False,
      "do_not_enforce_on_create": False,
      "required_status_checks": [{"context": c, "integration_id": int(sys.argv[1])} for c in sys.argv[2:]]}}
  ]
}' "$GITHUB_ACTIONS_APP_ID" "${REQUIRED_CHECKS[@]}")"
existing=""
if gh api "repos/$SLUG/rulesets" >/dev/null 2>&1; then
  existing="$(gh api "repos/$SLUG/rulesets" --jq '.[] | select(.name == "main") | .id' 2>/dev/null || true)"
fi
if [ -n "$existing" ]; then
  api PUT "repos/$SLUG/rulesets/$existing" "$RULESET"
else
  api POST "repos/$SLUG/rulesets" "$RULESET"
fi

echo "== Labels (.github/labels.yml)"
# The file is a flat list of {name, color, description}; parsed without PyYAML.
while IFS=$'\t' read -r name color desc; do
  if [ "$APPLY" -eq 0 ]; then
    echo "  → gh label create \"$name\" --color $color --description \"$desc\" --force"
  else
    gh label create "$name" --color "$color" --description "$desc" --force -R "$SLUG" >/dev/null
    echo "  ✓ label $name"
  fi
done < <(python3 - "$REPO_DIR/.github/labels.yml" <<'PY'
import re, sys
items, cur = [], {}
for line in open(sys.argv[1], encoding="utf-8"):
    m = re.match(r'^(- )?\s*(name|color|description):\s*(.*)$', line.rstrip("\n"))
    if not m:
        continue
    if m.group(1) and cur:
        items.append(cur); cur = {}
    cur[m.group(2)] = m.group(3).strip().strip('"')
if cur:
    items.append(cur)
for i in items:
    print(f"{i['name']}\t{i['color']}\t{i.get('description', '')}")
PY
)

echo "== Environment pypi (Trusted Publishing)"
api PUT "repos/$SLUG/environments/pypi" \
  '{"deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}'
policies=""
if gh api "repos/$SLUG/environments/pypi/deployment-branch-policies" >/dev/null 2>&1; then
  policies="$(gh api "repos/$SLUG/environments/pypi/deployment-branch-policies" \
    --jq '.branch_policies[] | "\(.type):\(.name)"' 2>/dev/null || true)"
fi
for p in "tag:v*" "branch:main"; do
  if grep -qxF "$p" <<<"$policies"; then
    echo "  = deployment policy $p exists"
  else
    api POST "repos/$SLUG/environments/pypi/deployment-branch-policies" \
      "$(json '{"type": sys.argv[1], "name": sys.argv[2]}' "${p%%:*}" "${p#*:}")"
  fi
done

echo
if [ "$APPLY" -eq 0 ]; then
  echo "Dry run complete. Re-run with --apply to change $SLUG."
else
  echo "Done. Remaining manual steps: PyPI Trusted Publisher, secret RELEASE_PLEASE_TOKEN, variable PUBLISH_PYPI=true."
fi
