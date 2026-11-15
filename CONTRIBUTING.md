# Contributing

Thanks for helping! Issues, discussions and pull requests are welcome in English or German. Project communication
(commits, PR titles, issues, changelog) is in English; code comments and tool descriptions are German – please keep
them German when you edit them.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Security issues: see
[SECURITY.md](SECURITY.md) – never in a public issue.

## Development setup

Requirements: `git`, [uv](https://docs.astral.sh/uv/) (it installs Python ≥ 3.12 if needed), optionally `make` and
Docker. A [dev container](.devcontainer/devcontainer.json) is available as well.

```bash
git clone https://github.com/tomwellnitz/fritzos8-mcp.git
cd fritzos8-mcp
make setup     # = scripts/bootstrap.sh: uv sync (all extras + dev/docs groups), git hooks, .private-patterns template
make check     # everything CI runs: lint, mypy, tests, generated-docs checks, docs build, package build
make help      # all targets (format, test, docs-serve, docker, audit, …)
```

The git hooks (via [pre-commit](https://pre-commit.com/)) run automatically:

| Stage        | Checks                                                                                                   |
|--------------|----------------------------------------------------------------------------------------------------------|
| `pre-commit` | ruff (lint + format), mypy, YAML/TOML/JSON syntax, whitespace/EOF/line endings, merge conflicts, large files, private keys, **gitleaks**, private-data check |
| `commit-msg` | Conventional Commit format                                                                               |
| `pre-push`   | pytest (mocks only), mypy, `docs/TOOLS.md` and `docs/COVERAGE.md` statistics up to date                  |

Run them by hand with `uv run pre-commit run --all-files` (add `--hook-stage pre-push` for the push checks).

The **private-data** hook reads patterns from the untracked file `.private-patterns` (one string per line – e.g. your
public IP, street, real device names; created as a template by `make setup`). If neither `.private-patterns` nor a
local `CLAUDE.local.md` exists, the hook is skipped with a notice.

## Tests – no real box needed

All tests run against mocks and fixtures – **no test may talk to a real FRITZ!Box**. CI runs them on Python 3.12 and
3.13 (3.14 informational).

**Live suite (opt-in, read-only):** to check your own box, run

```bash
FRITZ_LIVE_TEST=1 FRITZ_HOST=fritz.box FRITZ_USER=… FRITZ_PASSWORD_FILE=~/.config/fritzos8/pw make test-live
```

It only reads. Share the result in a [compatibility report](https://github.com/tomwellnitz/fritzos8-mcp/issues/new?template=compatibility.yml),
and contribute anonymized box answers as fixtures with `fritzos8-anonymize` (see [docs/fixtures.md](docs/fixtures.md);
review the result by hand before submitting).

## Workflow

1. Open an issue or discussion first for larger changes (new tools, anything `critical`).
2. Create a branch: `git switch -c feat/wlan-schedule` (fork first if you are not a maintainer).
3. Commit with Conventional Commits (checked by the `commit-msg` hook). Small, focused commits are nice, but the
   branch is **squash-merged**, so only the PR title ends up on `main`.
4. Open a pull request. Its **title must be a Conventional Commit** (checked in CI); it becomes the commit message on
   `main` and the changelog entry. Fill in the checklist of the PR template.
5. CI must be green (lint, typecheck, tests, docs, package, docker, PR title, gitleaks). `main` only accepts squash
   merges of PRs with green checks; branches are deleted after the merge.

### Conventional Commits

Format: `<type>[(scope)][!]: <description>` – description in lowercase imperative, no trailing period. Only visible
types (`feat`, `fix`, `perf`, `revert`) lead to a release; hidden ones are released with the next visible change.

| Type       | Use for                                       | Changelog section | Version bump (0.x)  |
|------------|-----------------------------------------------|-------------------|---------------------|
| `feat`     | a new tool, parameter or capability           | Added             | minor               |
| `fix`      | a bug fix                                     | Fixed             | patch               |
| `perf`     | a performance improvement                     | Changed           | patch               |
| `revert`   | reverting an earlier commit                   | Changed           | patch               |
| `docs`     | documentation only                            | hidden            | –                   |
| `refactor` | code change without behaviour change          | hidden            | –                   |
| `test`     | tests only                                    | hidden            | –                   |
| `build`    | packaging, dependencies, dev tooling          | hidden            | –                   |
| `ci`       | GitHub Actions workflows                      | hidden            | –                   |
| `chore`    | anything else (maintenance)                   | hidden            | –                   |
| `style`    | formatting only                               | hidden            | –                   |

Breaking changes: `!` after the type/scope **or** a `BREAKING CHANGE:` footer. Before 1.0.0 they bump the minor
version, afterwards the major version. Optional scopes: `tr064`, `api-v0`, `smarthome`, `telephony`, `wifi`,
`monitoring`, `safety`, `http`, `docker`, `deps`, `release`, …

Examples:

```text
feat: add wlan_schedule tool
fix(tr064): treat missing NewX_AVM-DE_UserIsolation as unknown
docs: explain the secrets tier in the README
feat(safety)!: require elicitation for every critical execute

BREAKING CHANGE: clients without elicitation support must pass confirm=true.
```

Security fixes use `fix:` (mention "security" in the description) and are announced through a GitHub security
advisory.

## Rules for code changes

- **Safety model first.** New tools are registered with the `tool(tier, annotations)` decorator in `server.py` (or a
  `register_*_tools` function): read tools never change the box; write tools call `gate.require(Tier.WRITE)` and read
  the result back (`verified`); anything risky is critical and split into `*_plan` (returns `consequence`,
  `warnings`, `token`) and `*_execute` (redeems the token, ideally bound to the target's identity).
- **Never bypass the box guard** (`guard.py`) – go through `Tr064Client`, `RestClient` or `AhaClient`.
- **Secrets:** new fields that can carry secrets must be covered by `redact.py` and a test.
- **Document action names** against the official AVM interface documents (https://fritz.com/pages/schnittstellen) and
  add the action/endpoint to `docs/COVERAGE.md` – a test checks that every curated TR-064 action is listed there
  (`uv run python scripts/coverage_stats.py` recounts the statistics).
- **New `/api/v0` endpoints** (undocumented web UI API) only after a browser capture on a real box – never guessed.
- After adding or changing tools: add the right to `src/fritzos8_mcp/rights.py`, regenerate the reference with
  `uv run python scripts/gen_tool_reference.py` and update the README tables.
- **No personal data in the repository:** use documentation addresses (`192.0.2.x`, `198.51.100.x`, `2001:db8::`),
  MACs `AA:BB:CC:…` and invented names in tests and docs.
- Third-party code only from compatibly licensed (MIT) sources, noted in `NOTICE`.

## Releases (maintainers)

Releases are fully automated with [release-please](https://github.com/googleapis/release-please):

1. Every push to `main` updates the release PR **"chore: release x.y.z"**. It bumps the version (SemVer, derived from
   the Conventional Commits since the last release) in `pyproject.toml`, `src/fritzos8_mcp/__init__.py`, `uv.lock` and
   the Home Assistant add-on, and prepends the generated section to `CHANGELOG.md`.
2. Merging the release PR creates the tag `vX.Y.Z` and the GitHub release.
3. The release triggers `.github/workflows/release.yml`: tests, build, build-provenance attestation, sdist/wheel
   attached to the release together with their SLSA provenance (`fritzos8-mcp-X.Y.Z.intoto.jsonl`), PyPI upload via
   Trusted Publishing (only when the repository variable `PUBLISH_PYPI=true`) and the multi-arch image
   `ghcr.io/tomwellnitz/fritzos8-mcp` (`X.Y.Z`, `X.Y`, `latest`, with SBOM and provenance), and the Claude Desktop
   bundle `fritzos8-mcp-X.Y.Z.mcpb` attached to the release with its provenance `fritzos8-mcp-X.Y.Z.mcpb.intoto.jsonl`
   (`make mcpb` builds and smoke-tests it locally; the version in `mcpb/manifest.json` is bumped by release-please).
   How users verify the artifacts: [SECURITY.md → Verifying release
   artifacts](SECURITY.md#verifying-release-artifacts). After a release, check that both `*.intoto.jsonl` assets are
   present – OpenSSF Scorecard (*Signed-Releases*) looks for them on the last five releases.

Never bump versions, edit version sections of the changelog or push tags by hand. To force a specific version, add a
commit with the footer `Release-As: X.Y.Z`. If a release was created without `RELEASE_PLEASE_TOKEN`, start
`release.yml` manually (*Actions → Release → Run workflow*, tag `vX.Y.Z`).

Repository settings (ruleset, merge options, labels, security features, `pypi` environment) are kept as code in
`scripts/github_setup.sh` (dry run by default, `--apply` to change the repository).
