"""Release tooling: every place that carries the version agrees, release-please config is sane."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def _pyproject_version() -> str:
    return str(tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"])


def test_versions_are_consistent() -> None:
    """release-please bumps all of these together (pyproject, __init__, uv.lock + extra-files)."""
    from fritzos8_mcp import __version__

    version = _pyproject_version()
    assert SEMVER.match(version)
    assert __version__ == version
    addon = (ROOT / "ha-addon" / "fritzos8-mcp" / "config.yaml").read_text(encoding="utf-8")
    assert f'version: "{version}" # x-release-please-version' in addon
    addon_docker = (ROOT / "ha-addon" / "fritzos8-mcp" / "Dockerfile").read_text(encoding="utf-8")
    assert f"ARG FRITZOS8_MCP_VERSION={version}" in addon_docker
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    own = [p for p in lock["package"] if p["name"] == "fritzos8-mcp"]
    assert own and own[0]["version"] == version


def test_release_please_config() -> None:
    config = json.loads((ROOT / "release-please-config.json").read_text(encoding="utf-8"))
    manifest = json.loads((ROOT / ".release-please-manifest.json").read_text(encoding="utf-8"))
    assert set(manifest) == {"."} and SEMVER.match(manifest["."])
    pkg = config["packages"]["."]
    assert pkg.get("release-type", config.get("release-type")) == "python"
    for extra in pkg["extra-files"]:
        path = extra if isinstance(extra, str) else extra["path"]
        assert (ROOT / path).is_file(), path
    # every Conventional Commit type allowed by the commit-msg hook has a changelog section
    types = {s["type"] for s in config["changelog-sections"]}
    hook = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    allowed = re.search(r"args: \[--strict, ([^\]]+)\]", hook)
    assert allowed
    assert {t.strip() for t in allowed.group(1).split(",")} <= types


def test_changelog_is_release_please_compatible() -> None:
    """release-please inserts new entries before the first '## x.y.z'/'### x' header – no '[Unreleased]' block."""
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert text.startswith("# Changelog\n")
    assert "[Unreleased]" not in text
    assert re.search(r"\n###? v?[0-9\[]", text), "release-please needs an existing version header as anchor"


def test_release_attaches_slsa_provenance() -> None:
    """Every attested release file gets its provenance as *.intoto.jsonl asset (OpenSSF Scorecard Signed-Releases)."""
    import yaml

    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    expected = {"build": "fritzos8-mcp-${TAG#v}.intoto.jsonl", "mcpb": "fritzos8-mcp-${TAG#v}.mcpb.intoto.jsonl"}
    for job, provenance in expected.items():
        steps = workflow["jobs"][job]["steps"]
        attest = [s for s in steps if str(s.get("uses", "")).startswith("actions/attest-build-provenance@")]
        assert attest and attest[0].get("id") == "attest", job
        upload = [s for s in steps if "gh release upload" in s.get("run", "")]
        assert upload, job
        assert upload[0]["env"]["BUNDLE"] == "${{ steps.attest.outputs.bundle-path }}", job
        assert provenance in upload[0]["run"], job
