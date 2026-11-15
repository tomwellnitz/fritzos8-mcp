"""mcpb/manifest.json (Claude Desktop bundle): version in sync, user_config mapped onto FRITZ_*, booleans parsed."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest

from fritzos8_mcp import config

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = json.loads((ROOT / "mcpb" / "manifest.json").read_text(encoding="utf-8"))
ENV_MAP = {
    "FRITZ_HOST": "fritz_host",
    "FRITZ_USER": "fritz_user",
    "FRITZ_PASSWORD": "fritz_password",
    "FRITZ_ALLOW_WRITE": "allow_write",
    "FRITZ_ALLOW_CRITICAL": "allow_critical",
}


def _host_env(values: dict[str, object]) -> dict[str, str]:
    """Substitute ${user_config.*} like the host: defaults first, booleans as "true"/"false" (mcpb config.ts)."""
    merged = {k: v["default"] for k, v in MANIFEST["user_config"].items() if "default" in v}
    merged.update(values)
    strings = {k: ("true" if v else "false") if isinstance(v, bool) else str(v) for k, v in merged.items()}
    return {
        name: re.sub(r"\$\{user_config\.(\w+)\}", lambda m: strings[m.group(1)], template)
        for name, template in MANIFEST["server"]["mcp_config"]["env"].items()
    }


def test_manifest_version_matches_pyproject() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert MANIFEST["version"] == pyproject["project"]["version"]


def test_release_please_bumps_the_manifest() -> None:
    cfg = json.loads((ROOT / "release-please-config.json").read_text(encoding="utf-8"))
    extra = cfg["packages"]["."]["extra-files"]
    assert {"type": "json", "path": "mcpb/manifest.json", "jsonpath": "$.version"} in extra


def test_server_runs_the_bundled_project_as_locked() -> None:
    server = MANIFEST["server"]
    assert MANIFEST["manifest_version"] == "0.4" and server["type"] == "uv"
    args = server["mcp_config"]["args"]
    assert server["mcp_config"]["command"] == "uv"
    assert args[:3] == ["run", "--directory", "${__dirname}"]
    assert {"--frozen", "--no-dev"} <= set(args) and args[-1] == "fritzos8-mcp"
    assert (ROOT / server["entry_point"]).is_file()


def test_user_config_maps_onto_fritz_env() -> None:
    env = MANIFEST["server"]["mcp_config"]["env"]
    assert env == {name: f"${{user_config.{key}}}" for name, key in ENV_MAP.items()}
    uc = MANIFEST["user_config"]
    assert set(uc) == set(ENV_MAP.values())
    assert uc["fritz_host"]["default"] == "fritz.box"
    assert uc["fritz_user"]["required"] is True
    assert uc["fritz_password"]["sensitive"] is True and uc["fritz_password"]["required"] is True
    for key in ("allow_write", "allow_critical"):
        assert uc[key]["type"] == "boolean" and uc[key]["default"] is False


@pytest.mark.parametrize(
    ("write", "critical", "expected"),
    [
        (False, False, (False, False)),
        (True, False, (True, False)),
        (True, True, (True, True)),
        (False, True, (False, False)),  # critical only together with write
    ],
)
def test_boolean_toggles_reach_the_config(write: bool, critical: bool, expected: tuple[bool, bool]) -> None:
    env = _host_env({"fritz_user": "mcp", "fritz_password": "dummy", "allow_write": write, "allow_critical": critical})
    assert env["FRITZ_ALLOW_WRITE"] in {"true", "false"}
    cfg = config.load(env)
    assert (cfg.allow_write, cfg.allow_critical) == expected
    assert cfg.host == "fritz.box"
