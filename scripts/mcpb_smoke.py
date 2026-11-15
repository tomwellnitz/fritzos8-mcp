"""Smoke test for the Claude Desktop bundle: unpack it, start the server exactly as manifest.json describes
(variable substitution like the host does it, booleans as "true"/"false") and run initialize + tools/list –
once read-only and once with allow_write=true.

Dummy configuration only – FRITZ_HOST is a documentation address (192.0.2.1), no real box is contacted.

    python3 scripts/mcpb_smoke.py dist/fritzos8-mcp-<version>.mcpb
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

DUMMY_CONFIG: dict[str, Any] = {
    "fritz_host": "192.0.2.1",
    "fritz_user": "smoke-test",
    "fritz_password": "not-a-real-password",
}


class SmokeError(RuntimeError):
    pass


def _substitute(value: str, variables: dict[str, str]) -> str:
    return re.sub(r"\$\{([^}]+)\}", lambda m: variables.get(m.group(1), m.group(0)), value)


def _send(proc: subprocess.Popen[str], message: dict[str, Any]) -> None:
    if proc.stdin is None:
        raise SmokeError("no stdin")
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()


def _request(proc: subprocess.Popen[str], msg_id: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
    _send(proc, {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params})
    if proc.stdout is None:
        raise SmokeError("no stdout")
    while True:
        line = proc.stdout.readline()
        if not line:
            raise SmokeError(f"server closed stdout (exit code {proc.poll()})")
        reply = json.loads(line)
        if reply.get("id") == msg_id:
            if "error" in reply:
                raise SmokeError(f"{method} failed: {reply['error']}")
            return dict(reply["result"])


def _command(root: Path, manifest: dict[str, Any], overrides: dict[str, Any]) -> tuple[list[str], dict[str, str]]:
    """Resolve mcp_config the way the host does: defaults, then user values; booleans become "true"/"false"."""
    values: dict[str, Any] = {k: v["default"] for k, v in manifest["user_config"].items() if "default" in v}
    values.update(DUMMY_CONFIG)
    values.update(overrides)
    variables = {"__dirname": str(root), "/": os.sep, "pathSeparator": os.sep}
    for key, val in values.items():
        variables[f"user_config.{key}"] = ("true" if val else "false") if isinstance(val, bool) else str(val)
    cfg = manifest["server"]["mcp_config"]
    cmd = [cfg["command"], *(_substitute(a, variables) for a in cfg.get("args", []))]
    env = {k: _substitute(v, variables) for k, v in cfg.get("env", {}).items()}
    unresolved = [a for a in [*cmd, *env.values()] if "${" in a]
    if unresolved:
        raise SmokeError(f"unresolved variables: {unresolved}")
    return cmd, env


def _session(root: Path, tmp: str, manifest: dict[str, Any], overrides: dict[str, Any]) -> list[str]:
    """Start the server once with the given user_config values; returns the tool names."""
    cmd, env_extra = _command(root, manifest, overrides)
    # Isolate from the caller's FRITZ_* settings and state directories.
    env = {k: v for k, v in os.environ.items() if not k.startswith("FRITZ_")}
    env.update(env_extra)
    env["XDG_STATE_HOME"] = str(Path(tmp) / "state")
    env["XDG_CACHE_HOME"] = str(Path(tmp) / "cache")

    print("start:", " ".join(cmd), "| FRITZ_ALLOW_WRITE =", env["FRITZ_ALLOW_WRITE"])
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env)  # noqa: S603
    try:
        init = _request(
            proc,
            1,
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "mcpb-smoke", "version": "0"},
            },
        )
        info = init["serverInfo"]
        print(f"initialize: {info.get('name')} {info.get('version')}")
        if info.get("version") != manifest["version"]:
            raise SmokeError(f"server version {info.get('version')} != bundle version {manifest['version']}")
        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        names = [t["name"] for t in _request(proc, 2, "tools/list", {})["tools"]]
        print(f"tools/list: {len(names)} tools")
        if not {"setup_check", "server_status"} <= set(names):
            raise SmokeError("expected tools setup_check/server_status are missing")
        return names
    finally:
        if proc.stdin:
            proc.stdin.close()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def main(bundle: str) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "bundle"
        with zipfile.ZipFile(bundle) as archive:
            archive.extractall(root)
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        if manifest["server"]["type"] != "uv":
            raise SmokeError("expected server.type uv")
        read_only = _session(root, tmp, manifest, {})
        # The boolean toggle arrives as the string "true" and must enable the write tools.
        writable = _session(root, tmp, manifest, {"allow_write": True})
        if not set(read_only) < set(writable):
            raise SmokeError("allow_write=true did not add write tools")
        print(f"allow_write=true adds {len(writable) - len(read_only)} write tools")
    print("mcpb smoke test ok")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
