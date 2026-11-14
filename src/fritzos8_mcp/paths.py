"""Local directories for cache (OUI registry) and state (snapshots).

Both follow the XDG base directory convention and can be overridden for tests/deployments:
``FRITZ_CACHE_DIR`` / ``XDG_CACHE_HOME`` and ``FRITZ_STATE_DIR`` / ``XDG_STATE_HOME``.
Directories are created with mode 0700 – they may hold personal data (device names, MACs).
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path

APP = "fritzos8-mcp"


def _env(environ: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if environ is None else environ


def cache_dir(environ: Mapping[str, str] | None = None) -> Path:
    e = _env(environ)
    if e.get("FRITZ_CACHE_DIR"):
        return Path(e["FRITZ_CACHE_DIR"]).expanduser()
    base = Path(e.get("XDG_CACHE_HOME") or Path.home() / ".cache").expanduser()
    return base / APP


def state_dir(environ: Mapping[str, str] | None = None) -> Path:
    e = _env(environ)
    if e.get("FRITZ_STATE_DIR"):
        return Path(e["FRITZ_STATE_DIR"]).expanduser()
    base = Path(e.get("XDG_STATE_HOME") or Path.home() / ".local" / "state").expanduser()
    return base / APP


def safe_component(name: str) -> str:
    """Make a host name / label usable as one path component (no separators, no '..')."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", (name or "").strip()).strip(".")
    return cleaned or "box"


def ensure_private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def write_private(path: Path, data: bytes) -> None:
    """Atomically write a file with mode 0600."""
    ensure_private_dir(path.parent)
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        tmp.chmod(0o600)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()
