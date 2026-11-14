"""Configuration from environment variables only. Never from CLI arguments."""

from __future__ import annotations

import importlib
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .guard import GuardSettings

TRUTHY = {"1", "true", "yes", "on"}


def _flag(value: str | None) -> bool:
    return (value or "").strip().lower() in TRUTHY


DEFAULT_BOX = "default"
_BOX_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
# Per-box overridable variables (FRITZ_<NAME>_<VAR>); tiers stay global.
PER_BOX_VARS = (
    "HOST",
    "USER",
    "PASSWORD",
    "PASSWORD_FILE",
    "KEYRING_SERVICE",
    "USE_TLS",
    "TIMEOUT",
    # stage 7.1 box protection
    "MAX_PARALLEL",
    "RATE_LIMIT",
    "BURST",
    "CACHE_TTL",
    "RETRIES",
    "BREAKER_THRESHOLD",
    "BREAKER_COOLDOWN",
)

# (env suffix, GuardSettings field, type, min, max)
_GUARD_VARS: tuple[tuple[str, str, type, float, float], ...] = (
    ("MAX_PARALLEL", "max_parallel", int, 1, 16),
    ("RATE_LIMIT", "rate_per_s", float, 0, 100),
    ("BURST", "burst", int, 1, 100),
    ("CACHE_TTL", "cache_ttl", float, 0, 600),
    ("RETRIES", "retries", int, 0, 5),
    ("BREAKER_THRESHOLD", "breaker_threshold", int, 1, 100),
    ("BREAKER_COOLDOWN", "breaker_cooldown", float, 1, 3600),
)


@dataclass(frozen=True)
class Config:
    host: str
    user: str
    password: str = field(repr=False)
    allow_write: bool = False
    allow_critical: bool = False
    allow_secrets: bool = False  # stage 8.4: FRITZ_ALLOW_SECRETS (WLAN key only inside a QR image file)
    use_tls: bool = False
    timeout: float = 15.0
    plan_ttl: float = 300.0
    snapshot_keep: int = 30
    name: str = DEFAULT_BOX
    guard: GuardSettings = field(default_factory=GuardSettings)

    @property
    def web_base_url(self) -> str:
        return f"{'https' if self.use_tls else 'http'}://{self.host}"

    @property
    def secrets(self) -> tuple[str, ...]:
        return (self.password,)


def _read_password_file(path: str) -> str:
    p = Path(path).expanduser()
    try:
        content = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"FRITZ_PASSWORD_FILE nicht lesbar: {p} ({exc.strerror})") from None
    # Only strip the trailing line break; other whitespace belongs to the password.
    return content.rstrip("\r\n")


KEYRING_SERVICE = "fritzos8-mcp"


def keyring_password(user: str, host: str, service: str = KEYRING_SERVICE) -> str:
    """Password from the OS keychain via the optional ``keyring`` package: entry ``<user>@<host>`` first (several
    boxes with the same user name), then ``<user>``. Empty if keyring is missing, locked or has no entry."""
    try:
        keyring: Any = importlib.import_module("keyring")
    except ImportError:
        return ""
    for account in (f"{user}@{host}", user):
        try:
            value = keyring.get_password(service, account)
        except Exception:  # no backend / locked keychain – fall through to the "no password" error
            return ""
        if value:
            return str(value)
    return ""


def _guard_settings(e: Mapping[str, str]) -> GuardSettings:
    values: dict[str, float | int] = {}
    for suffix, attr, typ, low, high in _GUARD_VARS:
        raw = (e.get(f"FRITZ_{suffix}") or "").strip()
        if not raw:
            continue
        try:
            value = typ(raw)
        except ValueError:
            kind = "eine ganze Zahl" if typ is int else "eine Zahl"
            raise ConfigError(f"FRITZ_{suffix} muss {kind} sein.") from None
        if not low <= value <= high:
            raise ConfigError(f"FRITZ_{suffix} muss zwischen {low:g} und {high:g} liegen.")
        values[attr] = value
    return replace(GuardSettings(), **values)  # type: ignore[arg-type]


def load(environ: Mapping[str, str] | None = None) -> Config:
    e = os.environ if environ is None else environ

    user = (e.get("FRITZ_USER") or "").strip()
    if not user:
        raise ConfigError("FRITZ_USER ist nicht gesetzt (FRITZ!Box-Benutzername).")

    password = e.get("FRITZ_PASSWORD") or ""
    password_file = (e.get("FRITZ_PASSWORD_FILE") or "").strip()
    if password and password_file:
        raise ConfigError("Entweder FRITZ_PASSWORD oder FRITZ_PASSWORD_FILE setzen, nicht beides.")
    if password_file:
        password = _read_password_file(password_file)
    host = (e.get("FRITZ_HOST") or "").strip() or "fritz.box"
    if not password:  # stage 9.3: cross-platform keychain (macOS Keychain, Windows Credential Locker, Secret Service)
        password = keyring_password(user, host, (e.get("FRITZ_KEYRING_SERVICE") or KEYRING_SERVICE).strip())
    if not password:
        raise ConfigError(
            "Kein Passwort: FRITZ_PASSWORD, FRITZ_PASSWORD_FILE oder einen Schlüsselbund-Eintrag setzen "
            f"(keyring set {KEYRING_SERVICE} {user}; braucht das Extra fritzos8-mcp[keyring])."
        )

    allow_write = _flag(e.get("FRITZ_ALLOW_WRITE"))
    # critical only together with write
    allow_critical = allow_write and _flag(e.get("FRITZ_ALLOW_CRITICAL"))

    try:
        timeout = float(e.get("FRITZ_TIMEOUT") or 15.0)
    except ValueError:
        raise ConfigError("FRITZ_TIMEOUT muss eine Zahl (Sekunden) sein.") from None

    try:
        snapshot_keep = int(e.get("FRITZ_SNAPSHOT_KEEP") or 30)
    except ValueError:
        raise ConfigError("FRITZ_SNAPSHOT_KEEP muss eine ganze Zahl sein.") from None
    if not 1 <= snapshot_keep <= 1000:
        raise ConfigError("FRITZ_SNAPSHOT_KEEP muss 1–1000 sein.")

    return Config(
        host=host,
        user=user,
        password=password,
        allow_write=allow_write,
        allow_critical=allow_critical,
        allow_secrets=_flag(e.get("FRITZ_ALLOW_SECRETS")),
        use_tls=_flag(e.get("FRITZ_USE_TLS")),
        timeout=timeout,
        snapshot_keep=snapshot_keep,
        guard=_guard_settings(e),
    )


def _box_prefix(name: str) -> str:
    return "FRITZ_" + re.sub(r"[^A-Z0-9]", "_", name.upper()) + "_"


def load_all(environ: Mapping[str, str] | None = None) -> list[Config]:
    """All configured boxes. Without FRITZ_BOXES: exactly one box from FRITZ_HOST/USER/PASSWORD
    (backwards compatible). With FRITZ_BOXES=heim,zweit: per box FRITZ_<NAME>_HOST/_USER/
    _PASSWORD(_FILE) (optionally _USE_TLS/_TIMEOUT); FRITZ_ALLOW_* apply to all boxes."""
    e = os.environ if environ is None else environ
    raw = (e.get("FRITZ_BOXES") or "").strip()
    if not raw:
        return [load(e)]
    names = [n.strip().lower() for n in raw.split(",") if n.strip()]
    if not names:
        raise ConfigError("FRITZ_BOXES ist leer.")
    if len(set(names)) != len(names):
        raise ConfigError("FRITZ_BOXES enthält einen Namen doppelt.")
    configs = []
    for name in names:
        if not _BOX_NAME.match(name):
            raise ConfigError(f'Ungültiger Boxname "{name}" in FRITZ_BOXES (erlaubt: a–z 0–9 _ -, max. 32).')
        prefix = _box_prefix(name)
        sub = {k: v for k, v in e.items() if not any(k == f"FRITZ_{var}" for var in PER_BOX_VARS)}
        for var in PER_BOX_VARS:
            value = e.get(prefix + var)
            if value is not None:
                sub[f"FRITZ_{var}"] = value
        if not (sub.get("FRITZ_HOST") or "").strip():
            raise ConfigError(f"{prefix}HOST ist nicht gesetzt (Box '{name}').")
        try:
            cfg = load(sub)
        except ConfigError as exc:
            raise ConfigError(f"Box '{name}' ({prefix}…): {exc}") from None
        configs.append(replace(cfg, name=name))
    return configs
