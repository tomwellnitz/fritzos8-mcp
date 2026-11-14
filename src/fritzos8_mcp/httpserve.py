"""Stage 10.4 – secure remote administration: the MCP server over Streamable HTTP with a mandatory bearer token.

* Transport: ``fritzos8-mcp --http`` or ``FRITZ_TRANSPORT=http`` (default stays stdio).
* Bind: ``FRITZ_HTTP_HOST`` (default ``127.0.0.1``), ``FRITZ_HTTP_PORT`` (default 8765), path ``/mcp``.
  A non-loopback bind (e.g. ``0.0.0.0``) logs a warning: only behind a VPN (FRITZ!Box WireGuard) or a TLS reverse
  proxy – the token travels in clear text over plain HTTP. Optional TLS directly: ``FRITZ_HTTP_TLS_CERT`` +
  ``FRITZ_HTTP_TLS_KEY``.
* Authentication is mandatory – without a token the server refuses to start. Token sources (first hit wins):
  ``FRITZ_HTTP_TOKEN``, ``FRITZ_HTTP_TOKEN_FILE``, keyring (service ``FRITZ_HTTP_KEYRING_SERVICE``, default
  ``fritzos8-mcp``, user ``http-token``; needs the optional ``keyring`` package). At least 32 characters;
  ``fritzos8-mcp --generate-token`` prints a fresh one. The token is a secret and redacted everywhere.
* Every HTTP request needs ``Authorization: Bearer <token>`` (constant-time comparison); otherwise 401 without any
  detail. DNS-rebinding protection: automatic for loopback, otherwise via ``FRITZ_HTTP_ALLOWED_HOSTS``
  (comma-separated ``host:port`` patterns, ``*`` as port wildcard).
"""

from __future__ import annotations

import hmac
import importlib
import ipaddress
import json
import logging
import os
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .errors import ConfigError

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer
    from starlette.types import ASGIApp, Receive, Scope, Send

log = logging.getLogger(__name__)

DEFAULT_PORT = 8765
MIN_TOKEN_LEN = 32
KEYRING_USER = "http-token"
TRUTHY = {"1", "true", "yes", "on"}


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def _keyring_token(service: str) -> str:
    try:
        keyring: Any = importlib.import_module("keyring")
    except ImportError:
        return ""
    try:
        return str(keyring.get_password(service, KEYRING_USER) or "")
    except Exception as exc:  # no backend, locked keychain … – never fatal here, the caller reports "no token"
        log.debug("keyring nicht nutzbar (%s)", type(exc).__name__)
        return ""


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class HttpSettings:
    host: str = "127.0.0.1"
    port: int = DEFAULT_PORT
    token: str = field(default="", repr=False)
    allowed_hosts: tuple[str, ...] = ()
    tls_cert: str = ""
    tls_key: str = ""

    @property
    def secrets(self) -> tuple[str, ...]:
        return (self.token,) if self.token else ()

    @property
    def exposed(self) -> bool:
        return not is_loopback(self.host)

    @property
    def url(self) -> str:
        scheme = "https" if self.tls_cert else "http"
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{scheme}://{host}:{self.port}/mcp"


def wants_http(environ: Mapping[str, str] | None = None, argv: Sequence[str] = ()) -> bool:
    e = os.environ if environ is None else environ
    transport = (e.get("FRITZ_TRANSPORT") or "stdio").strip().lower()
    if transport not in ("stdio", "http", "streamable-http"):
        raise ConfigError("FRITZ_TRANSPORT muss stdio oder http sein.")
    return "--http" in argv or transport in ("http", "streamable-http")


def load_http_settings(environ: Mapping[str, str] | None = None) -> HttpSettings:
    e = os.environ if environ is None else environ
    host = (e.get("FRITZ_HTTP_HOST") or "127.0.0.1").strip()
    try:
        port = int(e.get("FRITZ_HTTP_PORT") or DEFAULT_PORT)
    except ValueError:
        raise ConfigError("FRITZ_HTTP_PORT muss eine ganze Zahl sein.") from None
    if not 1 <= port <= 65535:
        raise ConfigError("FRITZ_HTTP_PORT muss 1–65535 sein.")
    token = (e.get("FRITZ_HTTP_TOKEN") or "").strip()
    token_file = (e.get("FRITZ_HTTP_TOKEN_FILE") or "").strip()
    if token and token_file:
        raise ConfigError("Entweder FRITZ_HTTP_TOKEN oder FRITZ_HTTP_TOKEN_FILE setzen, nicht beides.")
    if token_file:
        try:
            token = Path(token_file).expanduser().read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigError(f"FRITZ_HTTP_TOKEN_FILE nicht lesbar ({exc.strerror}).") from None
    if not token:
        token = _keyring_token((e.get("FRITZ_HTTP_KEYRING_SERVICE") or "fritzos8-mcp").strip()).strip()
    if not token:
        raise ConfigError(
            "HTTP-Transport ohne Token verweigert: FRITZ_HTTP_TOKEN, FRITZ_HTTP_TOKEN_FILE oder Schlüsselbund "
            "(keyring, Dienst fritzos8-mcp, Benutzer http-token) setzen. Neues Token: fritzos8-mcp --generate-token"
        )
    if len(token) < MIN_TOKEN_LEN:
        raise ConfigError(f"Token zu kurz (mindestens {MIN_TOKEN_LEN} Zeichen) – fritzos8-mcp --generate-token.")
    cert = (e.get("FRITZ_HTTP_TLS_CERT") or "").strip()
    key = (e.get("FRITZ_HTTP_TLS_KEY") or "").strip()
    if bool(cert) != bool(key):
        raise ConfigError("Für TLS beide setzen: FRITZ_HTTP_TLS_CERT und FRITZ_HTTP_TLS_KEY.")
    allowed = tuple(h.strip() for h in (e.get("FRITZ_HTTP_ALLOWED_HOSTS") or "").split(",") if h.strip())
    return HttpSettings(host=host, port=port, token=token, allowed_hosts=allowed, tls_cert=cert, tls_key=key)


def exposure_warnings(settings: HttpSettings) -> list[str]:
    out = []
    if settings.exposed:
        out.append(
            f"HTTP-Transport lauscht auf {settings.host} (nicht nur lokal). Nur im Heimnetz hinter VPN "
            "(z. B. FRITZ!Box-WireGuard) oder einem TLS-Reverse-Proxy betreiben, nie per Portfreigabe ins Internet."
        )
        if not settings.tls_cert:
            out.append("Ohne TLS geht das Token im Klartext über das Netz – TLS-Proxy oder VPN verwenden.")
        if not settings.allowed_hosts:
            out.append("FRITZ_HTTP_ALLOWED_HOSTS nicht gesetzt – DNS-Rebinding-Schutz aus (Token schützt weiterhin).")
    return out


class BearerAuthMiddleware:
    """Pure ASGI middleware: every HTTP request needs the bearer token; lifespan passes through."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        if len(token) < MIN_TOKEN_LEN:
            raise ConfigError("Token zu kurz.")
        self.app = app
        self._token = token.encode("utf-8")

    def _authorized(self, scope: Scope) -> bool:
        for name, value in scope.get("headers") or []:
            if name.lower() == b"authorization":
                scheme, _, credential = value.partition(b" ")
                return scheme.lower() == b"bearer" and hmac.compare_digest(credential.strip(), self._token)
        return False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket") or self._authorized(scope):
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":  # pragma: no cover - MCP uses no websockets
            await send({"type": "websocket.close", "code": 1008})
            return
        body = json.dumps({"error": "unauthorized"}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"www-authenticate", b'Bearer realm="fritzos8-mcp"'),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def build_http_app(server: MCPServer, settings: HttpSettings, *, json_response: bool = False) -> ASGIApp:
    from mcp.server.transport_security import TransportSecuritySettings

    security = None
    if settings.allowed_hosts:
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(settings.allowed_hosts),
            allowed_origins=[f"{s}://{h}" for h in settings.allowed_hosts for s in ("http", "https")],
        )
    elif settings.exposed:
        security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    app = server.streamable_http_app(
        transport_security=security,
        host=settings.host,
        json_response=json_response,
    )
    return BearerAuthMiddleware(app, settings.token)


def serve_http(server: MCPServer, settings: HttpSettings) -> None:  # pragma: no cover - blocking, uvicorn
    import uvicorn

    for warning in exposure_warnings(settings):
        log.warning(warning)
    log.info("MCP über Streamable HTTP: %s (Bearer-Token erforderlich)", settings.url)
    uvicorn.run(
        build_http_app(server, settings),
        host=settings.host,
        port=settings.port,
        log_level="warning",
        ssl_certfile=settings.tls_cert or None,
        ssl_keyfile=settings.tls_key or None,
        proxy_headers=False,
        server_header=False,
    )
