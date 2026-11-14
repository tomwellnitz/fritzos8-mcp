"""Stage 10.4 – Streamable HTTP transport with mandatory bearer token (in-process ASGI, no network, no box)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from starlette.testclient import TestClient

from fritzos8_mcp.errors import ConfigError
from fritzos8_mcp.httpserve import (
    BearerAuthMiddleware,
    HttpSettings,
    build_http_app,
    exposure_warnings,
    generate_token,
    is_loopback,
    load_http_settings,
    wants_http,
)
from fritzos8_mcp.security import Gate
from fritzos8_mcp.server import build_server

TOKEN = "t" * 40  # test value only

INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
}
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def test_transport_selection() -> None:
    assert wants_http({}, []) is False
    assert wants_http({}, ["--http"]) is True
    assert wants_http({"FRITZ_TRANSPORT": "http"}, []) is True
    with pytest.raises(ConfigError):
        wants_http({"FRITZ_TRANSPORT": "sse"}, [])


def test_token_is_mandatory_and_long(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("fritzos8_mcp.httpserve._keyring_token", lambda service: "")
    with pytest.raises(ConfigError, match="ohne Token verweigert"):
        load_http_settings({})
    with pytest.raises(ConfigError, match="zu kurz"):
        load_http_settings({"FRITZ_HTTP_TOKEN": "kurz"})
    f = tmp_path / "token"
    f.write_text(TOKEN + "\n", encoding="utf-8")
    s = load_http_settings({"FRITZ_HTTP_TOKEN_FILE": str(f)})
    assert s.token == TOKEN and s.host == "127.0.0.1" and s.port == 8765
    assert TOKEN not in repr(s) and s.secrets == (TOKEN,)
    with pytest.raises(ConfigError):
        load_http_settings({"FRITZ_HTTP_TOKEN": TOKEN, "FRITZ_HTTP_TLS_CERT": "/x.pem"})


def test_token_from_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []
    monkeypatch.setattr("fritzos8_mcp.httpserve._keyring_token", lambda service: seen.append(service) or TOKEN)
    s = load_http_settings({"FRITZ_HTTP_KEYRING_SERVICE": "mein-dienst"})
    assert s.token == TOKEN and seen == ["mein-dienst"]


def test_generated_tokens_are_long_and_unique() -> None:
    a, b = generate_token(), generate_token()
    assert a != b and len(a) >= 32


def test_exposure_warnings() -> None:
    assert is_loopback("127.0.0.1") and is_loopback("::1") and is_loopback("localhost")
    assert not is_loopback("0.0.0.0") and not is_loopback("192.0.2.5")
    assert exposure_warnings(HttpSettings(token=TOKEN)) == []
    w = exposure_warnings(HttpSettings(host="0.0.0.0", token=TOKEN))
    assert any("VPN" in x for x in w) and any("Klartext" in x for x in w)
    assert HttpSettings(host="::", token=TOKEN).url == "http://[::]:8765/mcp"


def test_middleware_rejects_short_token() -> None:
    with pytest.raises(ConfigError):
        BearerAuthMiddleware(MagicMock(), "x")


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer falsch-" + "x" * 40}, {"Authorization": f"Basic {TOKEN}"}],
)
def test_requests_without_valid_token_get_401(headers: dict[str, str]) -> None:
    app = build_http_app(build_server(MagicMock(), Gate(False, False)), HttpSettings(token=TOKEN), json_response=True)
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        r = client.post("/mcp", json=INIT, headers={**HEADERS, **headers})
    assert r.status_code == 401
    assert r.headers["www-authenticate"].startswith("Bearer")
    assert TOKEN not in r.text


def test_valid_token_reaches_mcp() -> None:
    app = build_http_app(build_server(MagicMock(), Gate(False, False)), HttpSettings(token=TOKEN), json_response=True)
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        r = client.post("/mcp", json=INIT, headers={**HEADERS, "Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200, r.text
    assert r.json()["result"]["serverInfo"]["name"] == "fritzos8-mcp"


def test_dns_rebinding_protection_with_allowed_hosts() -> None:
    settings = HttpSettings(host="0.0.0.0", token=TOKEN, allowed_hosts=("pi.example:8765",))
    app = build_http_app(build_server(MagicMock(), Gate(False, False)), settings, json_response=True)
    auth = {**HEADERS, "Authorization": f"Bearer {TOKEN}"}
    with TestClient(app, base_url="http://pi.example:8765") as client:
        assert client.post("/mcp", json=INIT, headers={**auth, "Host": "evil.example:8765"}).status_code in (403, 421)
        assert client.post("/mcp", json=INIT, headers=auth).status_code == 200
