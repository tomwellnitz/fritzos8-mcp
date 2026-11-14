"""Stage 6, security first: every /api/v0 answer is redacted centrally in the RestClient."""

from __future__ import annotations

import json

import httpx
import pytest

from fritzos8_mcp.auth import SessionManager
from fritzos8_mcp.redact import MASK, is_api_secret_field, redact, redact_api
from fritzos8_mcp.rest import RestClient

from .conftest import BASE, CHALLENGE_XML, PASSWORD, session_xml
from .fixtures_api import FAKE_PRIV, FAKE_PSK, FAKE_SECRETS, FAKE_WG_CONF, PLC, VPN


def _rest(respx_mock) -> RestClient:
    respx_mock.get(f"{BASE}/login_sid.lua?version=2").mock(return_value=httpx.Response(200, text=CHALLENGE_XML))
    respx_mock.post(f"{BASE}/login_sid.lua?version=2").mock(return_value=httpx.Response(200, text=session_xml()))
    http = httpx.Client(base_url=BASE)
    return RestClient(http, SessionManager(http, "mcp", PASSWORD))


def _no_secret(data: object) -> None:
    text = json.dumps(data, ensure_ascii=False)
    for secret in FAKE_SECRETS:
        assert secret not in text, secret


def test_vpn_answer_redacted_by_rest_client(respx_mock) -> None:
    respx_mock.get(f"{BASE}/api/v0/generic/vpn").mock(return_value=httpx.Response(200, json=VPN))
    data = _rest(respx_mock).request("GET", "/api/v0/generic/vpn")
    _no_secret(data)
    wg, ipsec = data["connection"]
    assert wg["wg_preshared_key"] == MASK
    assert wg["wg_public_key"] == MASK
    for field in ("wg_slave_config", "wg_master_config", "wg_mastered_slave_config"):
        assert wg[field] == MASK
    assert ipsec["access_psk"] == MASK
    assert ipsec["xauth_password"] == MASK
    assert ipsec["access_username"] == MASK
    assert data["global"][0]["wg_device_config"] == MASK
    # harmless fields stay readable
    assert wg["name"] == "Box B"
    assert wg["state"] == "ready"
    assert wg["wg_allowed_ips"] == "198.51.100.0/24"
    assert data["global"][0]["wg_listen_port"] == "51820"
    # empty secret fields stay empty (no fake MASK for "not set")
    assert wg["access_psk"] == ""


def test_plc_security_id_and_password_redacted() -> None:
    out = redact_api(PLC)
    _no_secret(out)
    assert out["device"][0]["securityID"] == MASK
    assert out["device"][0]["model"] == "FRITZ!Powerline 1260"


@pytest.mark.parametrize(
    "field",
    [
        "wg_preshared_key",
        "wg_public_key",
        "wg_slave_config",
        "wg_device_config",
        "access_psk",
        "xauth_password",
        "xauth_username",
        "some_secret_value",
        "privateKey",
        "api_token",
        "new_passwd",
        "credentials",
        "ipsec_key",
        "unknown_preshared_thing",
    ],
)
def test_api_secret_field_names(field: str) -> None:
    assert is_api_secret_field(field)


@pytest.mark.parametrize(
    "field",
    ["name", "state", "UID", "eee_mode", "speed", "carrier", "wg_allowed_ips", "display_remote_net", "friendly_name"],
)
def test_api_harmless_field_names(field: str) -> None:
    assert not is_api_secret_field(field)


def test_unknown_field_with_config_document_value_is_masked() -> None:
    out = redact_api({"export": FAKE_WG_CONF, "list": [{"note": f"PresharedKey = {FAKE_PSK}"}]})
    assert out["export"] == MASK
    assert out["list"][0]["note"] == MASK
    _no_secret(out)


def test_nested_structures_under_secret_field_masked_whole() -> None:
    out = redact_api({"wg_peer_config": {"a": FAKE_PRIV}, "keys": {"private_key": [FAKE_PRIV]}})
    _no_secret(out)


def test_text_redaction_masks_wireguard_key_lines() -> None:
    out = redact(f"log: PrivateKey = {FAKE_PRIV} PresharedKey={FAKE_PSK}")
    assert FAKE_PRIV not in out and FAKE_PSK not in out
