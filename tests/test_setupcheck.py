"""Stage 9.3 – setup check (K-13) and keyring credentials (fake box, fake keyring)."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any

import pytest
from fritzconnection.core.exceptions import FritzConnectionException

from fritzos8_mcp import config
from fritzos8_mcp.errors import ConfigError
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.setupcheck import SetupChecker, parse_rights_xml

from .conftest import FakeFC, make_service

RIGHTS_XML = (
    "<rights><path>BoxAdmin</path><access>readwrite</access><path>Phone</path><access>none</access>"
    "<path>NAS</path><access>readonly</access><path>HomeAuto</path><access>none</access></rights>"
)


def _fc(overrides: dict[tuple[str, str], Any] | None = None) -> FakeFC:
    responses: dict[tuple[str, str], Any] = {
        ("DeviceInfo1", "GetInfo"): {"NewModelName": "FRITZ!Box 7590", "NewSoftwareVersion": "8.20"},
        ("LANConfigSecurity1", "X_AVM-DE_GetCurrentUser"): {
            "NewX_AVM-DE_CurrentUsername": "mcp",
            "NewX_AVM-DE_CurrentUserRights": RIGHTS_XML,
        },
        ("LANConfigSecurity1", "X_AVM-DE_GetAnonymousLogin"): {"NewX_AVM-DE_AnonymousLoginEnabled": "1"},
        ("LANConfigSecurity1", "GetInfo"): {"NewX_AVM-DE_IsDefaultPasswordActive": "0"},
        ("X_AVM-DE_Auth1", "GetInfo"): {"NewEnabled": "1"},
    }
    responses.update(overrides or {})
    return FakeFC(responses)


def test_parse_rights_xml() -> None:
    assert parse_rights_xml(RIGHTS_XML) == {
        "settings": "readwrite",
        "phone": "none",
        "nas": "readonly",
        "smarthome": "none",
    }
    assert parse_rights_xml("kaputt") == {}


def test_setup_check_reports_rights_and_affected_tools(landevices: LanDeviceClient) -> None:
    svc = make_service(landevices, _fc(), write=False, critical=False)
    svc._smarthome = SimpleNamespace(list_devices=lambda: [])  # type: ignore[assignment]
    r = SetupChecker(svc).check({"call_list", "list_landevices", "smarthome_overview", "nas_status"})
    by = {c["check"]: c for c in r["checks"]}
    assert by["tr064"]["status"] == "ok" and "7590" in by["tr064"]["detail"]
    assert by["rights"]["user"] == "mcp"
    assert by["anonymous_login"]["status"] == "warn"
    assert by["two_factor"]["status"] == "info" and "two_factor_status" in by["two_factor"]["detail"]
    assert by["api_v0"]["status"] == "ok"
    assert by["smarthome_rest"]["status"] == "unavailable"  # no REST routes in the fake → 404
    assert r["missing_rights"] == {
        "Sprachnachrichten, Faxnachrichten, FRITZ!App Fon und Anrufliste": ["call_list"],
        "Smart Home": ["smarthome_overview"],
    }
    assert any("FRITZ_ALLOW_WRITE" in h for h in r["hints"])
    assert r["ready"] is True


def test_setup_check_appsetup_fallback_and_tr064_down(landevices: LanDeviceClient) -> None:
    fc = _fc(
        {
            ("LANConfigSecurity1", "X_AVM-DE_GetCurrentUser"): FritzConnectionException("errorCode: 401"),
            ("X_AVM-DE_AppSetup1", "GetConfig"): {"NewConfigRight": "NO", "NewAppRight": "RW", "NewPhoneRight": "RO"},
            ("DeviceInfo1", "GetInfo"): FritzConnectionException("Unable to get a connection: timed out"),
        }
    )
    svc = make_service(landevices, fc)
    svc._smarthome = SimpleNamespace(list_devices=lambda: [])  # type: ignore[assignment]
    r = SetupChecker(svc).check({"call_list", "list_landevices", "set_internet_access"})
    by = {c["check"]: c for c in r["checks"]}
    assert by["tr064"]["status"] == "fail" and r["ready"] is False
    assert by["rights"]["source"] == "AppSetup:GetConfig"
    assert r["missing_rights"] == {"FRITZ!Box Einstellungen": ["list_landevices"]}


class FakeKeyring:
    def __init__(self, entries: dict[tuple[str, str], str]) -> None:
        self.entries = entries

    def get_password(self, service: str, account: str) -> str | None:
        return self.entries.get((service, account))


def test_keyring_password_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.undo()  # drop the autouse "no keychain" patch for this test only
    monkeypatch.setitem(
        sys.modules, "keyring", FakeKeyring({("fritzos8-mcp", "mcp@192.0.2.1"): "pw-box-a", ("x", "mcp"): "pw-x"})
    )
    assert config.keyring_password("mcp", "192.0.2.1") == "pw-box-a"
    assert config.keyring_password("mcp", "198.51.100.1", "x") == "pw-x"
    assert config.keyring_password("other", "192.0.2.1") == ""
    cfg = config.load({"FRITZ_USER": "mcp", "FRITZ_HOST": "192.0.2.1"})
    assert cfg.password == "pw-box-a"


def test_missing_password_mentions_keyring() -> None:
    with pytest.raises(ConfigError, match="keyring"):
        config.load({"FRITZ_USER": "mcp"})
