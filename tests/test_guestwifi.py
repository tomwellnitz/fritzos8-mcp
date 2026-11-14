"""Stage 8.4 – guest WLAN session with time limit, QR code (secrets tier) and WPS button."""

from __future__ import annotations

import stat
from pathlib import Path
from typing import Any

import pytest

from fritzos8_mcp.errors import InvalidParameterError, TierDisabledError
from fritzos8_mcp.guestwifi import wifi_qr_payload
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.security import Gate

from .conftest import FakeFC, make_service
from .test_wlan import KEY, Radios, wlan_fc


class Clock:
    def __init__(self) -> None:
        self.t = 1_800_000_000.0

    def __call__(self) -> float:
        return self.t


def setup(
    landevices: LanDeviceClient, secrets: bool = False, wps_status: str = "inactive"
) -> tuple[Any, Radios, FakeFC, Clock]:
    radios = Radios()
    fc = wlan_fc(radios)
    wps = {"status": wps_status}

    def set_wps(**kw: Any) -> dict[str, Any]:
        wps["status"] = "active" if kw["NewX_AVM-DE_WPSMode"] == "pbc" else "inactive"
        return {"NewX_AVM-DE_WPSStatus": wps["status"]}

    for i in (1, 3):
        fc.responses[(f"WLANConfiguration{i}", "X_AVM-DE_GetWPSInfo")] = lambda: {
            "NewX_AVM-DE_WPSMode": "pbc",
            "NewX_AVM-DE_WPSStatus": wps["status"],
        }
        fc.responses[(f"WLANConfiguration{i}", "X_AVM-DE_SetWPSConfig")] = set_wps
    fc.responses[("WLANConfiguration3", "GetSecurityKeys")] = {"NewKeyPassphrase": KEY, "NewPreSharedKey": "x" * 64}
    svc = make_service(landevices, fc)
    svc.gate = Gate(True, True, allow_secrets=secrets)
    clock = Clock()
    svc.guest.now = clock
    svc.guest._start_timer = False
    return svc, radios, fc, clock


def test_session_start_and_expiry(landevices: LanDeviceClient) -> None:
    svc, radios, _, clock = setup(landevices)
    r = svc.guest.session_start(60)
    assert r["verified"] is True and radios.state[3]["NewEnable"] is True
    assert r["session"]["minutes"] == 60 and "Web-UI" in r["warning"] and r["box_timeout"]["active"] is True
    status = svc.guest.session_status()
    assert status["session"]["remaining_s"] == 3600
    assert svc.guest.enforce_expiry() is None  # not yet
    clock.t += 3601
    assert svc.guest.enforce_expiry()["verified"] is True
    assert radios.state[3]["NewEnable"] is False and svc.guest.session_status()["session"] is None


def test_session_validation_and_stop(landevices: LanDeviceClient) -> None:
    svc, radios, _, _ = setup(landevices)
    with pytest.raises(InvalidParameterError):
        svc.guest.session_start(5)
    svc.guest.session_start(15)
    r = svc.guest.session_stop()
    assert r["verified"] is True and radios.state[3]["NewEnable"] is False


def test_session_not_started_when_unverified(landevices: LanDeviceClient) -> None:
    svc, radios, _, _ = setup(landevices)
    radios.discard = True
    r = svc.guest.session_start(30)
    assert r["verified"] is False and r["session"] is None


def test_qr_needs_secrets_tier(landevices: LanDeviceClient) -> None:
    svc, *_ = setup(landevices, secrets=False)
    with pytest.raises(TierDisabledError):
        svc.guest.qr_code()


def test_qr_file_contains_key_only_in_image(landevices: LanDeviceClient) -> None:
    pytest.importorskip("segno")
    svc, *_ = setup(landevices, secrets=True)
    r = svc.guest.qr_code()
    assert KEY not in str(r) and r["key_in_output"] is False and r["ssid"] == "Gast"
    path = Path(r["qr_file"])
    content = path.read_bytes()
    assert content.startswith(b"<?xml") and KEY.encode() not in content
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_qr_payload_escaping() -> None:
    assert wifi_qr_payload('Gast;"1"', r"a:b\c") == r"WIFI:T:WPA;S:Gast\;\"1\";P:a\:b\\c;;"


def test_wps_start_stop(landevices: LanDeviceClient) -> None:
    svc, _, fc, _ = setup(landevices)
    r = svc.guest.wps("start")
    assert r["verified"] is True and r["status"] == "active" and "2 Minuten" in r["warning"]
    assert ("WLANConfiguration1", "X_AVM-DE_SetWPSConfig", {"NewX_AVM-DE_WPSMode": "pbc"}) in fc.calls
    assert svc.guest.wps("stop")["verified"] is True
    r = svc.guest.wps("start", guest=True)
    assert r["service"] == "WLANConfiguration3"


def test_wps_refused_when_disabled_in_box(landevices: LanDeviceClient) -> None:
    svc, _, fc, _ = setup(landevices, wps_status="off")
    with pytest.raises(InvalidParameterError) as ei:
        svc.guest.wps("start")
    assert "nicht dauerhaft" in str(ei.value)
    assert not any(c[1] == "X_AVM-DE_SetWPSConfig" for c in fc.calls)


def test_wps_needs_write(landevices: LanDeviceClient) -> None:
    svc = make_service(landevices, FakeFC(), write=False, critical=False)
    with pytest.raises(TierDisabledError):
        svc.guest.wps("start")


async def test_qr_tool_registered_only_with_secrets() -> None:
    from unittest.mock import MagicMock

    from fritzos8_mcp.server import build_server

    names = {t.name for t in await build_server(MagicMock(), Gate(True, True)).list_tools()}
    assert "guest_wifi_qr" not in names
    names = {t.name for t in await build_server(MagicMock(), Gate(False, False, allow_secrets=True)).list_tools()}
    assert "guest_wifi_qr" in names
