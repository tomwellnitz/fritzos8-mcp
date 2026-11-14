from __future__ import annotations

import httpx
import pytest

from fritzos8_mcp.auth import SessionManager
from fritzos8_mcp.errors import (
    AuthError,
    ConfirmationRequiredError,
    InvalidParameterError,
    NotFoundError,
    PermissionDeniedError,
    UnsupportedFirmwareError,
)
from fritzos8_mcp.landevice import LanDevice, LanDeviceClient
from fritzos8_mcp.rest import RestClient, looks_like_two_factor

from .conftest import BASE, CHALLENGE_XML, PASSWORD, SID, FakeBox, session_xml

LIST = f"{BASE}/api/v0/generic/landevice"


def _rest(respx_mock, sids: list[str] | None = None) -> RestClient:
    respx_mock.get(f"{BASE}/login_sid.lua?version=2").mock(return_value=httpx.Response(200, text=CHALLENGE_XML))
    responses = [httpx.Response(200, text=session_xml(s)) for s in (sids or [SID, SID])]
    respx_mock.post(f"{BASE}/login_sid.lua?version=2").mock(side_effect=responses)
    http = httpx.Client(base_url=BASE)
    return RestClient(http, SessionManager(http, "mcp", PASSWORD))


# ------------------------------------------------------------------ RestClient


def test_rest_sends_avm_sid_header(respx_mock) -> None:
    route = respx_mock.get(LIST).mock(return_value=httpx.Response(200, json={"landevice": []}))
    _rest(respx_mock).request("GET", "/api/v0/generic/landevice")
    assert route.calls[0].request.headers["AUTHORIZATION"] == f"AVM-SID {SID}"


def test_rest_relogin_once_on_invalid_sid(respx_mock) -> None:
    route = respx_mock.get(LIST).mock(
        side_effect=[httpx.Response(401, text='{"errors":["INVALID-SID"]}'), httpx.Response(200, json={"ok": 1})]
    )
    rest = _rest(respx_mock, [SID, "1111222233334444"])
    assert rest.request("GET", "/api/v0/generic/landevice") == {"ok": 1}
    assert route.calls[1].request.headers["AUTHORIZATION"] == "AVM-SID 1111222233334444"


def test_rest_relogin_once_on_http_400(respx_mock) -> None:
    # Live (FRITZ!OS 8.25): abgelaufene Sitzung -> HTTP 400 statt 401
    route = respx_mock.get(LIST).mock(
        side_effect=[httpx.Response(400, text="bad"), httpx.Response(200, json={"ok": 1})]
    )
    rest = _rest(respx_mock, [SID, "1111222233334444"])
    assert rest.request("GET", "/api/v0/generic/landevice") == {"ok": 1}
    assert route.calls[1].request.headers["AUTHORIZATION"] == "AVM-SID 1111222233334444"


def test_rest_400_twice_reports_body(respx_mock) -> None:
    from fritzos8_mcp.errors import FritzError

    respx_mock.get(LIST).mock(return_value=httpx.Response(400, text='{"errors":["BAD-REQUEST"]}'))
    with pytest.raises(FritzError) as ei:
        _rest(respx_mock).request("GET", "/api/v0/generic/landevice")
    assert "HTTP 400" in str(ei.value) and "BAD-REQUEST" in str(ei.value)


def test_rest_403_twice_is_permission_error(respx_mock) -> None:
    respx_mock.get(LIST).mock(return_value=httpx.Response(403, text="forbidden"))
    with pytest.raises(PermissionDeniedError) as ei:
        _rest(respx_mock).request("GET", "/api/v0/generic/landevice")
    assert "FRITZ!Box Einstellungen" in (ei.value.hint or "")


def test_rest_401_twice_is_auth_error(respx_mock) -> None:
    respx_mock.get(LIST).mock(return_value=httpx.Response(401, text=""))
    with pytest.raises(AuthError):
        _rest(respx_mock).request("GET", "/api/v0/generic/landevice")


@pytest.mark.parametrize(
    "status,body",
    [(403, '{"errors":["TWO-FACTOR"]}'), (200, '{"errors":[{"code":"TWO-FACTOR-AUTH-REQUIRED"}]}')],
)
def test_rest_two_factor_detected(respx_mock, status: int, body: str) -> None:
    respx_mock.put(f"{LIST}/landevice/landevice1").mock(return_value=httpx.Response(status, text=body))
    with pytest.raises(ConfirmationRequiredError) as ei:
        _rest(respx_mock).request("PUT", "/api/v0/generic/landevice/landevice/landevice1", {"x": "1"})
    assert "NICHTS geändert" in (ei.value.hint or "")


def test_two_factor_marker_helper() -> None:
    assert looks_like_two_factor("... two-factor ...")
    assert not looks_like_two_factor('{"landevice": []}')


def test_rest_404_mapping(respx_mock) -> None:
    respx_mock.get(LIST).mock(return_value=httpx.Response(404))
    rest = _rest(respx_mock)
    with pytest.raises(UnsupportedFirmwareError):
        rest.request("GET", "/api/v0/generic/landevice", missing="firmware")
    with pytest.raises(NotFoundError):
        rest.request("GET", "/api/v0/generic/landevice")


# ------------------------------------------------------------------ LanDeviceClient


def test_list_maps_fields(landevices: LanDeviceClient) -> None:
    devices = {d.uid: d for d in landevices.list()}
    pc = devices["landevice1001"]
    assert pc == LanDevice(
        uid="landevice1001",
        name="pc-buero",
        friendly_name="PC Büro",
        mac="AA:BB:CC:DD:EE:01",
        ip="192.0.2.20",
        static_dhcp=False,
        active=True,
        online=True,
        deleteable=True,
    )
    assert devices["landevice1002"].mac == "AA:BB:CC:DD:EE:02"
    assert devices["landevice1002"].static_dhcp is True
    assert devices["landevice1"].deleteable is False  # ownentry


def test_find_rejects_multiple_matches(landevices: LanDeviceClient) -> None:
    with pytest.raises(InvalidParameterError, match="mehrere"):
        landevices.find("aa:bb:cc:dd:ee:03")
    assert landevices.find("aa:bb:cc:dd:ee:03", uid="landevice2002").name == "dup-b"


def test_find_unknown(landevices: LanDeviceClient) -> None:
    with pytest.raises(NotFoundError):
        landevices.find("00:00:00:00:00:99")


def test_set_static_dhcp_writes_and_verifies(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    r = landevices.set_static_dhcp("AA:BB:CC:DD:EE:01", True)
    assert r["verified"] is True and r["changed"] is True and r["ip"] == "192.0.2.20"
    put = next(q for q in fake_box.requests if q.method == "PUT")
    assert put.url.path == "/api/v0/generic/landevice/landevice/landevice1001"
    assert put.content == b'{"static_dhcp": "1"}'


def test_set_static_dhcp_noop_when_already_set(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    r = landevices.set_static_dhcp("AA:BB:CC:DD:EE:02", True)
    assert r == r | {"changed": False, "verified": True}
    assert not [q for q in fake_box.requests if q.method == "PUT"]


def test_set_static_dhcp_silent_discard_is_confirmation_required(
    landevices: LanDeviceClient, fake_box: FakeBox
) -> None:
    fake_box.discard_writes = True
    with pytest.raises(ConfirmationRequiredError, match="still"):
        landevices.set_static_dhcp("AA:BB:CC:DD:EE:01", True)


def test_set_friendly_name_verified(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    r = landevices.set_friendly_name("aabbccddee01", "  Arbeits-PC ")
    assert r["verified"] is True and r["friendly_name"] == "Arbeits-PC"
    assert fake_box._find("landevice1001")["friendly_name"] == "Arbeits-PC"


def test_set_friendly_name_validates(landevices: LanDeviceClient) -> None:
    with pytest.raises(InvalidParameterError):
        landevices.set_friendly_name("aabbccddee01", "x" * 64)


def test_delete_verifies_gone(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    dev = landevices.find("AA:BB:CC:DD:EE:02")
    r = landevices.delete(dev)
    assert r["verified"] is True
    assert fake_box._find("landevice1002") is None


def test_delete_silently_discarded(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    fake_box.discard_writes = True
    r = landevices.delete(landevices.find("AA:BB:CC:DD:EE:02"))
    assert r["verified"] is False and "note" in r
