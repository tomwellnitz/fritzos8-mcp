from __future__ import annotations

from typing import Any

import httpx
import pytest

from fritzos8_mcp.auth import SessionManager
from fritzos8_mcp.errors import InvalidParameterError, NotFoundError, PermissionDeniedError, TierDisabledError
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.security import Gate, PlanStore
from fritzos8_mcp.service import FritzService
from fritzos8_mcp.smarthome import (
    AhaClient,
    decode_tsoll,
    encode_target,
    normalize_ain,
    parse_device_list,
    parse_stats,
)
from fritzos8_mcp.tr064 import Tr064Client

from .conftest import BASE, CHALLENGE_XML, PASSWORD, SID, FakeFC, session_xml

AHA = f"{BASE}/webservices/homeautoswitch.lua"

DEVICE_XML = """<devicelist version="1" fwversion="8.26">
<device identifier="08761 0000434" id="17" functionbitmask="35712" fwversion="04.25"
        manufacturer="AVM" productname="FRITZ!DECT 200">
  <present>1</present><txbusy>0</txbusy><name>Kaffeemaschine</name>
  <switch><state>0</state><mode>manuell</mode><lock>0</lock><devicelock>0</devicelock></switch>
  <powermeter><voltage>230051</voltage><power>1500</power><energy>707</energy></powermeter>
  <temperature><celsius>215</celsius><offset>-5</offset></temperature>
</device>
<device identifier="11960 0089208" id="20" functionbitmask="320" fwversion="05.16"
        manufacturer="AVM" productname="FRITZ!DECT 301">
  <present>1</present><txbusy>0</txbusy><name>Heizung Bad</name>
  <temperature><celsius>205</celsius><offset>0</offset></temperature>
  <hkr><tist>41</tist><tsoll>42</tsoll><absenk>32</absenk><komfort>44</komfort>
    <battery>80</battery><batterylow>0</batterylow><windowopenactiv>0</windowopenactiv><errorcode>0</errorcode></hkr>
</device>
<group identifier="grp303E4F-3F7E1E4D4" id="900" functionbitmask="512">
  <present>1</present><name>Alle Steckdosen</name><switch><state>0</state></switch>
</group>
</devicelist>"""

STATS_XML = """<devicestats>
<temperature><stats count="3" grid="900" datatime="1700000000">215,-,210</stats></temperature>
<power><stats count="2" grid="10">150000,0</stats></power>
<energy><stats count="2" grid="86400">120,95</stats></energy>
</devicestats>"""


class FakeAha:
    def __init__(self, xml: str = DEVICE_XML) -> None:
        self.xml = xml
        self.switch = {"087610000434": "0"}
        self.tsoll = {"119600089208": "42"}
        self.discard = False
        self.calls: list[dict[str, str]] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        q = dict(request.url.params)
        self.calls.append(q)
        if q.get("sid") != SID:
            return httpx.Response(403, text="")
        cmd = q.get("switchcmd")
        ain = (q.get("ain") or "").replace(" ", "")
        if cmd == "getdevicelistinfos":
            return httpx.Response(200, text=self.xml)
        if cmd == "getbasicdevicestats":
            return httpx.Response(200, text=STATS_XML)
        if cmd in ("setswitchon", "setswitchoff") and ain in self.switch:
            if not self.discard:
                self.switch[ain] = "1" if cmd == "setswitchon" else "0"
            return httpx.Response(200, text=self.switch[ain] + "\n")
        if cmd == "getswitchstate" and ain in self.switch:
            return httpx.Response(200, text=self.switch[ain] + "\n")
        if cmd == "sethkrtsoll" and ain in self.tsoll:
            if not self.discard:
                self.tsoll[ain] = q["param"]
            return httpx.Response(200, text="")
        if cmd == "gethkrtsoll" and ain in self.tsoll:
            return httpx.Response(200, text=self.tsoll[ain] + "\n")
        return httpx.Response(400, text="bad request")

    def writes(self) -> list[dict[str, str]]:
        return [c for c in self.calls if c.get("switchcmd", "").startswith("set")]


@pytest.fixture
def aha(respx_mock: Any) -> FakeAha:
    fake = FakeAha()
    respx_mock.get(f"{BASE}/login_sid.lua?version=2").mock(return_value=httpx.Response(200, text=CHALLENGE_XML))
    respx_mock.post(f"{BASE}/login_sid.lua?version=2").mock(return_value=httpx.Response(200, text=session_xml()))
    respx_mock.get(AHA).mock(side_effect=fake.handle)
    return fake


def service(write: bool = True) -> FritzService:
    http = httpx.Client(base_url=BASE)
    return FritzService(
        Tr064Client(lambda: FakeFC(), (PASSWORD,)),  # type: ignore[arg-type,return-value]
        LanDeviceClient(None),  # type: ignore[arg-type]
        Gate(write, False),
        PlanStore(),
        smarthome=AhaClient(http, SessionManager(http, "mcp", PASSWORD)),
    )


# ------------------------------------------------------------------ parsing / encoding


def test_parse_device_list() -> None:
    devices = {d["ain"]: d for d in parse_device_list(DEVICE_XML)}
    plug = devices["08761 0000434"]
    assert plug["type"] == "switch" and plug["product"] == "FRITZ!DECT 200"
    assert plug["switch"]["on"] is False
    assert plug["power"] == {"power_w": 1.5, "energy_wh": 707, "voltage_v": 230.051}
    assert plug["temperature_c"] == 21.5
    hkr = devices["11960 0089208"]
    assert hkr["type"] == "thermostat"
    assert hkr["thermostat"]["current_c"] == 20.5
    assert hkr["thermostat"]["target"] == {"raw": 42, "mode": "temp", "celsius": 21.0}
    assert hkr["thermostat"]["battery_pct"] == 80
    assert devices["grp303E4F-3F7E1E4D4"]["kind"] == "group"


@pytest.mark.parametrize("xml", ["", '<devicelist version="1"></devicelist>'])
def test_parse_empty_device_list(xml: str) -> None:
    assert parse_device_list(xml) == []


def test_parse_stats_scales_units() -> None:
    s = parse_stats(STATS_XML)
    assert s["temperature"]["unit"] == "°C"
    assert s["temperature"]["series"][0]["values"] == [21.5, None, 21.0]
    assert s["power"]["series"][0]["values"] == [1500.0, 0.0]
    assert s["energy"]["series"][0] == {"grid_s": 86400, "count": 2, "datatime": None, "values": [120.0, 95.0]}


@pytest.mark.parametrize(
    "target,mode,param",
    [(8.0, None, 16), (21.5, None, 43), (28.0, None, 56), (None, "off", 253), (None, "max", 254)],
)
def test_encode_target(target: float | None, mode: str | None, param: int) -> None:
    assert encode_target(target, mode) == param


@pytest.mark.parametrize("target,mode", [(7.5, None), (28.5, None), (None, None), (20.0, "off"), (None, "eco")])
def test_encode_target_rejects(target: float | None, mode: str | None) -> None:
    with pytest.raises(InvalidParameterError):
        encode_target(target, mode)


def test_decode_tsoll_special_values() -> None:
    assert decode_tsoll("253")["mode"] == "off"
    assert decode_tsoll("254")["mode"] == "max"
    assert decode_tsoll("inval")["mode"] == "unknown"


@pytest.mark.parametrize("ain", ["", "x" * 50, "08761&sid=1", "087 61/0"])
def test_normalize_ain_rejects(ain: str) -> None:
    with pytest.raises(InvalidParameterError):
        normalize_ain(ain)


# ------------------------------------------------------------------ client / service


def test_list_devices_sends_sid_as_query(aha: FakeAha) -> None:
    r = service().smarthome_list_devices()
    assert r["count"] == 3
    assert aha.calls[0] == {"switchcmd": "getdevicelistinfos", "sid": SID}


def test_list_devices_empty_is_fine(aha: FakeAha) -> None:
    aha.xml = '<devicelist version="1" fwversion="8.26"></devicelist>'
    r = service().smarthome_list_devices()
    assert r["count"] == 0 and r["devices"] == [] and "Keine" in r["note"]


def test_device_stats(aha: FakeAha) -> None:
    r = service().smarthome_device_stats("087610000434")  # without space is accepted
    assert r["ain"] == "08761 0000434" and r["name"] == "Kaffeemaschine"
    assert "temperature" in r["stats"]


def test_unknown_ain(aha: FakeAha) -> None:
    with pytest.raises(NotFoundError):
        service().smarthome_device_stats("99999 9999999")


def test_permission_denied_after_relogin(respx_mock: Any) -> None:
    respx_mock.get(f"{BASE}/login_sid.lua?version=2").mock(return_value=httpx.Response(200, text=CHALLENGE_XML))
    respx_mock.post(f"{BASE}/login_sid.lua?version=2").mock(return_value=httpx.Response(200, text=session_xml()))
    respx_mock.get(AHA).mock(return_value=httpx.Response(403, text=""))
    with pytest.raises(PermissionDeniedError) as ei:
        service().smarthome_list_devices()
    assert "Smart Home" in (ei.value.hint or "")


def test_set_switch_needs_write(aha: FakeAha) -> None:
    with pytest.raises(TierDisabledError):
        service(write=False).smarthome_set_switch("08761 0000434", True)
    assert aha.calls == []


def test_set_switch_verified(aha: FakeAha) -> None:
    r = service().smarthome_set_switch("08761 0000434", True)
    assert r["verified"] is True and r["changed"] is True
    assert aha.switch["087610000434"] == "1"


def test_set_switch_unchanged(aha: FakeAha) -> None:
    r = service().smarthome_set_switch("08761 0000434", False)
    assert r["changed"] is False and aha.writes() == []


def test_set_switch_discarded(aha: FakeAha) -> None:
    aha.discard = True
    r = service().smarthome_set_switch("08761 0000434", True)
    assert r["verified"] is False and r["read_back"] is False


def test_set_switch_rejects_thermostat(aha: FakeAha) -> None:
    with pytest.raises(InvalidParameterError, match="keine schaltbare"):
        service().smarthome_set_switch("11960 0089208", True)
    assert aha.writes() == []


def test_set_thermostat_verified(aha: FakeAha) -> None:
    r = service().smarthome_set_thermostat("11960 0089208", 22.5)
    assert r["verified"] is True and r["target"]["celsius"] == 22.5
    assert aha.tsoll["119600089208"] == "45"


def test_set_thermostat_off(aha: FakeAha) -> None:
    r = service().smarthome_set_thermostat("11960 0089208", mode="off")
    assert r["verified"] is True and aha.tsoll["119600089208"] == "253"


def test_set_thermostat_validates_before_any_request(aha: FakeAha) -> None:
    with pytest.raises(InvalidParameterError):
        service().smarthome_set_thermostat("11960 0089208", 35.0)
    assert aha.calls == []


def test_set_thermostat_rejects_switch(aha: FakeAha) -> None:
    with pytest.raises(InvalidParameterError, match="kein Heizkörperthermostat"):
        service().smarthome_set_thermostat("08761 0000434", 20.0)
    assert aha.writes() == []


def test_set_thermostat_discarded(aha: FakeAha) -> None:
    aha.discard = True
    r = service().smarthome_set_thermostat("11960 0089208", 22.5)
    assert r["verified"] is False and r["read_back"]["celsius"] == 21.0


def test_aha_relogin_once_on_http_400(respx_mock: Any) -> None:
    """Same as RestClient (live FRITZ!OS 8.25): an expired session may answer 400 – one fresh login first."""
    from fritzos8_mcp.smarthome import AhaClient

    respx_mock.get(f"{BASE}/login_sid.lua?version=2").mock(return_value=httpx.Response(200, text=CHALLENGE_XML))
    login = respx_mock.post(f"{BASE}/login_sid.lua?version=2").mock(
        side_effect=[httpx.Response(200, text=session_xml()), httpx.Response(200, text=session_xml("1111222233334444"))]
    )
    route = respx_mock.get(AHA).mock(
        side_effect=[httpx.Response(400, text=""), httpx.Response(200, text="<devicelist/>")]
    )
    http = httpx.Client(base_url=BASE)
    assert AhaClient(http, SessionManager(http, "mcp", PASSWORD)).command("getdevicelistinfos") == "<devicelist/>"
    assert login.call_count == 2 and route.calls[1].request.url.params["sid"] == "1111222233334444"


def test_aha_400_twice_is_invalid_parameter(respx_mock: Any) -> None:
    from fritzos8_mcp.smarthome import AhaClient

    respx_mock.get(f"{BASE}/login_sid.lua?version=2").mock(return_value=httpx.Response(200, text=CHALLENGE_XML))
    respx_mock.post(f"{BASE}/login_sid.lua?version=2").mock(return_value=httpx.Response(200, text=session_xml()))
    route = respx_mock.get(AHA).mock(return_value=httpx.Response(400, text="bad request"))
    http = httpx.Client(base_url=BASE)
    with pytest.raises(InvalidParameterError):
        AhaClient(http, SessionManager(http, "mcp", PASSWORD)).command("getswitchstate", "087610000434")
    assert route.call_count == 2
