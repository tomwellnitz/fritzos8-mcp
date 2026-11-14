"""Stage 10.6b – Smart-Home configuration, pairing and TR-064 fallback (fakes after the AVM OpenAPI 8.5, invented
values)."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fritzconnection.core.exceptions import FritzActionError

from fritzos8_mcp.errors import InvalidParameterError, PlanError, TierDisabledError
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.smarthome_config import Period, holiday_body, minutes_to_date, summer_body

from .conftest import FakeBox, FakeFC, make_service

BASE = "/api/v0/smarthome"


class ConfigFake:
    def __init__(self) -> None:
        self.units: dict[str, dict[str, Any]] = {
            "unit-thermo": {
                "UID": "unit-thermo",
                "name": "Heizung Bad",
                "interfaces": {
                    "thermostatInterface": {
                        "comfortTemperature": {"mode": "temperature", "celsius": 21.0},
                        "reducedTemperature": {"mode": "temperature", "celsius": 17.0},
                        "holidayPeriods": {"temperature": {"mode": "temperature", "celsius": 16}, "periods": []},
                        "summerPeriod": {"enabled": False},
                        "isHolidayActive": False,
                    }
                },
            },
            "unit-plug": {"UID": "unit-plug", "name": "Lampe", "interfaces": {"onOffInterface": {"active": True}}},
        }
        self.groups = {"grp-1": {"UID": "grp-1", "name": "Wohnzimmer"}}
        self.bases = [
            {"serial": "base-1", "isZigbeeAvailable": True, "isDectAvailable": True, "isSmarthomeMaster": True,
             "activeSubscriptionUid": ""}
        ]  # fmt: skip
        self.subscriptions: dict[str, dict[str, Any]] = {}
        self.writes: list[tuple[str, str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response | None:
        path = request.url.path
        if not path.startswith(BASE):
            return None
        sub = path.removeprefix(BASE)
        body = json.loads(request.content) if request.content else None
        if request.method != "GET":
            self.writes.append((request.method, sub, body))
        if sub == "/overview/globals":
            return httpx.Response(200, json={})
        if sub.startswith("/configuration/units/"):
            uid = sub.rsplit("/", 1)[-1]
            unit = self.units.get(uid)
            if unit is None:
                return httpx.Response(404, text="not found")
            if request.method == "PUT":
                if "name" in body:
                    unit["name"] = body["name"]
                for k, v in (body.get("interfaces") or {}).get("thermostatInterface", {}).items():
                    unit["interfaces"]["thermostatInterface"][k] = v
                return httpx.Response(200, text="")
            return httpx.Response(200, json=unit)
        if sub.startswith("/configuration/groups/"):
            uid = sub.rsplit("/", 1)[-1]
            if uid not in self.groups:
                return httpx.Response(404, text="not found")
            if request.method == "DELETE":
                del self.groups[uid]
                return httpx.Response(200, text="")
            return httpx.Response(200, json=self.groups[uid])
        if sub == "/connect/radioBases":
            return httpx.Response(200, json=self.bases)
        if sub.startswith("/connect/startSubscription/"):
            self.bases[0]["activeSubscriptionUid"] = "sub-9"
            self.subscriptions["sub-9"] = {"UID": "sub-9", "state": "dectPending", "time": 1800000000}
            return httpx.Response(200, json={"subscriptionUid": "sub-9"})
        if sub.startswith("/connect/stopSubscription/"):
            self.bases[0]["activeSubscriptionUid"] = ""
            return httpx.Response(200, text="")
        if sub.startswith("/connect/subscriptionState/"):
            s = self.subscriptions.get(sub.rsplit("/", 1)[-1])
            return httpx.Response(200, json=s) if s else httpx.Response(404, text="nf")
        return httpx.Response(404, text="not found")


@pytest.fixture
def cfg(landevices: LanDeviceClient, fake_box: FakeBox) -> tuple[Any, ConfigFake]:
    fake = ConfigFake()
    fake_box.extra_handler = fake
    return make_service(landevices, FakeFC()).smarthome_config, fake


# ------------------------------------------------------------------ date helpers


def test_holiday_minutes_leap_year_and_validation() -> None:
    body = holiday_body([Period(start="01.03.", end="2026-03-07", start_hour=12)], 16)
    # 1 March is day 60 (0-based) in a leap year: 60 * 1440 + 12 h
    assert body["periods"] == [{"startTime": 60 * 1440 + 720, "endTime": 66 * 1440}]
    assert body["temperature"] == {"mode": "temperature", "celsius": 16}
    assert minutes_to_date(60 * 1440 + 720) == "01.03. 12:00"
    assert minutes_to_date(66 * 1440) == "07.03."
    with pytest.raises(InvalidParameterError, match="überschneiden"):
        holiday_body([Period(start="01.03.", end="10.03."), Period(start="05.03.", end="12.03.")], None)
    with pytest.raises(InvalidParameterError):
        holiday_body([Period(start="31.02.", end="01.03.")], None)
    with pytest.raises(InvalidParameterError):
        holiday_body([], 16.3)
    # over new year is allowed
    assert holiday_body([Period(start="27.12.", end="02.01.")], None)["periods"][0]["endTime"] == 1440
    assert summer_body(True, "01.06.", "31.08.") == {"enabled": True, "startTime": 152 * 1440, "endTime": 243 * 1440}
    assert summer_body(False, None, None) == {"enabled": False}


# ------------------------------------------------------------------ holidays / summer


def test_thermostat_config_read(cfg: tuple[Any, ConfigFake]) -> None:
    sh, _ = cfg
    r = sh.thermostat_config("unit-thermo")
    assert r["comfort"] == 21.0 and r["holiday"]["temperature_c"] == 16 and r["summer"]["enabled"] is False
    with pytest.raises(InvalidParameterError, match="kein Thermostat"):
        sh.thermostat_config("unit-plug")


def test_holidays_plan_execute_read_back(cfg: tuple[Any, ConfigFake]) -> None:
    sh, fake = cfg
    periods = [Period(start="23.12.", end="02.01.", start_hour=8)]
    plan = sh.holidays_plan("unit-thermo", periods, 15.5)
    assert "Ersetzt ALLE" in plan["warnings"][0]
    assert plan["after"]["periods"] == ["23.12. 08:00 – 02.01."]
    r = sh.holidays_execute(plan["token"], "unit-thermo", periods, 15.5)
    assert r["verified"] is True and r["holiday"]["temperature_c"] == 15.5
    method, path, body = fake.writes[-1]
    assert (method, path) == ("PUT", "/configuration/units/unit-thermo")
    assert set(body["interfaces"]["thermostatInterface"]) == {"holidayPeriods"}


def test_holidays_token_bound_to_periods(cfg: tuple[Any, ConfigFake]) -> None:
    sh, fake = cfg
    plan = sh.holidays_plan("unit-thermo", [Period(start="01.08.", end="14.08.")], None)
    with pytest.raises(PlanError):
        sh.holidays_execute(plan["token"], "unit-thermo", [Period(start="01.08.", end="21.08.")], None)
    assert fake.writes == []


def test_summer_period(cfg: tuple[Any, ConfigFake]) -> None:
    sh, _ = cfg
    plan = sh.summer_plan("unit-thermo", True, "01.06.", "31.08.")
    assert plan["warnings"]
    r = sh.summer_execute(plan["token"], "unit-thermo", True, "01.06.", "31.08.")
    assert r["verified"] is True and r["summer"]["startTime"] == 152 * 1440


def test_config_writes_need_critical(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    fake_box.extra_handler = ConfigFake()
    sh = make_service(landevices, FakeFC(), critical=False).smarthome_config
    with pytest.raises(TierDisabledError):
        sh.holidays_plan("unit-thermo", [], None)


# ------------------------------------------------------------------ delete / rename


def test_delete_group(cfg: tuple[Any, ConfigFake]) -> None:
    sh, fake = cfg
    plan = sh.delete_plan("group", "grp-1")
    assert plan["name"] == "Wohnzimmer" and "Gruppe" in plan["consequence"]
    r = sh.delete_execute(plan["token"], "group", "grp-1")
    assert r == {"kind": "group", "uid": "grp-1", "deleted": True, "verified": True}
    assert fake.groups == {}


def test_rename_unit_rest(cfg: tuple[Any, ConfigFake]) -> None:
    sh, fake = cfg
    plan = sh.rename_plan("unit-plug", "Stehlampe")
    assert plan["before"] == "Lampe" and plan["via"] == "rest"
    r = sh.rename_execute(plan["token"], "unit-plug", "Stehlampe")
    assert r["verified"] is True and fake.units["unit-plug"]["name"] == "Stehlampe"
    with pytest.raises(InvalidParameterError):
        sh.rename_plan("unit-plug", "x" * 40)


def test_rename_falls_back_to_tr064(landevices: LanDeviceClient) -> None:
    names = {"11630 0000002": "Lampe"}
    fc = FakeFC(
        {
            ("X_AVM-DE_Homeauto1", "GetSpecificDeviceInfos"): lambda NewAIN: {"NewDeviceName": names[NewAIN]},
            ("X_AVM-DE_Homeauto1", "SetDeviceName"): lambda NewAIN, NewDeviceName: (
                names.update({NewAIN: NewDeviceName}) or {}
            ),
        }
    )
    sh = make_service(landevices, fc).smarthome_config  # no REST routes → 404 → TR-064
    plan = sh.rename_plan("11630 0000002", "Stehlampe")
    assert plan["via"] == "tr064"
    assert sh.rename_execute(plan["token"], "11630 0000002", "Stehlampe")["verified"] is True


# ------------------------------------------------------------------ pairing


def test_pairing_rest_flow(cfg: tuple[Any, ConfigFake]) -> None:
    sh, fake = cfg
    plan = sh.pairing_plan(None, True, True)
    assert plan["radio_base"]["serial"] == "base-1"
    assert any("JEDES Gerät" in w for w in plan["warnings"])
    r = sh.pairing_execute(plan["token"], None, True, True)
    assert r["verified"] is True and r["subscription_uid"] == "sub-9"
    assert fake.writes[-1] == (
        "POST",
        "/connect/startSubscription/base-1",
        {"triggerDect": True, "triggerZigbee": True},
    )
    st = sh.pairing_status("sub-9")
    assert st["state"] == "dectPending" and "Anmeldetaste" in st["meaning"]
    assert sh.pairing_stop(None) == {"serial": "base-1", "stopped": True, "verified": True}


def test_pairing_aha_fallback(landevices: LanDeviceClient) -> None:
    sent: list[str] = []

    def command(cmd: str, ain: Any = None, **extra: Any) -> str:
        sent.append(cmd)
        return '<state code="1"><latestain></latestain></state>'

    svc = make_service(landevices, FakeFC())
    svc._smarthome = SimpleNamespace(command=command)  # type: ignore[assignment]
    sh = svc.smarthome_config
    with pytest.raises(Exception, match="Zigbee"):
        sh.pairing_plan(None, False, True)
    plan = sh.pairing_plan(None, True, False)
    assert plan["via"] == "aha"
    r = sh.pairing_execute(plan["token"], None, True, False)
    assert r["verified"] is True and sent == ["startulesubscription", "getsubscriptionstate"]


# ------------------------------------------------------------------ TR-064 Homeauto


def test_tr064_devices_and_switch(landevices: LanDeviceClient) -> None:
    state = {"v": "OFF"}
    dev = {
        "NewAIN": "11630 0000002",
        "NewDeviceName": "Waschmaschine",
        "NewProductName": "FRITZ!Smart Energy 200",
        "NewPresent": "CONNECTED",
        "NewSwitchIsEnabled": "ENABLED",
        "NewMultimeterIsEnabled": "ENABLED",
        "NewMultimeterPower": 12345,
        "NewMultimeterEnergy": 4321,
        "NewTemperatureIsEnabled": "ENABLED",
        "NewTemperatureCelsius": 215,
        "NewHkrIsEnabled": "DISABLED",
    }

    def generic(NewIndex: int) -> dict[str, Any]:
        if NewIndex > 0:
            raise FritzActionError("errorCode: 713 Invalid array index")
        return {**dev, "NewSwitchState": state["v"]}

    fc = FakeFC(
        {
            ("X_AVM-DE_Homeauto1", "GetGenericDeviceInfos"): generic,
            ("X_AVM-DE_Homeauto1", "GetSpecificDeviceInfos"): lambda NewAIN: {**dev, "NewSwitchState": state["v"]},
            ("X_AVM-DE_Homeauto1", "SetSwitch"): lambda NewAIN, NewSwitchState: state.update(v=NewSwitchState) or {},
        }
    )
    sh = make_service(landevices, fc).smarthome_config
    r = sh.tr064_devices()
    assert r["count"] == 1
    d = r["devices"][0]
    assert d["power_w"] == 123.45 and d["energy_wh"] == 4321 and d["temperature_c"] == 21.5
    assert "thermostat" not in d
    w = sh.tr064_set_switch("11630 0000002", True)
    assert w["verified"] is True and state["v"] == "ON"
    assert sh.tr064_set_switch("11630 0000002", True)["changed"] is False


def test_pairing_never_outputs_codes(cfg: tuple[Any, ConfigFake]) -> None:
    sh, fake = cfg
    fake.bases[0]["installCode"] = "ABCD-1234-EFGH"
    fake.bases[0]["resetCode"] = "9999"
    out = json.dumps(sh.pairing_status(None))
    assert "ABCD-1234" not in out and "9999" not in out
