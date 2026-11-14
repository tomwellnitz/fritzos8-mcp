"""Stage 8.5a – Smart-Home-REST read (fixtures shaped after the AVM OpenAPI 8.2/8.5, invented values)."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from fritzos8_mcp.errors import InvalidParameterError, NotFoundError, UnsupportedFirmwareError
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.redact import MASK, redact_api

from .conftest import FakeBox, FakeFC, make_service

OVERVIEW: dict[str, Any] = {
    "devices": [
        {
            "UID": "dev-thermo",
            "ain": "09995 0000001",
            "name": "Heizung Bad",
            "productName": "FRITZ!Smart Thermo 301",
            "productCategory": "thermostat",
            "isConnected": True,
            "firmwareVersion": "05.10",
            "isUpdateAvailable": False,
            "batteryValue": 15,
            "isBatteryLow": True,
            "unitUids": ["unit-thermo"],
            "pushMail": {"enabled": True, "recipient": "person@example.org"},
        },
        {
            "UID": "dev-plug",
            "ain": "11630 0000002",
            "name": "Waschmaschine",
            "productName": "FRITZ!Smart Energy 200",
            "isConnected": True,
            "isUpdateAvailable": True,
            "unitUids": ["unit-plug"],
        },
    ],
    "units": [
        {
            "UID": "unit-thermo",
            "name": {"name": "Heizung Bad"},
            "unitType": "avmThermostat",
            "isConnected": True,
            "deviceUid": "dev-thermo",
            "interfaces": {
                "thermostatInterface": {
                    "state": "valid",
                    "thermostatState": "noError",
                    "setPointTemperature": {"mode": "temperature", "celsius": 21.0},
                    "comfortTemperature": {"mode": "temperature", "celsius": 21.0},
                    "reducedTemperature": {"mode": "temperature", "celsius": 17.0},
                    "windowOpenMode": {"enabled": True, "endTime": 1800000600},
                    "boost": {"enabled": False, "endTime": None},
                    "isHolidayActive": False,
                    "isSummertimeActive": False,
                    "nextChange": {
                        "changeTime": 1800003600,
                        "temperatureChange": {"mode": "temperature", "celsius": 17.0},
                    },
                },
                "temperatureInterface": {"state": "valid", "celsius": 19.5},
            },
        },
        {
            "UID": "unit-plug",
            "name": {"name": "Waschmaschine"},
            "unitType": "avmPlugSocket",
            "deviceUid": "dev-plug",
            "interfaces": {
                "onOffInterface": {"state": "valid", "active": True},
                "multimeterInterface": {
                    "state": "valid",
                    "power": 2150000,
                    "voltage": 230100,
                    "current": 9350,
                    "energy": 12345,
                },
            },
        },
    ],
    "groups": [
        {"UID": "grp-1", "name": "Erdgeschoss", "groupCategory": "thermostat", "memberUnitUids": ["unit-thermo"]}
    ],
    "templates": [
        {"UID": "tmpl-1", "name": "Alles aus", "applyType": "oneShot"},
        {
            "UID": "tmpl-2",
            "name": "Webhook",
            "applyType": "oneShot",
            "httpRequest": {"method": "GET", "url": "https://user:pw@example.org/hook?token=abc", "header": "X-Key: 1"},
        },
    ],
    "triggers": [{"UID": "trg-1", "name": "Abends", "enabled": True}],
    "globals": {
        "location": {"latitude": 52.5, "longitude": 13.4},
        "energyKeyFigures": {"electricityRate": 32.5, "co2emmissions": 400},
    },
}


@pytest.fixture
def svc(landevices: LanDeviceClient, fake_box: FakeBox) -> Any:
    fake_box.generic["/api/v0/smarthome/overview"] = copy.deepcopy(OVERVIEW)
    unit = copy.deepcopy(OVERVIEW["units"][0])
    unit["timer"] = {"timerMode": "weekly", "weekly": [{"start": "06:00", "temperature": "comfort"}]}
    unit["statistics"] = {
        "temperatures": [{"statisticsState": "valid", "period": "day", "interval": 900, "values": [19.5, 20.0, None]}]
    }
    fake_box.generic["/api/v0/smarthome/overview/units/unit-thermo"] = unit
    return make_service(landevices, FakeFC())


def test_redaction_of_location_recipient_and_http_templates() -> None:
    red = redact_api(copy.deepcopy(OVERVIEW))
    assert red["globals"]["location"] == {"latitude": MASK, "longitude": MASK}
    assert red["devices"][0]["pushMail"]["recipient"] == MASK
    http = red["templates"][1]["httpRequest"]
    assert http == {"method": "GET", "url": MASK, "header": MASK}
    assert redact_api({"installCode": "1234-5678", "resetCode": "x", "geofenceZones": [1]}) == {
        "installCode": MASK,
        "resetCode": MASK,
        "geofenceZones": MASK,
    }


def test_overview_summary(svc: Any) -> None:
    r = svc.smarthome_rest.overview()
    assert r["summary"]["battery_low"] == ["Heizung Bad"] and r["summary"]["updates"] == ["Waschmaschine"]
    assert r["summary"]["windows_open"] == ["Heizung Bad"]
    thermo = next(u for u in r["units"] if u["type"] == "avmThermostat")
    assert thermo["thermostat"]["setpoint"] == 21.0 and thermo["temperature_c"] == 19.5
    assert thermo["thermostat"]["next_change"]["to"] == 17.0
    plug = next(u for u in r["units"] if u["type"] == "avmPlugSocket")
    assert plug["power"] == {"power_w": 2150.0, "voltage_v": 230.1, "current_a": 9.35, "energy_kwh": 12.345}
    assert r["globals"]["location"] == "geschwärzt" and r["routines"][0]["enabled"] is True
    text = str(r)
    assert "52.5" not in text and "person@example.org" not in text and "pw@" not in text


def test_unit_detail_with_timer_and_statistics(svc: Any) -> None:
    r = svc.smarthome_rest.unit("unit-thermo")
    assert r["timer"]["timerMode"] == "weekly"
    assert r["statistics"]["temperatures"][0]["values"] == [19.5, 20.0, None]
    with pytest.raises(NotFoundError):
        svc.smarthome_rest.unit("gibts-nicht")


def test_energy_report(svc: Any) -> None:
    r = svc.smarthome_rest.energy_report()
    h = r["heating"][0]
    assert h["deviation_c"] == -1.5 and h["window_open"] is True and h["battery_low"] is True
    m = r["meters"][0]
    assert m["energy_kwh"] == 12.345 and m["cost_eur"] == round(12.345 * 0.325, 2) and m["co2_kg"] == 4.94
    assert r["electricity_rate_eur_kwh"] == 0.325


def test_old_firmware_points_to_aha(landevices: LanDeviceClient) -> None:
    svc = make_service(landevices, FakeFC())
    with pytest.raises(UnsupportedFirmwareError) as ei:
        svc.smarthome_rest.overview()
    assert "8.2" in str(ei.value) and "smarthome_list_devices" in (ei.value.hint or "")


# ------------------------------------------------------------------ 8.5b control


class SmartHomeFake:
    """In-memory /api/v0/smarthome for units, triggers and templates."""

    def __init__(self, ignore_writes: bool = False) -> None:
        self.units = {u["UID"]: copy.deepcopy(u) for u in OVERVIEW["units"]}
        self.units["unit-lamp"] = {
            "UID": "unit-lamp",
            "name": {"name": "Lampe"},
            "unitType": "dimmableLight",
            "interfaces": {
                "levelControlInterface": {"state": "valid", "level": 10},
                "onOffInterface": {"state": "valid", "active": False},
            },
        }
        self.triggers = {"trg-1": {"UID": "trg-1", "name": "Abends", "enabled": True}}
        self.applied: list[str] = []
        self.ignore = ignore_writes
        self.bodies: list[Any] = []

    def __call__(self, request: Any) -> Any:
        import json as _json

        import httpx

        path = request.url.path.removeprefix("/api/v0/smarthome")
        parts = path.strip("/").split("/")
        if parts[:2] == ["overview", "units"] and len(parts) == 3:
            unit = self.units.get(parts[2])
            if unit is None:
                return httpx.Response(404, text="not found")
            if request.method == "PUT":
                body = _json.loads(request.content)
                self.bodies.append(body)
                if not self.ignore:
                    for iface, values in body["interfaces"].items():
                        unit["interfaces"].setdefault(iface, {}).update(values)
                return httpx.Response(200, json={})
            return httpx.Response(200, json=unit)
        if parts[:2] == ["overview", "triggers"] and len(parts) == 3:
            trg = self.triggers.get(parts[2])
            if trg is None:
                return httpx.Response(404, text="not found")
            if request.method == "PUT" and not self.ignore:
                trg.update(_json.loads(request.content))
            return httpx.Response(200, json=trg)
        if parts == ["overview", "globals"]:
            return httpx.Response(200, json={})
        if parts[:2] == ["overview", "templates"] and len(parts) == 3:
            if request.method == "POST":
                self.applied.append(parts[2])
                self.bodies.append(_json.loads(request.content))
            return httpx.Response(200, json={"UID": parts[2], "name": "Alles aus"})
        return None


@pytest.fixture
def ctl(landevices: LanDeviceClient, fake_box: FakeBox) -> tuple[Any, SmartHomeFake]:
    fake = SmartHomeFake()
    fake_box.extra_handler = fake
    svc = make_service(landevices, FakeFC())
    svc.smarthome_rest.now = lambda: 1_800_000_000.0
    return svc, fake


def test_set_unit_on_level_blind(ctl: tuple[Any, SmartHomeFake]) -> None:
    svc, fake = ctl
    r = svc.smarthome_rest.set_unit("unit-lamp", level=60)
    assert (
        r["verified"] is True
        and r["changed"] is True
        and fake.units["unit-lamp"]["interfaces"]["levelControlInterface"]["level"] == 60
    )
    assert fake.bodies[-1] == {"interfaces": {"levelControlInterface": {"level": 60}}}
    r = svc.smarthome_rest.set_unit("unit-plug", on=True)
    assert r == {**r, "changed": False, "verified": True}  # already on → nothing sent
    with pytest.raises(InvalidParameterError):
        svc.smarthome_rest.set_unit("unit-plug", level=10)  # plug has no level interface
    with pytest.raises(InvalidParameterError):
        svc.smarthome_rest.set_unit("unit-lamp", on=True, level=5)
    with pytest.raises(NotFoundError):
        svc.smarthome_rest.set_unit("unit-gibts-nicht", on=True)


def test_set_unit_not_verified_when_ignored(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    fake_box.extra_handler = SmartHomeFake(ignore_writes=True)
    svc = make_service(landevices, FakeFC())
    r = svc.smarthome_rest.set_unit("unit-lamp", on=True)
    assert r["verified"] is False and "note" in r


def test_thermostat_boost_with_end_time(ctl: tuple[Any, SmartHomeFake]) -> None:
    svc, fake = ctl
    r = svc.smarthome_rest.thermostat_mode("unit-thermo", "boost", 30)
    assert r["verified"] is True and r["enabled"] is True
    assert fake.bodies[-1] == {
        "interfaces": {"thermostatInterface": {"boost": {"enabled": True, "endTime": 1_800_001_800}}}
    }
    r = svc.smarthome_rest.thermostat_mode("unit-thermo", "boost", 0)
    assert r["enabled"] is False and fake.bodies[-1]["interfaces"]["thermostatInterface"]["boost"]["endTime"] == -1
    with pytest.raises(InvalidParameterError):
        svc.smarthome_rest.thermostat_mode("unit-thermo", "boost", 1441)
    with pytest.raises(InvalidParameterError):
        svc.smarthome_rest.thermostat_mode("unit-plug", "window_open", 10)


def test_routine_and_template(ctl: tuple[Any, SmartHomeFake]) -> None:
    svc, fake = ctl
    r = svc.smarthome_rest.set_routine("trg-1", False)
    assert r["verified"] is True and fake.triggers["trg-1"]["enabled"] is False
    assert svc.smarthome_rest.set_routine("trg-1", False)["changed"] is False
    r = svc.smarthome_rest.apply_template("tmpl-1")
    assert fake.applied == ["tmpl-1"] and fake.bodies[-1] == {"triggerEvent": True}
    assert r["verified"] is False and r["name"] == "Alles aus"


def test_writes_need_write_tier(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    from fritzos8_mcp.errors import TierDisabledError

    fake_box.extra_handler = SmartHomeFake()
    svc = make_service(landevices, FakeFC(), write=False, critical=False)
    with pytest.raises(TierDisabledError):
        svc.smarthome_rest.set_unit("unit-lamp", on=True)


def test_aha_fallback_on_old_firmware(landevices: LanDeviceClient) -> None:
    from types import SimpleNamespace

    sent: list[tuple[str, Any, dict[str, Any]]] = []

    def command(cmd: str, ain: Any = None, **extra: Any) -> str:
        sent.append((cmd, ain, extra))
        return str(extra.get("endtimestamp", ""))

    svc = make_service(landevices, FakeFC())  # no smarthome routes → 404 → AHA
    svc._smarthome = SimpleNamespace(command=command, find=lambda ain: {"simpleonoff": {"on": True}})  # type: ignore[assignment]
    svc.smarthome_rest.now = lambda: 1_800_000_000.0
    r = svc.smarthome_rest.thermostat_mode("09995 0000001", "window_open", 15)
    assert r["via"] == "aha" and r["verified"] is True
    assert sent[-1] == ("sethkrwindowopen", "09995 0000001", {"endtimestamp": 1_800_000_900})
    r = svc.smarthome_rest.set_unit("09995 0000001", on=True)
    assert r["via"] == "aha" and r["verified"] is True and sent[-1][0] == "setsimpleonoff"
    svc.smarthome_rest.apply_template("tmpl")
    assert sent[-1][0] == "applytemplate"


def test_redaction_http_request_interface_and_geofence_coordinates() -> None:
    """Stage 9.9: httpRequestInterface (URL with credentials) and coordinates in geofence registrations."""
    data = {
        "units": [{"interfaces": {"httpRequestInterface": {"method": "POST", "url": "https://u:p@example.org/x"}}}],
        "registrations": [{"name": "Handy", "latitude": 52.5, "longitude": 13.4, "radius": 100}],
    }
    red = redact_api(data)
    assert red["units"][0]["interfaces"]["httpRequestInterface"] == {"method": "POST", "url": MASK}
    reg = red["registrations"][0]
    assert reg["latitude"] == MASK and reg["longitude"] == MASK and reg["radius"] == 100
