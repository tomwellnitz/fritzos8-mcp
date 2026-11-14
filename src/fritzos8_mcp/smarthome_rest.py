"""Stage 8.5a/8.5b – Smart-Home-REST-API (FRITZ!OS ≥ 8.2) under ``/api/v0/smarthome``.

Own implementation after the official AVM OpenAPI documents "FRITZ! Smart Home REST API" (0.9.5 for FRITZ!OS 8.2,
1.0.0 for 8.5). Authentication and redaction as every ``/api/v0`` call (``RestClient``; geofencing/location,
push-mail recipient, pairing codes and ``httpRequest`` templates are masked there before this module sees them).

Read (8.5a): ``GET overview`` (devices, units with interfaces, groups, triggers, templates, globals),
``GET overview/units/{UID}`` (incl. timer = heating plan and statistics). Units per OpenAPI: power mW, voltage mV,
current mA, energy Wh, temperature °C (0.1/0.5 steps), humidity %. Boxes before 8.2 answer 404 → the AHA tools
(``smarthome_list_devices``) remain the fallback.

"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import Field

from .errors import (
    FritzError,
    InvalidParameterError,
    NotFoundError,
    UnsupportedFirmwareError,
)
from .nasremote import ToolDecorator
from .security import Gate, Tier
from .toolargs import READ, WRITE, AinArg, BoxArg

if TYPE_CHECKING:
    from .rest import RestClient
    from .smarthome import AhaClient

BASE = "/api/v0/smarthome"
MAX_SPECIAL_MODE_MIN = 24 * 60  # AVM: end time at most 24 h in the future (boost / window open)
BLIND_ACTIONS = {"down": "moveDown", "up": "moveUp", "stop": "stop"}
AHA_BLIND = {"down": "close", "up": "open", "stop": "stop"}


def _num(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _scaled(value: Any, divisor: float, digits: int = 2) -> float | None:
    v = _num(value)
    return None if v is None else round(v / divisor, digits)


def _temp(value: Any) -> Any:
    """helper_temperature {mode, celsius} → 21.5 / 'on' / 'off' / None."""
    if not isinstance(value, dict):
        return None
    mode = value.get("mode")
    return value.get("celsius") if mode == "temperature" else mode


def _iso(ts: Any) -> str | None:
    v = _num(ts)
    if v is None or v <= 0:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(v))


def summarize_unit(unit: dict[str, Any]) -> dict[str, Any]:
    """One function unit → compact, typed values per interface (unknown fields stay out)."""
    ifs = unit.get("interfaces") or {}
    name = unit.get("name")
    out: dict[str, Any] = {
        "uid": unit.get("UID"),
        "name": name.get("name") if isinstance(name, dict) else name,
        "type": unit.get("unitType"),
        "connected": unit.get("isConnected"),
        "device_uid": unit.get("deviceUid"),
        "group_uid": unit.get("groupUid"),
    }
    t = ifs.get("thermostatInterface")
    if isinstance(t, dict):
        nxt = t.get("nextChange") or {}
        out["thermostat"] = {
            "state": t.get("thermostatState") or t.get("state"),
            "setpoint": _temp(t.get("setPointTemperature")),
            "comfort": _temp(t.get("comfortTemperature")),
            "reduced": _temp(t.get("reducedTemperature")),
            "boost": t.get("boost"),
            "window_open": t.get("windowOpenMode"),
            "holiday_active": t.get("isHolidayActive"),
            "summer_active": t.get("isSummertimeActive"),
            "adaptive_active": t.get("isAdaptiveActive"),
            "next_change": {"at": _iso(nxt.get("changeTime")), "to": _temp(nxt.get("temperatureChange"))}
            if nxt
            else None,
            "locked_local": t.get("isLockedDeviceLocal"),
        }
    temp = ifs.get("temperatureInterface")
    if isinstance(temp, dict):
        out["temperature_c"] = temp.get("celsius")
    hum = ifs.get("humidityInterface")
    if isinstance(hum, dict):
        out["humidity_pct"] = hum.get("relativeHumidity")
    onoff = ifs.get("onOffInterface")
    if isinstance(onoff, dict):
        out["on"] = onoff.get("active")
    meter = ifs.get("multimeterInterface")
    if isinstance(meter, dict):
        out["power"] = {
            "power_w": _scaled(meter.get("power"), 1000),
            "voltage_v": _scaled(meter.get("voltage"), 1000),
            "current_a": _scaled(meter.get("current"), 1000, 3),
            "energy_kwh": _scaled(meter.get("energy"), 1000, 3),
        }
    level = ifs.get("levelControlInterface")
    if isinstance(level, dict):
        out["level"] = level.get("level")
    blind = ifs.get("blindInterface")
    if isinstance(blind, dict):
        out["blind"] = {"state": blind.get("blindState"), "last_action": blind.get("blindAction")}
    alert = ifs.get("alertInterface")
    if isinstance(alert, dict):
        out["alert"] = {"alerts": alert.get("alerts"), "last": _iso(alert.get("lastAlertTime"))}
    color = ifs.get("colorControlInterface")
    if isinstance(color, dict):
        out["color"] = {k: color.get(k) for k in ("colorMode", "hsColor", "colorTemperature") if k in color}
    return out


def summarize_device(dev: dict[str, Any]) -> dict[str, Any]:
    return {
        "uid": dev.get("UID"),
        "ain": dev.get("ain"),
        "name": dev.get("name"),
        "product": dev.get("productName"),
        "category": dev.get("productCategory"),
        "connected": dev.get("isConnected"),
        "firmware": dev.get("firmwareVersion") or None,
        "update_available": dev.get("isUpdateAvailable"),
        "battery_pct": dev.get("batteryValue"),
        "battery_low": dev.get("isBatteryLow"),
        "zigbee": dev.get("isZigbeeDevice"),
        "unit_uids": dev.get("unitUids") or [],
    }


class SmartHomeRest:
    def __init__(
        self,
        rest: RestClient | None,
        gate: Gate | None = None,
        sleep: Callable[[float], None] = time.sleep,
        aha: Callable[[], AhaClient] | None = None,
        now: Callable[[], float] = time.time,
    ):
        self.rest = rest
        self.gate = gate or Gate(False, False)
        self.sleep = sleep
        self._aha = aha
        self.now = now

    def _get(self, path: str, missing: Literal["firmware", "not_found"] = "firmware") -> Any:
        if self.rest is None:
            raise FritzError("REST-Client nicht konfiguriert.")
        try:
            return self.rest.request("GET", f"{BASE}{path}", missing=missing)
        except UnsupportedFirmwareError:
            raise UnsupportedFirmwareError(
                "Smart-Home-REST-API nicht vorhanden (erst ab FRITZ!OS 8.2).",
                hint="Für ältere Boxen smarthome_list_devices/smarthome_set_* (AHA-HTTP-Interface) verwenden.",
            ) from None

    # ------------------------------------------------------------ read (8.5a)

    def raw_overview(self) -> dict[str, Any]:
        data = self._get("/overview")
        if not isinstance(data, dict):
            raise FritzError("Smart-Home-Übersicht hat ein unerwartetes Format.")
        return data

    def overview(self) -> dict[str, Any]:
        data = self.raw_overview()
        devices = [summarize_device(d) for d in data.get("devices") or [] if isinstance(d, dict)]
        units = [summarize_unit(u) for u in data.get("units") or [] if isinstance(u, dict)]
        groups = [
            {
                "uid": g.get("UID"),
                "name": g.get("name"),
                "category": g.get("groupCategory"),
                "members": g.get("memberUnitUids") or [],
                "unit_uid": g.get("unitUid"),
            }
            for g in data.get("groups") or []
            if isinstance(g, dict)
        ]
        templates = [
            {"uid": t.get("UID"), "name": t.get("name"), "apply_type": t.get("applyType")}
            for t in data.get("templates") or []
            if isinstance(t, dict)
        ]
        triggers = [
            {"uid": t.get("UID"), "name": t.get("name"), "enabled": t.get("enabled")}
            for t in data.get("triggers") or []
            if isinstance(t, dict)
        ]
        globals_ = data.get("globals") or {}
        return {
            "devices": devices,
            "units": units,
            "groups": groups,
            "templates": templates,
            "routines": triggers,
            "globals": {
                "energy_key_figures": globals_.get("energyKeyFigures"),
                "feature_flags": globals_.get("featureFlags"),
                "location": "geschwärzt" if globals_.get("location") else None,
            },
            "summary": {
                "devices": len(devices),
                "not_connected": [d["name"] for d in devices if d["connected"] is False],
                "battery_low": [d["name"] for d in devices if d["battery_low"]],
                "updates": [d["name"] for d in devices if d["update_available"]],
                "windows_open": [
                    u["name"]
                    for u in units
                    if isinstance((u.get("thermostat") or {}).get("window_open"), dict)
                    and u["thermostat"]["window_open"].get("enabled")
                ],
            },
            "source": "Smart-Home-REST /api/v0/smarthome/overview (AVM-Doku 8.2/8.5); Felder live unverifiziert",
        }

    def unit(self, uid: str) -> dict[str, Any]:
        uid = (uid or "").strip()
        if not uid:
            raise InvalidParameterError("uid fehlt (UID aus smarthome_overview).")
        try:
            data = self._get(f"/overview/units/{uid}", missing="not_found")
        except NotFoundError:
            raise NotFoundError(f'Smart-Home-Einheit "{uid}" nicht gefunden.') from None
        if not isinstance(data, dict):
            raise FritzError("Antwort hat ein unerwartetes Format.")
        out = summarize_unit(data)
        if data.get("timer") is not None:
            out["timer"] = data["timer"]  # heating plan / switching times as delivered (structure per OpenAPI)
        stats = data.get("statistics")
        if isinstance(stats, dict):
            out["statistics"] = {
                kind: [
                    {
                        "period": s.get("period"),
                        "interval_s": s.get("interval"),
                        "state": s.get("statisticsState"),
                        "values": (s.get("values") or [])[:400],
                    }
                    for s in series
                    if isinstance(s, dict)
                ]
                for kind, series in stats.items()
                if isinstance(series, list)
            }
        return out

    def energy_report(self) -> dict[str, Any]:
        """Heating & energy report: thermostats (setpoint vs. measured, window open, battery, holiday/summer) and
        metering plugs (power now, energy total, cost estimate from the box's electricity rate)."""
        ov = self.overview()
        devices = {d["uid"]: d for d in ov["devices"]}
        figures = ov["globals"].get("energy_key_figures") or {}
        rate = _num(figures.get("electricityRate"))
        rate_eur = None if rate is None else (rate / 100 if rate > 2 else rate)  # doc: "price [¢] … €/kWh"
        co2 = _num(figures.get("co2emmissions"))
        heating = []
        meters = []
        for u in ov["units"]:
            dev = devices.get(u.get("device_uid")) or {}
            if "thermostat" in u:
                th = u["thermostat"]
                setpoint = th.get("setpoint")
                current = u.get("temperature_c")
                heating.append(
                    {
                        "name": u["name"],
                        "setpoint_c": setpoint,
                        "measured_c": current,
                        "deviation_c": round(current - setpoint, 1)
                        if isinstance(current, int | float) and isinstance(setpoint, int | float)
                        else None,
                        "window_open": (th.get("window_open") or {}).get("enabled")
                        if isinstance(th.get("window_open"), dict)
                        else None,
                        "boost": (th.get("boost") or {}).get("enabled") if isinstance(th.get("boost"), dict) else None,
                        "holiday_active": th.get("holiday_active"),
                        "summer_active": th.get("summer_active"),
                        "battery_pct": dev.get("battery_pct"),
                        "battery_low": dev.get("battery_low"),
                        "next_change": th.get("next_change"),
                    }
                )
            if "power" in u:
                p = u["power"]
                kwh = p.get("energy_kwh")
                meters.append(
                    {
                        "name": u["name"],
                        "power_w": p.get("power_w"),
                        "energy_kwh": kwh,
                        "cost_eur": round(kwh * rate_eur, 2) if kwh is not None and rate_eur is not None else None,
                        "co2_kg": round(kwh * co2 / 1000, 2) if kwh is not None and co2 is not None else None,
                    }
                )
        total = sum(m["energy_kwh"] or 0 for m in meters)
        return {
            "heating": heating,
            "meters": meters,
            "totals": {
                "energy_kwh": round(total, 3),
                "power_now_w": round(sum(m["power_w"] or 0 for m in meters), 1),
                "cost_eur": round(total * rate_eur, 2) if rate_eur is not None else None,
            },
            "electricity_rate_eur_kwh": rate_eur,
            "notes": [
                "Energie = Zählerstand seit Aufzeichnungsbeginn der Steckdose (laut AVM-Doku), kein Monatswert.",
                "Strompreis aus den Smart-Home-Einstellungen der Box; Einheit laut Doku mehrdeutig (¢ bzw. €/kWh) – "
                "Werte > 2 werden als Cent gewertet (live prüfen).",
            ],
        }


class SmartHomeControl(SmartHomeRest):
    """Stage 8.5b – control via REST (``PUT overview/units/{UID}``, ``PUT overview/triggers/{UID}``,
    ``POST overview/templates/{UID}``), every change read back; AHA commands as fallback for FRITZ!OS < 8.2
    (``setsimpleonoff``, ``setlevelpercentage``, ``setblind``, ``settriggeractive``, ``applytemplate``,
    ``sethkrboost``, ``sethkrwindowopen`` – AHA-HTTP-Interface). ``PUT overview/globals`` is deliberately NOT used:
    it only carries lamp presets, the location and the one-shot geofence switch – holiday periods live in the
    thermostat configuration (``configuration/units``, stage 10)."""

    def _write(self, method: Literal["PUT", "POST"], path: str, body: Any) -> Any:
        if self.rest is None:
            raise FritzError("REST-Client nicht konfiguriert.")
        return self.rest.request(method, f"{BASE}{path}", body, missing="firmware")

    def _entity(self, path: str) -> Any:
        """GET one unit/trigger/template. A 404 is ambiguous (unknown UID or FRITZ!OS < 8.2): the small globals
        endpoint decides – missing as well → UnsupportedFirmwareError (callers fall back to AHA)."""
        try:
            return self._get(path, missing="not_found")
        except NotFoundError:
            self._get("/overview/globals")  # raises UnsupportedFirmwareError without REST API
            raise NotFoundError(f"Smart-Home-Objekt {path.rsplit('/', 1)[-1]} nicht gefunden.") from None

    def _unit_raw(self, uid: str) -> dict[str, Any]:
        data = self._entity(f"/overview/units/{uid}")
        if not isinstance(data, dict):
            raise FritzError("Antwort hat ein unerwartetes Format.")
        return data

    def _aha_or_raise(self) -> AhaClient:
        if self._aha is None:
            raise UnsupportedFirmwareError("Smart-Home-REST-API nicht vorhanden und kein AHA-Client konfiguriert.")
        return self._aha()

    @staticmethod
    def _uid(uid: str) -> str:
        uid = (uid or "").strip()
        if not uid or "/" in uid or ".." in uid:
            raise InvalidParameterError("uid fehlt oder ist ungültig (UID aus smarthome_overview).")
        return uid

    # ------------------------------------------------------------ units

    def set_unit(
        self, uid: str, on: bool | None = None, level: int | None = None, blind: str | None = None
    ) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        uid = self._uid(uid)
        given = [x for x in (on, level, blind) if x is not None]
        if len(given) != 1:
            raise InvalidParameterError("Genau eins angeben: on, level oder blind.")
        if level is not None and not 0 <= level <= 100:
            raise InvalidParameterError("level muss 0–100 (%) sein.")
        if blind is not None and blind not in BLIND_ACTIONS:
            raise InvalidParameterError("blind: up, down oder stop.")
        body: dict[str, Any]
        check: tuple[str, Any]
        if on is not None:
            iface, body, check = "onOffInterface", {"active": on}, ("active", on)
        elif level is not None:
            iface, body, check = "levelControlInterface", {"level": level}, ("level", level)
        else:
            action = BLIND_ACTIONS[str(blind)]
            iface, body, check = "blindInterface", {"blindAction": action}, ("blindAction", action)
        try:
            before = self._unit_raw(uid)
        except UnsupportedFirmwareError:
            return self._aha_unit(uid, on, level, blind)
        current = (before.get("interfaces") or {}).get(iface)
        base = {"uid": uid, "name": summarize_unit(before)["name"], "interface": iface, "set": body, "via": "rest"}
        if not isinstance(current, dict):
            raise InvalidParameterError(f"Einheit {uid} hat keine {iface} – siehe smarthome_overview (type).")
        if current.get(check[0]) == check[1] and iface != "blindInterface":
            return {**base, "changed": False, "verified": True}
        self._write("PUT", f"/overview/units/{uid}", {"interfaces": {iface: body}})
        after = ((self._unit_raw(uid).get("interfaces") or {}).get(iface)) or {}
        verified = after.get(check[0]) == check[1]
        out = {**base, "changed": True, "verified": verified, "read_back": after.get(check[0])}
        if not verified:
            out["note"] = (
                "Die Box meldet nach dem Schreiben einen anderen Wert – Gerät nicht erreichbar oder abgelehnt."
            )
        return out

    def _aha_unit(self, uid: str, on: bool | None, level: int | None, blind: str | None) -> dict[str, Any]:
        aha = self._aha_or_raise()
        base: dict[str, Any] = {"uid": uid, "via": "aha"}
        if on is not None:
            aha.command("setsimpleonoff", uid, onoff=int(on))
            dev = aha.find(uid)
            state = (dev.get("simpleonoff") or dev.get("switch") or {}).get("on")
            return {**base, "set": {"on": on}, "changed": True, "verified": state is on, "read_back": state}
        if level is not None:
            aha.command("setlevelpercentage", uid, level=level)
            return {
                **base,
                "set": {"level": level},
                "changed": True,
                "verified": False,
                "note": "AHA: Level nicht rücklesbar über die kuratierten Felder – smarthome_list_devices prüfen.",
            }
        aha.command("setblind", uid, target=AHA_BLIND[str(blind)])
        return {
            **base,
            "set": {"blind": blind},
            "changed": True,
            "verified": False,
            "note": "Rollo-Befehl gesendet; die Endposition ist nicht sofort rücklesbar.",
        }

    # ------------------------------------------------------------ thermostat special modes

    def thermostat_mode(self, uid: str, mode: str, minutes: int) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        uid = self._uid(uid)
        if mode not in ("boost", "window_open"):
            raise InvalidParameterError("mode: boost oder window_open.")
        if not 0 <= minutes <= MAX_SPECIAL_MODE_MIN:
            raise InvalidParameterError("minutes: 0 (beenden) bis 1440 (24 h, Grenze laut AVM).")
        enabled = minutes > 0
        end = int(self.now()) + minutes * 60 if enabled else 0
        key = "boost" if mode == "boost" else "windowOpenMode"
        try:
            before = self._unit_raw(uid)
        except UnsupportedFirmwareError:
            return self._aha_mode(uid, mode, end)
        thermo = (before.get("interfaces") or {}).get("thermostatInterface")
        if not isinstance(thermo, dict):
            raise InvalidParameterError(f"Einheit {uid} ist kein Thermostat.")
        body = {key: {"enabled": enabled, "endTime": end if enabled else -1}}
        self._write("PUT", f"/overview/units/{uid}", {"interfaces": {"thermostatInterface": body}})
        after = (((self._unit_raw(uid).get("interfaces") or {}).get("thermostatInterface")) or {}).get(key) or {}
        verified = bool(after.get("enabled")) == enabled
        return {
            "uid": uid,
            "name": summarize_unit(before)["name"],
            "mode": mode,
            "enabled": enabled,
            "until": _iso(end) if enabled else None,
            "via": "rest",
            "changed": True,
            "verified": verified,
            "read_back": after,
            "note": "Batteriebetriebene Thermostate übernehmen das beim nächsten Funkkontakt (bis ca. 15 min).",
        }

    def _aha_mode(self, uid: str, mode: str, end: int) -> dict[str, Any]:
        aha = self._aha_or_raise()
        echo = aha.command("sethkrboost" if mode == "boost" else "sethkrwindowopen", uid, endtimestamp=end).strip()
        verified = echo == str(end)
        return {
            "uid": uid,
            "mode": mode,
            "enabled": end > 0,
            "until": _iso(end) if end else None,
            "via": "aha",
            "changed": True,
            "verified": verified,
            "read_back": echo or None,
        }

    # ------------------------------------------------------------ routines & templates

    def set_routine(self, uid: str, enabled: bool) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        uid = self._uid(uid)
        try:
            before = self._entity(f"/overview/triggers/{uid}")
        except UnsupportedFirmwareError:
            aha = self._aha_or_raise()
            aha.command("settriggeractive", uid, active=int(enabled))
            return {
                "uid": uid,
                "enabled": enabled,
                "via": "aha",
                "changed": True,
                "verified": False,
                "note": "AHA: Routinenzustand nicht rücklesbar – smarthome_overview prüfen (ab 8.2).",
            }
        base = {"uid": uid, "name": (before or {}).get("name"), "enabled": enabled, "via": "rest"}
        if isinstance(before, dict) and before.get("enabled") is enabled:
            return {**base, "changed": False, "verified": True}
        self._write("PUT", f"/overview/triggers/{uid}", {"enabled": enabled})
        after = self._get(f"/overview/triggers/{uid}", missing="not_found")
        return {**base, "changed": True, "verified": isinstance(after, dict) and after.get("enabled") is enabled}

    def apply_template(self, uid: str) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        uid = self._uid(uid)
        try:
            tmpl = self._entity(f"/overview/templates/{uid}")
            self._write("POST", f"/overview/templates/{uid}", {"triggerEvent": True})
            via = "rest"
        except UnsupportedFirmwareError:
            self._aha_or_raise().command("applytemplate", uid)
            tmpl, via = {}, "aha"
        return {
            "uid": uid,
            "name": (tmpl or {}).get("name") if isinstance(tmpl, dict) else None,
            "via": via,
            "applied": True,
            "verified": False,
            "note": "Eine Vorlage löst Aktionen an mehreren Geräten aus – das ist als Ganzes nicht rücklesbar. "
            "Wirkung mit smarthome_overview prüfen.",
        }


def register_smarthome_rest_tools(tool: ToolDecorator, svc: Callable[[str | None], SmartHomeControl]) -> None:
    @tool(Tier.READ, READ)
    def smarthome_overview(box: BoxArg = None) -> dict[str, Any]:
        """Smart Home über die REST-API (FRITZ!OS ≥ 8.2): Geräte (Produkt, verbunden, Batterie, Firmware/Update),
        Einheiten mit Werten (Thermostat Soll/Komfort/Absenk, Boost, Fenster offen, Urlaub/Sommer, nächste Änderung;
        Temperatur, Luftfeuchte, Schalter, Leistung/Energie, Rollo, Melder), Gruppen, Vorlagen, Routinen, globale
        Werte (ohne Standort). Ältere Boxen: smarthome_list_devices (AHA)."""
        return svc(box).overview()

    @tool(Tier.READ, READ)
    def smarthome_unit(uid: AinArg, box: BoxArg = None) -> dict[str, Any]:
        """Eine Smart-Home-Einheit im Detail (REST overview/units/{UID}): Werte, Zeitschaltung/Heizplan (wie von der
        Box geliefert) und Statistik (Temperatur, Luftfeuchte, Leistung, Energie je Zeitraum)."""
        return svc(box).unit(uid)

    @tool(Tier.READ, READ)
    def smarthome_energy_report(box: BoxArg = None) -> dict[str, Any]:
        """Heiz- und Energiebericht (REST): je Thermostat Soll/Ist/Abweichung, Fenster offen, Boost, Urlaub/Sommer,
        Batterie, nächste Schaltzeit; je Messsteckdose Leistung, Energie, Kosten/CO2 aus den Box-Kennzahlen."""
        return svc(box).energy_report()

    @tool(Tier.WRITE, WRITE)
    def smarthome_set_unit(
        uid: AinArg,
        on: Annotated[bool | None, Field(description="Schalten: true = an, false = aus")] = None,
        level: Annotated[int | None, Field(description="Dimmen/Höhe in % (0–100)", ge=0, le=100)] = None,
        blind: Annotated[Literal["up", "down", "stop"] | None, Field(description="Rollo: up, down oder stop")] = None,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Steuert eine Smart-Home-Einheit (REST PUT overview/units/{UID}; FRITZ!OS < 8.2: AHA setsimpleonoff/
        setlevelpercentage/setblind): genau eins von on, level oder blind. Liest den Wert zurück (verified)."""
        return svc(box).set_unit(uid, on, level, blind)

    @tool(Tier.WRITE, WRITE)
    def smarthome_thermostat_mode(
        uid: AinArg,
        mode: Annotated[Literal["boost", "window_open"], Field(description="boost oder window_open (Fenster offen)")],
        minutes: Annotated[int, Field(description="Dauer in Minuten (1–1440), 0 = beenden", ge=0, le=1440)],
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Thermostat-Sondermodus Boost bzw. Fenster offen für höchstens 24 h setzen oder beenden (REST
        thermostatInterface; FRITZ!OS < 8.2: AHA sethkrboost/sethkrwindowopen) und zurücklesen."""
        return svc(box).thermostat_mode(uid, mode, minutes)

    @tool(Tier.WRITE, WRITE)
    def smarthome_set_routine(
        uid: AinArg,
        enabled: Annotated[bool, Field(description="true = Routine aktiv, false = deaktiviert")],
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Routine (Trigger) aktivieren/deaktivieren (REST PUT overview/triggers/{UID}; AHA settriggeractive) und
        zurücklesen."""
        return svc(box).set_routine(uid, enabled)

    @tool(Tier.WRITE, WRITE)
    def smarthome_apply_template(uid: AinArg, box: BoxArg = None) -> dict[str, Any]:
        """Wendet eine Smart-Home-Vorlage an (REST POST overview/templates/{UID}; AHA applytemplate). Die Wirkung auf
        mehrere Geräte ist nicht als Ganzes rücklesbar (verified=false) – danach smarthome_overview prüfen."""
        return svc(box).apply_template(uid)
