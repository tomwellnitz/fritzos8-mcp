"""Stage 10.6b – Smart Home configuration over the documented interfaces (AVM Smart-Home-REST 8.2/8.5, AHA, TR-064).

Critical (plan → token → execute + elicitation, read-back):

* **Holiday periods** of a thermostat (moved here from 8.5b: they live in ``configuration/units``, not in
  ``overview/globals``): ``PUT /smarthome/configuration/units/{UID}`` with
  ``interfaces.thermostatInterface.holidayPeriods`` = temperature + up to 4 periods. Times are "minutes since the
  beginning of the year, leap day always counted" (start: full hour, end: the day, active until its end).
* **Summer period** (thermostat off/frost protection every year): ``summerPeriod`` (full days).
* **Delete** a group, template or routine (``DELETE configuration/{groups|templates|triggers}/{UID}``).
* **Rename** a unit (``PUT configuration/units/{UID}`` ``name``, ≤ 39 characters); TR-064
  ``X_AVM-DE_Homeauto:SetDeviceName`` as fallback for boxes without the REST API.
* **Pairing (K-19)** – start a DECT-ULE/Zigbee subscription for a limited time
  (``POST connect/startSubscription/{serial}`` on a radio base from ``GET connect/radioBases``; AHA
  ``startulesubscription`` as fallback), status via ``GET connect/subscriptionState/{UID}`` / AHA
  ``getsubscriptionstate``. Install/reset/pairing codes are never requested or output.

Read / write (K-28, Smart Home over TR-064 without web login): ``X_AVM-DE_Homeauto:GetGenericDeviceInfos`` /
``GetSpecificDeviceInfos`` (read) and ``SetSwitch`` (write, like the other switch tools) with read-back.

Not built (documented as open): creating groups/templates/routines and editing heating schedules (``timer``) –
large bodies, templates can carry ``httpRequest`` actions with credentials; needs live verification first.
"""

from __future__ import annotations

import datetime as dt
import itertools
import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated, Any, Literal

from defusedxml import ElementTree as ET
from pydantic import BaseModel, Field

from .errors import FritzError, InvalidParameterError, NotFoundError, UnsupportedFirmwareError
from .nasremote import ToolDecorator
from .security import Gate, PlanStore, Tier
from .smarthome_rest import SmartHomeControl
from .toolargs import DESTRUCTIVE, READ, WRITE, AinArg, BoxArg, TokenArg
from .util import truthy

if TYPE_CHECKING:
    from .rest import RestClient
    from .smarthome import AhaClient
    from .tr064 import Tr064Client

HOMEAUTO = "X_AVM-DE_Homeauto1"
REF_LEAP_YEAR = 2024  # AVM: "leap year (29th February) is always included"
MAX_HOLIDAYS = 4
MAX_NAME = 39
MAX_DEVICES = 200
KIND_PATH = {"group": "groups", "template": "templates", "routine": "triggers"}
SUBSCRIPTION_STATES = {
    "initial": "gestartet",
    "dectPending": "wartet auf ein DECT-Gerät (Anmeldetaste am Gerät drücken)",
    "zigbeePending": "wartet auf ein Zigbee-Gerät (Gerät in den Anlernmodus versetzen)",
    "alreadyRunning": "es läuft bereits eine Anmeldung",
    "abortedByUser": "abgebrochen",
    "timeout": "Zeit abgelaufen, kein Gerät angemeldet",
    "genericError": "Fehler",
    "success": "Gerät angemeldet",
    "unknown": "unbekannt",
}
BASE_FIELDS = ("serial", "isDectAvailable", "isZigbeeAvailable", "isSmarthomeMaster", "activeSubscriptionUid")
AHA_SUBSCRIPTION = {"0": "läuft nicht", "1": "läuft", "2": "Zeit abgelaufen", "3": "Fehler"}


class Period(BaseModel):
    start: Annotated[str, Field(description="Beginn TT.MM. oder JJJJ-MM-TT (Jahr wird ignoriert, jährlich)")]
    end: Annotated[str, Field(description="Ende TT.MM. oder JJJJ-MM-TT (aktiv bis Tagesende)")]
    start_hour: Annotated[int, Field(description="Beginn-Stunde 0–23 (nur Urlaub, Standard 0)", ge=0, le=23)] = 0


_DATE = re.compile(r"^(?:(\d{4})-(\d{1,2})-(\d{1,2})|(\d{1,2})\.(\d{1,2})\.?(\d{2,4})?)$")


def _day_of_year(text: str) -> int:
    """0-based day in a leap year for 'DD.MM.' or 'YYYY-MM-DD' (year ignored)."""
    m = _DATE.match((text or "").strip())
    if not m:
        raise InvalidParameterError(f'Datum "{text}" nicht erkannt – TT.MM. oder JJJJ-MM-TT.')
    month, day = (int(m.group(2)), int(m.group(3))) if m.group(1) else (int(m.group(5)), int(m.group(4)))
    try:
        d = dt.date(REF_LEAP_YEAR, month, day)
    except ValueError:
        raise InvalidParameterError(f'Datum "{text}" gibt es nicht.') from None
    return d.timetuple().tm_yday - 1


def minutes_to_date(minutes: Any) -> str | None:
    try:
        m = int(minutes)
    except (TypeError, ValueError):
        return None
    d = dt.datetime(REF_LEAP_YEAR, 1, 1) + dt.timedelta(minutes=m)
    return d.strftime("%d.%m. %H:%M") if m % 1440 else d.strftime("%d.%m.")


def holiday_body(periods: list[Period], temperature_c: float | None) -> dict[str, Any]:
    if len(periods) > MAX_HOLIDAYS:
        raise InvalidParameterError(f"Höchstens {MAX_HOLIDAYS} Urlaubszeiträume (AVM).")
    if temperature_c is not None and not (8 <= temperature_c <= 28 and (temperature_c * 2).is_integer()):
        raise InvalidParameterError("temperature_c: 8–28 °C in 0,5er-Schritten.")
    out = []
    for p in periods:
        start = _day_of_year(p.start) * 1440 + p.start_hour * 60
        end = _day_of_year(p.end) * 1440
        out.append({"startTime": start, "endTime": end})
    spans = []
    for o in out:
        s, e = o["startTime"], o["endTime"] + 1439
        spans += [(s, e)] if s <= e else [(s, 527039), (0, e)]  # over new year
    spans.sort()
    if any(b[0] <= a[1] for a, b in itertools.pairwise(spans)):
        raise InvalidParameterError("Urlaubszeiträume dürfen sich nicht überschneiden (AVM).")
    body: dict[str, Any] = {"periods": out}
    if temperature_c is not None:
        body["temperature"] = {"mode": "temperature", "celsius": temperature_c}
    return body


def summer_body(enabled: bool, start: str | None, end: str | None) -> dict[str, Any]:
    if not enabled:
        return {"enabled": False}
    if not start or not end:
        raise InvalidParameterError("Für die Sommerzeit start und end angeben (TT.MM.).")
    return {"enabled": True, "startTime": _day_of_year(start) * 1440, "endTime": _day_of_year(end) * 1440}


def summarize_thermostat_config(unit: dict[str, Any]) -> dict[str, Any]:
    th = (unit.get("interfaces") or {}).get("thermostatInterface") or {}
    hol = th.get("holidayPeriods") or {}
    summer = th.get("summerPeriod") or {}
    temp = hol.get("temperature") or {}
    return {
        "uid": unit.get("UID"),
        "name": unit.get("name"),
        "comfort": (th.get("comfortTemperature") or {}).get("celsius"),
        "reduced": (th.get("reducedTemperature") or {}).get("celsius"),
        "holiday": {
            "active": th.get("isHolidayActive"),
            "temperature_c": temp.get("celsius") if temp.get("mode") == "temperature" else temp.get("mode"),
            "periods": [
                {
                    "from": minutes_to_date(p.get("startTime")),
                    "to": minutes_to_date(p.get("endTime")),
                    "raw": {"startTime": p.get("startTime"), "endTime": p.get("endTime")},
                }
                for p in hol.get("periods") or []
                if isinstance(p, dict)
            ],
        },
        "summer": {
            "enabled": summer.get("enabled"),
            "active": th.get("isSummertimeActive"),
            "from": minutes_to_date(summer.get("startTime")),
            "to": minutes_to_date(summer.get("endTime")),
        },
        "window_open": {
            k: (th.get("windowOpenMode") or {}).get(k)
            for k in ("sensorMode", "internalSensitivity", "internalDuration")
        },
    }


class SmartHomeConfig(SmartHomeControl):
    def __init__(
        self,
        rest: RestClient | None,
        gate: Gate,
        plans: PlanStore,
        tr064: Tr064Client,
        aha: Callable[[], AhaClient] | None = None,
    ) -> None:
        super().__init__(rest, gate, aha=aha)
        self.plans = plans
        self.tr064 = tr064

    # ------------------------------------------------------------ helpers

    def _req(self, method: Literal["PUT", "POST", "DELETE"], path: str, body: Any = None) -> Any:
        if self.rest is None:
            raise FritzError("REST-Client nicht konfiguriert.")
        return self.rest.request(method, f"/api/v0/smarthome{path}", body, missing="firmware")

    def _config_unit(self, uid: str) -> dict[str, Any]:
        data = self._entity(f"/configuration/units/{self._uid(uid)}")
        if not isinstance(data, dict):
            raise FritzError("Antwort hat ein unerwartetes Format.")
        return data

    def _thermostat(self, uid: str) -> dict[str, Any]:
        unit = self._config_unit(uid)
        if "thermostatInterface" not in (unit.get("interfaces") or {}):
            raise InvalidParameterError(f"Einheit {uid} ist kein Thermostat.")
        return unit

    # ------------------------------------------------------------ read

    def thermostat_config(self, uid: str) -> dict[str, Any]:
        return {
            **summarize_thermostat_config(self._thermostat(uid)),
            "source": "GET /api/v0/smarthome/configuration/units/{UID} (AVM-Doku 8.2/8.5)",
        }

    # ------------------------------------------------------------ holidays / summer

    def holidays_plan(self, uid: str, periods: list[Period], temperature_c: float | None) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        unit = self._thermostat(uid)
        body = holiday_body(periods, temperature_c)
        before = summarize_thermostat_config(unit)
        if (
            body["periods"]
            and temperature_c is None
            and not isinstance(before["holiday"]["temperature_c"], int | float)
        ):
            # live (6660/8.25): without a stored holiday temperature the box answers HTTP 400
            # "[MISSING] please provide a valid temperature for holidayPeriods" (code 1009)
            raise InvalidParameterError(
                "temperature_c angeben: Für dieses Thermostat ist noch keine Urlaubstemperatur gespeichert – "
                "die Box lehnt Urlaubszeiträume ohne Temperatur ab.",
                hint="z. B. temperature_c=16 (8–28 °C in 0,5er-Schritten).",
            )
        params = {"uid": unit.get("UID") or uid, "holidayPeriods": body}
        token = self.plans.issue("smarthome_holidays", params)
        new = [f"{minutes_to_date(p['startTime'])} – {minutes_to_date(p['endTime'])}" for p in body["periods"]]
        return {
            "action": "smarthome_holidays",
            "unit": {"uid": params["uid"], "name": unit.get("name")},
            "before": before["holiday"],
            "after": {"periods": new, "temperature_c": temperature_c},
            "consequence": (
                f"Urlaubsschaltung für {unit.get('name') or uid}: "
                + ("; ".join(new) if new else "alle Zeiträume löschen")
            )
            + (f", {temperature_c} °C" if temperature_c is not None else "")
            + ". Die Zeiträume gelten jedes Jahr.",
            "warnings": ["Ersetzt ALLE bisherigen Urlaubszeiträume dieses Thermostats (AVM: nur als Ganzes änderbar)."],
            "token": token,
            "token_valid_s": int(self.plans.ttl),
        }

    def holidays_execute(
        self, token: str, uid: str, periods: list[Period], temperature_c: float | None
    ) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        unit = self._thermostat(uid)
        body = holiday_body(periods, temperature_c)
        uid = unit.get("UID") or uid
        self.plans.redeem(token, "smarthome_holidays", {"uid": uid, "holidayPeriods": body})
        self._req(
            "PUT", f"/configuration/units/{uid}", {"interfaces": {"thermostatInterface": {"holidayPeriods": body}}}
        )
        after = summarize_thermostat_config(self._config_unit(uid))
        got = [p["raw"] for p in after["holiday"]["periods"]]
        ok = got == body["periods"] and (temperature_c is None or after["holiday"]["temperature_c"] == temperature_c)
        return {"uid": uid, "holiday": after["holiday"], "changed": True, "verified": ok}

    def summer_plan(self, uid: str, enabled: bool, start: str | None, end: str | None) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        unit = self._thermostat(uid)
        body = summer_body(enabled, start, end)
        params = {"uid": unit.get("UID") or uid, "summerPeriod": body}
        token = self.plans.issue("smarthome_summer", params)
        text = (
            f"Sommerzeit {minutes_to_date(body['startTime'])} – {minutes_to_date(body['endTime'])} (Thermostat aus/"
            "Frostschutz, jedes Jahr)"
            if enabled
            else "Sommerzeit ausschalten"
        )
        return {
            "action": "smarthome_summer",
            "unit": {"uid": params["uid"], "name": unit.get("name")},
            "before": summarize_thermostat_config(unit)["summer"],
            "consequence": f"{unit.get('name') or uid}: {text}.",
            "warnings": ["Während der Sommerzeit heizt das Thermostat nicht (nur Frostschutz)."] if enabled else [],
            "token": token,
            "token_valid_s": int(self.plans.ttl),
        }

    def summer_execute(self, token: str, uid: str, enabled: bool, start: str | None, end: str | None) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        unit = self._thermostat(uid)
        body = summer_body(enabled, start, end)
        uid = unit.get("UID") or uid
        self.plans.redeem(token, "smarthome_summer", {"uid": uid, "summerPeriod": body})
        self._req("PUT", f"/configuration/units/{uid}", {"interfaces": {"thermostatInterface": {"summerPeriod": body}}})
        raw = ((self._config_unit(uid).get("interfaces") or {}).get("thermostatInterface") or {}).get("summerPeriod")
        raw = raw or {}
        ok = raw.get("enabled") is enabled and (
            not enabled or (raw.get("startTime") == body["startTime"] and raw.get("endTime") == body["endTime"])
        )
        return {"uid": uid, "summer": raw, "changed": True, "verified": ok}

    # ------------------------------------------------------------ delete group/template/routine

    def delete_plan(self, kind: str, uid: str) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        if kind not in KIND_PATH:
            raise InvalidParameterError("kind: group, template oder routine.")
        entity = self._entity(f"/configuration/{KIND_PATH[kind]}/{self._uid(uid)}")
        name = entity.get("name") if isinstance(entity, dict) else None
        token = self.plans.issue("smarthome_delete", {"kind": kind, "uid": uid}, str(name))
        label = {"group": "Gruppe", "template": "Vorlage", "routine": "Routine"}[kind]
        return {
            "action": "smarthome_delete",
            "kind": kind,
            "uid": uid,
            "name": name,
            "consequence": f"{label} „{name or uid}“ wird endgültig gelöscht.",
            "warnings": [
                "Nicht rückgängig zu machen – Routinen/Vorlagen, die darauf verweisen, funktionieren nicht mehr."
            ]
            + (["Die Geräte der Gruppe bleiben erhalten, nur die Gruppe verschwindet."] if kind == "group" else []),
            "token": token,
            "token_valid_s": int(self.plans.ttl),
        }

    def delete_execute(self, token: str, kind: str, uid: str) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        if kind not in KIND_PATH:
            raise InvalidParameterError("kind: group, template oder routine.")
        path = f"/configuration/{KIND_PATH[kind]}/{self._uid(uid)}"

        def identity() -> str:
            try:
                e = self._entity(path)
            except NotFoundError:
                return ""
            return str(e.get("name") if isinstance(e, dict) else None)

        self.plans.redeem(token, "smarthome_delete", {"kind": kind, "uid": uid}, identity)
        self._req("DELETE", path)
        try:
            self._get(path, missing="not_found")
            gone = False
        except NotFoundError:
            gone = True
        return {"kind": kind, "uid": uid, "deleted": True, "verified": gone}

    # ------------------------------------------------------------ rename unit

    @staticmethod
    def _name(name: str) -> str:
        n = (name or "").strip()
        if not 1 <= len(n) <= MAX_NAME:
            raise InvalidParameterError(f"name: 1–{MAX_NAME} Zeichen (AVM).")
        return n

    def rename_plan(self, uid: str, name: str) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        n = self._name(name)
        try:
            before = self._config_unit(uid).get("name")
            via = "rest"
        except UnsupportedFirmwareError:
            info = self.tr064.call(HOMEAUTO, "GetSpecificDeviceInfos", NewAIN=uid)
            before, via = info.get("NewDeviceName"), "tr064"
        token = self.plans.issue("smarthome_rename", {"uid": uid, "name": n}, str(before))
        return {
            "action": "smarthome_rename",
            "uid": uid,
            "before": before,
            "after": n,
            "via": via,
            "consequence": f"„{before}“ heißt danach „{n}“ (Web-UI, App, Routinen-Anzeige).",
            "warnings": [
                "Automationen, die per Name statt UID/AIN auf das Gerät zugreifen (z. B. in Home Assistant), "
                "können danach ins Leere laufen."
            ],
            "token": token,
            "token_valid_s": int(self.plans.ttl),
        }

    def rename_execute(self, token: str, uid: str, name: str) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        n = self._name(name)
        current: dict[str, Any] = {}

        def identity() -> str:
            try:
                current["name"] = self._config_unit(uid).get("name")
                current["via"] = "rest"
            except UnsupportedFirmwareError:
                current["name"] = self.tr064.call(HOMEAUTO, "GetSpecificDeviceInfos", NewAIN=uid).get("NewDeviceName")
                current["via"] = "tr064"
            except FritzError:
                return ""
            return str(current["name"])

        self.plans.redeem(token, "smarthome_rename", {"uid": uid, "name": n}, identity)
        if current.get("via") == "rest":
            self._req("PUT", f"/configuration/units/{uid}", {"name": n})
            after = self._config_unit(uid).get("name")
        else:
            self.tr064.call(HOMEAUTO, "SetDeviceName", NewAIN=uid, NewDeviceName=n)
            after = self.tr064.call(HOMEAUTO, "GetSpecificDeviceInfos", NewAIN=uid).get("NewDeviceName")
        return {"uid": uid, "name": n, "via": current.get("via"), "changed": True, "verified": after == n}

    # ------------------------------------------------------------ pairing (K-19)

    def _radio_bases(self) -> list[dict[str, Any]]:
        data = self._get("/connect/radioBases")
        return [b for b in data if isinstance(b, dict)] if isinstance(data, list) else []

    def pairing_plan(self, serial: str | None, dect: bool, zigbee: bool) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        if not dect and not zigbee:
            raise InvalidParameterError("Mindestens dect oder zigbee wählen.")
        try:
            bases = self._radio_bases()
            via = "rest"
        except UnsupportedFirmwareError:
            if zigbee and not dect:
                raise UnsupportedFirmwareError("Zigbee-Anmeldung braucht die Smart-Home-REST-API (ab 8.2).") from None
            bases, via = [], "aha"
        base: dict[str, Any] | None = None
        if via == "rest":
            if serial:
                base = next((b for b in bases if b.get("serial") == serial), None)
                if base is None:
                    raise NotFoundError(f"Funkbasis {serial} unbekannt – vorhanden: {[b.get('serial') for b in bases]}")
            else:
                base = next((b for b in bases if b.get("isSmarthomeMaster")), bases[0] if bases else None)
            if base is None:
                raise NotFoundError("Keine Smart-Home-Funkbasis gefunden.")
            if zigbee and not base.get("isZigbeeAvailable"):
                raise InvalidParameterError("Diese Funkbasis kann kein Zigbee.")
            if dect and not base.get("isDectAvailable"):
                raise InvalidParameterError("Diese Funkbasis kann kein DECT.")
        target = (base or {}).get("serial") or "aha"
        params = {"serial": target, "dect": dect, "zigbee": zigbee}
        token = self.plans.issue("smarthome_pairing", params)
        radio = " und ".join(x for x, on in (("DECT-ULE", dect), ("Zigbee", zigbee)) if on)
        warnings = [
            "Während der Anmeldephase kann sich JEDES Gerät in Funkreichweite anmelden – nur starten, wenn das eigene "
            "Gerät bereitliegt.",
            "Die Box beendet die Anmeldung nach kurzer Zeit selbst; smarthome_pairing_stop bricht sie ab.",
        ]
        if base and base.get("activeSubscriptionUid"):
            warnings.append("Auf dieser Funkbasis läuft bereits eine Anmeldung.")
        return {
            "action": "smarthome_pairing",
            "radio_base": {k: base.get(k) for k in BASE_FIELDS[:4]} if base else None,
            "via": via,
            "consequence": f"Startet die {radio}-Geräteanmeldung an der Box (zeitlich begrenzt).",
            "warnings": warnings,
            "token": token,
            "token_valid_s": int(self.plans.ttl),
        }

    def pairing_execute(self, token: str, serial: str | None, dect: bool, zigbee: bool) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        try:
            bases = self._radio_bases()
            via = "rest"
        except UnsupportedFirmwareError:
            bases, via = [], "aha"
        if via == "rest":
            chosen = (
                serial
                or next((b.get("serial") for b in bases if b.get("isSmarthomeMaster")), None)
                or (bases[0].get("serial") if bases else None)
            )
        else:
            chosen = "aha"
        self.plans.redeem(token, "smarthome_pairing", {"serial": chosen, "dect": dect, "zigbee": zigbee})
        if via == "aha":
            self._aha_or_raise().command("startulesubscription")
            state = self._aha_state()
            return {"via": "aha", "started": True, "state": state, "verified": state.get("code") == "1"}
        r = self._req("POST", f"/connect/startSubscription/{chosen}", {"triggerDect": dect, "triggerZigbee": zigbee})
        sub = (r or {}).get("subscriptionUid") if isinstance(r, dict) else None
        state = self._rest_state(sub) if sub else {}
        running = state.get("state") in ("initial", "dectPending", "zigbeePending", "success")
        return {
            "via": "rest",
            "serial": chosen,
            "subscription_uid": sub,
            "started": True,
            "state": state,
            "verified": bool(sub) and running,
            "next_step": "Gerät in den Anlernmodus versetzen, dann smarthome_pairing_status(subscription_uid=…).",
        }

    def _rest_state(self, sub: str) -> dict[str, Any]:
        data = self._get(f"/connect/subscriptionState/{self._uid(sub)}", missing="not_found")
        st = str((data or {}).get("state") or "unknown") if isinstance(data, dict) else "unknown"
        return {
            "state": st,
            "meaning": SUBSCRIPTION_STATES.get(st, st),
            "device_uid": (data or {}).get("deviceUid") or None if isinstance(data, dict) else None,
        }

    def _aha_state(self) -> dict[str, Any]:
        xml = self._aha_or_raise().command("getsubscriptionstate")
        try:
            root = ET.fromstring(xml)
            code = root.get("code") or ""
            latest = (root.findtext("latestain") or "").strip() or None
        except ET.ParseError:
            code, latest = "", None
        return {"code": code, "meaning": AHA_SUBSCRIPTION.get(code, "unbekannt"), "latest_ain": latest}

    def pairing_status(self, subscription_uid: str | None) -> dict[str, Any]:
        if subscription_uid:
            return {"via": "rest", "subscription_uid": subscription_uid, **self._rest_state(subscription_uid)}
        try:
            bases = self._radio_bases()
            return {
                "via": "rest",
                "radio_bases": [{k: b.get(k) for k in BASE_FIELDS} for b in bases],
            }
        except UnsupportedFirmwareError:
            return {"via": "aha", **self._aha_state()}

    def pairing_stop(self, serial: str | None) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        bases = self._radio_bases()
        chosen = serial or next((b.get("serial") for b in bases if b.get("activeSubscriptionUid")), None)
        if not chosen:
            return {"stopped": False, "verified": True, "note": "Keine laufende Anmeldung gefunden."}
        self._req("POST", f"/connect/stopSubscription/{chosen}")
        after = next((b for b in self._radio_bases() if b.get("serial") == chosen), {})
        return {"serial": chosen, "stopped": True, "verified": not after.get("activeSubscriptionUid")}

    # ------------------------------------------------------------ TR-064 Homeauto (K-28)

    @staticmethod
    def _tr064_device(r: dict[str, Any]) -> dict[str, Any]:
        def num(key: str, div: float) -> float | None:
            try:
                return round(int(r.get(key)) / div, 2)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                return None

        def enabled(prefix: str) -> bool:
            return str(r.get(f"New{prefix}IsEnabled")) == "ENABLED"

        out: dict[str, Any] = {
            "ain": r.get("NewAIN"),
            "name": r.get("NewDeviceName"),
            "product": r.get("NewProductName"),
            "firmware": r.get("NewFirmwareVersion") or None,
            "present": r.get("NewPresent"),
        }
        if enabled("Switch"):
            out["switch"] = {
                "state": r.get("NewSwitchState"),
                "mode": r.get("NewSwitchMode"),
                "locked": truthy(r.get("NewSwitchLock")),
            }
        if enabled("Multimeter"):
            out["power_w"] = num("NewMultimeterPower", 100)
            out["energy_wh"] = num("NewMultimeterEnergy", 1)
        if enabled("Temperature"):
            out["temperature_c"] = num("NewTemperatureCelsius", 10)
        if enabled("Hkr"):
            out["thermostat"] = {
                "current_c": num("NewHkrIsTemperature", 10),
                "target_c": num("NewHkrSetTemperature", 10),
                "comfort_c": num("NewHkrComfortTemperature", 10),
                "reduced_c": num("NewHkrReduceTemperature", 10),
            }
        return out

    def tr064_devices(self) -> dict[str, Any]:
        devices = []
        for idx in range(MAX_DEVICES):
            try:
                r = self.tr064.call(HOMEAUTO, "GetGenericDeviceInfos", NewIndex=idx)
            except FritzError as exc:
                if isinstance(exc, NotFoundError) or exc.tr064_code in ("713", "714", "402"):
                    break
                raise
            devices.append(self._tr064_device(r))
        return {
            "count": len(devices),
            "devices": devices,
            "source": "TR-064 X_AVM-DE_Homeauto (ohne Web-Anmeldung; Recht Smart Home)",
        }

    def tr064_set_switch(self, ain: str, on: bool) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        ain = (ain or "").strip()
        if not ain:
            raise InvalidParameterError("ain fehlt.")
        before = self._tr064_device(self.tr064.call(HOMEAUTO, "GetSpecificDeviceInfos", NewAIN=ain))
        if "switch" not in before:
            raise InvalidParameterError(f"{before.get('name') or ain} hat keinen Schalter.")
        want = "ON" if on else "OFF"
        base = {"ain": ain, "name": before.get("name"), "on": on, "via": "tr064"}
        if before["switch"]["state"] == want:
            return {**base, "changed": False, "verified": True}
        self.tr064.call(HOMEAUTO, "SetSwitch", NewAIN=ain, NewSwitchState=want)
        after = self._tr064_device(self.tr064.call(HOMEAUTO, "GetSpecificDeviceInfos", NewAIN=ain))
        return {**base, "changed": True, "verified": (after.get("switch") or {}).get("state") == want}


KindArg = Annotated[Literal["group", "template", "routine"], Field(description="group, template oder routine")]
PeriodsArg = Annotated[list[Period], Field(description="Urlaubszeiträume (max. 4, leer = alle löschen)", max_length=4)]
TempArg = Annotated[float | None, Field(description="Urlaubstemperatur 8–28 °C (0,5er-Schritte)", ge=8, le=28)]
DateArg = Annotated[str | None, Field(description="TT.MM. (Jahr egal, gilt jährlich)")]
SerialArg = Annotated[
    str | None, Field(description="Funkbasis (serial aus smarthome_pairing_status); Standard: Master")
]


def register_smarthome_config_tools(tool: ToolDecorator, svc: Callable[[str | None], SmartHomeConfig]) -> None:
    @tool(Tier.READ, READ)
    def smarthome_thermostat_config(uid: AinArg, box: BoxArg = None) -> dict[str, Any]:
        """Thermostat-Konfiguration (Smart-Home-REST configuration/units): Komfort/Absenk, Urlaubszeiträume mit
        Temperatur, Sommerzeit, Fenster-offen-Einstellungen. Datumsangaben jährlich (TT.MM.)."""
        return svc(box).thermostat_config(uid)

    @tool(Tier.CRITICAL, READ)
    def smarthome_holidays_plan(
        uid: AinArg, periods: PeriodsArg, temperature_c: TempArg = None, box: BoxArg = None
    ) -> dict[str, Any]:
        """Plant die Urlaubsschaltung eines Thermostats (ersetzt alle Zeiträume, max. 4, jährlich): vorher/nachher +
        Token (5 min). Leere Liste = Urlaubszeiträume löschen."""
        return svc(box).holidays_plan(uid, periods, temperature_c)

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def smarthome_holidays_execute(
        token: TokenArg, uid: AinArg, periods: PeriodsArg, temperature_c: TempArg = None, box: BoxArg = None
    ) -> dict[str, Any]:
        """Setzt die geplante Urlaubsschaltung (PUT configuration/units/{UID}) und liest sie zurück."""
        return svc(box).holidays_execute(token, uid, periods, temperature_c)

    @tool(Tier.CRITICAL, READ)
    def smarthome_summer_period_plan(
        uid: AinArg,
        enabled: Annotated[bool, Field(description="true = Sommerzeit an (start/end nötig), false = aus")],
        start: DateArg = None,
        end: DateArg = None,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Plant die Sommerzeit eines Thermostats (heizt dann nicht, jährlich): Folgen + Token (5 min)."""
        return svc(box).summer_plan(uid, enabled, start, end)

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def smarthome_summer_period_execute(
        token: TokenArg,
        uid: AinArg,
        enabled: Annotated[bool, Field(description="wie im Plan")],
        start: DateArg = None,
        end: DateArg = None,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Setzt die geplante Sommerzeit (PUT configuration/units/{UID}) und liest sie zurück."""
        return svc(box).summer_execute(token, uid, enabled, start, end)

    @tool(Tier.CRITICAL, READ)
    def smarthome_delete_plan(kind: KindArg, uid: AinArg, box: BoxArg = None) -> dict[str, Any]:
        """Plant das endgültige Löschen einer Smart-Home-Gruppe, -Vorlage oder -Routine: Name, Folgen + Token."""
        return svc(box).delete_plan(kind, uid)

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def smarthome_delete_execute(token: TokenArg, kind: KindArg, uid: AinArg, box: BoxArg = None) -> dict[str, Any]:
        """Löscht die geplante Gruppe/Vorlage/Routine (DELETE configuration/…/{UID}) und prüft, dass sie weg ist."""
        return svc(box).delete_execute(token, kind, uid)

    @tool(Tier.CRITICAL, READ)
    def smarthome_rename_plan(
        uid: AinArg,
        name: Annotated[str, Field(description="Neuer Name (1–39 Zeichen)")],
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Plant das Umbenennen einer Smart-Home-Einheit (REST configuration/units, Fallback TR-064 SetDeviceName):
        alt/neu + Token (5 min)."""
        return svc(box).rename_plan(uid, name)

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def smarthome_rename_execute(
        token: TokenArg, uid: AinArg, name: Annotated[str, Field(description="wie im Plan")], box: BoxArg = None
    ) -> dict[str, Any]:
        """Benennt die Einheit wie geplant um und liest den Namen zurück."""
        return svc(box).rename_execute(token, uid, name)

    @tool(Tier.READ, READ)
    def smarthome_pairing_status(
        subscription_uid: Annotated[str | None, Field(description="subscription_uid aus dem Execute")] = None,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Status der Geräteanmeldung (REST connect/subscriptionState bzw. AHA getsubscriptionstate); ohne
        subscription_uid die Funkbasen mit laufender Anmeldung. Gibt nie Pairing-/Install-Codes aus."""
        return svc(box).pairing_status(subscription_uid)

    @tool(Tier.CRITICAL, READ)
    def smarthome_pairing_plan(
        serial: SerialArg = None,
        dect: Annotated[bool, Field(description="DECT-ULE-Geräte anlernen")] = True,
        zigbee: Annotated[bool, Field(description="Zigbee-Geräte anlernen (nur REST, Box mit Zigbee)")] = True,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Plant das Anlernen neuer Smart-Home-Geräte (DECT-ULE/Zigbee, zeitlich begrenzt): Funkbasis, Warnungen +
        Token (5 min)."""
        return svc(box).pairing_plan(serial, dect, zigbee)

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def smarthome_pairing_execute(
        token: TokenArg,
        serial: SerialArg = None,
        dect: Annotated[bool, Field(description="wie im Plan")] = True,
        zigbee: Annotated[bool, Field(description="wie im Plan")] = True,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Startet die geplante Geräteanmeldung (REST connect/startSubscription, AHA startulesubscription) und prüft,
        dass sie läuft. Nur nach Zustimmung."""
        return svc(box).pairing_execute(token, serial, dect, zigbee)

    @tool(Tier.WRITE, WRITE)
    def smarthome_pairing_stop(serial: SerialArg = None, box: BoxArg = None) -> dict[str, Any]:
        """Bricht eine laufende Geräteanmeldung ab (REST connect/stopSubscription) und prüft das."""
        return svc(box).pairing_stop(serial)

    @tool(Tier.READ, READ)
    def smarthome_tr064_devices(box: BoxArg = None) -> dict[str, Any]:
        """Smart-Home-Geräte über TR-064 (X_AVM-DE_Homeauto, ohne Web-Anmeldung) – Fallback, wenn REST/AHA nicht
        nutzbar sind: AIN, Name, Produkt, verbunden, Schalter, Leistung/Energie, Temperatur, Thermostat."""
        return svc(box).tr064_devices()

    @tool(Tier.WRITE, WRITE)
    def smarthome_tr064_set_switch(
        ain: AinArg,
        on: Annotated[bool, Field(description="true = an, false = aus")],
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Schaltet eine Steckdose über TR-064 (X_AVM-DE_Homeauto:SetSwitch) und liest den Zustand zurück – Fallback
        zu smarthome_set_switch für Setups ohne Web-/AHA-Zugriff."""
        return svc(box).tr064_set_switch(ain, on)
