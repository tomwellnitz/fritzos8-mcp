"""Smart Home via AVM's documented AHA-HTTP interface (``/webservices/homeautoswitch.lua``).

Own implementation after AVM's "AHA-HTTP-Interface" documentation:

- ``getdevicelistinfos``         → XML ``<devicelist>`` with ``<device>``/``<group>``
- ``getbasicdevicestats``        → XML ``<devicestats>`` (temperature/voltage/power/energy/humidity)
- ``setswitchon`` / ``setswitchoff`` + ``getswitchstate`` (read back)
- ``sethkrtsoll`` (param 16…56 = 8…28 °C in 0.5-°C steps, 253 = off, 254 = on/max) + ``gethkrtsoll``

The SID goes as query parameter (as documented); it is masked by the central redaction.
Invalid SID → HTTP 403 (one re-login), unknown AIN / unsupported command → HTTP 400 (after one re-login, because
FRITZ!OS 8.25 also answers expired sessions with 400 on /api/v0 – same handling as ``RestClient``).
The newer Smart-Home REST API of FRITZ!OS 8.2 is not used yet: without any DECT device at
the reference box its payloads cannot be verified.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx
from defusedxml import ElementTree as ET

from .auth import SessionManager
from .errors import (
    AuthError,
    ConfirmationRequiredError,
    FritzConnectionError,
    FritzError,
    InvalidParameterError,
    NotFoundError,
    PermissionDeniedError,
)
from .guard import BoxGuard, guarded
from .health import record as record_health
from .util import box_int

log = logging.getLogger(__name__)

AHA_PATH = "/webservices/homeautoswitch.lua"
_AIN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z :\-]{0,39}$")

TEMP_MIN = 8.0
TEMP_MAX = 28.0
HKR_OFF = 253
HKR_ON = 254

# functionbitmask bits (AHA-HTTP-Interface)
FUNCTION_BITS = {
    0: "hanfun_device",
    2: "light",
    4: "alarm_sensor",
    5: "button",
    6: "thermostat",
    7: "energy_meter",
    8: "temperature_sensor",
    9: "switch",
    10: "dect_repeater",
    11: "microphone",
    13: "hanfun_unit",
    15: "on_off",
    16: "dimmable",
    17: "color",
    18: "blind",
    20: "humidity_sensor",
}

# Unit scaling of getbasicdevicestats values.
STATS_SCALE = {
    "temperature": (0.1, "°C"),
    "voltage": (0.001, "V"),
    "power": (0.01, "W"),
    "energy": (1.0, "Wh"),
    "humidity": (1.0, "%"),
}

PERMISSION_HINT = "Der FRITZ!Box-Benutzer braucht das Recht 'Smart Home' (System > FRITZ!Box-Benutzer)."


def normalize_ain(ain: str) -> str:
    value = (ain or "").strip()
    if not _AIN.match(value):
        raise InvalidParameterError(f'Ungültige AIN: "{ain}" (z. B. "08761 0000434").')
    return value


def _ain_key(ain: str) -> str:
    return re.sub(r"\s", "", ain).lower()


def encode_target(target_c: float | None, mode: str | None) -> int:
    """°C → AHA param (2 × °C, 0.5-steps) or 253/254 for 'off'/'max'."""
    if (target_c is None) == (mode is None):
        raise InvalidParameterError("Entweder target_c ODER mode ('off'/'max') angeben.")
    if mode is not None:
        m = mode.strip().lower()
        if m == "off":
            return HKR_OFF
        if m in {"max", "on"}:
            return HKR_ON
        raise InvalidParameterError(f'Unbekannter Modus "{mode}" – erlaubt: off, max.')
    if target_c is None or not TEMP_MIN <= target_c <= TEMP_MAX:
        raise InvalidParameterError(f"Solltemperatur muss {TEMP_MIN:g}–{TEMP_MAX:g} °C sein (ist {target_c:g}).")
    return round(target_c * 2)


def decode_tsoll(raw: Any) -> dict[str, Any]:
    value = box_int(raw)
    if value is None:
        return {"raw": raw, "mode": "unknown", "celsius": None}
    if value == HKR_OFF:
        return {"raw": value, "mode": "off", "celsius": None}
    if value == HKR_ON:
        return {"raw": value, "mode": "max", "celsius": None}
    return {"raw": value, "mode": "temp", "celsius": value / 2}


def _int(value: Any) -> int | None:
    return box_int(value)


def _functions(mask: int) -> list[str]:
    return [name for bit, name in FUNCTION_BITS.items() if mask & (1 << bit)]


def parse_device(node: Any) -> dict[str, Any]:
    mask = _int(node.get("functionbitmask")) or 0
    functions = _functions(mask)
    dev: dict[str, Any] = {
        "ain": (node.get("identifier") or "").strip(),
        "name": node.findtext("name") or "",
        "kind": "group" if node.tag == "group" else "device",
        "product": node.get("productname") or None,
        "manufacturer": node.get("manufacturer") or None,
        "firmware": node.get("fwversion") or None,
        "present": node.findtext("present") == "1",
        "busy": node.findtext("txbusy") == "1",
        "functions": functions,
        "type": "thermostat"
        if "thermostat" in functions
        else "switch"
        if "switch" in functions
        else (functions[0] if functions else "unknown"),
    }
    sw = node.find("switch")
    if sw is not None:
        state = sw.findtext("state")
        dev["switch"] = {
            "on": None if state in (None, "") else state == "1",
            "mode": sw.findtext("mode"),
            "locked": sw.findtext("lock") == "1",
            "device_locked": sw.findtext("devicelock") == "1",
        }
    pm = node.find("powermeter")
    if pm is not None:
        power = _int(pm.findtext("power"))
        energy = _int(pm.findtext("energy"))
        voltage = _int(pm.findtext("voltage"))
        dev["power"] = {
            "power_w": None if power is None else power / 1000,
            "energy_wh": energy,
            "voltage_v": None if voltage is None else voltage / 1000,
        }
    temp = node.find("temperature")
    if temp is not None:
        celsius = _int(temp.findtext("celsius"))
        offset = _int(temp.findtext("offset"))
        dev["temperature_c"] = None if celsius is None else celsius / 10
        dev["temperature_offset_c"] = None if offset is None else offset / 10
    hum = node.find("humidity")
    if hum is not None:
        dev["humidity_pct"] = _int(hum.findtext("rel_humidity"))
    hkr = node.find("hkr")
    if hkr is not None:
        tist = _int(hkr.findtext("tist"))
        dev["thermostat"] = {
            "current_c": None if tist is None else tist / 2,
            "target": decode_tsoll(hkr.findtext("tsoll")),
            "comfort": decode_tsoll(hkr.findtext("komfort")),
            "economy": decode_tsoll(hkr.findtext("absenk")),
            "battery_pct": _int(hkr.findtext("battery")),
            "battery_low": hkr.findtext("batterylow") == "1",
            "window_open": hkr.findtext("windowopenactiv") == "1",
            "error_code": _int(hkr.findtext("errorcode")),
        }
    return dev


def parse_device_list(xml_text: str) -> list[dict[str, Any]]:
    text = (xml_text or "").strip()
    if not text:
        return []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        raise FritzError("Antwort von getdevicelistinfos ist kein gültiges XML.") from None
    return [parse_device(n) for n in root if n.tag in ("device", "group")]


def parse_stats(xml_text: str) -> dict[str, Any]:
    try:
        root = ET.fromstring((xml_text or "").strip() or "<devicestats/>")
    except ET.ParseError:
        raise FritzError("Antwort von getbasicdevicestats ist kein gültiges XML.") from None
    out: dict[str, Any] = {}
    for section in root:
        scale, unit = STATS_SCALE.get(section.tag, (1.0, None))
        series = []
        for st in section.findall("stats"):
            values: list[float | None] = []
            for v in (st.text or "").split(","):
                v = v.strip()
                n = _int(v) if v and v != "-" else None
                values.append(None if n is None else round(n * scale, 3))
            series.append(
                {
                    "grid_s": _int(st.get("grid")),
                    "count": _int(st.get("count")),
                    "datatime": _int(st.get("datatime")),
                    "values": values,
                }
            )
        out[section.tag] = {"unit": unit, "series": series}
    return out


class AhaClient:
    def __init__(self, http: httpx.Client, session: SessionManager, guard: BoxGuard | None = None) -> None:
        self._http = http
        self._session = session
        self.guard = guard  # stage 7.1: throttling + breaker (no cache for Smart Home)

    def command(self, cmd: str, ain: str | None = None, **extra: Any) -> str:
        read = cmd.startswith("get")
        try:
            text = guarded(
                self.guard, lambda: self._command(cmd, ain, **extra), what=f"Smart Home {cmd}", idempotent=read
            )
        except FritzError as exc:
            record_health(self.guard, "aha", exc)
            raise
        else:
            record_health(self.guard, "aha", None)
            return text
        finally:
            if not read and self.guard is not None:
                self.guard.invalidate()

    def _command(self, cmd: str, ain: str | None = None, **extra: Any) -> str:
        for attempt in range(2):
            sid = self._session.get_sid() if attempt == 0 else self._session.relogin()
            params: dict[str, Any] = {"switchcmd": cmd, "sid": sid}
            if ain is not None:
                params["ain"] = ain
            params.update(extra)
            try:
                response = self._http.get(AHA_PATH, params=params)
            except httpx.HTTPError as exc:
                raise FritzConnectionError(f"Smart Home {cmd}: {type(exc).__name__}") from None
            status = response.status_code
            text = response.text or ""
            if "TWO-FACTOR" in text.upper():
                raise ConfirmationRequiredError(f"Smart Home {cmd}: Zusatzbestätigung verlangt.")
            if status in (401, 403):
                if attempt == 0:
                    log.info("Smart Home %s: Sitzung abgelehnt (HTTP %s) – neuer Login", cmd, status)
                    continue
                if status == 403:
                    raise PermissionDeniedError(
                        f"Smart Home {cmd}: Zugriff verweigert (HTTP 403).", hint=PERMISSION_HINT
                    )
                raise AuthError(f"Smart Home {cmd}: Sitzung auch nach erneutem Login abgelehnt.")
            # Like /api/v0 (live FRITZ!OS 8.25): an expired/displaced session can come back as HTTP 400 instead of
            # 403 – so one fresh login first; a second 400 is the documented meaning (unknown AIN/command).
            if status == 400 and attempt == 0:
                log.info("Smart Home %s: HTTP 400 – Sitzung evtl. ungültig, neuer Login", cmd)
                continue
            if status == 400:
                raise InvalidParameterError(
                    f"Smart Home {cmd}: von der Box abgelehnt (HTTP 400) – AIN unbekannt oder Befehl "
                    "für dieses Gerät nicht unterstützt."
                )
            if status == 404:
                raise NotFoundError(f"Smart Home {cmd}: AHA-Schnittstelle nicht gefunden (HTTP 404).")
            if not 200 <= status < 300:
                raise FritzError(f"Smart Home {cmd}: HTTP {status}")
            return text
        raise AssertionError("unreachable")  # pragma: no cover

    # ---------------------------------------------------------------- read

    def list_devices(self) -> list[dict[str, Any]]:
        return parse_device_list(self.command("getdevicelistinfos"))

    def find(self, ain: str) -> dict[str, Any]:
        key = _ain_key(normalize_ain(ain))
        for dev in self.list_devices():
            if _ain_key(dev["ain"]) == key:
                return dev
        raise NotFoundError(f"Kein Smart-Home-Gerät mit AIN {ain} – siehe smarthome_list_devices.")

    def device_stats(self, ain: str) -> dict[str, Any]:
        dev = self.find(ain)
        stats = parse_stats(self.command("getbasicdevicestats", dev["ain"]))
        return {"ain": dev["ain"], "name": dev["name"], "stats": stats}

    # ---------------------------------------------------------------- write

    def set_switch(self, ain: str, on: bool) -> dict[str, Any]:
        dev = self.find(ain)
        if "switch" not in dev["functions"]:
            raise InvalidParameterError(f"{dev['name']} ({dev['ain']}) ist keine schaltbare Steckdose.")
        base = {"ain": dev["ain"], "name": dev["name"], "on": on}
        current = dev.get("switch", {}).get("on")
        if current is on:
            return {**base, "changed": False, "verified": True}
        if dev.get("switch", {}).get("locked") or dev.get("switch", {}).get("device_locked"):
            raise InvalidParameterError(f"{dev['name']} ist gesperrt (Bedien-/Tastensperre) – nicht geschaltet.")
        self.command("setswitchon" if on else "setswitchoff", dev["ain"])
        state = self.command("getswitchstate", dev["ain"]).strip()
        if state not in ("0", "1"):
            return {
                **base,
                "changed": None,
                "verified": False,
                "read_back": state or None,
                "note": "Schaltbefehl gesendet, Zustand aber nicht rücklesbar (Gerät nicht erreichbar?).",
            }
        if (state == "1") != on:
            return {
                **base,
                "changed": False,
                "verified": False,
                "read_back": state == "1",
                "note": "Die Box meldet nach dem Schalten weiterhin den alten Zustand – nicht übernommen.",
            }
        return {**base, "changed": True, "verified": True}

    def set_thermostat(self, ain: str, target_c: float | None = None, mode: str | None = None) -> dict[str, Any]:
        param = encode_target(target_c, mode)
        dev = self.find(ain)
        if "thermostat" not in dev["functions"]:
            raise InvalidParameterError(f"{dev['name']} ({dev['ain']}) ist kein Heizkörperthermostat.")
        wanted = decode_tsoll(param)
        base = {"ain": dev["ain"], "name": dev["name"], "target": wanted}
        current = dev.get("thermostat", {}).get("target", {}).get("raw")
        if current == param:
            return {**base, "changed": False, "verified": True}
        self.command("sethkrtsoll", dev["ain"], param=param)
        after = self.command("gethkrtsoll", dev["ain"]).strip()
        read_back = decode_tsoll(after)
        if read_back["mode"] == "unknown":
            return {
                **base,
                "changed": None,
                "verified": False,
                "read_back": after or None,
                "note": "Solltemperatur gesendet, aber nicht rücklesbar.",
            }
        if read_back["raw"] != param:
            return {
                **base,
                "changed": False,
                "verified": False,
                "read_back": read_back,
                "note": "Die Box meldet weiterhin einen anderen Sollwert – nicht übernommen.",
            }
        return {
            **base,
            "changed": True,
            "verified": True,
            "note": "Sollwert in der Box gespeichert; batteriebetriebene Thermostate übernehmen ihn beim "
            "nächsten Funkkontakt (bis ca. 15 min).",
        }
