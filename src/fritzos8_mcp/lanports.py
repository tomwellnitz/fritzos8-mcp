"""LAN ports (Ethernet) of the FRITZ!Box via /api/v0/generic/eth_ports (FRITZ!OS 8).

Live-verified read on FRITZ!Box 7583 / FRITZ!OS 8.26 (browser capture, 2026-11-14):

- ``GET /api/v0/generic/eth_ports`` → ``{"eth": [{ifname, label "LAN:1"/"WAN:1", UID "ethport8054",
  function lan|guest|wan, carrier 0|1, speed 0|10|100|1000, speed_list, maxspeed, mode, portmode,
  eee_supported, eee_mode, eee_active}]}``
- ``PUT /api/v0/generic/eth_ports/eth/<UID>`` (HTTP 200) – the web UI's write. Its body was NOT captured;
  we send only the changed field (``{"eee_mode": "2"}``), like the live-verified landevice writes.

Observed values: ``eee_mode`` "0" = web UI "Automatisch", "2" = "Aus". ``mode`` "2" = "1 Gbit/s Power
Mode"; the value for "100 Mbit/s Green Mode" is not known, so switching power/green is NOT offered.
On the 7583 EEE acted box-wide: after changing one port, all ports showed ``eee_mode`` "2". Every write
therefore re-reads ALL ports and reports ports the box changed along with the target.

Background (stage-6 live incident): a Raspberry Pi 5 with EEE on a FRITZ!Box port showed link flapping
every ~10 s and 25–45 % packet loss (raspberrypi/linux#7511, home-assistant/operating-system#4861).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from .errors import ConfirmationRequiredError, FritzError, InvalidParameterError, NotFoundError
from .rest import RestClient
from .util import truthy

LIST_PATH = "/api/v0/generic/eth_ports"

EEE_MODES = {"0": "auto", "2": "off"}
EEE_VALUES = {"auto": "0", "off": "2"}
POWER_MODES = {"2": "power"}  # "1 Gbit/s Power Mode"; Green-Mode value unknown

BOX_WIDE_NOTE = (
    "Auf manchen Modellen wirkt die EEE-Einstellung box-weit (live beobachtet an einer FRITZ!Box 7583: "
    "nach Änderung an einem Port standen alle Ports auf demselben Wert)."
)
RELINK_NOTE = (
    "Die betroffenen Ports handeln den Link danach neu aus – kurze Unterbrechung (Sekunden) für dort "
    "angeschlossene Geräte möglich."
)
SILENT_DISCARD = (
    "Die FRITZ!Box hat die Anfrage angenommen, den Wert aber nicht übernommen. Typische Ursache: "
    "Zusatzbestätigung (2FA) für diesen Benutzer aktiv oder das Feld ist auf diesem Modell nicht änderbar. "
    "Nichts geändert."
)


def port_path(uid: str) -> str:
    return f"{LIST_PATH}/eth/{quote(uid, safe='')}"


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def parse_port(raw: dict[str, Any]) -> dict[str, Any]:
    eee_raw = str(raw.get("eee_mode") if raw.get("eee_mode") is not None else "")
    mode_raw = str(raw.get("mode") if raw.get("mode") is not None else "")
    connected = truthy(raw.get("carrier"))
    speed = _int(raw.get("speed"))
    maxspeed = _int(raw.get("maxspeed"))
    speeds = [s for s in (_int(x) for x in str(raw.get("speed_list") or "").split(",")) if s]
    return {
        "label": raw.get("label") or raw.get("ifname"),
        "uid": raw.get("UID") or raw.get("uid"),
        "ifname": raw.get("ifname"),
        "function": raw.get("function") or None,
        "connected": connected,
        "speed_mbit": speed if connected and speed else None,
        "max_speed_mbit": maxspeed,
        "supported_speeds_mbit": speeds or None,
        "below_max_speed": bool(connected and speed and maxspeed and speed < maxspeed),
        "power_mode": POWER_MODES.get(mode_raw, f"unbekannt ({mode_raw})" if mode_raw else None),
        "eee_supported": truthy(raw.get("eee_supported")),
        "eee_mode": EEE_MODES.get(eee_raw, f"unbekannt ({eee_raw})" if eee_raw else None),
        "eee_active": truthy(raw.get("eee_active")),
        "raw": {k: raw.get(k) for k in ("mode", "portmode", "eee_mode", "eee_active", "speed", "carrier")},
    }


def _norm_label(text: str) -> str:
    return re.sub(r"[\s:_-]+", "", text).lower()


class LanPortClient:
    def __init__(self, rest: RestClient) -> None:
        self.rest = rest

    def raw_ports(self) -> list[dict[str, Any]]:
        data = self.rest.request("GET", LIST_PATH, missing="firmware")
        entries = data.get("eth") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            raise FritzError(f'Unerwartete Antwort von GET {LIST_PATH}: keine "eth"-Liste.')
        return [e for e in entries if isinstance(e, dict)]

    def ports(self) -> list[dict[str, Any]]:
        return [parse_port(p) for p in self.raw_ports()]

    def status(self) -> dict[str, Any]:
        ports = self.ports()
        eee_on = [p["label"] for p in ports if p["eee_mode"] == "auto" and p["eee_supported"]]
        notes = [BOX_WIDE_NOTE]
        slow = [p["label"] for p in ports if p["below_max_speed"]]
        if slow:
            notes.append(
                f"Unter Maximalrate verbunden: {', '.join(map(str, slow))} – Kabel (mind. Cat5e, alle 8 Adern), "
                "Stecker oder Gegenstelle prüfen bzw. bewusster Green Mode."
            )
        return {
            "count": len(ports),
            "ports": ports,
            "eee_enabled_ports": eee_on,
            "eee_uniform": len({p["eee_mode"] for p in ports}) <= 1,
            "notes": notes,
            "value_mapping": {
                "eee_mode": {"0": "auto (Web-UI: Automatisch)", "2": "off (Web-UI: Aus)"},
                "mode": {"2": "power (1 Gbit/s Power Mode)", "sonst": "unbekannt – Green-Mode-Wert unbelegt"},
            },
            "source": f"GET {LIST_PATH} (Lesen live bestätigt auf FRITZ!OS 8.26)",
        }

    def resolve(self, port: str, raw: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Port by label ("LAN:1", "LAN 1", "lan1", "1"), ifname ("eth0") or UID."""
        wanted = (port or "").strip()
        if not wanted:
            raise InvalidParameterError('Port angeben, z. B. "LAN:1" (oder "all").')
        entries = raw if raw is not None else self.raw_ports()
        key = _norm_label(wanted)
        if key.isdigit():
            key = f"lan{key}"
        for e in entries:
            names = {str(e.get("UID") or ""), str(e.get("ifname") or ""), str(e.get("label") or "")}
            if wanted in names or key in {_norm_label(n) for n in names if n}:
                return e
        labels = ", ".join(str(e.get("label")) for e in entries)
        raise NotFoundError(f'Port "{port}" nicht gefunden – vorhanden: {labels}.')

    def set_eee(self, port: str, mode: str) -> dict[str, Any]:
        mode = (mode or "").strip().lower()
        if mode not in EEE_VALUES:
            raise InvalidParameterError('mode muss "auto" oder "off" sein.')
        value = EEE_VALUES[mode]
        before = self.raw_ports()
        if port.strip().lower() in {"all", "alle"}:
            targets = [e for e in before if truthy(e.get("eee_supported"))]
        else:
            target = self.resolve(port, before)
            if not truthy(target.get("eee_supported")):
                raise InvalidParameterError(f"Port {target.get('label')} unterstützt kein EEE.")
            targets = [target]
        if not targets:
            raise NotFoundError("Kein Port mit EEE-Unterstützung gefunden.")
        before_by_uid = {str(e.get("UID")): str(e.get("eee_mode")) for e in before}
        target_uids = [str(t.get("UID")) for t in targets]

        written: list[str] = []
        done_by_box: list[str] = []  # targets the box switched along with an earlier write
        current = before
        for uid in target_uids:
            now = {str(e.get("UID")): str(e.get("eee_mode")) for e in current}
            if now.get(uid) == value:
                if written and before_by_uid.get(uid) != value:
                    done_by_box.append(uid)
                continue
            self.rest.request("PUT", port_path(uid), {"eee_mode": value})
            written.append(uid)
            current = self.raw_ports()  # box-wide effect: later targets may already be done

        after = {str(e.get("UID")): e for e in current}
        label = {str(e.get("UID")): e.get("label") for e in before}
        results = []
        for uid in target_uids:
            got = str((after.get(uid) or {}).get("eee_mode"))
            results.append(
                {
                    "port": label.get(uid),
                    "uid": uid,
                    "before": EEE_MODES.get(before_by_uid.get(uid, ""), before_by_uid.get(uid)),
                    "after": EEE_MODES.get(got, got),
                    "written": uid in written,
                    "verified": got == value,
                }
            )
        also_changed = [
            {"port": label.get(uid), "before": EEE_MODES.get(old, old), "after": EEE_MODES.get(new, new)}
            for uid, old in before_by_uid.items()
            if uid not in target_uids and (new := str((after.get(uid) or {}).get("eee_mode"))) != old
        ]
        if written and not any(r["verified"] for r in results):
            raise ConfirmationRequiredError(SILENT_DISCARD)
        out: dict[str, Any] = {
            "mode": mode,
            "changed": bool(written),
            "verified": all(r["verified"] for r in results),
            "ports": results,
            "other_ports_changed": also_changed,
            "box_wide_effect": bool(also_changed or done_by_box),
            "notes": [RELINK_NOTE] if written else [],
        }
        if out["box_wide_effect"]:
            out["notes"].append(
                "Die Box hat weitere Ports mitgeändert bzw. Ports waren nach dem ersten Schreiben schon "
                "umgestellt – EEE wirkt auf diesem Modell box-weit."
            )
        if not written:
            out["notes"].append("Alle Ziel-Ports hatten den Wert schon – nichts geschrieben.")
        if not out["verified"]:
            out["notes"].append(
                "Mindestens ein Port zeigt nach dem Schreiben nicht den Sollwert – NICHT als Erfolg werten."
            )
        return out
