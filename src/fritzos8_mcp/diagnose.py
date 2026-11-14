"""Diagnosis (event log, DSL line, firmware) and a read-only security check via TR-064.

The security check is an own compilation: every item reports ``ok`` / ``warn`` / ``unknown``,
a failing service never aborts the whole report. No credentials are requested
(``GetDDNSInfo``, ``GetSecurityKeys`` etc. stay untouched).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from defusedxml import ElementTree as ET

from .errors import FritzConnectionError, FritzError, InvalidParameterError, NotFoundError
from .tr064 import Tr064Client
from .util import truthy
from .wlan import WlanClient

MAX_LOG_LINES = 500
MAX_PORT_MAPPINGS = 100
_LOG_LINE = re.compile(r"^(?P<date>\d{2}\.\d{2}\.\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<msg>.*)$")


def _strip_new(d: dict[str, Any]) -> dict[str, Any]:
    return {k.removeprefix("New"): v for k, v in d.items()}


def _tenth_db(value: Any) -> float | None:
    try:
        return round(int(value) / 10, 1)
    except (TypeError, ValueError):
        return None


def parse_log_text(text: str) -> list[dict[str, Any]]:
    entries = []
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        m = _LOG_LINE.match(line)
        if m:
            entries.append({"date": m["date"], "time": m["time"], "message": m["msg"]})
        else:
            entries.append({"date": None, "time": None, "message": line})
    return entries


def parse_log_xml(xml_bytes: bytes | str) -> list[dict[str, Any]]:
    root = ET.fromstring(xml_bytes)
    out = []
    for ev in root.iter("Event"):
        out.append(
            {
                "date": ev.findtext("date"),
                "time": ev.findtext("time"),
                "group": ev.findtext("group"),
                "id": ev.findtext("id"),
                "message": ev.findtext("msg") or "",
            }
        )
    return out


# Score weights (points deducted per warning). Information-only checks weigh 0.
SECURITY_WEIGHTS: dict[str, int] = {
    "fernzugriff": 15,
    "myfritz": 5,
    "portfreigaben": 15,
    "upnp": 0,
    "tr064": 0,
    "wps": 10,
    "gast_wlan": 15,
    "firmware": 15,
    "wpa_modus": 15,
    "gast_isolierung": 5,
    "fernzugriff_2fa": 5,
    "dns_over_tls": 3,
    "firmware_auto_update": 5,
    "feste_ips": 0,
    "provider_fernwartung": 0,
}

REMEDIATION: dict[str, str] = {
    "fernzugriff": "Internet > Freigaben > FRITZ!Box-Dienste: 'Internetzugriff auf die FRITZ!Box über HTTPS' "
    "abschalten, wenn nicht nötig – sonst nur mit Zusatzbestätigung (System > FRITZ!Box-Benutzer).",
    "myfritz": "Internet > MyFRITZ!-Konto: MyFRITZ! deaktivieren, falls nicht genutzt.",
    "portfreigaben": "Internet > Freigaben > Portfreigaben: nicht benötigte Freigaben löschen, "
    "'Selbstständige Portfreigaben' nur für Geräte erlauben, die es brauchen.",
    "upnp": "Heimnetz > Netzwerk > Netzwerkeinstellungen: 'Statusinformationen über UPnP übertragen' nur bei Bedarf.",
    "tr064": "Heimnetz > Netzwerk > Netzwerkeinstellungen: 'Zugriff für Anwendungen zulassen' (nötig für diesen "
    "Server); Internetzugriff darauf nur über Fernzugriff mit 2FA.",
    "wps": "WLAN > Sicherheit > WPS-Schnellverbindung: deaktivieren oder nur Push-Button-Verfahren nutzen.",
    "gast_wlan": "WLAN > Gastzugang: Verschlüsselung WPA2 + WPA3 mit eigenem Kennwort statt 'unverschlüsselt'.",
    "firmware": "System > Update: FRITZ!OS auf die aktuelle Version aktualisieren.",
    "wpa_modus": "WLAN > Sicherheit > Verschlüsselung: 'WPA2 + WPA3' (oder 'WPA3'), nicht 'WPA + WPA2' oder "
    "unverschlüsselt.",
    "gast_isolierung": "WLAN > Gastzugang: 'Angemeldete Geräte dürfen untereinander kommunizieren' deaktivieren.",
    "fernzugriff_2fa": "System > FRITZ!Box-Benutzer > Anmeldung: Zusatzbestätigung (2FA) für den Internetzugriff "
    "aktivieren und prüfen.",
    "dns_over_tls": "Internet > Zugangsdaten > DNS-Server: 'Verschlüsselte Namensauflösung im Internet "
    "(DNS over TLS)' aktivieren.",
    "firmware_auto_update": "System > Update > Auto-Update: 'Neue Versionen automatisch installieren' wählen.",
    "feste_ips": "Heimnetz > Netzwerk > Netzwerkverbindungen: feste IPv4 nur für Geräte, die sie brauchen.",
    "provider_fernwartung": "Internet > Zugangsdaten > Anbieter-Dienste: TR-069-Fernwartung bzw. Firmware-Updates "
    "durch den Anbieter – nur abschalten, wenn der Anschluss ohne Anbieter-Konfiguration funktioniert.",
}


def wpa_label(beacon_type: Any) -> str:
    """TR-064 BeaconType → readable mode (heuristic; exact values vary by firmware)."""
    v = str(beacon_type or "").strip().lower()
    if v in {"none", "", "open"}:
        return "offen" if v else "unbekannt"
    if v == "basic":
        return "WEP"
    if "wpa3" in v:
        return "WPA2+WPA3" if ("11i" in v or "wpa2" in v) else "WPA3"
    if v in {"wpaand11i", "wpa+wpa2", "wpawpa2"}:
        return "WPA+WPA2"
    if v in {"11i", "wpa2"}:
        return "WPA2"
    if v == "wpa":
        return "WPA"
    return "unbekannt"


class DiagnoseClient:
    def __init__(self, tr064: Tr064Client, wlan: WlanClient) -> None:
        self.tr064 = tr064
        self.wlan = wlan

    # ---------------------------------------------------------------- event log

    def _log_entries(self) -> tuple[list[dict[str, Any]], str]:
        r = self.tr064.try_call("DeviceInfo1", "GetDeviceLog")
        if r is not None and r.get("NewDeviceLog") is not None:
            return parse_log_text(str(r["NewDeviceLog"])), "GetDeviceLog"
        path = self.tr064.try_call("DeviceInfo1", "X_AVM-DE_GetDeviceLogPath")
        if path and path.get("NewDeviceLogPath"):
            fc = self.tr064.fc
            try:
                response = self.tr064.session_get(f"{fc.address}:{fc.port}{path['NewDeviceLogPath']}")
                if getattr(response, "ok", False):
                    return parse_log_xml(response.content), "X_AVM-DE_GetDeviceLogPath"
            except FritzConnectionError:
                raise
            except Exception:  # noqa: S110 - fall through to a clear NotFoundError
                pass
        raise NotFoundError("Ereignisprotokoll nicht lesbar (weder GetDeviceLog noch DeviceLogPath).")

    def system_log(self, count: int = 50, text_filter: str | None = None) -> dict[str, Any]:
        if not 1 <= count <= MAX_LOG_LINES:
            raise InvalidParameterError(f"count muss 1–{MAX_LOG_LINES} sein.")
        entries, source = self._log_entries()
        total = len(entries)
        if text_filter:
            needle = text_filter.lower()
            entries = [e for e in entries if needle in str(e.get("message") or "").lower()]
        matched = len(entries)
        return {
            "source": source,
            "total": total,
            "matched": matched,
            "returned": min(count, matched),
            "order": "neueste zuerst (wie von der Box geliefert)",
            "entries": entries[:count],
        }

    # ---------------------------------------------------------------- DSL

    def dsl_info(self) -> dict[str, Any]:
        r = self.tr064.try_call("WANDSLInterfaceConfig1", "GetInfo")
        if r is None:
            link = self.tr064.try_call("WANCommonInterfaceConfig1", "GetCommonLinkProperties") or {}
            return {
                "available": False,
                "access_type": link.get("NewWANAccessType"),
                "note": "Kein WANDSLInterfaceConfig – kein DSL-Anschluss (Kabel/Glasfaser/LTE) oder nicht freigegeben.",
            }
        out: dict[str, Any] = {
            "available": True,
            "enabled": truthy(r.get("NewEnable")),
            "status": r.get("NewStatus"),
            "data_path": r.get("NewDataPath"),
            "down_kbps": r.get("NewDownstreamCurrRate"),
            "up_kbps": r.get("NewUpstreamCurrRate"),
            "down_max_kbps": r.get("NewDownstreamMaxRate"),
            "up_max_kbps": r.get("NewUpstreamMaxRate"),
            "snr_down_db": _tenth_db(r.get("NewDownstreamNoiseMargin")),
            "snr_up_db": _tenth_db(r.get("NewUpstreamNoiseMargin")),
            "attenuation_down_db": _tenth_db(r.get("NewDownstreamAttenuation")),
            "attenuation_up_db": _tenth_db(r.get("NewUpstreamAttenuation")),
            "power_down": r.get("NewDownstreamPower"),
            "power_up": r.get("NewUpstreamPower"),
            "dslam_vendor": r.get("NewATURVendor"),
            "units": "Raten in kbit/s; SNR-Marge und Dämpfung aus 1/10 dB umgerechnet",
        }
        stats = self.tr064.try_call("WANDSLInterfaceConfig1", "GetStatisticsTotal")
        if stats:
            out["errors_total"] = _strip_new(stats)
        return out

    # ---------------------------------------------------------------- firmware

    def firmware_status(self) -> dict[str, Any]:
        info = self.tr064.try_call("DeviceInfo1", "GetInfo") or {}
        ui = self.tr064.try_call("UserInterface1", "GetInfo")
        if ui is None:
            raise NotFoundError("UserInterface1:GetInfo nicht verfügbar – Update-Status unbekannt.")
        available = truthy(ui.get("NewUpgradeAvailable"))
        out: dict[str, Any] = {
            "installed": info.get("NewSoftwareVersion"),
            "model": info.get("NewModelName"),
            "update_available": available,
            "available_version": ui.get("NewX_AVM-DE_Version") or None,
            "update_state": ui.get("NewX_AVM-DE_UpdateState"),
            "info_url": ui.get("NewX_AVM-DE_InfoURL") or None,
            # AVM doc UserInterface v19+: X_AVM-DE_LaborVersion was renamed to X_AVM-DE_BuildType
            # (Release, Labor_Beta, …). labor_version stays as alias for compatibility.
            "build_type": ui.get("NewX_AVM-DE_BuildType") or ui.get("NewX_AVM-DE_LaborVersion") or None,
        }
        out["labor_version"] = out["build_type"]
        auto = self.tr064.try_call("UserInterface1", "X_AVM-DE_GetInfo")
        if auto:
            out["auto_update_mode"] = auto.get("NewX_AVM-DE_AutoUpdateMode")
            out["last_update_successful"] = auto.get("NewX_AVM-DE_UpdateSuccessful")
        return out

    # ---------------------------------------------------------------- port mappings

    def port_mappings(self) -> list[dict[str, Any]]:
        status = self.tr064.wan_connection_status()
        service = status["service"]
        n = self.tr064.try_call(service, "GetPortMappingNumberOfEntries")
        count = int(n.get("NewPortMappingNumberOfEntries") or 0) if n else MAX_PORT_MAPPINGS
        out = []
        for idx in range(min(count, MAX_PORT_MAPPINGS)):
            e = self.tr064.try_call(service, "GetGenericPortMappingEntry", NewPortMappingIndex=idx)
            if e is None:  # 713 SpecifiedArrayIndexInvalid = end of list
                break
            out.append(
                {
                    "external_port": e.get("NewExternalPort"),
                    "protocol": e.get("NewProtocol"),
                    "internal_client": e.get("NewInternalClient"),
                    "internal_port": e.get("NewInternalPort"),
                    "enabled": truthy(e.get("NewEnabled")),
                    "description": e.get("NewPortMappingDescription"),
                    "remote_host": e.get("NewRemoteHost") or None,
                    "lease_s": e.get("NewLeaseDuration"),
                }
            )
        return out

    # ---------------------------------------------------------------- security check

    def security_check(
        self,
        dns_over_tls: Callable[[], bool | None] | None = None,
        static_ip_count: Callable[[], int] | None = None,
        extra_checks: list[tuple[str, Callable[[], tuple[str, str, dict[str, Any]]]]] | None = None,
    ) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []

        def check(name: str, fn: Callable[[], tuple[str, str, dict[str, Any]]]) -> None:
            meta = {"weight": SECURITY_WEIGHTS.get(name, 0), "remediation": REMEDIATION.get(name)}
            try:
                status, summary, details = fn()
                checks.append({"check": name, "status": status, "summary": summary, "details": details, **meta})
            except FritzError as exc:
                checks.append(
                    {"check": name, "status": "unknown", "summary": "nicht prüfbar", "error": exc.to_dict(), **meta}
                )

        def remote_access() -> tuple[str, str, dict[str, Any]]:
            r = self.tr064.call("X_AVM-DE_RemoteAccess1", "GetInfo")
            enabled = truthy(r.get("NewEnabled"))
            details = {"enabled": enabled, "port": r.get("NewPort")}
            if enabled:
                return "warn", "Internetzugriff auf die FRITZ!Box (HTTPS) ist aktiv – nur mit 2FA nutzen", details
            return "ok", "kein Internetzugriff auf die Benutzeroberfläche", details

        def myfritz() -> tuple[str, str, dict[str, Any]]:
            r = self.tr064.call("X_AVM-DE_MyFritz1", "GetInfo")
            enabled = truthy(r.get("NewEnabled"))
            details = {"enabled": enabled, "registered": truthy(r.get("NewDeviceRegistered"))}
            if enabled:
                return "warn", "MyFRITZ!-Konto aktiv (Fernzugang/DynDNS möglich)", details
            return "ok", "MyFRITZ! nicht aktiv", details

        def ports() -> tuple[str, str, dict[str, Any]]:
            mappings = self.port_mappings()
            active = [m for m in mappings if m["enabled"]]
            details = {"count": len(mappings), "active": len(active), "mappings": mappings}
            if active:
                return "warn", f"{len(active)} aktive Portfreigabe(n) ins Internet", details
            return "ok", "keine aktiven Portfreigaben (laut WAN-Portmapping)", details

        def upnp() -> tuple[str, str, dict[str, Any]]:
            r = self.tr064.call("X_AVM-DE_UPnP1", "GetInfo")
            details = {
                "status_via_upnp": truthy(r.get("NewEnable")),
                "media_server": truthy(r.get("NewUPnPMediaServer")),
            }
            note = "UPnP-Statusinformationen sind an" if details["status_via_upnp"] else "UPnP-Status aus"
            return "ok", f"{note} (Portfreigaben per UPnP erlaubt FRITZ!OS nur je Gerät, s. Portfreigaben)", details

        def tr064_access() -> tuple[str, str, dict[str, Any]]:
            # We are talking TR-064 right now – local app access is on by definition.
            return (
                "ok",
                "TR-064 im Heimnetz aktiv (nötig für diesen Server); aus dem Internet nur mit Fernzugriff",
                {"local": True},
            )

        def wps() -> tuple[str, str, dict[str, Any]]:
            r = self.tr064.call("WLANConfiguration1", "X_AVM-DE_GetWPSInfo")
            mode = str(r.get("NewX_AVM-DE_WPSMode") or "")
            state = str(r.get("NewX_AVM-DE_WPSStatus") or "")
            details = {"mode": mode or None, "status": state or None}
            if "pin" in mode.lower():
                return "warn", "WPS mit PIN-Verfahren aktiv (angreifbar)", details
            if state.lower() in {"active", "inprogress", "in_progress"}:
                return "warn", "WPS-Anmeldung läuft gerade", details
            return "ok", "kein WPS-PIN-Verfahren, keine laufende WPS-Anmeldung", details

        def guest() -> tuple[str, str, dict[str, Any]]:
            g = self.wlan.guest()
            details = {k: g.get(k) for k in ("service", "enabled", "ssid", "security", "encrypted")}
            if not g["enabled"]:
                return "ok", "Gast-WLAN aus", details
            if not g["encrypted"]:
                return "warn", "Gast-WLAN ist an und UNVERSCHLÜSSELT (offen)", details
            return "ok", "Gast-WLAN an, verschlüsselt", details

        def firmware() -> tuple[str, str, dict[str, Any]]:
            f = self.firmware_status()
            if f["update_available"]:
                return "warn", f"Firmware-Update verfügbar ({f.get('available_version') or 'neue Version'})", f
            return "ok", f"Firmware aktuell ({f.get('installed')})", f

        def wpa_mode() -> tuple[str, str, dict[str, Any]]:
            nets = [n for n in self.wlan.networks() if not n.get("guest") and n.get("enabled") and not n.get("error")]
            modes = {str(n["service"]): wpa_label(n.get("security")) for n in nets}
            details = {"networks": modes, "raw": {str(n["service"]): n.get("security") for n in nets}}
            if not nets:
                return "ok", "kein (Nicht-Gast-)WLAN aktiv", details
            weak = sorted(s for s, m in modes.items() if m in {"offen", "WEP", "WPA", "WPA+WPA2"})
            if weak:
                return "warn", f"schwache WLAN-Verschlüsselung: {', '.join(f'{s}={modes[s]}' for s in weak)}", details
            if all(m == "unbekannt" for m in modes.values()):
                return "unknown", "Verschlüsselungsmodus nicht erkennbar", details
            label = ", ".join(sorted(set(modes.values())))
            if any("WPA3" in m for m in modes.values()):
                return "ok", f"WLAN-Verschlüsselung {label}", details
            return "ok", f"WLAN-Verschlüsselung {label} (WPA2 + WPA3 empfohlen, falls alle Geräte es können)", details

        def guest_isolation() -> tuple[str, str, dict[str, Any]]:
            g = self.wlan.guest()
            extra = g.get("guest_extra") or {}
            details = {"enabled": g["enabled"], "user_isolation": extra.get("user_isolation")}
            if not g["enabled"]:
                return "ok", "Gast-WLAN aus", details
            if extra.get("user_isolation") is None:
                return "unknown", "Gast-Isolierung nicht lesbar", details
            if extra["user_isolation"]:
                return "ok", "Gastgeräte sind voneinander isoliert", details
            return "warn", "Gastgeräte dürfen untereinander kommunizieren", details

        def remote_2fa() -> tuple[str, str, dict[str, Any]]:
            r = self.tr064.call("X_AVM-DE_RemoteAccess1", "GetInfo")
            if not truthy(r.get("NewEnabled")):
                return "ok", "kein Internetzugriff auf die Oberfläche – 2FA hier nicht relevant", {"remote": False}
            return (
                "unknown",
                "Fernzugriff aktiv; ob die Zusatzbestätigung (2FA) dafür greift, ist per TR-064 nicht erkennbar",
                {"remote": True},
            )

        def dot() -> tuple[str, str, dict[str, Any]]:
            if dns_over_tls is None:
                raise NotFoundError("DNS-Einstellungen nicht verfügbar.")
            value = dns_over_tls()
            if value is None:
                raise NotFoundError("DNS over TLS nicht lesbar (/api/v0/generic/dnscfg).")
            if value:
                return "ok", "DNS over TLS aktiv", {"dns_over_tls": True}
            return "warn", "DNS-Anfragen ins Internet unverschlüsselt (DNS over TLS aus)", {"dns_over_tls": False}

        def auto_update() -> tuple[str, str, dict[str, Any]]:
            r = self.tr064.call("UserInterface1", "X_AVM-DE_GetInfo")
            mode = str(r.get("NewX_AVM-DE_AutoUpdateMode") or "").strip()
            details = {"auto_update_mode": mode or None}
            if not mode:
                return "unknown", "Auto-Update-Modus nicht lesbar", details
            if mode.lower() in {"all", "important"}:
                return "ok", f"Automatische Updates aktiv ({mode})", details
            return "warn", f"FRITZ!OS-Updates werden nicht automatisch installiert ({mode})", details

        def static_ips() -> tuple[str, str, dict[str, Any]]:
            if static_ip_count is None:
                raise NotFoundError("Geräteliste nicht verfügbar.")
            n = static_ip_count()
            return "ok", f"{n} Gerät(e) mit fester IPv4-Zuweisung (Information)", {"count": n}

        check("fernzugriff", remote_access)
        check("myfritz", myfritz)
        check("portfreigaben", ports)
        check("upnp", upnp)
        check("tr064", tr064_access)
        check("wps", wps)
        check("gast_wlan", guest)
        check("firmware", firmware)
        check("wpa_modus", wpa_mode)
        check("gast_isolierung", guest_isolation)
        check("fernzugriff_2fa", remote_2fa)
        check("dns_over_tls", dot)
        check("firmware_auto_update", auto_update)
        check("feste_ips", static_ips)
        for name, fn in extra_checks or []:  # stage 8.12: e.g. provider remote management (information)
            check(name, fn)

        counts = {s: sum(1 for c in checks if c["status"] == s) for s in ("ok", "warn", "unknown")}
        overall = "warn" if counts["warn"] else ("unknown" if counts["unknown"] else "ok")
        penalty = sum(c["weight"] for c in checks if c["status"] == "warn")
        score = max(0, 100 - penalty)
        return {
            "overall": overall,
            "score": score,
            "grade": "gut" if score >= 85 else "mittel" if score >= 60 else "kritisch",
            "score_basis": "100 minus Gewicht je Warnung (siehe weight je Check); unknown wird nicht abgezogen"
            + (f" – {counts['unknown']} Check(s) nicht bewertet" if counts["unknown"] else ""),
            "counts": counts,
            "checks": checks,
            "menu_note": "Menüpfade nach FRITZ!OS 8; Bezeichnungen können je Version/Modell leicht abweichen.",
            "not_covered": [
                "Benutzer ohne Zusatzbestätigung (2FA) – per TR-064 nicht abfragbar",
                "Portfreigaben, die nur in der Web-UI angelegt wurden, erscheinen ggf. nicht im WAN-Portmapping",
            ],
        }
