"""Stage 8.12 – system transparency (read only): provider remote management (TR-069), time/NTP incl. clock offset,
IPv6 status (connection, prefix, DS-Lite, IPv6 firewall), static routes, forced-disconnect hour, auto-update mode.

Own implementation after the AVM documents:

* ``ManagementServer:GetInfo`` (ACS URL, periodic inform, upgrades managed) and
  ``X_AVM_DE_GetTR069FirmwareDownloadEnabled``. User names, connection request URL and parameter key are not output.
* ``Time:GetInfo`` → NTPServer1/2, CurrentLocalTime (time zone fields are "not supported" per AVM doc).
* ``WANIPConnection``/``WANPPPConnection:GetInfo`` → ``X_AVM-DE_IPv6ConnectionStatus``/``X_AVM-DE_IPv6Uptime``
  (doc 2025-12); IGD ``WANIPConn1``: ``X_AVM_DE_GetIPv6Prefix``, ``X_AVM_DE_GetDsliteStatus``; IGD
  ``WANIPv6FirewallControl:GetFirewallStatus`` (service id differs between descriptions → several names tried).
* ``Layer3Forwarding``: ``GetForwardNumberOfEntries``/``GetGenericForwardingEntry`` (static routes).
* ``WANPPPConnection:X_AVM_DE_GetAutoDisconnectTimeSpan`` → DisconnectPreventionEnable/Hour.
"""

from __future__ import annotations

import ipaddress
import time
from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from .errors import AuthError, ConfirmationRequiredError, FritzConnectionError, FritzError, NotFoundError
from .nasremote import ToolDecorator
from .security import Tier
from .toolargs import READ, BoxArg
from .tr064 import IGD_WAN_IP
from .util import truthy

if TYPE_CHECKING:
    from .diagnose import DiagnoseClient
    from .tr064 import Tr064Client

CLOCK_OFFSET_WARN_S = 60
IPV6_FIREWALL_SERVICES = ("WANIPv6Firewall1", "WANIPv6FirewallControl1")
MAX_ROUTES = 32


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _url_host(url: Any) -> str | None:
    text = str(url or "").strip()
    if not text:
        return None
    parts = urlsplit(text)
    return f"{parts.scheme}://{parts.hostname}" if parts.scheme and parts.hostname else None


def parse_firewall_status(r: dict[str, Any]) -> dict[str, Any]:
    """Fields with or without the ``New`` prefix; a missing field is None (unknown), never False."""

    def flag(name: str) -> bool | None:
        value = r.get(f"New{name}", r.get(name))
        return None if value in (None, "") else truthy(value)

    enabled = flag("FirewallEnabled")
    allowed = flag("InboundPinholeAllowed")
    out: dict[str, Any] = {"enabled": enabled, "inbound_pinholes_allowed": allowed}
    if enabled is None and allowed is None:
        out["status"] = "unknown"
    return out


class SystemTransparency:
    def __init__(self, tr064: Tr064Client, diag: DiagnoseClient, now: Callable[[], float] = time.time) -> None:
        self.tr064 = tr064
        self.diag = diag
        self.now = now

    def tr069(self) -> dict[str, Any]:
        r = self.tr064.call("ManagementServer1", "GetInfo")
        acs = _url_host(r.get("NewURL"))
        periodic = truthy(r.get("NewPeriodicInformEnable"))
        fw = self.tr064.try_call("ManagementServer1", "X_AVM_DE_GetTR069FirmwareDownloadEnabled")
        return {
            "available": True,
            "active": bool(acs) and periodic,
            "acs": acs,
            "periodic_inform": periodic,
            "inform_interval_s": _int(r.get("NewPeriodicInformInterval")),
            "upgrades_managed_by_provider": truthy(r.get("NewUpgradesManaged")),
            "provider_firmware_download": None if fw is None else truthy(fw.get("NewTR069FirmwareDownloadEnabled")),
            "meaning": "TR-069 = Fernwartung durch den Provider (Konfiguration, ggf. Firmware). Abschalten nur, wenn "
            "der Anschluss ohne Provider-Konfiguration läuft (Internet > Zugangsdaten > Anbieter-Dienste).",
        }

    def time_info(self) -> dict[str, Any]:
        r = self.tr064.call("Time1", "GetInfo")
        raw = str(r.get("NewCurrentLocalTime") or "")
        offset = None
        try:
            box_time = datetime.fromisoformat(raw)
            box_ts = box_time.timestamp() if box_time.tzinfo else time.mktime(box_time.timetuple())
            offset = round(box_ts - self.now(), 1)
        except ValueError:
            pass
        return {
            "available": True,
            "ntp_servers": [s for s in (r.get("NewNTPServer1"), r.get("NewNTPServer2")) if s],
            "box_time": raw or None,
            "offset_s": offset,
            "offset_ok": None if offset is None else abs(offset) <= CLOCK_OFFSET_WARN_S,
            "note": "Abweichung = Box-Uhr minus Uhr dieses Rechners (beide können falsch gehen). Falsche Uhrzeit "
            "führt zu TLS-/Zertifikatsfehlern und falschen Zeitplänen.",
        }

    def ipv6(self) -> dict[str, Any]:
        out: dict[str, Any] = {"available": True}
        try:
            service = str(self.tr064.wan_connection_status()["service"])
        except FritzError:
            service = IGD_WAN_IP
        # AVM doc (WANIPConnection v7 / WANPPPConnection v16, 2025-12-18): GetInfo of the active WAN service carries
        # X_AVM-DE_IPv6ConnectionStatus/-Uptime. Live on 8.25/8.26 the field is missing → status from the prefix.
        info = self.tr064.try_call(service, "GetInfo") or {}
        status = info.get("NewX_AVM-DE_IPv6ConnectionStatus") or None
        out["connection_status"] = status or "unknown"
        out["uptime_s"] = _int(info.get("NewX_AVM-DE_IPv6Uptime"))
        prefix = self.tr064.call_igd_first(service, "X_AVM_DE_GetIPv6Prefix")
        out["prefix"] = None
        if prefix:
            p = prefix[1]
            raw = str(p.get("NewIPv6Prefix") or "").strip()
            length = _int(p.get("NewPrefixLength"))
            valid = _int(p.get("NewValidLifetime"))
            try:
                unspecified = ipaddress.IPv6Address(raw).is_unspecified if raw else True
            except ValueError:
                unspecified = True
            # Live (6660 Cable ohne IPv6): "::"/0 mit Lebensdauer 0 = kein Präfix, kein Fehler.
            if not unspecified and length and valid != 0:
                out["prefix"] = f"{raw}/{length}"
                out["prefix_valid_s"] = valid
                out["prefix_preferred_s"] = _int(p.get("NewPreferedLifetime"))
        out["ipv6_active"] = (status == "Connected") if status else bool(out["prefix"])
        if not out["prefix"]:
            out["prefix_note"] = "kein IPv6-Präfix vom Provider (IPv6 aus oder nicht angeboten)"
        if not status:
            out["connection_status_note"] = (
                "X_AVM-DE_IPv6ConnectionStatus liefert diese FRITZ!OS-Version nicht (laut AVM-Doku neu seit 12/2025); "
                "ipv6_active ist aus dem Präfix abgeleitet."
            )
        dslite = self.tr064.call_igd_first(service, "X_AVM_DE_GetDsliteStatus")
        out["ds_lite"] = None if dslite is None else truthy(dslite[1].get("NewX_AVM_DE_DsliteStatus"))
        if out["ds_lite"]:
            out["ds_lite_note"] = (
                "DS-Lite: keine eigene öffentliche IPv4 – IPv4-Portfreigaben sind von außen nicht erreichbar; "
                "Dienste nur über IPv6 (Freigabe + Firewall) oder einen Tunnel/Relay anbieten."
            )
        out["firewall"] = self.ipv6_firewall()
        return out

    def ipv6_firewall(self) -> dict[str, Any]:
        """IGD ``WANIPv6FirewallControl:GetFirewallStatus`` – same source/logic as ``ipv6_firewall_status``.
        Live (7583/8.26): service ``WANIPv6Firewall1``, fields WITHOUT the ``New`` prefix. Unreadable = unknown."""
        for name in IPV6_FIREWALL_SERVICES:
            r = self.tr064.try_call(name, "GetFirewallStatus")
            if r:
                return {"service": name, **parse_firewall_status(r)}
        return {
            "status": "unknown",
            "enabled": None,
            "inbound_pinholes_allowed": None,
            "note": "IGD WANIPv6FirewallControl nicht erreichbar (UPnP-Statusinformationen aus?).",
        }

    def routes(self) -> dict[str, Any]:
        n = self.tr064.call("Layer3Forwarding1", "GetForwardNumberOfEntries")
        count = min(_int(n.get("NewForwardNumberOfEntries")) or 0, MAX_ROUTES)
        routes = []
        for idx in range(count):
            e = self.tr064.try_call("Layer3Forwarding1", "GetGenericForwardingEntry", NewForwardingIndex=idx)
            if e is None:
                break
            routes.append(
                {
                    "enabled": truthy(e.get("NewEnable")),
                    "status": e.get("NewStatus") or None,
                    "destination": e.get("NewDestIPAddress"),
                    "netmask": e.get("NewDestSubnetMask"),
                    "gateway": e.get("NewGatewayIPAddress"),
                    "interface": e.get("NewInterface") or None,
                    "metric": _int(e.get("NewForwardingMetric")),
                }
            )
        return {"available": True, "count": len(routes), "routes": routes}

    def forced_disconnect(self) -> dict[str, Any]:
        """AVM doc WANPPPConnection 1.23 ``X_AVM_DE_GetAutoDisconnectTimeSpan`` – only on the ACTIVE PPP service.
        Live: cable box (no PPP) and the 7583 (PPP, 8.26) both answer not_found → available false with a note."""
        try:
            service = str(self.tr064.wan_connection_status()["service"])
        except NotFoundError:
            service = ""
        if service != "WANPPPConnection1":
            return {
                "available": False,
                "note": "Zwangstrennung/Verlegung gibt es nur bei PPP-Anschlüssen (aktiver WAN-Dienst: "
                + (service or "unbekannt")
                + ").",
            }
        try:
            _, r = self.tr064.call_first(
                service, ("X_AVM_DE_GetAutoDisconnectTimeSpan", "X_AVM-DE_GetAutoDisconnectTimeSpan")
            )
        except NotFoundError:
            return {
                "available": False,
                "note": "Die Box bietet X_AVM_DE_GetAutoDisconnectTimeSpan nicht an (live auf FRITZ!OS 8.26 an einem "
                "PPP-Anschluss beobachtet) – Einstellung nur in der Web-UI (Internet > Zugangsdaten > Verbindung).",
            }
        enabled = truthy(r.get("NewX_AVM-DE_DisconnectPreventionEnable"))
        hour = _int(r.get("NewX_AVM-DE_DisconnectPreventionHour"))
        return {
            "available": True,
            "shift_enabled": enabled,
            "hour": hour,
            "meaning": f"Zwangstrennung wird in die Stunde {hour}–{(hour or 0) + 1} Uhr verlegt"
            if enabled and hour is not None
            else "keine Verlegung der Zwangstrennung eingestellt (bzw. Anschluss ohne PPP)",
        }

    def _section(self, fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        try:
            return fn()
        except (AuthError, ConfirmationRequiredError, FritzConnectionError):
            raise
        except FritzError as exc:
            return {"available": False, "status": "unknown", "error": exc.to_dict()}

    def overview(self) -> dict[str, Any]:
        fw = self._section(self.diag.firmware_status)
        return {
            "tr069": self._section(self.tr069),
            "time": self._section(self.time_info),
            "ipv6": self._section(self.ipv6),
            "static_routes": self._section(self.routes),
            "forced_disconnect": self._section(self.forced_disconnect),
            "auto_update": {
                "available": "installed" in fw,
                "mode": fw.get("auto_update_mode"),
                "modes": "all = alle Updates automatisch, important = nur wichtige, notify = nur informieren",
            },
        }

    def security_item(self) -> tuple[str, str, dict[str, Any]]:
        """security_check entry (weight 0 – information, no score impact)."""
        t = self.tr069()
        if t["active"]:
            who = "Provider darf auch Firmware einspielen" if t["provider_firmware_download"] else "Konfiguration"
            return "ok", f"Provider-Fernwartung (TR-069) aktiv über {t['acs']} ({who}) – Information", t
        return "ok", "Provider-Fernwartung (TR-069) nicht aktiv – Information", t

    def doctor_findings(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        t = self._section(self.time_info)
        if t.get("offset_ok") is False:
            out.append(
                {
                    "severity": "warn",
                    "area": "system",
                    "finding": f"Uhrzeit der Box weicht um {t['offset_s']} s von diesem Rechner ab.",
                    "likely_cause": "deutet auf fehlende Zeitsynchronisation (NTP) der Box oder dieses Rechners hin",
                    "recommendation": "Heimnetz > Netzwerk > Netzwerkeinstellungen > Zeitsynchronisation prüfen; "
                    "auch die Uhr dieses Rechners prüfen.",
                    "evidence": {"offset_s": t["offset_s"], "ntp_servers": t.get("ntp_servers")},
                }
            )
        v6 = self._section(self.ipv6)
        if v6.get("ds_lite"):
            out.append(
                {
                    "severity": "info",
                    "area": "wan",
                    "finding": "Anschluss mit DS-Lite (keine eigene öffentliche IPv4).",
                    "likely_cause": "Provider-Technik, kein Fehler",
                    "recommendation": "Erreichbarkeit von außen nur per IPv6 oder Tunnel planen; IPv4-Portfreigaben "
                    "wirken nicht.",
                    "evidence": {"prefix": v6.get("prefix")},
                }
            )
        status = str(v6.get("connection_status") or "")
        if status and status not in ("Connected", "unknown"):
            out.append(
                {
                    "severity": "info",
                    "area": "wan",
                    "finding": f"IPv6-Verbindung: {status}.",
                    "likely_cause": "IPv6 beim Anschluss nicht aktiv oder (noch) nicht aufgebaut",
                    "recommendation": "Internet > Zugangsdaten > IPv6 prüfen, falls IPv6 genutzt werden soll.",
                    "evidence": {"ipv6_connection_status": status},
                }
            )
        return out


def register_transparency_tools(tool: ToolDecorator, svc: Callable[[str | None], SystemTransparency]) -> None:
    @tool(Tier.READ, READ)
    def system_transparency(box: BoxArg = None) -> dict[str, Any]:
        """System-Transparenz (nur lesend): Provider-Fernwartung TR-069 (aktiv, Server, Firmware durch Provider),
        Zeit/NTP mit Abweichung zur Uhr dieses Rechners, IPv6 (Verbindungsstatus, Präfix + Lebensdauer, DS-Lite,
        IPv6-Firewall), statische Routen, Verlegung der Zwangstrennung, Auto-Update-Modus."""
        return svc(box).overview()
