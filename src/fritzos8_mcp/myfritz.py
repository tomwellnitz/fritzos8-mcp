"""MyFRITZ!, DynDNS, remote access (Fernzugriff), cloud management (USP) and app rights via TR-064.

Own implementation after the official AVM/FRITZ! TR-064 documents (2025-08):

- ``X_AVM-DE_MyFritz1`` (TR-064_MyFRITZ.pdf): ``GetInfo``, ``GetNumberOfServices``, ``GetServiceByIndex``.
  ``NewEmail`` (account e-mail) is personal data and never returned (only whether one is set).
- ``X_AVM-DE_RemoteAccess1`` (TR-064_Remote_Access_SCPD.pdf): ``GetInfo``, ``GetDDNSInfo`` (documented name,
  without ``X_AVM-DE_`` prefix; the earlier spelling is kept as fallback)
  (whitelisted: no user name, no update URL – it can carry account data), ``SetEnable`` (no password
  argument, returns the HTTPS port). ``SetConfig`` needs a password and is NOT used.
- ``X_AVM-DE_USPController1`` (TR-064_USP_Controller.pdf): MyFRITZ! cloud management flag and the
  configured USP controllers (without user names).
- ``X_AVM-DE_AppSetup1`` (TR-064_App_Setup.pdf): ``GetConfig`` = rights of the current (MCP) user.
  ``NewInternetRights`` = "are access rights from the internet configured?" (the RIGHT of the user);
  ``NewAccessFromInternet`` = "is the current access coming from the internet?" (THIS request) – neither says
  whether internet access is switched on; that is ``RemoteAccess:GetInfo`` ``NewEnabled``.
  There is no TR-064 action that lists registered apps.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from .errors import FritzError
from .tr064 import Tr064Client
from .util import truthy

MYFRITZ = "X_AVM-DE_MyFritz1"
REMOTE = "X_AVM-DE_RemoteAccess1"
USP = "X_AVM-DE_USPController1"
APPSETUP = "X_AVM-DE_AppSetup1"
# AVM doc "Remote Access" names the action GetDDNSInfo; the prefixed spelling used before is only a fallback.
DDNS_INFO_ACTIONS = ("GetDDNSInfo", "X_AVM-DE_GetDDNSInfo")

MAX_SERVICES = 50
MAX_CONTROLLERS = 20

MYFRITZ_STATES = {
    "myfritz_disabled": "MyFRITZ! aus oder Box nicht registriert",
    "register_failed": "Registrierung fehlgeschlagen (Box versucht es erneut)",
    "unregister": "Box wird abgemeldet",
    "dyndns_unknown": "registriert, DynDNS-Zustand unbekannt",
    "dyndns_active": "registriert, DynDNS aktiv",
    "dyndns_update_failed": "registriert, DynDNS-Update fehlgeschlagen",
    "dyndns_auth_error": "registriert, DynDNS-Update fehlgeschlagen (Anmeldefehler)",
    "dyndns_server_unreachable": "registriert, DynDNS-Server nicht erreichbar",
    "dyndns_server_error": "registriert, DynDNS-Server meldet Fehler",
    "dyndns_server_update": "registriert, DynDNS-Server: kein Adress-Update möglich",
    "dyndns_not_verified": "registriert, DynDNS aktualisiert, noch nicht verifiziert",
    "dyndns_verified": "registriert, DynDNS aktualisiert und verifiziert",
}
_MYFRITZ_STATE_ERRORS = {
    "register_failed",
    "dyndns_update_failed",
    "dyndns_auth_error",
    "dyndns_server_unreachable",
    "dyndns_server_error",
    "dyndns_server_update",
}
IPV4_FORWARDING = {0: "unbekannt", 1: "nicht nötig oder erfolgreich", 2: "fehlgeschlagen"}
USP_RIGHTS = ("Smarthome", "Mesh", "Internet", "System", "Controller", "WiFi", "VoIP")
APP_RIGHTS = {
    "config": "NewConfigRight",
    "app": "NewAppRight",
    "nas": "NewNasRight",
    "phone": "NewPhoneRight",
    "dial": "NewDialRight",
    "homeauto": "NewHomeautoRight",
}


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_myfritz_service(e: dict[str, Any], index: int) -> dict[str, Any]:
    forwarding = _int(e.get("NewIPv4ForwardingWarning"))
    return {
        "index": index,
        "name": e.get("NewName") or None,
        "enabled": truthy(e.get("NewEnabled")),
        "scheme": e.get("NewScheme") or None,
        "port": _int(e.get("NewPort")),
        "url_path": e.get("NewURLPath") or None,
        "type": e.get("NewType") or None,
        "target_ipv4": e.get("NewIPv4Addresses") or None,
        "target_host": e.get("NewHostName") or None,
        "status": _int(e.get("NewStatus")),
        "ipv4_forwarding": None if forwarding is None else IPV4_FORWARDING.get(forwarding, str(forwarding)),
    }


def parse_usp_controller(e: dict[str, Any], index: int) -> dict[str, Any]:
    return {
        "index": index,
        "enabled": truthy(e.get("NewEnable")),
        "endpoint_id": e.get("NewEndpointID") or None,
        "mtp": e.get("NewMTP") or None,
        "host": e.get("NewHostname") or None,
        "port": _int(e.get("NewPort")),
        "use_tls": truthy(e.get("NewUseTLS")),
        "rights": [r.lower() for r in USP_RIGHTS if truthy(e.get(f"NewAccessRight{r}"))],
    }


def _check(name: str, status: str, summary: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"check": name, "status": status, "summary": summary, "details": details or {}}


class MyFritzClient:
    def __init__(self, tr064: Tr064Client, sleep: Callable[[float], None] = time.sleep) -> None:
        self.tr064 = tr064
        self._sleep = sleep

    # ---------------------------------------------------------------- read

    def account(self) -> dict[str, Any]:
        r = self.tr064.call(MYFRITZ, "GetInfo")
        state = str(r.get("NewState") or "") or None
        return {
            "available": True,
            "enabled": truthy(r.get("NewEnabled")),
            "registered": truthy(r.get("NewDeviceRegistered")),
            "address": r.get("NewDynDNSName") or None,
            "port": _int(r.get("NewPort")),
            "state": state,
            "state_text": MYFRITZ_STATES.get(state or ""),
            "email_set": bool(r.get("NewEmail")),
        }

    def services(self) -> dict[str, Any]:
        n = self.tr064.call(MYFRITZ, "GetNumberOfServices")
        count = _int(n.get("NewNumberOfServices")) or 0
        items = []
        for idx in range(min(count, MAX_SERVICES)):
            e = self.tr064.try_call(MYFRITZ, "GetServiceByIndex", NewIndex=idx)
            if e is None:
                break
            items.append(parse_myfritz_service(e, idx))
        return {"available": True, "count": count, "services": items, "truncated": count > MAX_SERVICES}

    def remote_access(self) -> dict[str, Any]:
        r = self.tr064.call(REMOTE, "GetInfo")
        return {
            "available": True,
            "enabled": truthy(r.get("NewEnabled")),
            "port": _int(r.get("NewPort")),
            "https_only": True,
            "https_only_note": "Fernzugriff auf die FRITZ!Box gibt es nur per HTTPS (AVM TR-064 Remote Access, 4.2).",
            "internet_user_configured": bool(r.get("NewUsername")),
            "letsencrypt_enabled": truthy(r.get("NewLetsEncryptEnabled")),
            "letsencrypt_state": r.get("NewLetsEncryptState") or None,
        }

    def remote_enabled(self) -> bool:
        return truthy(self.tr064.call(REMOTE, "GetInfo").get("NewEnabled"))

    def dyndns(self) -> dict[str, Any]:
        _, r = self.tr064.call_first(REMOTE, DDNS_INFO_ACTIONS)
        # Whitelist: the answer also carries user name and update URL (may contain account data).
        return {
            "available": True,
            "enabled": truthy(r.get("NewEnabled")),
            "provider": r.get("NewProviderName") or None,
            "domain": r.get("NewDomain") or None,
            "mode": r.get("NewMode") or None,
            "status_ipv4": r.get("NewStatusIPv4") or None,
            "status_ipv6": r.get("NewStatusIPv6") or None,
        }

    def cloud_management(self) -> dict[str, Any]:
        data: dict[str, Any] = {"available": True}
        flag = self.tr064.try_call(USP, "GetUSPMyFRITZEnable")
        if flag is None:  # optional action – GetInfo carries the same flag (optional, too)
            flag = self.tr064.call(USP, "GetInfo")
        value = flag.get("NewUSPMyFRITZEnabled")
        data["myfritz_cloud_enabled"] = None if value is None else truthy(value)
        n = self.tr064.try_call(USP, "GetUSPControllerNumberOfEntries")
        count = _int((n or {}).get("NewUSPControllerNumberOfEntries"))
        controllers = []
        for idx in range(min(count or 0, MAX_CONTROLLERS)):
            e = self.tr064.try_call(USP, "GetUSPControllerByIndex", NewIndex=idx)
            if e is None:
                break
            controllers.append(parse_usp_controller(e, idx))
        data["controllers_count"] = count
        data["controllers"] = controllers
        data["note"] = "USP (TR-369) = Fernverwaltung über die Cloud; Benutzernamen/Passwörter werden nie ausgegeben."
        return data

    def apps(self) -> dict[str, Any]:
        r = self.tr064.call(APPSETUP, "GetConfig")
        return {
            "available": True,
            "mcp_user_rights": {k: r.get(v) or None for k, v in APP_RIGHTS.items()},
            # the user's RIGHT "Zugang auch aus dem Internet erlaubt" (AppSetup InternetRights)
            "mcp_user_internet_rights": truthy(r.get("NewInternetRights")),
            # whether THIS request reached the box via the internet (AppSetup AccessFromInternet) – not whether
            # internet access is enabled (that is remote_access.enabled)
            "current_request_from_internet": truthy(r.get("NewAccessFromInternet")),
            "registered_apps": {
                "available": False,
                "status": "unknown",
                "note": "Eine Liste der angemeldeten Apps (Anzahl/Namen) bietet TR-064 nicht. Web-Oberfläche: "
                "System > FRITZ!Box-Benutzer > Apps.",
            },
        }

    def access_from_internet(self) -> bool | None:
        r = self.tr064.try_call(APPSETUP, "GetConfig")
        return None if r is None else truthy(r.get("NewAccessFromInternet"))

    def set_remote(self, enabled: bool) -> dict[str, Any]:
        """RemoteAccess:SetEnable (no password argument). Returns the HTTPS port; port 0 on enabling
        means: no user with internet right exists (AVM doc 1.6) – nothing becomes reachable."""
        r = self.tr064.call(REMOTE, "SetEnable", NewEnabled=1 if enabled else 0)
        port = _int(r.get("NewPort"))
        after: bool | None = None
        for i in range(3):
            try:
                after = self.remote_enabled()
            except FritzError:
                after = None
            if after == enabled:
                break
            if i < 2:
                self._sleep(1.0)
        result: dict[str, Any] = {
            "action": "set_remote_access",
            "enabled": enabled,
            "port": port,
            "read_back": after,
            "verified": after == enabled,
        }
        if enabled and port == 0:
            result["verified"] = False
            result["note"] = (
                "Die Box meldet Port 0: es gibt keinen FRITZ!Box-Benutzer mit Zugang aus dem Internet – "
                "der Fernzugriff ist damit nicht nutzbar (Web-UI: System > FRITZ!Box-Benutzer)."
            )
        return result

    def status(self) -> dict[str, Any]:
        out: dict[str, Any] = {}

        def section(name: str, fn: Callable[[], dict[str, Any]]) -> None:
            try:
                out[name] = fn()
            except FritzError as exc:
                out[name] = {"available": False, "error": exc.to_dict()}

        section("account", self.account)
        section("services", self.services)
        section("dyndns", self.dyndns)
        section("remote_access", self.remote_access)
        section("cloud_management", self.cloud_management)
        section("apps", self.apps)
        out["assessments"] = assess(out)
        return out


def assess(status: dict[str, Any]) -> list[dict[str, Any]]:
    """Assessments in the format of ``security_check`` (check/status ok|warn|unknown/summary/details).

    Pure function over ``MyFritzClient.status()`` so ``security_check`` can include it later
    without extra box calls."""
    checks: list[dict[str, Any]] = []

    acc = status.get("account") or {}
    if not acc.get("available"):
        checks.append(_check("myfritz_konto", "unknown", "MyFRITZ!-Status nicht lesbar"))
    elif not acc["enabled"]:
        checks.append(_check("myfritz_konto", "ok", "MyFRITZ! aus", {"state": acc.get("state")}))
    elif acc.get("state") in _MYFRITZ_STATE_ERRORS:
        checks.append(
            _check(
                "myfritz_konto",
                "warn",
                f"MyFRITZ! aktiv, aber gestört: {acc.get('state_text') or acc.get('state')}",
                {"state": acc.get("state")},
            )
        )
    else:
        checks.append(
            _check(
                "myfritz_konto",
                "ok",
                f"MyFRITZ! aktiv ({acc.get('state_text') or acc.get('state') or 'Zustand unbekannt'})",
                {"registered": acc.get("registered"), "state": acc.get("state")},
            )
        )

    svc = status.get("services") or {}
    if not svc.get("available"):
        checks.append(_check("myfritz_dienste", "unknown", "MyFRITZ!-Freigaben nicht lesbar"))
    else:
        active = [s for s in svc["services"] if s["enabled"]]
        if active:
            names = ", ".join(f"{s['name'] or '?'} (Port {s['port']})" for s in active)
            checks.append(
                _check(
                    "myfritz_dienste",
                    "warn",
                    f"{len(active)} über MyFRITZ! aus dem Internet erreichbare(r) Dienst(e): {names}",
                    {"services": active},
                )
            )
        else:
            checks.append(_check("myfritz_dienste", "ok", "keine aktiven MyFRITZ!-Freigaben"))

    dd = status.get("dyndns") or {}
    if not dd.get("available"):
        checks.append(_check("dyndns", "unknown", "DynDNS-Status nicht lesbar"))
    elif not dd["enabled"]:
        checks.append(_check("dyndns", "ok", "eigenes DynDNS aus"))
    else:
        bad = {"account-disabled", "offline"}
        states = {dd.get("status_ipv4"), dd.get("status_ipv6")}
        status_ = "warn" if states & bad else "ok"
        checks.append(
            _check(
                "dyndns",
                status_,
                f"DynDNS aktiv ({dd.get('provider') or '?'}: {dd.get('domain') or '?'}, "
                f"IPv4 {dd.get('status_ipv4') or '?'}, IPv6 {dd.get('status_ipv6') or '?'})",
                dd,
            )
        )

    ra = status.get("remote_access") or {}
    if not ra.get("available"):
        checks.append(_check("fernzugriff", "unknown", "Fernzugriff-Status nicht lesbar"))
    elif not ra["enabled"]:
        checks.append(_check("fernzugriff", "ok", "kein Internetzugriff auf die Benutzeroberfläche", ra))
    else:
        summary = f"Internetzugriff auf die FRITZ!Box per HTTPS aktiv (Port {ra.get('port')}) – nur mit 2FA nutzen"
        if ra.get("letsencrypt_state") == "invalid":
            summary += "; Let's-Encrypt-Zertifikat ungültig"
        checks.append(_check("fernzugriff", "warn", summary, ra))

    cm = status.get("cloud_management") or {}
    if not cm.get("available"):
        checks.append(_check("cloud_fernverwaltung", "unknown", "Cloud-Fernverwaltung (USP) nicht lesbar"))
    else:
        active_ctrl = [c for c in cm.get("controllers") or [] if c["enabled"]]
        parts = []
        if cm.get("myfritz_cloud_enabled"):
            parts.append("MyFRITZ!-Fernverwaltung (USP) an")
        if active_ctrl:
            hosts = ", ".join(c["host"] or "?" for c in active_ctrl)
            parts.append(f"{len(active_ctrl)} aktive(r) USP-Controller ({hosts})")
        if parts:
            checks.append(_check("cloud_fernverwaltung", "warn", "; ".join(parts), {"controllers": active_ctrl}))
        elif cm.get("myfritz_cloud_enabled") is None and cm.get("controllers_count") is None:
            checks.append(_check("cloud_fernverwaltung", "unknown", "USP-Zustand nicht lesbar"))
        else:
            checks.append(_check("cloud_fernverwaltung", "ok", "keine Cloud-Fernverwaltung (USP) aktiv"))

    apps = status.get("apps") or {}
    if not apps.get("available"):
        checks.append(_check("mcp_benutzer_internet", "unknown", "Rechte des MCP-Benutzers nicht lesbar"))
    else:
        # Right (AppSetup InternetRights) vs. actually usable (remote access switched on, RemoteAccess:GetInfo).
        remote_on = ra.get("enabled") if ra.get("available") else None
        details = {
            "internet_right": apps["mcp_user_internet_rights"],
            "remote_access_enabled": remote_on,
            "current_request_from_internet": apps.get("current_request_from_internet"),
        }
        if not apps["mcp_user_internet_rights"]:
            summary = "MCP-Benutzer ohne Recht für den Zugang aus dem Internet"
            checks.append(_check("mcp_benutzer_internet", "ok", summary, details))
        elif remote_on is False:
            summary = (
                "Der MCP-Benutzer hat das Recht für den Zugang aus dem Internet, der Internetzugriff (Fernzugriff) "
                "ist aber aus – derzeit nicht nutzbar; das Recht ist für den MCP trotzdem entbehrlich"
            )
            checks.append(_check("mcp_benutzer_internet", "ok", summary, details))
        elif remote_on:
            summary = (
                "Der MCP-Benutzer hat das Recht für den Zugang aus dem Internet und der Internetzugriff (Fernzugriff) "
                "ist an – er kann sich von außen anmelden; für den MCP nicht nötig"
            )
            checks.append(_check("mcp_benutzer_internet", "warn", summary, details))
        else:
            summary = (
                "Der MCP-Benutzer hat das Recht für den Zugang aus dem Internet; ob der Internetzugriff an ist, "
                "war nicht lesbar – für den MCP nicht nötig"
            )
            checks.append(_check("mcp_benutzer_internet", "warn", summary, details))
    return checks
