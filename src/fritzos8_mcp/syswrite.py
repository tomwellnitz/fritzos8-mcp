"""Stage 10.6a – critical system writes from the AVM document comparison, each plan → token → execute (+ elicitation)
with read-back, plus 2FA detection (K-14).

* **Firmware update (K-12)** – ``UserInterface:X_AVM-DE_CheckUpdate`` (optional in the plan), ``GetInfo``
  (``NewUpgradeAvailable``, ``NewX_AVM-DE_Version``, ``NewX_AVM-DE_UpdateState``), ``X_AVM-DE_DoUpdate``. The box
  restarts – not verifiable at once (``accepted: true, verified: false``); afterwards ``firmware_update_status``
  reads ``X_AVM-DE_GetInfo.NewX_AVM-DE_UpdateSuccessful``. ``X_AVM-DE_DoUpdate`` stays on the generic denylist.
* **Static IPv4 routes** – ``Layer3Forwarding:AddForwardingEntry`` / ``DeleteForwardingEntry``, read back via
  ``GetSpecificForwardingEntry``. Source address/mask must be ``0.0.0.0`` (AVM doc), the interface is always the
  default connection (other values are ignored by the box). ``NewType`` (``Host``/``Network``) is not specified by
  AVM – unverified.
* **IPv6 pinholes** – IGD ``WANIPv6FirewallControl``: ``AddPinhole`` → ``UniqueID``, ``DeletePinhole``,
  ``UpdatePinhole`` (used as read-back: it only succeeds for an existing pinhole), ``GetFirewallStatus``. The box
  supports only these four actions (AVM IGD doc) – no listing, so created pinholes are remembered locally
  (``pinholes.json``, 0600). Pinholes are leased (≤ 86400 s) and, per UPnP, only for the requesting host; the IGD
  needs "Änderungen der Sicherheitseinstellungen über UPnP gestatten". Argument names are taken from the box's SCPD
  (``RemoteHost`` vs. ``NewRemoteHost``).
* **2FA (K-14)** – ``X_AVM-DE_Auth:GetInfo``/``GetState`` only: detect whether the second factor is enabled and
  what state it is in, and explain how the human confirms at the box. Completing a confirmed action needs the token
  in the SOAP header (AVM doc, chapter 6.4) – fritzconnection cannot send custom headers, and the server never
  starts or bypasses the process on its own. The human confirms and repeats the change in the web UI/app.
"""

from __future__ import annotations

import ipaddress
import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import Field

from .errors import FritzError, InvalidParameterError, NotFoundError, PermissionDeniedError
from .nasremote import ToolDecorator
from .paths import ensure_private_dir, safe_component, state_dir, write_private
from .security import Gate, PlanStore, Tier
from .toolargs import DESTRUCTIVE, READ, BoxArg, TokenArg
from .transparency import IPV6_FIREWALL_SERVICES, parse_firewall_status
from .util import truthy

if TYPE_CHECKING:
    from .tr064 import Tr064Client

UI = "UserInterface1"
L3 = "Layer3Forwarding1"
AUTH = "X_AVM-DE_Auth1"
MAX_LEASE_S = 86400
PROTOCOLS = {"TCP": 6, "UDP": 17}

TWO_FACTOR_STATES = {
    "disabled": "Zusatzbestätigung ist in der Box ausgeschaltet.",
    "waitingforauth": "Die Box wartet auf die Bestätigung: Taste an der Box drücken bzw. den angezeigten Code an "
    "einem Telefon der Box wählen.",
    "anotherauthprocess": "Gerade läuft eine Bestätigung für einen anderen Benutzer – bis zu 2 Minuten warten.",
    "authenticated": "Bestätigung für den aktuellen Benutzer erteilt.",
    "stopped": "Keine Bestätigung aktiv (abgebrochen oder abgelaufen).",
    "blocked": "Zu viele Versuche – bis zu 60 Minuten warten.",
    "failure": "Interner Fehler der Box bei der Zusatzbestätigung.",
}


def _ipv4(value: str, what: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address((value or "").strip())
    except ValueError:
        raise InvalidParameterError(f"{what}: keine gültige IPv4-Adresse.") from None


class SystemWriter:
    def __init__(
        self,
        tr064: Tr064Client,
        gate: Gate,
        plans: PlanStore,
        *,
        box_host: Callable[[], str] = lambda: "box",
        state_root: Path | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.tr064 = tr064
        self.gate = gate
        self.plans = plans
        self._box_host = box_host
        self._state_root = state_root
        self.now = now

    # ================================================================ firmware update (K-12)

    def _fw_info(self) -> dict[str, Any]:
        ui = self.tr064.call(UI, "GetInfo")
        dev = self.tr064.try_call("DeviceInfo1", "GetInfo") or {}
        return {
            "installed": dev.get("NewSoftwareVersion"),
            "model": dev.get("NewModelName"),
            "update_available": truthy(ui.get("NewUpgradeAvailable")),
            "available_version": ui.get("NewX_AVM-DE_Version") or None,
            "update_state": ui.get("NewX_AVM-DE_UpdateState") or None,
            "info_url": ui.get("NewX_AVM-DE_InfoURL") or None,
            "build_type": ui.get("NewX_AVM-DE_BuildType") or None,
        }

    def firmware_update_plan(self, check: bool = True) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        checked = False
        if check:
            try:
                self.tr064.call(UI, "X_AVM-DE_CheckUpdate")
                checked = True
            except NotFoundError:
                checked = False
        info = self._fw_info()
        if not info["update_available"]:
            return {
                "action": "firmware_update",
                **info,
                "checked_now": checked,
                "note": "Kein FRITZ!OS-Update verfügbar – nichts zu tun (kein Token ausgestellt).",
            }
        identity = f"{info['installed']}|{info['available_version']}|True"
        token = self.plans.issue("firmware_update", {}, identity)
        return {
            "action": "firmware_update",
            **info,
            "checked_now": checked,
            "consequence": f"Die FRITZ!Box lädt FRITZ!OS {info['available_version'] or '(neueste Version)'} und "
            "startet neu. Internet, WLAN und Telefonie fallen dabei einige Minuten aus.",
            "warnings": [
                "Während des Updates die Box nicht vom Strom trennen.",
                "Alle Verbindungen (auch dieser MCP-Server zur Box) brechen während des Neustarts ab.",
                "Vorher die Versionshinweise lesen (info_url) und eine Sicherung der Einstellungen anlegen.",
            ],
            "token": token,
            "token_valid_s": int(self.plans.ttl),
        }

    def firmware_update_execute(self, token: str) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        seen: dict[str, Any] = {}

        def identity() -> str:
            try:
                seen.update(self._fw_info())
            except FritzError:
                return ""
            return f"{seen['installed']}|{seen['available_version']}|{seen['update_available']}"

        self.plans.redeem(token, "firmware_update", {}, identity)
        r = self.tr064.call(UI, "X_AVM-DE_DoUpdate")
        return {
            "accepted": True,
            "verified": False,
            "from_version": seen.get("installed"),
            "to_version": seen.get("available_version"),
            "update_state": r.get("NewX_AVM-DE_UpdateState") or None,
            "note": "Update gestartet; die Box startet neu. Erfolg erst danach prüfbar: firmware_update_status "
            "(bzw. firmware_status) in einigen Minuten aufrufen.",
        }

    def firmware_update_status(self) -> dict[str, Any]:
        info = self._fw_info()
        last = self.tr064.try_call(UI, "X_AVM-DE_GetInfo") or {}
        return {
            **info,
            "last_update": {
                "successful": last.get("NewX_AVM-DE_UpdateSuccessful") or None,
                "time": last.get("NewX_AVM-DE_UpdateTime") or None,
                "previous_version": last.get("NewX_AVM-DE_LastFwVersion") or None,
            },
            "auto_update_mode": last.get("NewX_AVM-DE_AutoUpdateMode") or None,
        }

    # ================================================================ static routes

    def _route(self, dest: str, mask: str) -> dict[str, Any] | None:
        try:
            r = self.tr064.call(
                L3,
                "GetSpecificForwardingEntry",
                NewDestIPAddress=dest,
                NewDestSubnetMask=mask,
                NewSourceIPAddress="0.0.0.0",  # noqa: S104 - AVM doc: source must be 0.0.0.0
                NewSourceSubnetMask="0.0.0.0",  # noqa: S104
            )
        except FritzError as exc:
            if isinstance(exc, NotFoundError) or exc.tr064_code in ("714", "402"):
                return None
            raise
        return {
            "destination": dest,
            "netmask": mask,
            "gateway": r.get("NewGatewayIPAddress"),
            "enabled": truthy(r.get("NewEnable")),
            "status": r.get("NewStatus") or None,
            "metric": r.get("NewForwardingMetric"),
            "interface": r.get("NewInterface") or None,
        }

    @staticmethod
    def _route_args(destination: str, netmask: str) -> tuple[str, str, ipaddress.IPv4Network]:
        dest = _ipv4(destination, "destination")
        mask = _ipv4(netmask, "netmask")
        try:
            net = ipaddress.IPv4Network(f"{dest}/{mask}", strict=True)
        except ValueError:
            raise InvalidParameterError(
                "destination ist keine Netzadresse zu dieser Maske (Host-Bits gesetzt).",
                hint="Beispiel: destination=10.8.0.0 netmask=255.255.255.0",
            ) from None
        if net.prefixlen == 0:
            raise InvalidParameterError("Eine Default-Route (0.0.0.0/0) wird nicht gesetzt.")
        return str(dest), str(mask), net

    def static_route_add_plan(self, destination: str, netmask: str, gateway: str, metric: int = 1) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        dest, mask, net = self._route_args(destination, netmask)
        gw = _ipv4(gateway, "gateway")
        if gw in net:
            raise InvalidParameterError("Das Gateway darf nicht im Zielnetz liegen.")
        if not gw.is_private:
            raise InvalidParameterError("Das Gateway muss ein Gerät im Heimnetz sein (private IPv4-Adresse).")
        if not 1 <= metric <= 9999:
            raise InvalidParameterError("metric muss 1–9999 sein.")
        existing = self._route(dest, mask)
        if existing is not None:
            raise InvalidParameterError(
                f"Für {net} gibt es schon eine Route (Gateway {existing['gateway']}).",
                hint="Erst static_route_delete_plan, dann neu anlegen.",
            )
        params = {"destination": dest, "netmask": mask, "gateway": str(gw), "metric": metric}
        token = self.plans.issue("static_route_add", params, "absent")
        return {
            "action": "static_route_add",
            "route": {**params, "network": str(net)},
            "consequence": f"Die Box leitet Pakete an {net} künftig an {gw} weiter.",
            "warnings": [
                "Eine falsche Route kann Teile des Netzes unerreichbar machen (Zielnetz darf nicht das Heimnetz "
                "überlappen).",
                "Das Gateway muss die Pakete selbst weiterleiten (z. B. VPN-Router, Pi mit IP-Forwarding).",
            ]
            + (
                ["Zielnetz überschneidet sich mit 192.168.0.0/16 – Heimnetz-Überlappung prüfen."]
                if net.overlaps(ipaddress.IPv4Network("192.168.0.0/16"))
                else []
            ),
            "token": token,
            "token_valid_s": int(self.plans.ttl),
        }

    def static_route_add_execute(
        self, token: str, destination: str, netmask: str, gateway: str, metric: int = 1
    ) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        dest, mask, net = self._route_args(destination, netmask)
        gw = str(_ipv4(gateway, "gateway"))
        params = {"destination": dest, "netmask": mask, "gateway": gw, "metric": metric}
        self.plans.redeem(
            token, "static_route_add", params, lambda: "absent" if self._route(dest, mask) is None else "present"
        )
        iface = ""
        default = self.tr064.try_call(L3, "GetDefaultConnectionService")
        if default:
            iface = str(default.get("NewDefaultConnectionService") or "")
        self.tr064.call(
            L3,
            "AddForwardingEntry",
            NewType="Host" if net.prefixlen == 32 else "Network",
            NewDestIPAddress=dest,
            NewDestSubnetMask=mask,
            NewSourceIPAddress="0.0.0.0",  # noqa: S104
            NewSourceSubnetMask="0.0.0.0",  # noqa: S104
            NewGatewayIPAddress=gw,
            NewInterface=iface,
            NewForwardingMetric=metric,
        )
        after = self._route(dest, mask)
        return {
            "route": {**params, "network": str(net)},
            "changed": True,
            "verified": after is not None and after.get("gateway") == gw,
            "read_back": after,
        }

    def static_route_delete_plan(self, destination: str, netmask: str) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        dest, mask, net = self._route_args(destination, netmask)
        existing = self._route(dest, mask)
        if existing is None:
            raise NotFoundError(f"Keine statische Route für {net} – siehe system_transparency.static_routes.")
        params = {"destination": dest, "netmask": mask}
        token = self.plans.issue("static_route_delete", params, str(existing.get("gateway")))
        return {
            "action": "static_route_delete",
            "route": existing,
            "consequence": f"Die Route nach {net} über {existing.get('gateway')} wird gelöscht.",
            "warnings": ["Geräte/Netze, die nur über diese Route erreichbar sind, sind danach nicht mehr erreichbar."],
            "token": token,
            "token_valid_s": int(self.plans.ttl),
        }

    def static_route_delete_execute(self, token: str, destination: str, netmask: str) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        dest, mask, net = self._route_args(destination, netmask)

        def identity() -> str:
            r = self._route(dest, mask)
            return str(r.get("gateway")) if r else ""

        self.plans.redeem(token, "static_route_delete", {"destination": dest, "netmask": mask}, identity)
        self.tr064.call(
            L3,
            "DeleteForwardingEntry",
            NewDestIPAddress=dest,
            NewDestSubnetMask=mask,
            NewSourceIPAddress="0.0.0.0",  # noqa: S104
            NewSourceSubnetMask="0.0.0.0",  # noqa: S104
        )
        return {"network": str(net), "deleted": True, "verified": self._route(dest, mask) is None}

    # ================================================================ IPv6 pinholes (IGD)

    @property
    def _pinhole_path(self) -> Path:
        base = ensure_private_dir((self._state_root or state_dir()) / safe_component(self._box_host()))
        return base / "pinholes.json"

    def _pinholes(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(self._pinhole_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        items = data.get("pinholes") if isinstance(data, dict) else None
        return [p for p in items or [] if isinstance(p, dict)]

    def _save_pinholes(self, items: list[dict[str, Any]]) -> None:
        write_private(self._pinhole_path, json.dumps({"pinholes": items}, ensure_ascii=False, indent=1).encode())

    def _fw_service(self) -> str:
        for name in IPV6_FIREWALL_SERVICES:
            try:
                self.tr064.describe_action(name, "AddPinhole")
                return name
            except NotFoundError:
                continue
        raise NotFoundError(
            "IGD WANIPv6FirewallControl nicht erreichbar.",
            hint="In der Box „Heimnetz > Netzwerk > Netzwerkeinstellungen: Statusinformationen über UPnP übertragen“ "
            "und „Änderungen der Sicherheitseinstellungen über UPnP gestatten“ prüfen.",
        )

    def _igd_args(self, service: str, action: str, values: dict[str, Any]) -> dict[str, Any]:
        """Map canonical UPnP names (RemoteHost …) to the spelling of the box's SCPD (with/without 'New')."""
        known = {a["name"] for a in self.tr064.describe_action(service, action)["arguments"] if a["direction"] == "in"}
        out = {}
        for name, value in values.items():
            out[f"New{name}" if f"New{name}" in known and name not in known else name] = value
        return out

    def _pinhole_alive(self, service: str, uid: Any, lease: int) -> bool:
        try:
            args = self._igd_args(service, "UpdatePinhole", {"UniqueID": uid, "NewLeaseTime": lease})
            self.tr064.call(service, "UpdatePinhole", **args)
            return True
        except FritzError as exc:
            if isinstance(exc, NotFoundError) or exc.tr064_code in ("704", "714"):
                return False
            raise

    def firewall_status(self) -> dict[str, Any]:
        service = self._fw_service()
        fw = parse_firewall_status(self.tr064.call(service, "GetFirewallStatus"))
        now = self.now()
        local = [
            {**p, "expired": float(p.get("expires", 0)) < now, "expires": _iso(float(p.get("expires", 0)))}
            for p in self._pinholes()
        ]
        return {
            "service": service,
            "firewall_enabled": fw["enabled"],
            "inbound_pinholes_allowed": fw["inbound_pinholes_allowed"],
            "pinholes_created_here": local,
            "note": "Die Box bietet keine Liste der Pinholes (AVM-IGD-Doku: nur GetFirewallStatus, AddPinhole, "
            "UpdatePinhole, DeletePinhole) – gezeigt werden die über diesen Server angelegten (lokal gemerkt). "
            "Abgelaufene Leases schließt die Box selbst.",
        }

    @staticmethod
    def _pinhole_params(
        internal_client: str, internal_port: int, protocol: str, lease_s: int, remote_host: str, remote_port: int
    ) -> dict[str, Any]:
        try:
            client = ipaddress.IPv6Address((internal_client or "").strip())
        except ValueError:
            raise InvalidParameterError("internal_client: keine gültige IPv6-Adresse.") from None
        if not client.is_global:
            raise InvalidParameterError(
                "internal_client muss eine globale IPv6-Adresse sein (keine link-lokale/ULA – die sind aus dem "
                "Internet nicht erreichbar)."
            )
        proto = protocol.upper()
        if proto not in PROTOCOLS:
            raise InvalidParameterError("protocol: TCP oder UDP.")
        if not 1 <= internal_port <= 65535 or not 0 <= remote_port <= 65535:
            raise InvalidParameterError("Ports: 1–65535 (remote_port 0 = alle).")
        if not 60 <= lease_s <= MAX_LEASE_S:
            raise InvalidParameterError(f"lease_s: 60–{MAX_LEASE_S} Sekunden (UPnP-Lease, läuft danach ab).")
        remote = (remote_host or "").strip()
        if remote:
            try:
                ipaddress.IPv6Address(remote)
            except ValueError:
                raise InvalidParameterError("remote_host: leer (alle) oder eine IPv6-Adresse.") from None
        return {
            "internal_client": str(client),
            "internal_port": internal_port,
            "protocol": proto,
            "lease_s": lease_s,
            "remote_host": remote,
            "remote_port": remote_port,
        }

    def ipv6_pinhole_add_plan(
        self,
        internal_client: str,
        internal_port: int,
        protocol: str = "TCP",
        lease_s: int = 3600,
        remote_host: str = "",
        remote_port: int = 0,
    ) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        p = self._pinhole_params(internal_client, internal_port, protocol, lease_s, remote_host, remote_port)
        service = self._fw_service()
        allowed = parse_firewall_status(self.tr064.call(service, "GetFirewallStatus"))["inbound_pinholes_allowed"]
        warnings = [
            f"Öffnet {p['protocol']}-Port {p['internal_port']} von {p['internal_client']} für "
            + (p["remote_host"] or "das GESAMTE Internet")
            + " über IPv6 – der Dienst muss sicher (aktuell, mit Anmeldung) sein.",
            f"Die Freigabe läuft nach {p['lease_s']} s ab (UPnP-Lease) und muss bei Bedarf neu angelegt werden.",
            "Laut UPnP darf ein Gerät Pinholes nur für sich selbst öffnen – für andere Geräte lehnt die Box ab "
            "(dann die Freigabe in der Web-UI für das Gerät einrichten).",
        ]
        if allowed is False:
            warnings.append(
                "Die Box meldet InboundPinholeAllowed = false – das Anlegen wird voraussichtlich scheitern."
            )
        token = self.plans.issue("ipv6_pinhole_add", p)
        return {
            "action": "ipv6_pinhole_add",
            "pinhole": p,
            "consequence": f"IPv6-Pinhole für [{p['internal_client']}]:{p['internal_port']}/{p['protocol']} "
            f"aus dem Internet für {p['lease_s']} s.",
            "warnings": warnings,
            "token": token,
            "token_valid_s": int(self.plans.ttl),
        }

    def ipv6_pinhole_add_execute(
        self,
        token: str,
        internal_client: str,
        internal_port: int,
        protocol: str = "TCP",
        lease_s: int = 3600,
        remote_host: str = "",
        remote_port: int = 0,
    ) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        p = self._pinhole_params(internal_client, internal_port, protocol, lease_s, remote_host, remote_port)
        self.plans.redeem(token, "ipv6_pinhole_add", p)
        service = self._fw_service()
        values = {
            "RemoteHost": p["remote_host"],
            "RemotePort": p["remote_port"],
            "InternalClient": p["internal_client"],
            "InternalPort": p["internal_port"],
            "Protocol": PROTOCOLS[p["protocol"]],
            "LeaseTime": p["lease_s"],
        }
        try:
            r = self.tr064.call(service, "AddPinhole", **self._igd_args(service, "AddPinhole", values))
        except PermissionDeniedError:
            raise PermissionDeniedError(
                "Die Box hat das Pinhole abgelehnt (nicht berechtigt).",
                hint="UPnP erlaubt Pinholes nur für das anfragende Gerät; außerdem muss „Änderungen der "
                "Sicherheitseinstellungen über UPnP gestatten“ aktiv sein. Sonst die IPv6-Freigabe in der Web-UI "
                "(Internet > Freigaben) einrichten.",
            ) from None
        uid = r.get("UniqueID", r.get("NewUniqueID"))
        if uid in (None, ""):
            return {"pinhole": p, "changed": True, "verified": False, "note": "Box lieferte keine UniqueID."}
        alive = self._pinhole_alive(service, uid, p["lease_s"])
        items = [i for i in self._pinholes() if str(i.get("unique_id")) != str(uid)]
        items.append({"unique_id": uid, **p, "created": _iso(self.now()), "expires": self.now() + p["lease_s"]})
        self._save_pinholes(items)
        return {
            "pinhole": {**p, "unique_id": uid},
            "changed": True,
            "verified": alive,
            "note": "Rücklesen über UpdatePinhole (gelingt nur für ein bestehendes Pinhole; setzt die Lease neu).",
        }

    def ipv6_pinhole_delete_plan(self, unique_id: int) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        known = next((p for p in self._pinholes() if str(p.get("unique_id")) == str(unique_id)), None)
        token = self.plans.issue("ipv6_pinhole_delete", {"unique_id": unique_id})
        return {
            "action": "ipv6_pinhole_delete",
            "pinhole": known or {"unique_id": unique_id, "note": "nicht über diesen Server angelegt"},
            "consequence": f"Das IPv6-Pinhole {unique_id} wird geschlossen; der Dienst ist danach aus dem Internet "
            "nicht mehr über IPv6 erreichbar.",
            "warnings": [],
            "token": token,
            "token_valid_s": int(self.plans.ttl),
        }

    def ipv6_pinhole_delete_execute(self, token: str, unique_id: int) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        self.plans.redeem(token, "ipv6_pinhole_delete", {"unique_id": unique_id})
        service = self._fw_service()
        try:
            args = self._igd_args(service, "DeletePinhole", {"UniqueID": unique_id})
            self.tr064.call(service, "DeletePinhole", **args)
        except NotFoundError:
            pass  # already gone (lease expired) – verified below
        gone = not self._pinhole_alive(service, unique_id, 60)
        self._save_pinholes([p for p in self._pinholes() if str(p.get("unique_id")) != str(unique_id)])
        return {"unique_id": unique_id, "deleted": True, "verified": gone}

    # ================================================================ 2FA (K-14)

    def two_factor_status(self) -> dict[str, Any]:
        info = self.tr064.call(AUTH, "GetInfo")
        enabled = truthy(info.get("NewEnabled"))
        state = None
        if enabled:
            st = self.tr064.try_call(AUTH, "GetState")
            state = (st or {}).get("NewState") or None
        return {
            "enabled": enabled,
            "state": state,
            "meaning": TWO_FACTOR_STATES.get(str(state), "")
            if state
            else TWO_FACTOR_STATES["disabled"]
            if not enabled
            else "Status nicht lesbar.",
            "how_to_confirm": [
                "Meldet ein Schreib-Tool 'confirmation_required', wurde NICHTS geändert.",
                "Die Änderung in der FRITZ!Box-Oberfläche oder der FRITZ!App vornehmen und dort wie verlangt "
                "bestätigen: eine Taste an der Box drücken oder den angezeigten Code an einem Telefon der Box wählen.",
                "Danach das passende Lese-Tool aufrufen und den neuen Zustand prüfen.",
            ]
            if enabled
            else [],
            "note": "Nur Erkennung: dieser Server startet, umgeht oder beantwortet die Zusatzbestätigung nie selbst "
            "(das Abschließen bräuchte das Token im SOAP-Header – das macht nur der Mensch über Web-UI/App).",
        }


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts))


Ipv4Arg = Annotated[str, Field(description="IPv4-Adresse, z. B. 10.8.0.0")]
MaskArg = Annotated[str, Field(description="Netzmaske, z. B. 255.255.255.0")]
GatewayArg = Annotated[str, Field(description="Gateway im Heimnetz, z. B. 192.0.2.10")]
MetricArg = Annotated[int, Field(description="Metrik (Standard 1)", ge=1, le=9999)]
ClientArg = Annotated[str, Field(description="Globale IPv6-Adresse des Zielgeräts (in der Regel dieses Rechners)")]
PortArg = Annotated[int, Field(description="Port am Zielgerät", ge=1, le=65535)]
ProtoArg = Annotated[Literal["TCP", "UDP"], Field(description="TCP oder UDP")]
LeaseArg = Annotated[int, Field(description="Lease in Sekunden (60–86400), danach schließt die Box", ge=60, le=86400)]
RemoteHostArg = Annotated[str, Field(description="Nur von dieser IPv6-Adresse (leer = von überall)")]
RemotePortArg = Annotated[int, Field(description="Nur von diesem Quellport (0 = alle)", ge=0, le=65535)]
UidArg = Annotated[int, Field(description="UniqueID des Pinholes (aus ipv6_firewall_status)", ge=0, le=65535)]


def register_system_write_tools(tool: ToolDecorator, svc: Callable[[str | None], SystemWriter]) -> None:
    @tool(Tier.READ, READ)
    def firmware_update_status(box: BoxArg = None) -> dict[str, Any]:
        """FRITZ!OS-Update: installiert, verfügbar, Update-Zustand, letztes Update erfolgreich? (TR-064 UserInterface
        GetInfo + X_AVM-DE_GetInfo). Nach firmware_update_execute zum Prüfen verwenden."""
        return svc(box).firmware_update_status()

    @tool(Tier.CRITICAL, READ)
    def firmware_update_plan(
        check: Annotated[bool, Field(description="Vorher bei AVM nach Updates suchen (X_AVM-DE_CheckUpdate)")] = True,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Plant ein FRITZ!OS-Update: verfügbare Version, Versionshinweise, Folgen (Neustart, Ausfall) + Token (5 min).
        Ohne verfügbares Update kein Token."""
        return svc(box).firmware_update_plan(check)

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def firmware_update_execute(token: TokenArg, box: BoxArg = None) -> dict[str, Any]:
        """Startet das geplante FRITZ!OS-Update (TR-064 X_AVM-DE_DoUpdate). Die Box startet neu – Erfolg danach mit
        firmware_update_status prüfen. Nur nach ausdrücklicher Zustimmung."""
        return svc(box).firmware_update_execute(token)

    @tool(Tier.CRITICAL, READ)
    def static_route_add_plan(
        destination: Ipv4Arg, netmask: MaskArg, gateway: GatewayArg, metric: MetricArg = 1, box: BoxArg = None
    ) -> dict[str, Any]:
        """Plant eine statische IPv4-Route (Zielnetz → Gateway im Heimnetz): Prüfung, Folgen + Token (5 min)."""
        return svc(box).static_route_add_plan(destination, netmask, gateway, metric)

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def static_route_add_execute(
        token: TokenArg,
        destination: Ipv4Arg,
        netmask: MaskArg,
        gateway: GatewayArg,
        metric: MetricArg = 1,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Legt die geplante statische Route an (TR-064 Layer3Forwarding:AddForwardingEntry) und liest sie zurück."""
        return svc(box).static_route_add_execute(token, destination, netmask, gateway, metric)

    @tool(Tier.CRITICAL, READ)
    def static_route_delete_plan(destination: Ipv4Arg, netmask: MaskArg, box: BoxArg = None) -> dict[str, Any]:
        """Plant das Löschen einer statischen IPv4-Route: Route, Folgen + Token (5 min)."""
        return svc(box).static_route_delete_plan(destination, netmask)

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def static_route_delete_execute(
        token: TokenArg, destination: Ipv4Arg, netmask: MaskArg, box: BoxArg = None
    ) -> dict[str, Any]:
        """Löscht die geplante statische Route (DeleteForwardingEntry) und prüft, dass sie weg ist."""
        return svc(box).static_route_delete_execute(token, destination, netmask)

    @tool(Tier.READ, READ)
    def ipv6_firewall_status(box: BoxArg = None) -> dict[str, Any]:
        """IPv6-Firewall der Box (IGD GetFirewallStatus: an, Pinholes erlaubt) und die über diesen Server angelegten
        IPv6-Pinholes mit Ablaufzeit (die Box selbst bietet keine Liste)."""
        return svc(box).firewall_status()

    @tool(Tier.CRITICAL, READ)
    def ipv6_pinhole_add_plan(
        internal_client: ClientArg,
        internal_port: PortArg,
        protocol: ProtoArg = "TCP",
        lease_s: LeaseArg = 3600,
        remote_host: RemoteHostArg = "",
        remote_port: RemotePortArg = 0,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Plant ein IPv6-Pinhole (eingehende Verbindung aus dem Internet zu einem Gerät, IGD WANIPv6FirewallControl):
        Folgen, Warnungen + Token (5 min). Pinholes laufen nach lease_s ab."""
        return svc(box).ipv6_pinhole_add_plan(
            internal_client, internal_port, protocol, lease_s, remote_host, remote_port
        )

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def ipv6_pinhole_add_execute(
        token: TokenArg,
        internal_client: ClientArg,
        internal_port: PortArg,
        protocol: ProtoArg = "TCP",
        lease_s: LeaseArg = 3600,
        remote_host: RemoteHostArg = "",
        remote_port: RemotePortArg = 0,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Öffnet das geplante IPv6-Pinhole (AddPinhole) und prüft es per UpdatePinhole. Öffnet einen Dienst ins
        Internet – nur nach ausdrücklicher Zustimmung."""
        return svc(box).ipv6_pinhole_add_execute(
            token, internal_client, internal_port, protocol, lease_s, remote_host, remote_port
        )

    @tool(Tier.CRITICAL, READ)
    def ipv6_pinhole_delete_plan(unique_id: UidArg, box: BoxArg = None) -> dict[str, Any]:
        """Plant das Schließen eines IPv6-Pinholes: Folgen + Token (5 min)."""
        return svc(box).ipv6_pinhole_delete_plan(unique_id)

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def ipv6_pinhole_delete_execute(token: TokenArg, unique_id: UidArg, box: BoxArg = None) -> dict[str, Any]:
        """Schließt das geplante IPv6-Pinhole (DeletePinhole) und prüft, dass es weg ist."""
        return svc(box).ipv6_pinhole_delete_execute(token, unique_id)

    @tool(Tier.READ, READ)
    def two_factor_status(box: BoxArg = None) -> dict[str, Any]:
        """Zusatzbestätigung (2FA) der Box: aktiv?, aktueller Zustand (wartet/bestätigt/blockiert …) und wie der
        Mensch an der Box bestätigt (TR-064 X_AVM-DE_Auth GetInfo/GetState). Startet oder umgeht nie etwas."""
        return svc(box).two_factor_status()
