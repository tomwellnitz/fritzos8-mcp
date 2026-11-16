"""Device resolution (MAC/IP → host) and the internet block per device (Kindersicherung) via
TR-064 ``X_AVM-DE_HostFilter1`` (``GetWANAccessByIP`` / ``DisallowWANAccessByIP``).

Own implementation after AVM's TR-064 documentation (x_hostfilterSCPD). The block works on
the device's IPv4 address; the box stores it with the device entry. Access profiles, time budgets
and tickets (HostFilter version 4+, 2025) live in ``parental.py`` (stage 7.5).

Protection: blocking is refused for the FRITZ!Box itself and for the machine this server runs
on (its IPv4 address towards the box, if detectable). Unblocking is always allowed.
"""

from __future__ import annotations

import contextlib
import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .errors import InvalidParameterError, NotFoundError
from .tr064 import Tr064Client
from .util import normalize_mac, safe_mac, truthy

HOSTFILTER = "X_AVM-DE_HostFilter1"


@dataclass(frozen=True)
class Host:
    name: str
    ip: str
    mac: str
    active: bool
    guest: bool = False  # X_AVM-DE_Guest of the host list: connected via the guest network

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ip": self.ip, "mac": self.mac, "active": self.active}


def validate_ipv4(ip: str) -> str:
    try:
        addr = ipaddress.IPv4Address((ip or "").strip())
    except ValueError:
        raise InvalidParameterError(f'Ungültige IPv4-Adresse: "{ip}"') from None
    return str(addr)


def local_ips_towards(host: str) -> set[str]:
    """IPv4 address(es) of this machine on the route to the box. UDP connect sends no packet."""
    out: set[str] = set()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1.0)
            s.connect((host, 49000))
            out.add(str(s.getsockname()[0]))
    except OSError:
        pass
    return out


class HostResolver:
    def __init__(self, tr064: Tr064Client, local_ips: Callable[[], set[str]] | None = None) -> None:
        self.tr064 = tr064
        self._local_ips = local_ips

    def hosts(self) -> list[Host]:
        return [
            Host(
                str(h.get("name") or ""),
                str(h.get("ip") or ""),
                safe_mac(h.get("mac")),
                bool(h.get("active")),
                bool(h.get("guest")),
            )
            for h in self.tr064.list_hosts()
        ]

    def resolve(self, mac: str | None = None, ip: str | None = None) -> Host:
        """Exactly one of mac/ip. A MAC must map to exactly one IPv4 address."""
        if bool(mac) == bool(ip):
            raise InvalidParameterError("Genau eins von mac oder ip angeben.")
        hosts = self.hosts()
        if mac:
            wanted = normalize_mac(mac)
            matches = [h for h in hosts if h.mac == wanted]
            if not matches:
                raise NotFoundError(f"Kein Gerät mit MAC {wanted} in der Geräteliste – siehe list_hosts.")
            ips = {h.ip for h in matches if h.ip}
            if not ips:
                raise NotFoundError(f"Für MAC {wanted} ist keine IPv4-Adresse bekannt (Gerät nie per IPv4 verbunden?).")
            if len(ips) > 1:
                raise InvalidParameterError(
                    f"MAC {wanted} hat mehrere IPv4-Adressen ({', '.join(sorted(ips))}) – nicht eindeutig, "
                    "bitte ip angeben."
                )
            ip_v = ips.pop()
            best = next(h for h in matches if h.ip == ip_v)
            return Host(best.name, ip_v, wanted, any(h.active for h in matches), any(h.guest for h in matches))
        ip_v = validate_ipv4(str(ip))
        matches = [h for h in hosts if h.ip == ip_v]
        if not matches:
            raise NotFoundError(f"Kein Gerät mit IP {ip_v} in der Geräteliste – siehe list_hosts.")
        macs = {h.mac for h in matches if h.mac}
        if len(macs) > 1:
            raise InvalidParameterError(
                f"IP {ip_v} passt auf mehrere Geräte ({', '.join(sorted(macs))}) – bitte mac angeben."
            )
        h = matches[0]
        return Host(
            h.name,
            ip_v,
            h.mac or (macs.pop() if macs else ""),
            any(x.active for x in matches),
            any(x.guest for x in matches),
        )

    # ------------------------------------------------------------ protection

    def box_ips(self) -> set[str]:
        out: set[str] = set()
        host = urlparse(self.tr064.fc.address).hostname or ""
        with contextlib.suppress(ValueError):
            out.add(str(ipaddress.ip_address(host)))
        r = self.tr064.try_call("LANHostConfigManagement1", "GetIPRoutersList")
        for part in str((r or {}).get("NewIPRouters") or "").replace(";", ",").split(","):
            part = part.strip()
            if part:
                out.add(part)
        return out

    def server_ips(self) -> set[str]:
        return set(self._local_ips()) if self._local_ips else set()

    def protected_reason(self, host: Host) -> str | None:
        if host.ip in self.box_ips():
            return "Das ist die FRITZ!Box selbst."
        if host.ip in self.server_ips():
            return "Das ist das Gerät, auf dem dieser MCP-Server läuft (Aussperr-Gefahr)."
        return None


class HostFilterClient:
    def __init__(self, tr064: Tr064Client, resolver: HostResolver) -> None:
        self.tr064 = tr064
        self.resolver = resolver

    def _read(self, ip: str) -> dict[str, Any]:
        r = self.tr064.call(HOSTFILTER, "GetWANAccessByIP", NewIPv4Address=ip)
        return {
            "blocked": truthy(r.get("NewDisallow")) if r.get("NewDisallow") is not None else None,
            "wan_access": r.get("NewWANAccess"),
        }

    def status(self, mac: str | None = None, ip: str | None = None) -> dict[str, Any]:
        host = self.resolver.resolve(mac, ip)
        state = self._read(host.ip)
        return {
            **host.as_dict(),
            **state,
            "note": "blocked = Internetzugang für dieses Gerät gesperrt (Kindersicherung). wan_access zeigt das "
            "Ergebnis inkl. Zugangsprofil (granted/denied/error); Profil-Details: parental_device_status.",
        }

    def set_allowed(self, mac: str, allowed: bool) -> dict[str, Any]:
        host = self.resolver.resolve(mac=mac)
        if not allowed:
            reason = self.resolver.protected_reason(host)
            if reason:
                raise InvalidParameterError(f"Sperren abgelehnt: {reason}", hint="Dieses Gerät wird nie gesperrt.")
        before = self._read(host.ip)
        base = {**host.as_dict(), "allowed": allowed}
        if before["blocked"] is not None and before["blocked"] == (not allowed):
            return {**base, "wan_access": before["wan_access"], "changed": False, "verified": True}
        self.tr064.call(HOSTFILTER, "DisallowWANAccessByIP", NewIPv4Address=host.ip, NewDisallow=0 if allowed else 1)
        try:
            after = self._read(host.ip)
        except NotFoundError:
            after = {"blocked": None, "wan_access": None}
        if after["blocked"] is None:
            return {
                **base,
                "changed": None,
                "verified": False,
                "note": "Schreiben angenommen, Sperrstatus aber nicht rücklesbar – in der Web-UI unter "
                "Internet > Filter > Kindersicherung prüfen.",
            }
        if after["blocked"] != (not allowed):
            return {
                **base,
                "read_back_blocked": after["blocked"],
                "changed": False,
                "verified": False,
                "note": "Die Box meldet weiterhin den alten Zustand – nicht übernommen (evtl. Zusatzbestätigung).",
            }
        result = {**base, "wan_access": after["wan_access"], "changed": True, "verified": True}
        if allowed and str(after["wan_access"] or "").lower() == "denied":
            result["note"] = "Sperre aufgehoben, aber das Zugangsprofil verweigert weiterhin den Internetzugang."
        return result
