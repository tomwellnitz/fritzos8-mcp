"""IPv4 port forwardings via TR-064 ``WANIPConn1`` / ``WANPPPConnection1``
(``GetGenericPortMappingEntry``, ``GetSpecificPortMappingEntry``, ``AddPortMapping``,
``DeletePortMapping``). Own implementation after the UPnP IGD / AVM TR-064 documentation.

Opening ports to the internet is security-critical, therefore add/delete are only offered as
plan/execute tools (stage critical). FRITZ!OS may refuse TR-064 port mappings unless
"Selbstständige Portfreigaben für dieses Gerät erlauben" is enabled for the target device –
the UPnP error codes are translated into clear messages instead of a generic failure.
"""

from __future__ import annotations

import re
from typing import Any

from .access import Host, HostResolver
from .diagnose import DiagnoseClient
from .errors import FritzError, InvalidParameterError, NotFoundError, PermissionDeniedError
from .tr064 import Tr064Client
from .util import truthy

PROTOCOLS = ("TCP", "UDP")
MAX_DESCRIPTION = 64
_DESCRIPTION = re.compile(r"^[\w .:/()+\-]+$")

# Ports whose exposure is a classic attack surface – the plan warns explicitly.
SENSITIVE_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    135: "Windows RPC",
    139: "NetBIOS",
    445: "SMB/Windows-Freigaben",
    1433: "MS SQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8123: "Home Assistant",
}

SELF_PORTFORWARD_HINT = (
    "In der FRITZ!Box unter Internet > Freigaben > Portfreigaben beim Zielgerät "
    "'Selbstständige Portfreigaben für dieses Gerät erlauben' aktivieren – oder die Freigabe in der "
    "Web-Oberfläche anlegen."
)

# UPnP IGD error codes of AddPortMapping / DeletePortMapping.
UPNP_ERRORS: dict[str, str] = {
    "606": "Aktion nicht erlaubt",
    "714": "Freigabe existiert nicht",
    "716": "Platzhalter beim externen Port nicht erlaubt",
    "718": "Externer Port/Protokoll ist schon belegt (Konflikt mit bestehender Freigabe)",
    "724": "Interner und externer Port müssen gleich sein",
    "725": "Nur dauerhafte Freigaben (Lease 0) unterstützt",
    "726": "Remote-Host muss leer sein",
    "727": "Externer Port muss Platzhalter sein",
    "728": "Keine weiteren Portfreigaben möglich",
    "729": "Konflikt mit anderer Freigabe-Art (z. B. Web-UI/Exposed Host oder nicht erlaubt fürs Gerät)",
}


def normalize_protocol(protocol: str) -> str:
    p = (protocol or "").strip().upper()
    if p not in PROTOCOLS:
        raise InvalidParameterError(f'Unbekanntes Protokoll "{protocol}" – erlaubt: TCP, UDP.')
    return p


def validate_port(port: int, what: str) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise InvalidParameterError(f"{what} muss 1–65535 sein.")
    return port


def validate_description(text: str) -> str:
    d = (text or "").strip()
    if not 1 <= len(d) <= MAX_DESCRIPTION or not _DESCRIPTION.match(d):
        raise InvalidParameterError(
            f"description: 1–{MAX_DESCRIPTION} Zeichen, nur Buchstaben, Ziffern, Leerzeichen und . : / ( ) + - _"
        )
    return d


def translate_error(exc: FritzError, what: str) -> FritzError:
    code = exc.tr064_code
    if isinstance(exc, PermissionDeniedError) or code in {"606", "729"}:
        err: FritzError = PermissionDeniedError(
            f"{what}: von der FRITZ!Box abgelehnt ({UPNP_ERRORS.get(code or '', 'nicht berechtigt')}).",
            hint=SELF_PORTFORWARD_HINT,
        )
    elif code in UPNP_ERRORS:
        err = InvalidParameterError(f"{what}: {UPNP_ERRORS[code or '']} (TR-064-Fehler {code}).")
    else:
        return exc
    err.tr064_code = code
    return err


class PortForwardClient:
    def __init__(self, tr064: Tr064Client, diag: DiagnoseClient, resolver: HostResolver) -> None:
        self.tr064 = tr064
        self.diag = diag
        self.resolver = resolver

    def service(self) -> str:
        return str(self.tr064.wan_connection_status()["service"])

    def list_all(self) -> dict[str, Any]:
        mappings = self.diag.port_mappings()
        names = {h.ip: h.name for h in self._hosts_safe()}
        for m in mappings:
            m["internal_name"] = names.get(str(m.get("internal_client") or "")) or None
        return {
            "service": self.service(),
            "count": len(mappings),
            "active": sum(1 for m in mappings if m["enabled"]),
            "port_forwards": mappings,
            "note": "IPv4-Portfreigaben laut TR-064-WAN-Portmapping. IPv6-Freigaben (Pinholes) und ggf. nur "
            "in der Web-UI angelegte Freigaben sind hier nicht enthalten.",
        }

    def _hosts_safe(self) -> list[Host]:
        try:
            return self.resolver.hosts()
        except FritzError:
            return []

    def find(self, protocol: str, external_port: int) -> dict[str, Any] | None:
        for m in self.diag.port_mappings():
            if str(m.get("protocol") or "").upper() == protocol and str(m.get("external_port")) == str(external_port):
                return m
        return None

    def read_specific(
        self, service: str, protocol: str, external_port: int, remote_host: str = ""
    ) -> dict[str, Any] | None:
        r = self.tr064.try_call(
            service,
            "GetSpecificPortMappingEntry",
            NewRemoteHost=remote_host,
            NewExternalPort=external_port,
            NewProtocol=protocol,
        )
        if r is None:
            return None
        return {
            "internal_client": r.get("NewInternalClient"),
            "internal_port": r.get("NewInternalPort"),
            "enabled": truthy(r.get("NewEnabled")),
            "description": r.get("NewPortMappingDescription"),
        }

    def add(
        self, service: str, host: Host, protocol: str, external_port: int, internal_port: int, description: str
    ) -> dict[str, Any]:
        what = f"Portfreigabe {protocol} {external_port}"
        try:
            self.tr064.call(
                service,
                "AddPortMapping",
                NewRemoteHost="",
                NewExternalPort=external_port,
                NewProtocol=protocol,
                NewInternalPort=internal_port,
                NewInternalClient=host.ip,
                NewEnabled=1,
                NewPortMappingDescription=description,
                NewLeaseDuration=0,
            )
        except FritzError as exc:
            raise translate_error(exc, what) from None
        after = self.read_specific(service, protocol, external_port)
        base = {
            "service": service,
            "protocol": protocol,
            "external_port": external_port,
            "internal_client": host.ip,
            "internal_port": internal_port,
            "target": host.as_dict(),
            "description": description,
        }
        if after is None:
            return {
                **base,
                "verified": False,
                "note": "Angelegt gemeldet, aber nicht rücklesbar – list_port_forwards prüfen.",
            }
        ok = (
            str(after["internal_client"]) == host.ip
            and str(after["internal_port"]) == str(internal_port)
            and after["enabled"]
        )
        result = {**base, "read_back": after, "verified": ok}
        if not ok:
            result["note"] = "Die Box meldet eine abweichende Freigabe – nicht als Erfolg werten."
        return result

    def delete(self, service: str, entry: dict[str, Any], protocol: str, external_port: int) -> dict[str, Any]:
        what = f"Portfreigabe {protocol} {external_port}"
        remote = str(entry.get("remote_host") or "")
        try:
            self.tr064.call(
                service, "DeletePortMapping", NewRemoteHost=remote, NewExternalPort=external_port, NewProtocol=protocol
            )
        except FritzError as exc:
            raise translate_error(exc, what) from None
        still = self.read_specific(service, protocol, external_port, remote)
        result: dict[str, Any] = {"service": service, "deleted": entry, "verified": still is None}
        if still is not None:
            result["note"] = "Die Freigabe ist nach dem Löschen weiterhin vorhanden – nicht als Erfolg werten."
        return result


def require_absent(existing: dict[str, Any] | None, protocol: str, external_port: int) -> None:
    if existing is not None:
        raise InvalidParameterError(
            f"Externer Port {external_port}/{protocol} ist schon freigegeben "
            f"(→ {existing.get('internal_client')}:{existing.get('internal_port')}, "
            f'"{existing.get("description") or ""}").',
            hint="Erst delete_port_forward_plan/_execute, dann neu anlegen.",
        )


def require_present(existing: dict[str, Any] | None, protocol: str, external_port: int) -> dict[str, Any]:
    if existing is None:
        raise NotFoundError(f"Keine Portfreigabe für {external_port}/{protocol} – siehe list_port_forwards.")
    return existing
