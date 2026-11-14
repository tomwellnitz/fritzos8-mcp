"""TR-064 layer on top of fritzconnection: generic introspection/caller + curated actions."""

from __future__ import annotations

import ipaddress
import logging
import re
import threading
from collections.abc import Callable, Sequence
from typing import Any, Protocol

from defusedxml import ElementTree as ET

from .config import Config
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
from .redact import redact_obj
from .security import check_generic_action, is_denied, is_read_only_action, mask_service_fields

log = logging.getLogger(__name__)

# AVM TR-064 (X_AVM-DE_Auth): 866 second factor required, 867 blocked, 868 busy.
_TWO_FACTOR = re.compile(r"(errorCode:\s*86[678]\b|second factor|zweiter faktor|zusatzbest)", re.I)
_AUTH_CODE = re.compile(r"errorCode:\s*(606|820)\b")  # 606 action not authorized, 820 internal auth
_CONNECTIVITY = re.compile(
    r"(unable to get a connection|timed out|timeout|connection (refused|reset|aborted)"
    r"|max retries|name or service not known|no route to host)",
    re.I,
)
_ERROR_CODE = re.compile(r"errorCode:\s*(\d+)")

# V-7 (AVM doc): TR-064 services first; ``WANIPConn1``/``WANCommonIFC1`` are IGD (UPnP) service ids.
IGD_WAN_IP = "WANIPConn1"
IGD_WAN_COMMON = "WANCommonIFC1"
IGD_SERVICES = frozenset({IGD_WAN_IP, IGD_WAN_COMMON})
WAN_CONNECTION_SERVICES = ("WANIPConnection1", "WANPPPConnection1", IGD_WAN_IP)


class ConnectionLike(Protocol):
    address: str
    port: int
    session: Any

    @property
    def services(self) -> dict[str, Any]: ...

    def call_action(
        self, service_name: str, action_name: str, *, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]: ...


def default_connect(config: Config) -> Callable[[], ConnectionLike]:
    def connect() -> ConnectionLike:
        from fritzconnection import FritzConnection

        return FritzConnection(  # type: ignore[no-any-return]
            address=config.host,
            user=config.user,
            password=config.password,
            use_tls=config.use_tls,
            timeout=config.timeout,
        )

    return connect


def map_exception(exc: Exception, what: str) -> FritzError:
    """Translate fritzconnection / requests exceptions into our error classes.

    The SOAP ``errorCode`` (if any) is kept in ``tr064_code`` so callers can explain
    action-specific codes (e.g. 718 ConflictInMappingEntry for port mappings)."""
    err = _map_exception(exc, what)
    m = _ERROR_CODE.search(str(exc))
    if m:
        err.tr064_code = m.group(1)
    return err


def _map_exception(exc: Exception, what: str) -> FritzError:
    from fritzconnection.core.exceptions import (
        FritzActionError,
        FritzArgumentError,
        FritzAuthorizationError,
        FritzConnectionException,
        FritzSecurityError,
        FritzServiceError,
    )

    text = str(exc)
    if _TWO_FACTOR.search(text):
        return ConfirmationRequiredError(f"{what}: Zusatzbestätigung (2FA) verlangt.")
    if isinstance(exc, FritzAuthorizationError):
        return AuthError(f"{what}: TR-064-Anmeldung abgelehnt.")
    if isinstance(exc, FritzSecurityError) or _AUTH_CODE.search(text):
        return PermissionDeniedError(f"{what}: nicht berechtigt.")
    if isinstance(exc, FritzServiceError | FritzActionError):
        return NotFoundError(f"{what}: Service/Action auf dieser Box nicht vorhanden.")
    if isinstance(exc, FritzArgumentError):
        return InvalidParameterError(f"{what}: ungültiges Argument.")
    if isinstance(exc, FritzConnectionException):
        first = text.strip().splitlines()[0] if text.strip() else type(exc).__name__
        if _CONNECTIVITY.search(text):
            # Live beobachtet (7583, überlastete Box): "Unable to get a connection: …Read timed out".
            # Muss als Verbindungsfehler gelten – sonst schlucken optionale Abfragen (try_call) ihn
            # und Tools melden fälschlich "kein DSL" / "Protokoll nicht lesbar".
            return FritzConnectionError(f"{what}: FRITZ!Box antwortet nicht ({first[:120]}).")
        return FritzError(f"{what}: {first}")
    if type(exc).__module__.startswith(("requests", "urllib3")) or isinstance(exc, OSError):
        return FritzConnectionError(f"{what}: FRITZ!Box nicht erreichbar ({type(exc).__name__}).")
    return FritzError(f"{what}: {type(exc).__name__}")


def _norm_service(name: str) -> str:
    """'Hosts:1' / 'Hosts' → 'Hosts1' (fritzconnection's naming)."""
    name = name.strip()
    m = re.match(r"^(.*?):?(\d+)$", name)
    if m:
        return f"{m.group(1)}{m.group(2)}"
    return f"{name}1"


def parse_host_list_xml(xml_bytes: bytes | str) -> list[dict[str, str]]:
    root = ET.fromstring(xml_bytes)
    return [{child.tag: (child.text or "") for child in item} for item in root.iter("Item")]


class Tr064Client:
    def __init__(
        self,
        connect: Callable[[], ConnectionLike],
        secrets: tuple[str, ...] = (),
        guard: BoxGuard | None = None,
    ) -> None:
        self._connect = connect
        self._fc: ConnectionLike | None = None
        self._lock = threading.Lock()
        self._secrets = secrets
        self.guard = guard  # stage 7.1: throttling, cache, breaker (None = unguarded)

    # ---------------------------------------------------------------- plumbing

    @property
    def secrets(self) -> tuple[str, ...]:
        return self._secrets

    @property
    def fc(self) -> ConnectionLike:
        with self._lock:
            if self._fc is None:

                def connect() -> ConnectionLike:
                    try:
                        return self._connect()
                    except FritzError:
                        raise
                    except Exception as exc:
                        raise map_exception(exc, "TR-064-Verbindung") from None

                self._fc = guarded(self.guard, connect, what="TR-064-Verbindung", idempotent=True)
            return self._fc

    def call(self, service: str, action: str, **arguments: Any) -> dict[str, Any]:
        fc = self.fc

        def do() -> dict[str, Any]:
            try:
                return fc.call_action(_norm_service(service), action, arguments=arguments or None)
            except Exception as exc:
                raise map_exception(exc, f"{service}:{action}") from None

        read_only = is_read_only_action(action)
        try:
            result = guarded(self.guard, do, what=f"{service}:{action}", idempotent=read_only)
        except FritzError as exc:
            record_health(self.guard, "tr064", exc)
            raise
        else:
            record_health(self.guard, "tr064", None)
            return result
        finally:
            if not read_only and self.guard is not None:
                # Every write (even a failed one) may have changed the box: drop all cached reads.
                self.guard.invalidate()

    def call_first(self, service: str, actions: Sequence[str], **arguments: Any) -> tuple[str, dict[str, Any]]:
        """Call the first spelling of an action the box knows (documented name first, legacy names after).

        Only "action/service not found" moves on to the next name; every other error is raised at once.
        Returns (action actually used, result)."""
        last: NotFoundError | None = None
        for action in actions:
            try:
                return action, self.call(service, action, **arguments)
            except NotFoundError as exc:
                last = exc
        if last is None:
            raise InvalidParameterError("call_first: keine Action angegeben.")
        raise last

    def cached(self, key: str, loader: Callable[[], Any]) -> Any:
        """Short-lived cache of the box guard for expensive reads (no-op without guard)."""
        return loader() if self.guard is None else self.guard.cached(f"tr064:{key}", loader)

    def session_get(self, url: str) -> Any:
        """GET via fritzconnection's session (documents behind TR-064 paths), throttled like a call.
        Transport errors become FritzConnectionError; HTTP status handling stays with the caller."""
        fc = self.fc

        def do() -> Any:
            try:
                return fc.session.get(url)
            except Exception as exc:
                raise FritzConnectionError(f"Box-Dokument nicht abrufbar ({type(exc).__name__}).") from None

        try:
            response = guarded(self.guard, do, what="Box-Dokument", idempotent=True)
        except FritzError as exc:
            record_health(self.guard, "tr064", exc)
            raise
        record_health(self.guard, "tr064", None)
        return response

    def _service(self, service: str) -> Any:
        services = self.fc.services
        key = _norm_service(service)
        if key not in services:
            raise NotFoundError(f"TR-064-Service {service} gibt es auf dieser Box nicht.")
        return services[key]

    # ---------------------------------------------------------------- generic layer

    def list_services(self) -> list[dict[str, Any]]:
        out = []
        for name in sorted(self.fc.services):
            svc = self.fc.services[name]
            try:
                actions = sorted(svc.actions)
            except Exception as exc:  # SCPD not loadable for this service
                log.debug("SCPD für %s nicht lesbar: %s", name, type(exc).__name__)
                actions = []
            out.append(
                {
                    "service": name,
                    "actions": len(actions),
                    "read_actions": [a for a in actions if is_read_only_action(a) and not is_denied(a, name)],
                }
            )
        return out

    def describe_action(self, service: str, action: str) -> dict[str, Any]:
        svc = self._service(service)
        if action not in svc.actions:
            raise NotFoundError(f"Action {action} gibt es in {service} nicht.")
        act = svc.actions[action]
        state_vars = svc.state_variables
        args = []
        for arg_name, arg in act.arguments.items():
            sv = state_vars.get(arg.relatedStateVariable) if arg.relatedStateVariable else None
            args.append(
                {
                    "name": arg_name,
                    "direction": arg.direction,
                    "type": getattr(sv, "dataType", None),
                    "allowed_values": list(getattr(sv, "allowed_values", None) or []) or None,
                    "default": getattr(sv, "defaultValue", None),
                }
            )
        try:
            check_generic_action(_norm_service(service), action)
            callable_via_generic = True
        except FritzError:
            callable_via_generic = False
        return {
            "service": _norm_service(service),
            "action": action,
            "read_only": is_read_only_action(action),
            "denied": is_denied(action, _norm_service(service)),
            "callable_via_tr064_call": callable_via_generic,
            "arguments": args,
        }

    def generic_call(self, service: str, action: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        check_generic_action(_norm_service(service), action)
        arguments = arguments or {}
        svc = self._service(service)
        if action not in svc.actions:
            raise NotFoundError(f"Action {action} gibt es in {service} nicht.")
        known_in = {n for n, a in svc.actions[action].arguments.items() if a.direction == "in"}
        unknown = sorted(set(arguments) - known_in)
        if unknown:
            allowed = ", ".join(sorted(known_in)) or "–"
            raise InvalidParameterError(f"Unbekannte Argumente für {action}: {', '.join(unknown)} (erlaubt: {allowed})")
        result = mask_service_fields(_norm_service(service), action, self.call(service, action, **arguments))
        return {"service": _norm_service(service), "action": action, "result": redact_obj(result, self._secrets)}

    # ---------------------------------------------------------------- curated reads

    def system_info(self) -> dict[str, Any]:
        r = self.call("DeviceInfo1", "GetInfo")
        return {
            "model": r.get("NewModelName"),
            "description": r.get("NewDescription"),
            "software_version": r.get("NewSoftwareVersion"),
            "hardware_version": r.get("NewHardwareVersion"),
            "uptime_s": r.get("NewUpTime"),
            "manufacturer": r.get("NewManufacturerName"),
        }

    def try_call(self, service: str, action: str, **args: Any) -> dict[str, Any] | None:
        try:
            return self.call(service, action, **args)
        except (NotFoundError, FritzError) as exc:
            if isinstance(exc, AuthError | ConfirmationRequiredError | FritzConnectionError):
                raise
            return None

    def fetch(self, url_or_path: str) -> bytes:
        """GET a document the box hands out as URL/path next to a TR-064 action (call list, TAM
        message list, phonebook …). The URL usually carries a session id – it never appears in
        errors or logs."""
        fc = self.fc
        url = url_or_path if re.match(r"^https?://", url_or_path, re.I) else f"{fc.address}:{fc.port}{url_or_path}"
        response = self.session_get(url)
        if not getattr(response, "ok", False):
            status = getattr(response, "status_code", "?")
            raise FritzError(f"Box-Dokument nicht abrufbar (HTTP {status}).")
        return bytes(response.content)

    def wan_connection_status(self) -> dict[str, Any]:
        """Connection status from the first WAN connection service that answers (V-7, AVM doc).

        Order: TR-064 ``WANIPConnection1`` → ``WANPPPConnection1`` → IGD ``WANIPConn1`` (UPnP, only with
        "Statusinformationen über UPnP übertragen"). A service reporting ``Connected`` wins; otherwise the
        first one with any status. ``source`` says whether the TR-064 or the IGD service answered."""
        first: dict[str, Any] | None = None
        for service in WAN_CONNECTION_SERVICES:
            r = self.try_call(service, "GetStatusInfo")
            if not r or r.get("NewConnectionStatus") in (None, ""):
                continue
            entry = {
                "service": service,
                "source": "igd" if service in IGD_SERVICES else "tr064",
                "status": r.get("NewConnectionStatus"),
                "uptime_s": r.get("NewUptime"),
                "last_error": r.get("NewLastConnectionError"),
            }
            if entry["status"] == "Connected":
                return entry
            first = first or entry
        if first is not None:
            return first
        raise NotFoundError(
            "Kein WAN-Verbindungsdienst liefert einen Status (WANIPConnection1, WANPPPConnection1, WANIPConn1)."
        )

    def call_igd_first(self, service: str, action: str, **args: Any) -> tuple[str, dict[str, Any]] | None:
        """IGD-only actions (``X_AVM_DE_GetExternalIPv6Address``, ``X_AVM_DE_GetDNSServer`` …) exist only in the
        IGD service ``WANIPConn1``: try the given connection service first, then ``WANIPConn1``."""
        for svc in dict.fromkeys((service, IGD_WAN_IP)):
            r = self.try_call(svc, action, **args)
            if r:
                return svc, r
        return None

    def wan_status(self) -> dict[str, Any]:
        out: dict[str, Any] = {"connection": self.wan_connection_status()}
        service = out["connection"]["service"]
        link = self.try_call("WANCommonInterfaceConfig1", "GetCommonLinkProperties")
        if link:
            out["link"] = {
                "access_type": link.get("NewWANAccessType"),
                "physical_status": link.get("NewPhysicalLinkStatus"),
                "max_down_bps": link.get("NewLayer1DownstreamMaxBitRate"),
                "max_up_bps": link.get("NewLayer1UpstreamMaxBitRate"),
            }
        ip4 = self.try_call(service, "GetExternalIPAddress")
        raw4 = str((ip4 or {}).get("NewExternalIPAddress") or "").strip()
        out["external_ipv4"] = raw4 or None
        # AVM IGD doc: the external IPv6 address exists only as IGD action (WANIPConn1), also for PPP connections.
        ip6 = self.call_igd_first(service, "X_AVM_DE_GetExternalIPv6Address")
        out["external_ipv6"] = ip6[1].get("NewExternalIPv6Address") if ip6 else None
        if raw4:
            try:
                ipaddress.IPv4Address(raw4)
            except ValueError:
                # Live (7583/8.26, WANPPPConnection1, DS-Lite): GetExternalIPAddress returned the IPv6 address.
                out["external_ipv4"] = None
                out["ipv4_note"] = (
                    "Box meldet keine öffentliche IPv4 – DS-Lite/IPv6-only bzw. die Box liefert in "
                    "GetExternalIPAddress eine IPv6-Adresse (steht unter external_ipv6)."
                )
                return out
        if out["connection"].get("status") == "Connected" and not out["external_ipv4"] and out["external_ipv6"]:
            # Live auf 7583/8.26 beobachtet: verbunden, aber leere IPv4 → kein eigener öffentlicher
            # IPv4-Anschluss (DS-Lite/CGNAT). Kein Fehler, nur erklären statt "" stehen zu lassen.
            out["external_ipv4"] = None
            out["ipv4_note"] = "keine eigene öffentliche IPv4 (vermutlich DS-Lite/CGNAT); IPv4 läuft über den Provider"
        return out

    def list_hosts(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = self.cached("list_hosts", self._list_hosts)
        return result

    def host_list_items(self) -> list[dict[str, str]] | None:
        """Raw <Item> entries of the host list XML (all fields of AVM doc "Hosts" 4.1, e.g. X_AVM-DE_Model,
        X_AVM-DE_UpdateAvailable) or None if the box does not hand out the document. Cached briefly. Callers
        must whitelist fields – the items also carry the repeater login token (X_AVM-DE_URLParameters)."""
        items: list[dict[str, str]] | None = self.cached("host_list_items", self._host_list_items)
        return items

    def _host_list_items(self) -> list[dict[str, str]] | None:
        path_result = self.try_call("Hosts1", "X_AVM-DE_GetHostListPath")
        if path_result and path_result.get("NewX_AVM-DE_HostListPath"):
            fc = self.fc
            url = f"{fc.address}:{fc.port}{path_result['NewX_AVM-DE_HostListPath']}"
            try:
                response = self.session_get(url)
                if getattr(response, "ok", False):
                    return parse_host_list_xml(response.content)
            except FritzConnectionError:
                raise
            except Exception as exc:
                log.debug("Hostliste per Pfad fehlgeschlagen (%s) – Fallback", type(exc).__name__)
        return None

    def change_counter_raw(self) -> int | None:
        """Hosts ``X_AVM-DE_GetChangeCounter`` → ``NewX_AVM-DE_ChangeCounter`` (AVM doc "Hosts" 2.5) as delivered."""
        r = self.try_call("Hosts1", "X_AVM-DE_GetChangeCounter")
        value = (r or {}).get("NewX_AVM-DE_ChangeCounter")
        try:
            return int(value) if value not in (None, "") else None
        except (TypeError, ValueError):
            return None

    def change_counter(self) -> int | None:
        """Usable change counter (grows whenever the host list changes – a cheap "did anything change?" check) or
        None. Live (7583/8.26): the action exists but always answers 0 although devices come and go – 0 is
        therefore treated as "no counter", callers then read the host list instead of relying on it."""
        value = self.change_counter_raw()
        return value if value else None

    def _list_hosts(self) -> list[dict[str, Any]]:
        items = self.host_list_items()
        if items is not None:
            return [
                {
                    "name": i.get("HostName", ""),
                    "ip": i.get("IPAddress", ""),
                    "mac": i.get("MACAddress", ""),
                    "active": i.get("Active") == "1",
                    "interface": i.get("InterfaceType", ""),
                    "address_source": i.get("AddressSource", ""),
                    "guest": i.get("X_AVM-DE_Guest") == "1",
                }
                for i in items
            ]
        # Fallback: one SOAP call per host
        count = int(self.call("Hosts1", "GetHostNumberOfEntries").get("NewHostNumberOfEntries", 0))
        hosts = []
        for idx in range(count):
            e = self.call("Hosts1", "GetGenericHostEntry", NewIndex=idx)
            hosts.append(
                {
                    "name": e.get("NewHostName", ""),
                    "ip": e.get("NewIPAddress", ""),
                    "mac": e.get("NewMACAddress", ""),
                    "active": bool(e.get("NewActive")),
                    "interface": e.get("NewInterfaceType", ""),
                    "address_source": e.get("NewAddressSource", ""),
                }
            )
        return hosts

    def host_name_by_mac(self, mac: str) -> str | None:
        r = self.try_call("Hosts1", "GetSpecificHostEntry", NewMACAddress=mac)
        return None if r is None else str(r.get("NewHostName") or "")

    def get_lan_dns(self) -> dict[str, Any]:
        r = self.try_call("LANHostConfigManagement1", "GetDNSServer")
        source = "GetDNSServer"
        if r is None:
            r = self.call("LANHostConfigManagement1", "GetInfo")
            source = "GetInfo"
        raw = str(r.get("NewDNSServers") or "")
        return {"dns_servers": [s for s in re.split(r"[,\s]+", raw) if s], "source": source}

    def uptime(self) -> int | None:
        r = self.try_call("DeviceInfo1", "GetInfo")
        value = r.get("NewUpTime") if r else None
        return int(value) if value is not None else None

    # ---------------------------------------------------------------- curated writes

    def set_host_name(self, mac: str, name: str) -> None:
        self.call("Hosts1", "X_AVM-DE_SetHostNameByMACAddress", NewMACAddress=mac, NewHostName=name)

    def reboot(self) -> None:
        self.call("DeviceConfig1", "Reboot")

    def force_termination(self, service: str) -> None:
        self.call(service, "ForceTermination")
