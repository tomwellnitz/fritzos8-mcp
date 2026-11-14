"""DNS settings (read only).

Sources, each reported separately so a missing one never hides the others:

- TR-064 ``LANHostConfigManagement1:GetDNSServer`` – DNS server the box hands out via DHCP
  (live-verified, same as ``get_lan_dns``).
- ``WANIPConn1``/``WANPPPConnection1``: ``X_AVM_DE_GetDNSServer`` / ``X_GetDNSServers`` (upstream IPv4
  DNS in use) and ``X_AVM_DE_GetIPv6DNSServer`` (upstream IPv6 DNS in use). Spelling with underscores as in
  the AVM documents "Internet Gateway Device Support" v1/v2 (fields ``NewIPv4DNSServer1/2``,
  ``NewIPv6DNSServer1/2``); ``X_GetDNSServers`` is in the TR-064 WAN connection documents. The hyphenated
  spelling used before (``X_AVM-DE_…``) is only tried as a last resort.
- ``/api/v0/generic/dnscfg`` and ``/api/v0/generic/ipv6`` (undocumented web REST API):
  user-defined DNS servers, local DNSv6 server, DoT flags. The endpoint and field names are
  known from Meine-smarte-Welt/fritzbox_netzwerk (README states MIT, but the repo has no
  license file → used as a hint only, no code taken) and still need live verification.

Writing DNS/DNSv6 is NOT implemented: it is not possible via TR-064, and the REST ``PUT``
is unverified (see ROADMAP). On the 7583 such changes demand a Zusatzbestätigung (2FA).
"""

from __future__ import annotations

from typing import Any

from .errors import AuthError, FritzError
from .rest import RestClient
from .tr064 import Tr064Client

DNSCFG_PATH = "/api/v0/generic/dnscfg"
IPV6_PATH = "/api/v0/generic/ipv6"

EMPTY = {"", "0.0.0.0", "::"}  # noqa: S104 - the box's "not set" marker, not a bind address

DNSCFG_FIELDS = (
    "ipv4_use_user_dns",
    "ipv4_user_firstdns",
    "ipv4_user_seconddns",
    "ipv6_use_user_dns",
    "ipv6_user_firstdns",
    "ipv6_user_seconddns",
    "ipv4_dhcpserver_lan_dns",
    "dns_over_tls_enabled",
    "public_dns_servers_use_as_fallback",
)
IPV6_FIELDS = ("lan_dns6_server", "radv_advdns")


def _addr(value: Any) -> str | None:
    v = str(value if value is not None else "").strip()
    return None if v in EMPTY else v


def _flag(value: Any) -> bool | None:
    if value is None:
        return None
    return str(value).strip() == "1"


def _servers(r: dict[str, Any] | None) -> list[str]:
    out: list[str] = []
    for key, value in (r or {}).items():
        if "dnsserver" not in key.lower():
            continue
        for part in str(value or "").replace(";", ",").split(","):
            a = _addr(part)
            if a and a not in out:
                out.append(a)
    return out


# Tried in this order; the first one the box knows wins (see module docstring).
UPSTREAM_V4_ACTIONS = ("X_AVM_DE_GetDNSServer", "X_GetDNSServers", "X_AVM-DE_GetDNSServer")
UPSTREAM_V6_ACTIONS = ("X_AVM_DE_GetIPv6DNSServer", "X_AVM-DE_GetIPv6DNSServer")


class DnsClient:
    def __init__(self, tr064: Tr064Client, rest: RestClient | None) -> None:
        self.tr064 = tr064
        self.rest = rest

    def _section(self, fn: Any) -> dict[str, Any]:
        try:
            result: dict[str, Any] = fn()
            return result
        except AuthError:
            raise
        except FritzError as exc:
            return {"available": False, "error": exc.to_dict()}

    def _lan(self) -> dict[str, Any]:
        return {"available": True, **self.tr064.get_lan_dns()}

    def _upstream(self) -> dict[str, Any]:
        service = str(self.tr064.wan_connection_status()["service"])
        v4_source, v4 = self._first(service, UPSTREAM_V4_ACTIONS)
        v6_source, v6 = self._first(service, UPSTREAM_V6_ACTIONS)
        return {
            "available": v4 is not None or v6 is not None,
            "service": service,
            "ipv4_servers": _servers(v4),
            "ipv4_source": v4_source,
            "ipv6_servers": _servers(v6),
            "ipv6_source": v6_source,
            "note": "Vom Provider bzw. eigene Einstellung – aktuell genutzte Upstream-DNS-Server.",
        }

    def _first(self, service: str, actions: tuple[str, ...]) -> tuple[str | None, dict[str, Any] | None]:
        # The X_AVM_DE_* DNS actions are IGD actions (only in WANIPConn1, V-7) – try that service as well.
        for action in actions:
            found = self.tr064.call_igd_first(service, action)
            if found is not None:
                return action, found[1]
        return None, None

    def _rest_get(self, path: str) -> dict[str, Any]:
        if self.rest is None:
            raise FritzError("REST-Client nicht konfiguriert.")
        data = self.rest.request("GET", path, missing="firmware")
        if not isinstance(data, dict):
            raise FritzError(f"GET {path}: unerwartete Antwort.")
        return data

    def _web(self) -> dict[str, Any]:
        cfg = self._rest_get(DNSCFG_PATH)
        out: dict[str, Any] = {
            "available": True,
            "verified_endpoint": True,  # live gelesen: 7583/8.26 und 6660/8.25 (2026-11-14)
            "internet_ipv4": {
                "custom": _flag(cfg.get("ipv4_use_user_dns")),
                "dns1": _addr(cfg.get("ipv4_user_firstdns")),
                "dns2": _addr(cfg.get("ipv4_user_seconddns")),
            },
            "internet_ipv6": {
                "custom": _flag(cfg.get("ipv6_use_user_dns")),
                "dns1": _addr(cfg.get("ipv6_user_firstdns")),
                "dns2": _addr(cfg.get("ipv6_user_seconddns")),
            },
            "home_ipv4_dns": _addr(cfg.get("ipv4_dhcpserver_lan_dns")),
            "dns_over_tls": _flag(cfg.get("dns_over_tls_enabled")),
            "public_dns_fallback": _flag(cfg.get("public_dns_servers_use_as_fallback")),
            "fields_missing": [f for f in DNSCFG_FIELDS if f not in cfg],
            "fields_present": sorted(cfg),
        }
        try:
            v6 = self._rest_get(IPV6_PATH)
            out["home_ipv6_dns"] = _addr(v6.get("lan_dns6_server"))
            out["home_ipv6_via_router_advertisement"] = _flag(v6.get("radv_advdns"))
            out["ipv6_fields_missing"] = [f for f in IPV6_FIELDS if f not in v6]
        except AuthError:
            raise
        except FritzError as exc:
            out["home_ipv6_error"] = exc.to_dict()
        out["note"] = (
            "Quelle /api/v0 (undokumentiert; Lesen live bestätigt auf FRITZ!OS 8.25/8.26). "
            "Ändern ist bewusst nicht möglich – Web-Oberfläche benutzen (verlangt ggf. Zusatzbestätigung)."
        )
        return out

    def settings(self) -> dict[str, Any]:
        return {
            "lan_dhcp": self._section(self._lan),
            "upstream": self._section(self._upstream),
            "web_settings": self._section(self._web),
            "write_supported": False,
        }
