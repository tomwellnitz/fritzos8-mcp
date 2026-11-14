"""VPN connections, Powerline adapters and web-UI firewall lists via /api/v0 (FRITZ!OS 8), read-only.

Structures seen live on FRITZ!Box 7583 / FRITZ!OS 8.26 (browser capture, 2026-11-14):

- ``GET /api/v0/generic/vpn`` → ``{"connection": [...], "global": [...]}``. The raw answer contains
  WireGuard pre-shared keys and complete WireGuard configurations plus IPSec PSK/XAuth credentials in
  plain text. The RestClient already masks them (``redact_api``); on top of that only WHITELISTED fields
  leave this module.
- ``GET /api/v0/generic/plc`` → ``{"device": [...], "powerSave": …}`` (whitelisted fields only; the
  units of ``phyRateRX/TX`` are not documented – presumably Mbit/s).
- ``generic/forwardrules`` and ``generic/ipv6firewall`` exist, their structure is unknown: returned
  redacted and size-limited as ``raw`` with ``verified_structure: false``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from .errors import AuthError, ConfirmationRequiredError, FritzError
from .rest import RestClient
from .util import safe_mac, truthy

VPN_PATH = "/api/v0/generic/vpn"
PLC_PATH = "/api/v0/generic/plc"
FORWARDRULES_PATH = "/api/v0/generic/forwardrules"
IPV6FIREWALL_PATH = "/api/v0/generic/ipv6firewall"
RAW_LIMIT = 8000  # characters of a raw (unverified) document in a tool answer

VPN_STATE_LABELS = {
    "ready": "verbunden/bereit",
    "not active": "nicht aktiv",
    "connecting": "verbindet",
    "error": "Fehler",
}


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _str(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def epoch_to_iso(value: Any) -> str | None:
    ts = _int(value)
    if not ts or ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _nets(value: Any) -> list[str]:
    return [n.strip() for n in str(value or "").replace(";", ",").split(",") if n.strip()]


# Connected states: an error code next to them is the last (historical) error, not an active one. Live (7583,
# 8.26): state "ready" together with wg_error 3400 / wg_error_reason 3430. The codes are not documented (the
# /api/v0 interface is undocumented) – they are passed on raw, never guessed.
CONNECTED_STATES = {"ready"}
VPN_ERROR_TEXTS: dict[str, str] = {}  # only documented codes belong here – none known so far


def vpn_error(
    state: str | None, code: str | None, reason: str | None
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """(active error, last historical error) of a connection."""
    if not code or code == "0":
        return None, None
    note = "Fehlercodes der Box sind nicht dokumentiert – Rohwerte."
    entry: dict[str, Any] = {"code": code, "reason": reason, "description": VPN_ERROR_TEXTS.get(code)}
    if (state or "").lower() in CONNECTED_STATES:
        historical = note + " Die Verbindung steht – das ist der zuletzt gespeicherte Fehler, kein aktiver."
        return None, {**entry, "historical": True, "note": historical}
    return {**entry, "active": True, "note": note}, None


def parse_vpn_connection(c: dict[str, Any]) -> dict[str, Any]:
    wireguard = any(_str(c.get(k)) for k in ("wg_endpoint", "wg_connection_type", "wg_allowed_ips"))
    state = _str(c.get("state"))
    error, last_error = vpn_error(state, _str(c.get("wg_error")), _str(c.get("wg_error_reason")))
    return {
        "name": _str(c.get("name")),
        "uid": _str(c.get("UID") or c.get("uid")),
        "type": "WireGuard" if wireguard else "IPSec",
        "state": state,
        "state_label": VPN_STATE_LABELS.get(state or "", state),
        "activated": truthy(c.get("activated")),
        "connected_since": epoch_to_iso(c.get("connected_since")),
        "remote": _str(c.get("wg_endpoint") or c.get("dst")),
        "remote_ip": _str(c.get("remote_ip")),
        "local_networks": _nets(c.get("display_local_net")),
        "remote_networks": _nets(c.get("display_remote_net") or c.get("wg_allowed_ips")),
        "wireguard_type": _str(c.get("wg_connection_type")) if wireguard else None,
        "error": error,
        "last_error": last_error,
    }


def parse_vpn(doc: dict[str, Any]) -> dict[str, Any]:
    conns = [parse_vpn_connection(c) for c in doc.get("connection") or [] if isinstance(c, dict)]
    glob = next((g for g in doc.get("global") or [] if isinstance(g, dict)), {})
    return {
        "available": True,
        "count": len(conns),
        "connections": conns,
        "active": sum(1 for c in conns if c["state"] == "ready"),
        "wireguard_listen_port": _int(glob.get("wg_listen_port")),
        "source": f"GET {VPN_PATH} (Struktur live gesehen auf FRITZ!OS 8.26)",
        "note": "Schlüssel, Pre-Shared-Keys, WireGuard-/IPSec-Konfigurationen und Zugangsdaten werden nie "
        "ausgegeben (schon im REST-Client geschwärzt, hier zusätzlich nur freigegebene Felder).",
    }


def parse_plc(doc: dict[str, Any]) -> dict[str, Any]:
    devices: list[dict[str, Any]] = []
    for d in doc.get("device") or []:
        if not isinstance(d, dict):
            continue
        remotes = [r for r in d.get("remoteAdapters") or [] if isinstance(r, dict)]
        devices.append(
            {
                "model": _str(d.get("model")),
                "mac": safe_mac(d.get("mac")) or _str(d.get("mac")),
                "status": _str(d.get("status")),
                "coupling": _str(d.get("coupling")),
                "firmware": _str(d.get("firmwareVersion")),
                "firmware_update_available": truthy(d.get("hasFirmwareupdate")),
                "phy_rate_rx": _int(d.get("phyRateRX")),
                "phy_rate_tx": _int(d.get("phyRateTX")),
                "green_mode": truthy(d.get("green")),
                "led": truthy(d.get("led")),
                "local": truthy(d.get("isLocal")),
                "remote_adapters": [
                    {
                        "mac": safe_mac(r.get("mac")) or _str(r.get("mac")),
                        "phy_rate_rx": _int(r.get("phyRateRX")),
                        "phy_rate_tx": _int(r.get("phyRateTX")),
                    }
                    for r in remotes
                ],
            }
        )
    hints = []
    for d in devices:
        rates = [r for r in (d["phy_rate_rx"], d["phy_rate_tx"]) if isinstance(r, int) and r > 0]
        rate = min(rates, default=None)
        if rate is not None and rate < 100:
            hints.append(
                f"{d['model'] or d['mac']}: niedrige PHY-Rate ({rate}) – andere Steckdose (nicht an "
                "Mehrfachsteckdose/Netzfilter), andere Stromphase oder Störquellen prüfen."
            )
        if d["firmware_update_available"]:
            hints.append(f"{d['model'] or d['mac']}: Firmware-Update verfügbar.")
    return {
        "available": True,
        "count": len(devices),
        "devices": devices,
        "power_save": truthy(doc.get("powerSave")) if doc.get("powerSave") is not None else None,
        "hints": hints,
        "units": "PHY-Raten wie von der Box geliefert, vermutlich Mbit/s (nicht dokumentiert, unverifiziert)",
        "source": f"GET {PLC_PATH} (Struktur live gesehen auf FRITZ!OS 8.26)",
    }


class VpnPlcClient:
    def __init__(self, rest: RestClient) -> None:
        self.rest = rest

    def _get(self, path: str) -> dict[str, Any]:
        data = self.rest.request("GET", path, missing="firmware")
        if not isinstance(data, dict):
            raise FritzError(f"GET {path}: unerwartete Antwort.")
        return data

    def vpn_connections(self) -> dict[str, Any]:
        return parse_vpn(self._get(VPN_PATH))

    def powerline(self) -> dict[str, Any]:
        return parse_plc(self._get(PLC_PATH))

    def raw_document(self, path: str) -> dict[str, Any]:
        """Unknown structure → redacted (RestClient) + size-limited raw JSON, clearly marked."""
        try:
            data = self._get(path)
        except (AuthError, ConfirmationRequiredError):
            raise
        except FritzError as exc:
            return {"available": False, "error": exc.to_dict()}
        text = json.dumps(data, ensure_ascii=False)
        out: dict[str, Any] = {
            "available": True,
            "verified_structure": False,
            "source": f"GET {path}",
            "note": "unverifiziert: Struktur dieses /api/v0-Endpunkts ist nicht belegt – Rohdaten (geschwärzt).",
        }
        if len(text) > RAW_LIMIT:
            out["raw_truncated"] = True
            out["raw_json"] = text[:RAW_LIMIT]
        else:
            out["raw"] = data
        return out

    def web_firewall_lists(self) -> dict[str, Any]:
        return {
            "forwardrules": self.raw_document(FORWARDRULES_PATH),
            "ipv6firewall": self.raw_document(IPV6FIREWALL_PATH),
        }
