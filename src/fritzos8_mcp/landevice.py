"""LAN device entries via /api/v0/generic/landevice (FRITZ!OS 8).

Python port of the author's own TypeScript client (mcp-fritzbox src/client/landevice.ts),
live-verified on FRITZ!Box 7583 / FRITZ!OS 8.26:

- ``GET    /api/v0/generic/landevice``
- ``PUT    /api/v0/generic/landevice/landevice/<UID>``  body ``{"static_dhcp": "1"}`` / ``{"friendly_name": "…"}``
- ``DELETE /api/v0/generic/landevice/landevice/<UID>``

The box may answer 200 and still discard a change (e.g. Zusatzbestätigung active on the
account), so every write is read back. The bulk action ``cleanup_landevices`` is
deliberately NOT implemented.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from pydantic import BaseModel

from .errors import (
    AuthError,
    ConfirmationRequiredError,
    FritzError,
    InvalidParameterError,
    NotFoundError,
)
from .rest import RestClient
from .util import normalize_mac, safe_mac, truthy, validate_hostname

LIST_PATH = "/api/v0/generic/landevice"


def device_path(uid: str) -> str:
    return f"/api/v0/generic/landevice/landevice/{quote(uid, safe='')}"


SILENT_DISCARD = (
    "Die FRITZ!Box hat die Anfrage angenommen, den Wert aber nicht übernommen. "
    "Typische Ursache: Zusatzbestätigung (2FA) für diesen Benutzer aktiv – die Box verwirft "
    "die Änderung dann still. Nichts geändert."
)


class LanDevice(BaseModel):
    uid: str
    name: str
    friendly_name: str
    mac: str
    ip: str
    static_dhcp: bool
    active: bool
    online: bool
    deleteable: bool

    @property
    def display_name(self) -> str:
        return self.friendly_name or self.name or self.mac

    @classmethod
    def from_raw(cls, d: dict[str, Any]) -> LanDevice:
        flags = [f.strip() for f in str(d.get("flags") or "").split(",")]
        raw_mac = str(d.get("mac") or "")
        return cls(
            uid=str(d.get("UID") or d.get("uid") or ""),
            name=str(d.get("name") or ""),
            friendly_name=str(d.get("friendly_name") or ""),
            mac=safe_mac(raw_mac) or raw_mac,
            ip=str(d.get("ip") or ""),
            static_dhcp=truthy(d.get("static_dhcp")),
            active=truthy(d.get("active")),
            online=truthy(d.get("online")),
            deleteable=str(d.get("deleteable") if d.get("deleteable") is not None else "") != "0"
            and "ownentry" not in flags
            and "device_not_deleteable" not in flags,
        )


def _device_node(data: Any) -> dict[str, Any] | None:
    if isinstance(data, dict):
        node = data.get("landevice")
        if isinstance(node, list):
            return node[0] if node and isinstance(node[0], dict) else None
        if isinstance(node, dict):
            return node
        return data
    return None


class LanDeviceClient:
    def __init__(self, rest: RestClient) -> None:
        self._rest = rest

    @property
    def rest(self) -> RestClient:
        return self._rest

    # ---------------------------------------------------------------- read

    def _raw_list(self) -> list[dict[str, Any]]:
        data = self._rest.request("GET", LIST_PATH, missing="firmware")
        entries = data.get("landevice") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            raise FritzError(f'Unerwartete Antwort von GET {LIST_PATH}: keine "landevice"-Liste.')
        return [e for e in entries if isinstance(e, dict)]

    def raw_list(self) -> list[dict[str, Any]]:
        """Unmodified entries (all fields the box sends) – for analyses that need extra fields."""
        return self._raw_list()

    def list(self) -> list[LanDevice]:
        return [LanDevice.from_raw(d) for d in self._raw_list()]

    def find(self, mac: str, uid: str | None = None) -> LanDevice:
        wanted = normalize_mac(mac)
        matches = [d for d in self.list() if d.mac == wanted]
        if uid:
            matches = [d for d in matches if d.uid == uid]
        if not matches:
            suffix = f" und UID {uid}" if uid else ""
            raise NotFoundError(f"Kein LAN-Gerät mit MAC {wanted}{suffix} – siehe list_landevices.")
        if len(matches) > 1:
            uids = ", ".join(d.uid for d in matches)
            raise InvalidParameterError(f"MAC {wanted} passt auf mehrere Einträge ({uids}) – bitte uid angeben.")
        return matches[0]

    def read_field(self, uid: str, field: str) -> str | None:
        """Read one raw field: per-device GET first, list as fallback. None = not readable."""
        try:
            node = _device_node(self._rest.request("GET", device_path(uid)))
            if node is not None and node.get(field) is not None:
                return str(node[field])
        except (ConfirmationRequiredError, AuthError):
            raise
        except FritzError:
            pass
        for d in self._raw_list():
            if str(d.get("UID") or d.get("uid") or "") == uid:
                value = d.get(field)
                return None if value is None else str(value)
        return None

    # ---------------------------------------------------------------- write

    def set_static_dhcp(self, mac: str, enabled: bool, uid: str | None = None) -> dict[str, Any]:
        """Pin (or unpin) the device's CURRENT IPv4 address. Choosing another IP is not supported."""
        device = self.find(mac, uid)
        base = {"uid": device.uid, "name": device.display_name, "mac": device.mac, "ip": device.ip}
        if device.static_dhcp == enabled:
            return {**base, "static_dhcp": enabled, "changed": False, "verified": True}

        self._rest.request("PUT", device_path(device.uid), {"static_dhcp": "1" if enabled else "0"})

        after = self.read_field(device.uid, "static_dhcp")
        if after is None:
            return {
                **base,
                "static_dhcp": enabled,
                "changed": None,
                "verified": False,
                "note": "Schreiben angenommen, Wert aber nicht rücklesbar – in der Web-UI unter "
                "Heimnetz > Netzwerk prüfen.",
            }
        if truthy(after) != enabled:
            raise ConfirmationRequiredError(SILENT_DISCARD)
        return {**base, "static_dhcp": enabled, "changed": True, "verified": True}

    def set_friendly_name(self, mac: str, name: str, uid: str | None = None) -> dict[str, Any]:
        """Set the display name the web UI shows (field ``friendly_name``)."""
        friendly = validate_hostname(name)
        device = self.find(mac, uid)
        base = {"uid": device.uid, "mac": device.mac, "friendly_name": friendly}
        if device.friendly_name == friendly:
            return {**base, "changed": False, "verified": True}

        self._rest.request("PUT", device_path(device.uid), {"friendly_name": friendly})

        after = self.read_field(device.uid, "friendly_name")
        if after is None:
            return {
                **base,
                "changed": None,
                "verified": False,
                "note": "Schreiben angenommen, friendly_name aber nicht rücklesbar – in der Web-UI prüfen.",
            }
        if after != friendly:
            raise ConfirmationRequiredError(SILENT_DISCARD)
        return {**base, "changed": True, "verified": True}

    def delete(self, device: LanDevice) -> dict[str, Any]:
        """Delete exactly this entry (checks are done by the caller) and verify it is gone."""
        self._rest.request("DELETE", device_path(device.uid))
        still_there = any(d.uid == device.uid for d in self.list())
        result: dict[str, Any] = {"deleted": device.model_dump(), "verified": not still_there}
        if still_there:
            result["note"] = SILENT_DISCARD
        return result
