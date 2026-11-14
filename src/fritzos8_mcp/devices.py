"""Stage 8.11 – device & update overview: AVM devices (box, repeaters, Powerline, DECT handsets/ULE devices) with
their update state, DECT handsets, and the host change counter.

Own implementation after the AVM TR-064 documents:

* ``Hosts:X_AVM-DE_GetChangeCounter`` (no rights) – grows when the host list changes.
* Host list XML (``X_AVM-DE_GetHostListPath``, doc "Hosts" 4.1): ``X_AVM-DE_Model``, ``X_AVM-DE_IsMeshable``,
  ``X_AVM-DE_UpdateAvailable``, ``X_AVM-DE_UpdateSuccessful`` (unknown/failed/succeeded) per host. The items also
  carry the repeater login token (``X_AVM-DE_URLParameters``) – only whitelisted fields leave this module.
* ``X_AVM-DE_Dect1``: ``GetNumberOfDectEntries``, ``GetGenericDectEntry`` → ID (1–6 handsets, ≥ 16 DECT ULE),
  Active, Name, Model, UpdateAvailable, UpdateSuccessful, UpdateInfo. Rights App/Phone/Homeauto.
* ``X_AVM-DE_Homeplug1``: ``GetNumberOfDeviceEntries``, ``GetGenericDeviceEntry`` → MACAddress, Active, Name,
  Model, UpdateAvailable, UpdateSuccessful. Right App.
* ``X_AVM-DE_OnTel1``: ``GetDECTHandsetList`` (DectIDList), ``GetDECTHandsetInfo`` (HandsetName, PhonebookID).
  Right Phone.

Starting updates (``DectDoUpdate``, ``DeviceDoUpdate``, ``X_AVM-DE_HostDoUpdate``) stays on the denylist.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from .errors import (
    AuthError,
    ConfirmationRequiredError,
    FritzConnectionError,
    FritzError,
    InvalidParameterError,
    NotFoundError,
)
from .nasremote import ToolDecorator
from .security import Tier
from .toolargs import READ, BoxArg
from .util import safe_mac, truthy

if TYPE_CHECKING:
    from .diagnose import DiagnoseClient
    from .tr064 import Tr064Client

DECT = "X_AVM-DE_Dect1"
HOMEPLUG = "X_AVM-DE_Homeplug1"
ONTEL = "X_AVM-DE_OnTel1"
MAX_ENTRIES = 64  # safety net against a wrong count


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _update_state(value: Any) -> str:
    v = str(value or "").strip().lower()
    return v if v in {"failed", "succeeded"} else "unknown"


class DeviceUpdateClient:
    def __init__(
        self, tr064: Tr064Client, diag: DiagnoseClient, mesh: Callable[[], dict[str, Any]] | None = None
    ) -> None:
        self.tr064 = tr064
        self.diag = diag
        self._mesh = mesh  # stage 10.7: mesh topology document (AVM "Mesh Topology", via Hosts:GetMeshListPath)

    # ------------------------------------------------------------ building blocks

    def change_counter(self) -> dict[str, Any]:
        raw = self.tr064.change_counter_raw()
        if raw == 0:
            return {
                "available": False,
                "change_counter": 0,
                "note": "Box liefert keinen Zähler (X_AVM-DE_GetChangeCounter antwortet dauerhaft 0, live auf FRITZ!OS "
                "8.26 beobachtet) – Änderungen nur über list_hosts/list_landevices erkennbar. Messreihe und Alarme "
                "lesen dann jedes Mal die Hostliste.",
            }
        return {
            "available": raw is not None,
            "change_counter": raw,
            "note": "Steigt, sobald sich die Geräteliste der Box ändert (neues Gerät, online/offline, Name). "
            "Gleicher Wert wie beim letzten Abruf = keine Änderung; billiger als die ganze Liste zu lesen.",
        }

    def _entries(self, service: str, count_action: str, entry_action: str) -> list[dict[str, Any]]:
        n = self.tr064.call(service, count_action)
        count = min(_int(n.get("NewNumberOfEntries")) or 0, MAX_ENTRIES)
        out = []
        for idx in range(count):
            e = self.tr064.try_call(service, entry_action, NewIndex=idx)
            if e is None:  # 713/714: end of list
                break
            out.append(e)
        return out

    def dect_devices(self) -> list[dict[str, Any]]:
        out = []
        for e in self._entries(DECT, "GetNumberOfDectEntries", "GetGenericDectEntry"):
            dect_id = _int(e.get("NewID"))
            out.append(
                {
                    "id": dect_id,
                    "kind": "handset" if dect_id is not None and 1 <= dect_id <= 6 else "dect_ule",
                    "name": e.get("NewName") or None,
                    "model": e.get("NewModel") or None,
                    "active": truthy(e.get("NewActive")),
                    "update_available": truthy(e.get("NewUpdateAvailable")),
                    "last_update": _update_state(e.get("NewUpdateSuccessful")),
                    "update_info": e.get("NewUpdateInfo") or None,
                }
            )
        return out

    def powerline_devices(self) -> list[dict[str, Any]]:
        return [
            {
                "name": e.get("NewName") or None,
                "model": e.get("NewModel") or None,
                "mac": safe_mac(e.get("NewMACAddress")) or None,
                "active": truthy(e.get("NewActive")),
                "update_available": truthy(e.get("NewUpdateAvailable")),
                "last_update": _update_state(e.get("NewUpdateSuccessful")),
            }
            for e in self._entries(HOMEPLUG, "GetNumberOfDeviceEntries", "GetGenericDeviceEntry")
        ]

    def mesh_devices(self) -> list[dict[str, Any]] | None:
        """AVM devices from the host list (repeaters, Powerline with WLAN, mesh nodes) – None without host list XML."""
        items = self.tr064.host_list_items()
        if items is None:
            return None
        out = []
        for i in items:
            model = str(i.get("X_AVM-DE_Model") or "")
            meshable = truthy(i.get("X_AVM-DE_IsMeshable"))
            update = truthy(i.get("X_AVM-DE_UpdateAvailable"))
            if not (meshable or update or "FRITZ!" in model.upper()):
                continue
            out.append(
                {
                    "name": i.get("X_AVM-DE_FriendlyName") or i.get("HostName") or None,
                    "model": model or None,
                    "mac": safe_mac(i.get("MACAddress")) or None,
                    "ip": i.get("IPAddress") or None,
                    "active": truthy(i.get("Active")),
                    "meshable": meshable,
                    "update_available": update,
                    "last_update": _update_state(i.get("X_AVM-DE_UpdateSuccessful")),
                }
            )
        return out

    def handsets(self) -> list[dict[str, Any]]:
        """DECT handsets of the telephony part (OnTel): name and assigned phone book."""
        r = self.tr064.call(ONTEL, "GetDECTHandsetList")
        ids = [p.strip() for p in str(r.get("NewDectIDList") or "").split(",") if p.strip()]
        out = []
        for dect_id in ids[:MAX_ENTRIES]:
            info = self.tr064.try_call(ONTEL, "GetDECTHandsetInfo", NewDectID=dect_id) or {}
            out.append(
                {
                    "id": _int(dect_id) if _int(dect_id) is not None else dect_id,
                    "name": info.get("NewHandsetName") or None,
                    "phonebook_id": _int(info.get("NewPhonebookID")),
                }
            )
        return out

    # ------------------------------------------------------------ tools

    def _section(self, fn: Callable[[], Any]) -> dict[str, Any]:
        try:
            return {"available": True, "devices": fn()}
        except (AuthError, ConfirmationRequiredError, FritzConnectionError):
            raise
        except FritzError as exc:
            return {"available": False, "devices": [], "error": exc.to_dict()}

    def updates_overview(self) -> dict[str, Any]:
        try:
            fw = self.diag.firmware_status()
            box: dict[str, Any] = {
                "available": True,
                "model": fw.get("model"),
                "installed": fw.get("installed"),
                "update_available": bool(fw.get("update_available")),
                "available_version": fw.get("available_version"),
                "auto_update_mode": fw.get("auto_update_mode"),
            }
        except (AuthError, ConfirmationRequiredError, FritzConnectionError):
            raise
        except FritzError as exc:
            box = {"available": False, "status": "unknown", "error": exc.to_dict()}

        mesh = self.mesh_devices()
        mesh_section: dict[str, Any] = (
            {"available": True, "devices": mesh}
            if mesh is not None
            else {"available": False, "devices": [], "note": "Hostliste (XML) nicht verfügbar – unknown."}
        )
        dect = self._section(self.dect_devices)
        plc = self._section(self.powerline_devices)

        pending: list[str] = []
        if box.get("update_available"):
            pending.append(f"FRITZ!Box ({box.get('model') or '?'}) → {box.get('available_version') or 'neue Version'}")
        for label, section in (("Mesh/Repeater", mesh_section), ("DECT", dect), ("Powerline", plc)):
            for d in section["devices"]:
                if d.get("update_available"):
                    pending.append(f"{label}: {d.get('name') or d.get('model') or d.get('mac') or d.get('id')}")
        failed = [
            str(d.get("name") or d.get("model") or d.get("id"))
            for section in (mesh_section, dect, plc)
            for d in section["devices"]
            if d.get("last_update") == "failed"
        ]
        unknown = [
            name
            for name, section in (("box", box), ("mesh", mesh_section), ("dect", dect), ("powerline", plc))
            if not section.get("available")
        ]
        return {
            "box": box,
            "mesh": mesh_section,
            "dect": dect,
            "powerline": plc,
            "summary": {
                "updates_available": pending,
                "update_count": len(pending),
                "last_update_failed": failed,
                "not_readable": unknown,
            },
            "note": "Nur lesend. Updates starten geht nur in der Web-Oberfläche (System > Update bzw. Heimnetz > "
            "Mesh, DECT > Mobilteile); die TR-064-Update-Actions sind bewusst gesperrt.",
        }

    def dect_handsets(self) -> dict[str, Any]:
        dect = self._section(self.dect_devices)
        phone = self._section(self.handsets)
        by_id = {d["id"]: d for d in phone["devices"] if isinstance(d.get("id"), int)}
        merged = []
        for d in dect["devices"]:
            if d["kind"] != "handset":
                continue
            extra = by_id.pop(d["id"], {})
            merged.append({**d, "phonebook_id": extra.get("phonebook_id"), "telephony_name": extra.get("name")})
        for d in by_id.values():  # only known to the telephony part
            merged.append({"id": d["id"], "kind": "handset", "name": d.get("name"), "phonebook_id": d["phonebook_id"]})
        out: dict[str, Any] = {
            "count": len(merged),
            "handsets": sorted(merged, key=lambda h: h.get("id") or 0),
            "sources": {"dect": dect["available"], "telephony": phone["available"]},
        }
        errors = {k: v["error"] for k, v in (("dect", dect), ("telephony", phone)) if "error" in v}
        if errors:
            out["errors"] = errors
        return out

    # ------------------------------------------------------------ stage 10.7: one AVM device in detail

    def _mesh_node(self, mac: str | None, name: str | None) -> dict[str, Any] | None:
        if self._mesh is None:
            return None
        doc = self._mesh()
        nodes = [n for n in doc.get("nodes") or [] if isinstance(n, dict)]
        by_uid = {str(n.get("uid")): n for n in nodes}
        node = next(
            (
                n
                for n in nodes
                if (mac and safe_mac(n.get("device_mac_address")) == mac)
                or (name and str(n.get("device_name") or "").lower() == name.lower())
            ),
            None,
        )
        if node is None:
            return None
        links = []
        for iface in node.get("node_interfaces") or []:
            if not isinstance(iface, dict):
                continue
            for link in iface.get("node_links") or []:
                if not isinstance(link, dict) or str(link.get("state") or "").upper() != "CONNECTED":
                    continue
                other_uid = (
                    link.get("node_2_uid") if link.get("node_1_uid") == node.get("uid") else link.get("node_1_uid")
                )
                other = by_uid.get(str(other_uid)) or {}
                links.append(
                    {
                        "interface": iface.get("name"),
                        "type": link.get("type") or iface.get("type"),
                        "peer": other.get("device_name"),
                        "peer_is_mesh_node": bool(other.get("is_meshed")),
                        "rate_rx_mbit": round(int(link["cur_data_rate_rx"]) / 1000, 1)
                        if str(link.get("cur_data_rate_rx") or "").isdigit()
                        else None,
                        "rate_tx_mbit": round(int(link["cur_data_rate_tx"]) / 1000, 1)
                        if str(link.get("cur_data_rate_tx") or "").isdigit()
                        else None,
                    }
                )
        return {
            "name": node.get("device_name"),
            "mesh_role": node.get("mesh_role"),
            "is_meshed": node.get("is_meshed"),
            "model": node.get("device_model") or None,
            "firmware": node.get("device_firmware_version") or None,
            "uplinks": [lk for lk in links if lk["peer_is_mesh_node"]],
            "clients": sum(1 for lk in links if not lk["peer_is_mesh_node"]),
            "links": links[:30],
            "fields_verified": False,
        }

    def device_detail(self, device: str) -> dict[str, Any]:
        """One AVM device by MAC, DECT ID or name: DECT entry, Powerline entry, host list entry and mesh node."""
        query = (device or "").strip()
        if not query:
            raise InvalidParameterError("device angeben: MAC, DECT-ID (1–6 Mobilteil, ab 16 DECT-ULE) oder Name.")
        out: dict[str, Any] = {"query": query, "found_in": []}
        mac = safe_mac(query) or None
        if query.isdigit():
            r = self.tr064.try_call(DECT, "GetSpecificDectEntry", NewID=int(query))
            if r:
                dect_id = int(query)
                out["dect"] = {
                    "id": dect_id,
                    "kind": "handset" if 1 <= dect_id <= 6 else "dect_ule",
                    "name": r.get("NewName") or None,
                    "model": r.get("NewModel") or None,
                    "active": truthy(r.get("NewActive")),
                    "update_available": truthy(r.get("NewUpdateAvailable")),
                    "last_update": _update_state(r.get("NewUpdateSuccessful")),
                    "update_info": r.get("NewUpdateInfo") or None,
                }
                out["found_in"].append("dect")
        if mac:
            r = self.tr064.try_call(HOMEPLUG, "GetSpecificDeviceEntry", NewMACAddress=mac)
            if r:
                out["powerline"] = {
                    "name": r.get("NewName") or None,
                    "model": r.get("NewModel") or None,
                    "active": truthy(r.get("NewActive")),
                    "update_available": truthy(r.get("NewUpdateAvailable")),
                    "last_update": _update_state(r.get("NewUpdateSuccessful")),
                }
                out["found_in"].append("powerline")
        if not query.isdigit():
            hosts = self._section(self.mesh_devices)
            match = next(
                (
                    d
                    for d in hosts["devices"] or []
                    if (mac and d.get("mac") == mac) or (not mac and str(d.get("name") or "").lower() == query.lower())
                ),
                None,
            )
            if match:
                out["host"] = match
                out["found_in"].append("host_list")
                mac = mac or match.get("mac")
            try:
                node = self._mesh_node(mac, None if mac else query)
            except (AuthError, ConfirmationRequiredError, FritzConnectionError):
                raise
            except FritzError as exc:
                node, out["mesh_error"] = None, exc.to_dict()
            if node:
                out["mesh"] = node
                out["found_in"].append("mesh")
        if not out["found_in"]:
            raise NotFoundError(
                f'Kein AVM-Gerät "{query}" gefunden.', hint="avm_device_updates listet alle bekannten AVM-Geräte."
            )
        out["note"] = (
            "Nur über die Schnittstellen der Box (TR-064 Dect/Homeplug, Hostliste, Mesh-Topologie). Repeater und "
            "Powerline-Adapter haben eigene Oberflächen/TR-064 – deren direkte Abfrage ist nicht Teil dieses Servers."
        )
        return out


def register_device_tools(tool: ToolDecorator, svc: Callable[[str | None], DeviceUpdateClient]) -> None:
    """Register the stage-8.11 tools with the tier-aware ``tool`` decorator of ``build_server``."""

    @tool(Tier.READ, READ)
    def avm_device_updates(box: BoxArg = None) -> dict[str, Any]:
        """Update-Übersicht aller AVM-Geräte: FRITZ!Box (FRITZ!OS, Update verfügbar, Auto-Update), Repeater/Mesh-
        Knoten aus der Hostliste, DECT-Mobilteile und DECT-ULE-Geräte (X_AVM-DE_Dect), Powerline (X_AVM-DE_Homeplug)
        – je Gerät Modell, aktiv, update_available, letztes Update. Nicht lesbare Teile = available false."""
        return svc(box).updates_overview()

    @tool(Tier.READ, READ)
    def dect_handsets(box: BoxArg = None) -> dict[str, Any]:
        """DECT-Mobilteile: ID, Name, Modell, aktiv, Firmware-Update verfügbar (X_AVM-DE_Dect) und zugeordnetes
        Telefonbuch (X_AVM-DE_OnTel:GetDECTHandsetInfo)."""
        return svc(box).dect_handsets()

    @tool(Tier.READ, READ)
    def avm_device_detail(
        device: Annotated[str, Field(description="MAC (Repeater/Powerline), DECT-ID (1–6, ab 16 ULE) oder Name")],
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Ein AVM-Gerät im Detail, nur über die Box-Schnittstellen: DECT-Eintrag (X_AVM-DE_Dect:GetSpecificDectEntry),
        Powerline (X_AVM-DE_Homeplug:GetSpecificDeviceEntry), Hostliste (Modell, Mesh-fähig, Update) und Mesh-Knoten
        (Rolle, Uplink zur Box mit Rate, Anzahl Clients)."""
        return svc(box).device_detail(device)

    @tool(Tier.READ, READ)
    def devices_change_counter(box: BoxArg = None) -> dict[str, Any]:
        """Änderungszähler der Geräteliste (TR-064 Hosts:X_AVM-DE_GetChangeCounter): billiger Indikator, ob sich
        seit dem letzten Abruf etwas geändert hat (neues Gerät, online/offline) – vor teuren Abfragen nutzen."""
        return svc(box).change_counter()
