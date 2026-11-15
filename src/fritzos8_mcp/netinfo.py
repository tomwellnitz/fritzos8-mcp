"""Mesh overview, online monitor (throughput/volume) and VPN/remote-access status via TR-064.

Own implementation after AVM's TR-064 documentation:

- ``Hosts1:X_AVM-DE_GetMeshListPath`` → JSON document with ``nodes`` → ``node_interfaces`` →
  ``node_links`` (rates in kbit/s). Mesh-Topology schema v8.7 (FRITZ!OS 8.19–8.25): ``rx_rcpi`` = "receive
  channel power indicator in dBm measured at node 1", ``tx_rcpi`` = the same measured at node 2, 255 = unknown.
  Older firmware delivered the IEEE RCPI encoding (0–220 = (dBm + 110) × 2) – both are accepted.
- ``WLANConfiguration1:X_AVM-DE_GetWLANDeviceListPath`` (AVM "TR-064 Support – WLANConfiguration" v49, 2.23)
  → XML list of ALL connected WLAN stations (independent of the service) with ``X_AVM-DE_SignalStrength``,
  ``X_AVM-DE_Speed``, ``AssociatedDeviceChannel`` – one request instead of one per station. Fallback:
  ``GetTotalAssociations`` + ``GetGenericAssociatedDeviceInfo`` per WLAN service (bounded).
- ``WANCommonInterfaceConfig1:X_AVM-DE_GetOnlineMonitor`` (sample lists, newest first) and
  ``X_AVM-DE_GetAddonInfos`` / ``GetTotalBytesSent``/``GetTotalBytesReceived``.
- ``X_AVM-DE_MyFritz1:GetInfo``, ``X_AVM-DE_RemoteAccess1:GetInfo`` and ``GetDDNSInfo`` (AVM doc name; legacy
  ``X_AVM-DE_GetDDNSInfo`` as fallback).
  The DynDNS answer also carries the DynDNS user/password – only whitelisted, non-secret fields
  leave this module. WireGuard/IPSec connection states are not readable via TR-064.
"""

from __future__ import annotations

import json
import re
from typing import Any

from defusedxml import ElementTree as ET

from .errors import FritzConnectionError, FritzError, NotFoundError
from .myfritz import DDNS_INFO_ACTIONS
from .tr064 import IGD_WAN_COMMON, Tr064Client, parse_host_list_xml
from .util import box_int, safe_mac, truthy

INFRA_ROLES = {"master", "slave"}
WEAK_SIGNAL_DBM = -75  # weak_signal_clients (measured or estimated dBm)
MAX_GENERIC_STATIONS = 64  # fallback loop per WLAN service – bounded to protect the box
_WLAN_SERVICE = re.compile(r"^WLANConfiguration(\d+)$")
# X_AVM-DE_GetAddonInfos rate fields (NewX_AVM-DE_<Name>Downstream/Upstream), all bit/s
ADDON_INFO_ACTIONS = ("X_AVM-DE_GetAddonInfos", "X_AVM_DE_GetAddonInfos")  # doc spelling first
ADDON_RATES = {"sync": "Sync", "brutto": "Brutto", "tariff": "TariffDataRate", "l2": "L2", "manual": "Manual"}


# ------------------------------------------------------------------ helpers


def _int(value: Any) -> int | None:
    return box_int(value)


def rcpi_to_dbm(rcpi: Any) -> float | None:
    """Mesh ``rx_rcpi``/``tx_rcpi`` → dBm.

    Schema v8.7 documents the value as dBm (negative integer); 255 = unknown. Positive values up to 220 are
    read as the IEEE 802.11k RCPI encoding ((dBm + 110) × 2) of older firmware. 0 counts as not measured."""
    v = _int(rcpi)
    if v is None or v == 255:
        return None
    if -110 <= v < 0:
        return float(v)
    if 0 < v <= 220:
        return v / 2 - 110
    return None


def link_signal_dbm(link: dict[str, Any], ap_is_node_1: bool | None = None) -> float | None:
    """Signal of a WLAN link, preferably as measured by the access point (``rx_rcpi`` at node 1,
    ``tx_rcpi`` at node 2); the other side's measurement is the fallback."""
    rx, tx = rcpi_to_dbm(link.get("rx_rcpi")), rcpi_to_dbm(link.get("tx_rcpi"))
    first, second = (tx, rx) if ap_is_node_1 is False else (rx, tx)
    return first if first is not None else second


# Signal percent (X_AVM-DE_SignalStrength 0–100). AVM documents no unit or scale. Assumption, documented in every
# answer: linear like the Windows WLAN API (wlanSignalQuality: 0 = −100 dBm, 100 = −50 dBm) → dBm ≈ % / 2 − 100.
PERCENT_SCALE_NOTE = (
    "signal_percent = X_AVM-DE_SignalStrength der Box (0–100, von AVM ohne Skala dokumentiert); "
    "signal_dbm_estimated ≈ Prozent / 2 − 100 (Annahme: linear wie die Windows-WLAN-API, 0 % = −100 dBm, "
    "100 % = −50 dBm) – nur Schätzwert, gemessene dBm aus der Mesh-Liste haben Vorrang."
)


def percent_to_dbm(percent: Any) -> float | None:
    v = _int(percent)
    if v is None or not 0 < v <= 100:
        return None
    return v / 2 - 100


def _wlan_band(channel: Any, raw_band: Any = None) -> str | None:
    band = {"2400": "2.4", "5000": "5", "6000": "6"}.get(str(raw_band or ""))
    return band or band_of_channel(channel)


def parse_wlan_device_list(xml_bytes: bytes | str) -> dict[str, dict[str, Any]]:
    """``X_AVM-DE_GetWLANDeviceListPath`` document → {MAC: station info}."""
    out: dict[str, dict[str, Any]] = {}
    for item in parse_host_list_xml(xml_bytes):
        mac = safe_mac(item.get("AssociatedDeviceMACAddress"))
        if not mac:
            continue
        out[mac] = station_info(
            {
                "mac": mac,
                "ip": item.get("AssociatedDeviceIPAddress"),
                "signal": item.get("X_AVM-DE_SignalStrength"),
                "speed": item.get("X_AVM-DE_Speed"),
                "channel": item.get("AssociatedDeviceChannel"),
                "width": item.get("X_AVM-DE_ChannelWidth"),
                "guest": item.get("AssociatedDeviceGuest"),
            }
        )
    return out


def station_info(raw: dict[str, Any]) -> dict[str, Any]:
    signal = _int(raw.get("signal"))
    channel = _int(raw.get("channel"))
    width = _int(raw.get("width"))
    return {
        "mac": raw.get("mac"),
        "ip": raw.get("ip") or None,
        "signal_percent": signal if signal else None,  # 0 = default/unknown per AVM state variable table
        "signal_dbm_estimated": percent_to_dbm(signal),
        "speed_mbit": _int(raw.get("speed")) or None,
        "channel": channel or None,
        "band_ghz": _wlan_band(channel, raw.get("band")),
        "channel_width_mhz": width or None,
        "guest": truthy(raw.get("guest")) if raw.get("guest") not in (None, "") else None,
        "service": raw.get("service"),
    }


def merge_station(entry: dict[str, Any], station: dict[str, Any] | None) -> dict[str, Any]:
    """Adds TR-064 station data (signal %, speed, width) to a mesh client entry; mesh dBm stays first."""
    if not station:
        return entry
    out = dict(entry)
    out["signal_percent"] = station.get("signal_percent")
    if out.get("signal_dbm") is None:
        out["signal_dbm_estimated"] = station.get("signal_dbm_estimated")
    for key in ("speed_mbit", "channel_width_mhz"):
        if station.get(key) is not None:
            out.setdefault(key, station[key])
    if out.get("band_ghz") is None and station.get("band_ghz"):
        out["band_ghz"] = station["band_ghz"]
    return out


def effective_dbm(entry: dict[str, Any]) -> float | None:
    """Measured dBm (mesh) or the estimate from signal percent."""
    dbm = entry.get("signal_dbm")
    return dbm if dbm is not None else entry.get("signal_dbm_estimated")


def band_of_channel(channel: Any) -> str | None:
    c = _int(channel)
    if c is None or c <= 0:
        return None
    if c <= 14:
        return "2.4"
    if c <= 177:
        return "5"
    return None


def _first_key(d: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if d.get(k) not in (None, ""):
            return d[k]
    return None


def _mbit(kbit: Any) -> float | None:
    v = _int(kbit)
    return None if v is None else round(v / 1000, 1)


def _samples(value: Any) -> list[int]:
    out = []
    for part in str(value or "").split(","):
        n = _int(part)
        if n is not None:
            out.append(n)
    return out


# ------------------------------------------------------------------ mesh


def parse_mesh(doc: dict[str, Any], stations: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """Mesh document → nodes/backbone/clients. ``stations`` (MAC → TR-064 station info) adds signal percent
    for WLAN clients the mesh list carries no signal for."""
    stations = stations or {}
    nodes = [n for n in doc.get("nodes") or [] if isinstance(n, dict)]
    by_uid = {str(n.get("uid")): n for n in nodes}
    iface_owner: dict[str, dict[str, Any]] = {}
    iface_by_uid: dict[str, dict[str, Any]] = {}
    for n in nodes:
        for i in n.get("node_interfaces") or []:
            if isinstance(i, dict):
                iface_owner[str(i.get("uid"))] = n
                iface_by_uid[str(i.get("uid"))] = i

    def is_infra(n: dict[str, Any]) -> bool:
        return bool(n.get("is_meshed")) or str(n.get("mesh_role") or "").lower() in INFRA_ROLES

    def node_name(n: dict[str, Any] | None) -> str:
        if not n:
            return "?"
        return str(n.get("device_name") or n.get("device_model") or n.get("device_mac_address") or n.get("uid"))

    links: dict[str, dict[str, Any]] = {}
    for n in nodes:
        for i in n.get("node_interfaces") or []:
            for link in (i or {}).get("node_links") or []:
                if isinstance(link, dict) and link.get("uid") is not None:
                    links.setdefault(str(link["uid"]), link)

    infra = [n for n in nodes if is_infra(n)]
    master = next((n for n in nodes if str(n.get("mesh_role") or "").lower() == "master"), None)
    backbone: list[dict[str, Any]] = []
    clients: list[dict[str, Any]] = []
    for link in links.values():
        if str(link.get("state") or "").upper() not in {"CONNECTED", ""}:
            continue
        n1, n2 = by_uid.get(str(link.get("node_1_uid"))), by_uid.get(str(link.get("node_2_uid")))
        i1 = iface_by_uid.get(str(link.get("node_interface_1_uid"))) or {}
        i2 = iface_by_uid.get(str(link.get("node_interface_2_uid"))) or {}
        kind = str(link.get("type") or i1.get("type") or i2.get("type") or "").upper()
        band = None
        if kind == "WLAN":
            band = band_of_channel(i1.get("current_channel")) or band_of_channel(i2.get("current_channel"))
        entry = {
            "type": kind or None,
            "band_ghz": band,
            "rate_down_mbit": _mbit(link.get("cur_data_rate_rx")),
            "rate_up_mbit": _mbit(link.get("cur_data_rate_tx")),
            "max_rate_down_mbit": _mbit(link.get("max_data_rate_rx")),
            "max_rate_up_mbit": _mbit(link.get("max_data_rate_tx")),
            "signal_dbm": None,
        }
        if n1 and n2 and is_infra(n1) and is_infra(n2):
            entry["signal_dbm"] = link_signal_dbm(link) if kind == "WLAN" else None
            backbone.append({"from": node_name(n1), "to": node_name(n2), **entry})
            continue
        ap_is_node_1 = bool(n1 and is_infra(n1))
        ap, client = (n1, n2) if ap_is_node_1 else (n2, n1)
        if client is None:
            continue
        mac = safe_mac(client.get("device_mac_address")) or None
        if kind == "WLAN":
            entry["signal_dbm"] = link_signal_dbm(link, ap_is_node_1)
        item = {"name": node_name(client), "mac": mac, "connected_to": node_name(ap), **entry}
        if kind == "WLAN":
            item = merge_station(item, stations.get(mac or ""))
        clients.append(item)

    per_node: dict[str, int] = {}
    for c in clients:
        per_node[c["connected_to"]] = per_node.get(c["connected_to"], 0) + 1

    weak = [c["name"] for c in clients if (d := effective_dbm(c)) is not None and d < WEAK_SIGNAL_DBM]
    wlan_clients = [c for c in clients if c.get("type") == "WLAN"]
    without_signal = [c["name"] for c in wlan_clients if effective_dbm(c) is None]
    nodes_out = [
        {
            "name": node_name(n),
            "model": n.get("device_model"),
            "role": n.get("mesh_role"),
            "mac": safe_mac(n.get("device_mac_address")) or None,
            "firmware": n.get("device_firmware_version"),
            "interfaces": sorted({str(i.get("type")) for i in n.get("node_interfaces") or [] if i.get("type")}),
            "clients": per_node.get(node_name(n), 0),
        }
        for n in infra
    ]
    return {
        "schema_version": doc.get("schema_version"),
        "mesh_master": node_name(master) if master else None,
        "nodes": nodes_out,
        "backbone": backbone,
        "clients": sorted(clients, key=lambda c: (c["connected_to"], c["name"])),
        "summary": {
            "nodes": len(nodes_out),
            "clients": len(clients),
            "clients_per_node": per_node,
            "weak_signal_clients": weak,
            "wlan_clients_without_signal": without_signal,
        },
        "units": "Raten in Mbit/s (aus kbit/s der Box), signal_dbm = gemessen (Mesh-Liste, rx_rcpi/tx_rcpi); "
        + PERCENT_SCALE_NOTE
        + " Werte sind Momentaufnahmen.",
    }


# ------------------------------------------------------------------ client


class NetInfoClient:
    def __init__(self, tr064: Tr064Client) -> None:
        self.tr064 = tr064

    def mesh(self) -> dict[str, Any]:
        stations, source = self.wlan_stations_with_source()
        out = parse_mesh(self.mesh_document(), stations)
        out["signal_source"] = source
        return out

    def wlan_stations(self) -> dict[str, dict[str, Any]]:
        return self.wlan_stations_with_source()[0]

    def wlan_stations_with_source(self) -> tuple[dict[str, dict[str, Any]], str]:
        """All connected WLAN stations (MAC → signal %, speed, channel …), kept briefly in the guard cache.
        Never raises for missing actions – an empty dict means "no TR-064 station data"."""
        result: tuple[dict[str, dict[str, Any]], str] = self.tr064.cached("wlan_stations", self._wlan_stations)
        return result

    def _wlan_service_names(self) -> list[str]:
        try:
            names = [(int(m.group(1)), n) for n in self.tr064.fc.services if (m := _WLAN_SERVICE.match(n))]
        except FritzError:
            return []
        return [n for _, n in sorted(names)]

    def _wlan_stations(self) -> tuple[dict[str, dict[str, Any]], str]:
        services = self._wlan_service_names()
        if not services:
            return {}, "keine WLANConfiguration-Dienste"
        r = self.tr064.try_call(services[0], "X_AVM-DE_GetWLANDeviceListPath")
        path = (r or {}).get("NewX_AVM-DE_WLANDeviceListPath")
        if path:
            try:
                listed = parse_wlan_device_list(self.tr064.fetch(str(path)))
                return listed, "TR-064 X_AVM-DE_GetWLANDeviceListPath"
            except FritzConnectionError:
                raise
            except (FritzError, ValueError, ET.ParseError):
                pass  # fall back to the per-index loop
        stations: dict[str, dict[str, Any]] = {}
        for service in services:
            total = _int((self.tr064.try_call(service, "GetTotalAssociations") or {}).get("NewTotalAssociations"))
            for index in range(min(total or 0, MAX_GENERIC_STATIONS)):
                g = self.tr064.try_call(service, "GetGenericAssociatedDeviceInfo", NewAssociatedDeviceIndex=index)
                mac = safe_mac((g or {}).get("NewAssociatedDeviceMACAddress"))
                if not g or not mac:
                    continue
                stations[mac] = station_info(
                    {
                        "mac": mac,
                        "ip": g.get("NewAssociatedDeviceIPAddress"),
                        "signal": g.get("NewX_AVM-DE_SignalStrength"),
                        "speed": g.get("NewX_AVM-DE_Speed"),
                        "width": g.get("NewX_AVM-DE_ChannelWidth"),
                        "service": service,
                    }
                )
        return stations, ("TR-064 GetGenericAssociatedDeviceInfo" if stations else "keine TR-064-Signaldaten")

    def mesh_document(self) -> dict[str, Any]:
        """The raw mesh JSON document of the box (for analyses that need more than parse_mesh).
        Kept briefly in the box guard's cache (stage 7.1) – several tools read it in a row."""
        doc: dict[str, Any] = self.tr064.cached("mesh_document", self._mesh_document)
        return doc

    def _mesh_document(self) -> dict[str, Any]:
        r = self.tr064.try_call("Hosts1", "X_AVM-DE_GetMeshListPath")
        path = (r or {}).get("NewX_AVM-DE_MeshListPath")
        if not path:
            raise NotFoundError("Mesh-Übersicht nicht verfügbar (Hosts1:X_AVM-DE_GetMeshListPath fehlt).")
        raw = self.tr064.fetch(str(path))
        try:
            doc = json.loads(raw.decode("utf-8", errors="replace"))
        except ValueError:
            raise FritzError("Mesh-Liste der Box ist kein gültiges JSON.") from None
        if not isinstance(doc, dict):
            raise FritzError("Mesh-Liste hat ein unerwartetes Format.")
        return doc

    def online_monitor(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        mon = self.tr064.try_call("WANCommonInterfaceConfig1", "X_AVM-DE_GetOnlineMonitor", NewSyncGroupIndex=0)
        if mon is not None:
            ds, us = _samples(mon.get("Newds_current_bps")), _samples(mon.get("Newus_current_bps"))

            def rate(values: list[int]) -> dict[str, Any]:
                if not values:
                    return {"current_bytes_s": None, "current_mbit_s": None, "avg_mbit_s": None}
                return {
                    "current_bytes_s": values[0],
                    "current_mbit_s": round(values[0] * 8 / 1_000_000, 2),
                    "avg_mbit_s": round(sum(values) / len(values) * 8 / 1_000_000, 2),
                    "samples": len(values),
                }

            max_ds, max_us = _int(mon.get("Newmax_ds")), _int(mon.get("Newmax_us"))
            out["throughput"] = {
                "available": True,
                "sync_group": mon.get("NewSyncGroupName"),
                # SyncGroupMode is the box's raw label of the sync group ("Connection mod of sync group"); live a
                # G.fast line reported "VDSL" – it is not the line modulation (see line_modulation/line_diagnostics)
                "mode": mon.get("NewSyncGroupMode"),
                "mode_source": "Box-Rohwert SyncGroupMode (Bezeichnung der Sync-Gruppe, nicht die Modulation)",
                "down": rate(ds),
                "up": rate(us),
                "max_down_mbit_s": None if max_ds is None else round(max_ds * 8 / 1_000_000, 2),
                "max_up_mbit_s": None if max_us is None else round(max_us * 8 / 1_000_000, 2),
                "unit_note": "Die Box liefert Byte/s (Felder *_bps laut AVM-Doku WANCommonInterfaceConfig v22; "
                "Sample-Liste neueste zuerst); umgerechnet in Mbit/s = Byte/s × 8 / 10⁶.",
            }
            self._compare_line_mode(out["throughput"])
        else:
            out["throughput"] = {"available": False, "note": "X_AVM-DE_GetOnlineMonitor nicht verfügbar."}

        out["volume"] = self._volume()
        out["rates"] = self._addon_rates()
        out["day_month_volume"] = {
            "available": False,
            "note": "Tages-/Monatsvolumen (Online-Zähler) ist per TR-064 nicht lesbar – Web-Oberfläche: "
            "Internet > Online-Monitor > Online-Zähler.",
        }
        return out

    def _compare_line_mode(self, throughput: dict[str, Any]) -> None:
        """For DSL sync groups: add the actual line modulation (X_AVM-DE_GetDSLInfo) and flag a mismatch."""
        mode = str(throughput.get("mode") or "")
        if "DSL" not in mode.upper():
            return
        info = self.tr064.try_call("WANDSLInterfaceConfig1", "X_AVM-DE_GetDSLInfo") or {}
        modulation = str(info.get("NewModulationType") or "").strip()
        if not modulation:
            return
        throughput["line_modulation"] = modulation
        norm = re.sub(r"[^A-Z0-9]", "", modulation.upper())
        if re.sub(r"[^A-Z0-9]", "", mode.upper()) not in norm:
            throughput["mode_note"] = (
                f"Die Box bezeichnet die Sync-Gruppe als „{mode}“, die Leitung läuft laut DSL-Info mit "
                f"„{modulation}“ – maßgeblich ist line_diagnostics.modulation."
            )

    def _volume(self) -> dict[str, Any]:
        """V-6 (AVM doc): 64-bit counters only exist in the IGD action ``WANCommonIFC1:GetAddonInfos``; the TR-064
        32-bit counters "need IGD to work" and are 0 otherwise – 0 therefore counts as unknown, not as 0 bytes."""
        sent = recv = None
        source = None
        igd = self.tr064.try_call(IGD_WAN_COMMON, "GetAddonInfos")
        if igd:
            sent = _int(_first_key(igd, "NewX_AVM_DE_TotalBytesSent64", "NEWX_AVM_DE_TotalBytesSent64"))
            recv = _int(_first_key(igd, "NewX_AVM_DE_TotalBytesReceived64", "NEWX_AVM_DE_TotalBytesReceived64"))
            source = "IGD WANCommonIFC1:GetAddonInfos (64 bit)"
        if sent is None or recv is None:
            # legacy: some firmware versions may also carry the 64-bit fields in the TR-064 action
            addon = self.tr064.try_call("WANCommonInterfaceConfig1", "X_AVM-DE_GetAddonInfos") or {}
            sent = _int(addon.get("NewX_AVM_DE_TotalBytesSent64") or addon.get("NewX_AVM-DE_TotalBytesSent64"))
            recv = _int(addon.get("NewX_AVM_DE_TotalBytesReceived64") or addon.get("NewX_AVM-DE_TotalBytesReceived64"))
            source = "X_AVM-DE_GetAddonInfos (64 bit)" if sent is not None and recv is not None else None
        if sent is None or recv is None:
            s = self.tr064.try_call("WANCommonInterfaceConfig1", "GetTotalBytesSent")
            r = self.tr064.try_call("WANCommonInterfaceConfig1", "GetTotalBytesReceived")
            sent = _int((s or {}).get("NewTotalBytesSent")) or None  # 0 = IGD off → unknown
            recv = _int((r or {}).get("NewTotalBytesReceived")) or None
            source = "GetTotalBytesSent/Received (32 bit, läuft bei 4 GiB über)" if sent is not None else None
        out: dict[str, Any] = {
            "available": sent is not None,
            "sent_bytes": sent,
            "received_bytes": recv,
            "sent_gb": None if sent is None else round(sent / 1e9, 3),
            "received_gb": None if recv is None else round(recv / 1e9, 3),
            "source": source,
            "note": "Zähler der Box seit dem letzten Neustart/Verbindungsaufbau – kein Tages-/Monatsvolumen.",
        }
        if sent is None:
            out["status"] = "unknown"
            out["hint"] = (
                "Die Box liefert 64-bit-Zähler nur über IGD (UPnP). Zum Aktivieren: Heimnetz > Netzwerk > "
                "Netzwerkeinstellungen > 'Statusinformationen über UPnP übertragen'. Ohne IGD sind die 32-bit-Zähler 0."
            )
        return out

    def _addon_rates(self) -> dict[str, Any]:
        """Rates from TR-064 ``X_AVM-DE_GetAddonInfos`` (AVM doc WANCommonInterfaceConfig v22, 2026-02, all in bit/s).

        The action is new in that document version – live the 7583 (FRITZ!OS 8.26, PPP) did not offer it. The IGD
        ``GetAddonInfos`` (V-6) carries only counters/byte rates, no line rates. Fallback for the sync rate:
        ``GetCommonLinkProperties`` (``Layer1Down/UpstreamMaxBitRate``, bit/s)."""
        r: dict[str, Any] | None = None
        try:
            _, r = self.tr064.call_first("WANCommonInterfaceConfig1", ADDON_INFO_ACTIONS)
        except FritzConnectionError:
            raise
        except FritzError:
            r = None
        if r and any(r.get(f"NewX_AVM-DE_{name}Downstream") not in (None, "") for name in ADDON_RATES.values()):
            return self._rates_from_addon(r)
        link = self.tr064.try_call("WANCommonInterfaceConfig1", "GetCommonLinkProperties") or {}
        down, up = _int(link.get("NewLayer1DownstreamMaxBitRate")), _int(link.get("NewLayer1UpstreamMaxBitRate"))
        if not down and not up:
            return {
                "available": False,
                "note": "X_AVM-DE_GetAddonInfos auf dieser Box nicht vorhanden (erst seit AVM-Doku v22, 2026-02) und "
                "GetCommonLinkProperties ohne Leitungsrate.",
            }
        empty = {"down_mbit_s": None, "up_mbit_s": None}
        out: dict[str, Any] = {
            "available": True,
            "source": "GetCommonLinkProperties (Fallback: X_AVM-DE_GetAddonInfos fehlt auf dieser Box)",
            "wan_access_type": link.get("NewWANAccessType") or None,
            "sync": {
                "down_mbit_s": None if not down else round(down / 1_000_000, 2),
                "up_mbit_s": None if not up else round(up / 1_000_000, 2),
            },
            **{key: dict(empty) for key in ADDON_RATES if key != "sync"},
            "unit_note": "Layer1*MaxBitRate in bit/s = synchronisierte Leitungsrate; Brutto-/Vertrags-/L2-/manuelle "
            "Rate liefert nur X_AVM-DE_GetAddonInfos (hier nicht vorhanden).",
        }
        return out

    @staticmethod
    def _rates_from_addon(r: dict[str, Any]) -> dict[str, Any]:
        def mbit(field: str) -> float | None:
            v = _int(r.get(field))
            return None if not v else round(v / 1_000_000, 2)

        out: dict[str, Any] = {
            "available": True,
            "source": "X_AVM-DE_GetAddonInfos",
            "wan_access_type": r.get("NewX_AVM-DE_WANAccessType") or None,
        }
        for key, name in ADDON_RATES.items():
            out[key] = {
                "down_mbit_s": mbit(f"NewX_AVM-DE_{name}Downstream"),
                "up_mbit_s": mbit(f"NewX_AVM-DE_{name}Upstream"),
            }
        out["unit_note"] = (
            "Box liefert bit/s; sync = Leitungsrate, brutto = derzeit mögliche Rate, tariff = vom Provider gemeldete "
            "Vertragsrate (oft leer), l2 = Rate nach Shaping, manual = in der Web-UI eingetragene Rate. 0 = unbekannt."
        )
        return out

    def vpn_status(self) -> dict[str, Any]:
        out: dict[str, Any] = {}

        def section(name: str, fn: Any) -> None:
            try:
                out[name] = fn()
            except FritzError as exc:
                out[name] = {"available": False, "error": exc.to_dict()}

        def myfritz() -> dict[str, Any]:
            r = self.tr064.call("X_AVM-DE_MyFritz1", "GetInfo")
            data = {
                "available": True,
                "enabled": truthy(r.get("NewEnabled")),
                "registered": truthy(r.get("NewDeviceRegistered")),
                "dyndns_name": r.get("NewDynDNSName") or None,
                "port": r.get("NewPort"),
            }
            n = self.tr064.try_call("X_AVM-DE_MyFritz1", "GetNumberOfServices")
            if n is not None:
                data["services"] = _int(n.get("NewNumberOfServices"))
            return data

        def remote() -> dict[str, Any]:
            r = self.tr064.call("X_AVM-DE_RemoteAccess1", "GetInfo")
            return {"available": True, "enabled": truthy(r.get("NewEnabled")), "port": r.get("NewPort")}

        def dyndns() -> dict[str, Any]:
            _, r = self.tr064.call_first("X_AVM-DE_RemoteAccess1", DDNS_INFO_ACTIONS)
            # Whitelist only – the answer also contains user name and password.
            return {
                "available": True,
                "enabled": truthy(r.get("NewEnabled")),
                "provider": r.get("NewProviderName") or None,
                "domain": r.get("NewDomain") or None,
                "status_ipv4": r.get("NewStatusIPv4") or None,
                "status_ipv6": r.get("NewStatusIPv6") or None,
                "mode": r.get("NewMode") or None,
            }

        section("myfritz", myfritz)
        section("remote_access", remote)
        section("dyndns", dyndns)
        try:
            names = sorted(s for s in self.tr064.fc.services if "vpn" in s.lower() or "wireguard" in s.lower())
        except FritzError:
            names = []
        out["vpn_connections"] = {
            "available": False,
            "status": "unknown",
            "tr064_services_found": names,
            "note": "WireGuard-/IPSec-Verbindungen und ihr Zustand sind per TR-064 nicht lesbar (und die "
            "/api/v0-Endpunkte dafür sind nicht belegt). Web-Oberfläche: Internet > Freigaben > VPN. "
            "VPN-Schlüssel und Konfigurationsdateien werden nie abgefragt.",
        }
        return out
