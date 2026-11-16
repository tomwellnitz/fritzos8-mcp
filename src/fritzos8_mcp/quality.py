"""Connection quality per device: WLAN signal/band/channel/rate and LAN port/speed, with a rating and
plain-language tips (read-only).

Sources (own implementation after AVM's documentation):

- Mesh JSON (``Hosts1:X_AVM-DE_GetMeshListPath``): per link ``cur_data_rate_*``/``max_data_rate_*``
  (kbit/s), ``rx_rcpi``/``tx_rcpi`` (dBm per schema v8.7, AP-side measurement preferred), the box-side
  interface (``name`` e.g. ``"LAN:1"``/``"AP:5G:0"``,
  ``current_channel``) – field names partly unverified live.
- TR-064 ``WLANConfiguration*:GetSpecificAssociatedDeviceInfo`` (AVM "TR-064 Support –
  WLANConfiguration" v49): ``NewX_AVM-DE_Speed`` (Mbit/s), ``NewX_AVM-DE_SignalStrength`` (0–100, AVM
  gives no unit – treated as percent, rated via the dBm estimate ``netinfo.percent_to_dbm``),
  ``NewX_AVM-DE_ChannelWidth`` (MHz). For all stations at once: ``X_AVM-DE_GetWLANDeviceListPath``
  (``NetInfoClient.wlan_stations``).
- ``X_AVM-DE_GetWLANConnectionInfo`` answers for the REQUESTING device (the machine this server runs on).
- ``/api/v0/generic/eth_ports``: speed and EEE of the LAN port a device hangs on.
"""

from __future__ import annotations

import re
from typing import Any

from .netinfo import band_of_channel, link_signal_dbm, percent_to_dbm
from .util import json_objects, safe_mac, truthy

# Raspberry Pi OUIs (IEEE MA-L registry, checked 2026-11-14: Raspberry Pi Foundation / Raspberry Pi
# (Trading) Ltd). Used for the EEE hint (raspberrypi/linux#7511).
RASPBERRY_PI_OUIS = frozenset(
    {"B8:27:EB", "DC:A6:32", "E4:5F:01", "D8:3A:DD", "28:CD:C1", "2C:CF:67", "88:A2:9E", "98:FE:54"}
)
EEE_BUG_LINKS = (
    "https://github.com/raspberrypi/linux/issues/7511",
    "https://github.com/home-assistant/operating-system/issues/4861",
)

SIGNAL_DBM = {"good": -60, "ok": -70, "weak": -78}  # ≥ good → gut, ≥ ok → ok, ≥ weak → schwach, else sehr schwach
LOW_RATE_RATIO = 0.3

INFRA_ROLES = {"master", "slave"}


def is_raspberry_pi(mac: Any) -> bool:
    m = safe_mac(mac)
    return bool(m) and m[:8] in RASPBERRY_PI_OUIS


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _mbit(kbit: Any) -> float | None:
    v = _int(kbit)
    return None if v is None else round(v / 1000, 1)


def band_of_interface(name: Any, channel: Any) -> str | None:
    text = str(name or "").upper()
    for marker, band in (("2G", "2.4"), ("2.4", "2.4"), ("5G", "5"), ("6G", "6")):
        if marker in text:
            return band
    return band_of_channel(channel)


def lan_port_label(name: Any) -> str | None:
    """Mesh-Interface-Name → Port-Label wie in eth_ports ("LAN:1", "WAN:1").

    Live (7583/8.26): ein Gerät am als LAN genutzten WAN-Port hängt laut Mesh-Liste an "WAN:1";
    eth_ports führt den Port ebenfalls als "WAN:1". Ohne diese Zuordnung fehlten Port-Daten/EEE.
    """
    m = re.match(r"^\s*(LAN|WAN)\s*:?\s*(\d+)\s*$", str(name or ""), re.I)
    return f"{m.group(1).upper()}:{m.group(2)}" if m else None


# ------------------------------------------------------------------ mesh → per-client links


def mesh_clients(doc: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = json_objects(doc.get("nodes"))
    by_uid = {str(n.get("uid")): n for n in nodes}
    iface_by_uid: dict[str, dict[str, Any]] = {}
    links: dict[str, dict[str, Any]] = {}
    for n in nodes:
        for i in json_objects(n.get("node_interfaces")):
            iface_by_uid[str(i.get("uid"))] = i
            for link in json_objects(i.get("node_links")):
                if link.get("uid") is not None:
                    links.setdefault(str(link["uid"]), link)

    def infra(n: dict[str, Any] | None) -> bool:
        return bool(n) and (bool(n.get("is_meshed")) or str(n.get("mesh_role") or "").lower() in INFRA_ROLES)  # type: ignore[union-attr]

    out = []
    for link in links.values():
        if str(link.get("state") or "").upper() not in {"CONNECTED", ""}:
            continue
        n1, n2 = by_uid.get(str(link.get("node_1_uid"))), by_uid.get(str(link.get("node_2_uid")))
        i1 = iface_by_uid.get(str(link.get("node_interface_1_uid"))) or {}
        i2 = iface_by_uid.get(str(link.get("node_interface_2_uid"))) or {}
        if infra(n1) and infra(n2):
            continue  # backbone, not a client
        ap_is_node_1 = infra(n1)
        if ap_is_node_1:
            ap, ap_if, client, client_if = n1, i1, n2, i2
        elif infra(n2):
            ap, ap_if, client, client_if = n2, i2, n1, i1
        else:
            continue
        if client is None or ap is None:
            continue
        kind = str(link.get("type") or ap_if.get("type") or "").upper()
        channel = ap_if.get("current_channel") or client_if.get("current_channel")
        out.append(
            {
                "name": client.get("device_name") or client.get("device_mac_address"),
                "mac": safe_mac(client.get("device_mac_address")) or None,
                "connection": "wlan" if kind == "WLAN" else "lan" if kind == "LAN" else kind.lower() or None,
                "access_point": ap.get("device_name") or ap.get("device_model"),
                "access_point_is_master": str(ap.get("mesh_role") or "").lower() == "master",
                "ap_interface": ap_if.get("name"),
                "lan_port": lan_port_label(ap_if.get("name")) if kind == "LAN" else None,
                "band_ghz": band_of_interface(ap_if.get("name"), channel) if kind == "WLAN" else None,
                "channel": _int(channel) if kind == "WLAN" else None,
                "standards": client_if.get("phymodes") or ap_if.get("phymodes") or None,
                "rate_down_mbit": _mbit(link.get("cur_data_rate_rx")),
                "rate_up_mbit": _mbit(link.get("cur_data_rate_tx")),
                "max_rate_down_mbit": _mbit(link.get("max_data_rate_rx")),
                "max_rate_up_mbit": _mbit(link.get("max_data_rate_tx")),
                "signal_dbm": link_signal_dbm(link, ap_is_node_1) if kind == "WLAN" else None,
            }
        )
    return out


# ------------------------------------------------------------------ rating


def _signal_level(dbm: float | None, percent: int | None) -> str | None:
    """Rating from measured dBm, else from the dBm estimate of the TR-064 signal percent (same scale)."""
    if dbm is None:
        dbm = percent_to_dbm(percent)
    if dbm is None:
        return None
    if dbm >= SIGNAL_DBM["good"]:
        return "gut"
    if dbm >= SIGNAL_DBM["ok"]:
        return "ok"
    return "schwach" if dbm >= SIGNAL_DBM["weak"] else "sehr schwach"


def rate_device(d: dict[str, Any]) -> dict[str, Any]:
    """Adds ``rating`` (gut/ok/schwach/sehr schwach/unbekannt) and ``tips`` to a device entry."""
    tips: list[str] = []
    rating: str | None = None
    if d.get("connection") == "wlan":
        dbm = d.get("signal_dbm")
        rating = _signal_level(dbm, d.get("signal_percent"))
        band = d.get("band_ghz")
        pct = d.get("signal_percent")
        sig = (
            f"{dbm:.0f} dBm"
            if isinstance(dbm, int | float)
            else f"{pct} % Signal"
            if isinstance(pct, int)
            else "schwachem Signal"
        )
        if rating in {"schwach", "sehr schwach"}:
            if band == "2.4":
                tips.append(f"2,4 GHz mit {sig} → näher an Box/Repeater stellen oder 5 GHz nutzen, wenn erreichbar.")
            elif band in {"5", "6"}:
                tips.append(
                    f"{band} GHz mit {sig} → reicht schlecht durch Wände; Repeater/Mesh-Knoten näher platzieren "
                    "oder 2,4 GHz zulassen."
                )
            else:
                tips.append(f"Schwaches WLAN-Signal ({sig}) → Standort von Gerät oder Repeater prüfen.")
        rate, max_rate = d.get("rate_down_mbit") or d.get("speed_mbit"), d.get("max_rate_down_mbit")
        if rate and max_rate and rate < LOW_RATE_RATIO * max_rate:
            tips.append(
                f"Linkrate nur {rate:g} von max. {max_rate:g} Mbit/s – Funkstörungen oder Entfernung; "
                "Kanal/Standort prüfen."
            )
            if rating == "gut":
                rating = "ok"
        if band == "2.4" and rating in {"gut", "ok"} and rate and rate < 100:
            tips.append(
                "Gerät nutzt 2,4 GHz trotz brauchbarem Signal – kann es 5 GHz, dort ist mehr Durchsatz möglich."
            )
    elif d.get("connection") == "lan":
        speed, max_speed = d.get("port_speed_mbit"), d.get("port_max_speed_mbit")
        if speed:
            rating = "gut"
            if max_speed and speed < max_speed:
                rating = "schwach" if speed <= 10 else "ok"
                tips.append(
                    f"LAN nur mit {speed} Mbit/s (Port kann {max_speed}) – Kabel (Cat5e+, alle 8 Adern), Stecker, "
                    "Gegenstelle oder Green Mode prüfen."
                )
        if d.get("port_eee_active") and is_raspberry_pi(d.get("mac")):
            if d.get("port_eee_mode") == "off":
                tips.append(
                    "Raspberry Pi: EEE ist am Port schon aus, aber noch ausgehandelt – die Box baut den laufenden "
                    "Link nicht neu auf. Netzwerkkabel kurz trennen bzw. Pi neu starten oder am Pi abschalten "
                    f"(ethtool --set-eee eth0 eee off). {EEE_BUG_LINKS[0]}"
                )
            else:
                tips.append(
                    "Raspberry Pi mit aktivem EEE am Port: bekannter Fehler (Link-Flapping, Paketverlust) – EEE aus "
                    f"(set_lan_eee mode=off oder am Pi). {EEE_BUG_LINKS[0]}"
                )
            rating = "schwach" if rating in {None, "gut", "ok"} else rating
    return {**d, "rating": rating or "unbekannt", "tips": tips}


RATING_ORDER = {"sehr schwach": 0, "schwach": 1, "ok": 2, "unbekannt": 3, "gut": 4}


def assoc_info(r: dict[str, Any]) -> dict[str, Any]:
    """TR-064 GetSpecificAssociatedDeviceInfo / X_AVM-DE_GetWLANConnectionInfo → common fields."""
    width = _int(r.get("NewX_AVM-DE_ChannelWidth"))
    out = {
        "ip": r.get("NewAssociatedDeviceIPAddress") or None,
        "authenticated": truthy(r.get("NewAssociatedDeviceAuthState"))
        if r.get("NewAssociatedDeviceAuthState") is not None
        else None,
        "speed_mbit": _int(r.get("NewX_AVM-DE_Speed")),
        "signal_percent": _int(r.get("NewX_AVM-DE_SignalStrength")),
        "channel_width_mhz": width or None,
    }
    for key, field in (
        ("speed_rx_mbit", "NewX_AVM-DE_SpeedRX"),
        ("speed_max_mbit", "NewX_AVM-DE_SpeedMax"),
        ("speed_rx_max_mbit", "NewX_AVM-DE_SpeedRXMax"),
        ("channel", "NewChannel"),
    ):
        if r.get(field) is not None:
            out[key] = _int(r.get(field))
    for key, field in (("standard", "NewStandard"), ("ssid", "NewSSID")):
        if r.get(field) is not None:
            out[key] = r.get(field)
    band = str(r.get("NewX_AVM-DE_FrequencyBand") or "")
    if band in {"2400", "5000", "6000"}:
        out["band_ghz"] = {"2400": "2.4", "5000": "5", "6000": "6"}[band]
    return out
