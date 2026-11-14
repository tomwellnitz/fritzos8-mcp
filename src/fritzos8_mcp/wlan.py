"""WLAN and guest WLAN via TR-064 ``WLANConfiguration1..n``.

Only whitelisted fields are returned – keys/passphrases are never read (``GetSecurityKeys``
is on the denylist and not called here). Guest detection: ``X_AVM-DE_GetWLANExtInfo``
(``NewX_AVM-DE_APType == "guest"``), otherwise the convention also used by fritzconnection's
``FritzGuestWLAN``: with three or more WLAN services the highest one is the guest network.

Deliberately NOT via ``/api/v0``: partial radio changes there are reported to wipe channel/mode
fields (gr9driver/fritz-mesh-mcp); TR-064 ``SetEnable`` only toggles the network.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any

from .errors import (
    AuthError,
    ConfirmationRequiredError,
    FritzConnectionError,
    FritzError,
    InvalidParameterError,
    NotFoundError,
)
from .tr064 import Tr064Client
from .util import truthy

_SERVICE = re.compile(r"^WLANConfiguration(\d+)$")
OPEN_BEACON_TYPES = {"none", "basic"}

BANDS = ("2.4", "5", "6")


def _opt_flag(d: dict[str, Any], *keys: str) -> bool | None:
    """Boolean of the first present key; None if none of them is in the answer."""
    for key in keys:
        if d.get(key) not in (None, ""):
            return truthy(d[key])
    return None


def normalize_band(band: str) -> str:
    """'2.4', '2,4', '2.4 GHz', '24', '2g' → '2.4'; '5', '5ghz' → '5'; '6' → '6'."""
    b = re.sub(r"\s|ghz|g$", "", str(band or "").strip().lower()).replace(",", ".")
    mapping = {"2.4": "2.4", "24": "2.4", "2": "2.4", "5": "5", "6": "6"}
    if b not in mapping:
        raise InvalidParameterError(f'Unbekanntes WLAN-Band "{band}" – erlaubt: 2.4, 5, 6.')
    return mapping[b]


def band_from(info: dict[str, Any], ext: dict[str, Any] | None) -> tuple[str | None, str]:
    """Band from an explicit FrequencyBand field if the box has one, else from the channel."""
    for source in (info, ext or {}):
        for key, value in source.items():
            if "frequencyband" in key.lower() and value not in (None, ""):
                v = str(value).lower()
                if v.startswith("24") or v.startswith("2.4"):
                    return "2.4", "field"
                if v.startswith("5"):
                    return "5", "field"
                if v.startswith("6"):
                    return "6", "field"
    try:
        channel = int(info.get("NewChannel") or 0)
    except (TypeError, ValueError):
        channel = 0
    if 1 <= channel <= 14:
        return "2.4", "channel"
    if 32 <= channel <= 177:
        # 6-GHz channels overlap numerically; boxes with 6 GHz should report FrequencyBand.
        return "5", "channel"
    return None, "unknown"


def is_open(beacon_type: Any) -> bool:
    return str(beacon_type or "").strip().lower() in OPEN_BEACON_TYPES


class WlanClient:
    def __init__(self, tr064: Tr064Client, *, sleep: Callable[[float], None] = time.sleep) -> None:
        self.tr064 = tr064
        self._sleep = sleep

    def service_names(self) -> list[str]:
        names = [(int(m.group(1)), n) for n in self.tr064.fc.services if (m := _SERVICE.match(n))]
        return [n for _, n in sorted(names)]

    def _network(self, service: str, guest_by_position: bool) -> dict[str, Any]:
        info = self.tr064.call(service, "GetInfo")
        ext = self.tr064.try_call(service, "X_AVM-DE_GetWLANExtInfo")
        assoc = self.tr064.try_call(service, "GetTotalAssociations")
        ap_type = str((ext or {}).get("NewX_AVM-DE_APType") or "").lower() or None
        band, band_source = band_from(info, ext)
        if ap_type:
            guest, guest_source = ap_type == "guest", "ap_type"
        else:
            guest, guest_source = guest_by_position, "position"
        net: dict[str, Any] = {
            "service": service,
            "enabled": truthy(info.get("NewEnable")),
            "status": info.get("NewStatus"),
            "ssid": info.get("NewSSID"),
            "bssid": info.get("NewBSSID"),
            "channel": info.get("NewChannel"),
            "standard": info.get("NewStandard"),
            "band_ghz": band,
            "band_source": band_source,
            # V-12 (AVM doc): NewMaxBitRate is "not supported, returns a default value" – deliberately not output.
            # Likewise GetStatistics/GetPacketStatistics are always 0 since FRITZ!OS 8.10 and are never used.
            "security": info.get("NewBeaconType"),
            "encrypted": not is_open(info.get("NewBeaconType")),
            "guest": guest,
            "guest_detection": guest_source,
            "clients": int(assoc["NewTotalAssociations"])
            if assoc and assoc.get("NewTotalAssociations") is not None
            else None,
        }
        if guest and ext:
            net["guest_extra"] = {
                "timeout_active": truthy(ext.get("NewX_AVM-DE_TimeoutActive")),
                "timeout_min": ext.get("NewX_AVM-DE_Timeout"),
                "time_remaining_min": ext.get("NewX_AVM-DE_TimeRemain"),
                # AVM doc (WLANConfiguration, X_AVM-DE_GetWLANExtInfo): NewX_AVM-DE_UserIsolation and
                # NewX_AVM-DE_NoForcedOff. The "…Enabled" spelling read before is only a fallback; a missing
                # field stays None (unknown) instead of being reported as "not isolated".
                "user_isolation": _opt_flag(ext, "NewX_AVM-DE_UserIsolation", "NewX_AVM-DE_UserIsolationEnabled"),
                "no_forced_off": _opt_flag(ext, "NewX_AVM-DE_NoForcedOff"),
                "encryption_mode": ext.get("NewX_AVM-DE_EncryptionMode"),
            }
        return net

    def networks(self) -> list[dict[str, Any]]:
        names = self.service_names()
        if not names:
            raise NotFoundError("Diese FRITZ!Box hat keinen TR-064-Service WLANConfiguration.")
        last = names[-1] if len(names) >= 3 else None
        out = []
        for n in names:
            try:
                out.append(self._network(n, n == last))
            except (AuthError, ConfirmationRequiredError, FritzConnectionError):
                raise
            except FritzError as exc:  # one broken service must not hide the others
                out.append({"service": n, "enabled": None, "band_ghz": None, "guest": False, "error": exc.to_dict()})
        return out

    def guest(self) -> dict[str, Any]:
        guests = [n for n in self.networks() if n["guest"]]
        if not guests:
            raise NotFoundError("Kein Gast-WLAN gefunden (weder per APType noch per Service-Position).")
        return guests[0]

    def _read_enable(self, service: str) -> bool | None:
        try:
            r = self.tr064.call(service, "GetInfo")
        except FritzError:
            return None
        return truthy(r.get("NewEnable")) if r.get("NewEnable") is not None else None

    def set_enable(self, service: str, enabled: bool, *, attempts: int = 3, wait: float = 1.0) -> dict[str, Any]:
        """SetEnable + read back (a few tries – the radio may need a moment)."""
        self.tr064.call(service, "SetEnable", NewEnable=1 if enabled else 0)
        after: bool | None = None
        for i in range(attempts):
            after = self._read_enable(service)
            if after == enabled:
                return {"service": service, "enabled": enabled, "changed": True, "verified": True}
            if i < attempts - 1:
                self._sleep(wait)
        result: dict[str, Any] = {
            "service": service,
            "enabled": enabled,
            "read_back": after,
            "changed": None,
            "verified": False,
        }
        result["note"] = (
            "Schreiben angenommen, Wert aber nicht rücklesbar – in der Web-UI unter WLAN prüfen."
            if after is None
            else "Die Box meldet nach dem Schreiben weiterhin den alten Zustand – nicht übernommen "
            "(evtl. Zusatzbestätigung/2FA oder Zeitschaltung aktiv)."
        )
        return result


# ====================================================================== stage 7.4: WLAN settings
#
# After AVM "TR-064 Support – WLANConfiguration" (2026-03-10): GetChannelInfo (Channel,
# PossibleChannels, X_AVM-DE_AutoChannelEnabled – argument spelled "NewX_AVM-DEAuto_ChannelEnabled" in
# the document, so it is matched loosely –, X_AVM-DE_FrequencyBand), SetChannel (Channel "0 means auto
# channel"), X_AVM-DE_GetNightControl (NightControl = XML string, structure not documented;
# NightTimeControlNoForcedOff) and GetInfo X_AVM-DE_WLANGlobalEnable. The channel width of an access
# point and band steering are NOT part of TR-064 (only per client); there is no setter for the night
# control. Everything beyond that would need /api/v0 (wlan_light), which is unverified → read-only hints.

DFS_CHANNELS = range(52, 145)  # 5 GHz channels with radar detection (DFS) in the EU
_FREQ = {"2400": "2.4", "5000": "5", "6000": "6"}
_HINT_KEY = re.compile(r"steer|band|chan|width|autoch|night|timer|sched|mlo|standard|mode|enabled|active", re.I)
_HINT_DENY = re.compile(r"key|psk|pass|secret|wps|pin|token|user", re.I)


def _loose(d: dict[str, Any], needle: str) -> Any:
    """Value of the first key whose alphanumerics contain ``needle`` (case-insensitive)."""
    for key, value in d.items():
        if needle in re.sub(r"[^a-z0-9]", "", key.lower()):
            return value
    return None


def parse_channels(raw: Any) -> list[int]:
    out: list[int] = []
    for part in re.split(r"[,;\s]+", str(raw or "")):
        if part.isdigit():
            out.append(int(part))
    return out


def parse_night_control(xml_text: str) -> dict[str, Any]:
    """Generic flattening of the (undocumented) NightControl XML: tag path → text, lists for repeats."""
    from defusedxml import ElementTree as ET

    root = ET.fromstring(xml_text)
    flat: dict[str, Any] = {}

    def walk(node: Any, path: str) -> None:
        children = list(node)
        if not children:
            text = (node.text or "").strip()
            if path in flat:
                prev = flat[path]
                flat[path] = [*prev, text] if isinstance(prev, list) else [prev, text]
            else:
                flat[path] = text
            return
        for child in children:
            walk(child, f"{path}/{child.tag}" if path else child.tag)

    walk(root, root.tag)
    return flat


def wlan_light_hints(data: Any, limit: int = 200) -> dict[str, Any]:
    """Whitelist of scalar fields of /api/v0/generic/wlan_light that look like channel/band/steering/schedule
    settings. Everything key/password-like is dropped (on top of the central /api/v0 redaction)."""
    out: dict[str, Any] = {}

    def walk(node: Any, path: str) -> None:
        if len(out) >= limit:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}.{k}" if path else str(k))
        elif isinstance(node, list):
            for i, v in enumerate(node[:32]):
                walk(v, f"{path}[{i}]")
        else:
            leaf = path.rsplit(".", 1)[-1]
            if _HINT_KEY.search(leaf) and not _HINT_DENY.search(path):
                out[path] = node

    walk(data, "")
    return out


class WlanSettings:
    """Channel / auto channel / night control per radio (read) and SetChannel (write, read back)."""

    def __init__(self, wlan: WlanClient) -> None:
        self.wlan = wlan
        self.tr064 = wlan.tr064

    def channel_info(self, service: str) -> dict[str, Any]:
        info = self.tr064.try_call(service, "GetChannelInfo") or {}
        channel = info.get("NewChannel")
        auto_raw = _loose(info, "autochannelenabled")
        auto: bool | None = truthy(auto_raw) if auto_raw not in (None, "") else None
        try:
            channel_i: int | None = int(channel) if channel not in (None, "") else None
        except (TypeError, ValueError):
            channel_i = None
        if channel_i == 0:
            auto = True
        return {
            "channel": channel_i,
            "auto_channel": auto,
            "possible_channels": parse_channels(info.get("NewPossibleChannels")),
            "band_ghz": _FREQ.get(str(_loose(info, "frequencyband") or "")),
            "available": bool(info),
        }

    def radios(self) -> list[dict[str, Any]]:
        out = []
        for net in self.wlan.networks():
            if net.get("guest") or net.get("error"):
                continue
            ch = self.channel_info(net["service"])
            out.append(
                {
                    "service": net["service"],
                    "band_ghz": ch["band_ghz"] or net.get("band_ghz"),
                    "enabled": net.get("enabled"),
                    "ssid": net.get("ssid"),
                    "standard": net.get("standard"),
                    "channel": ch["channel"] if ch["channel"] is not None else net.get("channel"),
                    "auto_channel": ch["auto_channel"],
                    "possible_channels": ch["possible_channels"],
                    "dfs_channel": (ch["channel"] or 0) in DFS_CHANNELS,
                    "channel_width_mhz": None,
                    "clients": net.get("clients"),
                    "channel_info_available": ch["available"],
                }
            )
        return out

    def night_control(self) -> dict[str, Any]:
        names = self.wlan.service_names()
        r = self.tr064.try_call(names[0], "X_AVM-DE_GetNightControl") if names else None
        if r is None:
            return {"available": False, "note": "X_AVM-DE_GetNightControl ist auf dieser Box nicht vorhanden."}
        raw = str(r.get("NewNightControl") or "")
        out: dict[str, Any] = {
            "available": True,
            "no_forced_off": truthy(r.get("NewNightTimeControlNoForcedOff"))
            if r.get("NewNightTimeControlNoForcedOff") is not None
            else None,
            "structure_verified": False,
            "note": "Nachtschaltung/WLAN-Zeitplan laut AVM-Doku als XML ohne beschriebene Struktur – Felder "
            "unverändert wiedergegeben. no_forced_off = WLAN wird nicht zwangsweise abgeschaltet, solange "
            "noch Geräte verbunden sind. Ändern ist per TR-064 nicht möglich.",
        }
        if raw.strip().startswith("<"):
            try:
                out["settings"] = parse_night_control(raw)
            except Exception:
                out["raw"] = raw[:2000]
        else:
            out["raw"] = raw[:2000]
        return out

    def global_enable(self) -> bool | None:
        names = self.wlan.service_names()
        r = self.tr064.try_call(names[0], "GetInfo") if names else None
        value = (r or {}).get("NewX_AVM-DE_WLANGlobalEnable")
        return truthy(value) if value not in (None, "") else None

    def set_channel(self, net: dict[str, Any], channel: int, *, attempts: int = 4, wait: float = 2.0) -> dict[str, Any]:
        service = net["service"]
        before = self.channel_info(service)
        possible = before["possible_channels"]
        if channel != 0 and possible and channel not in possible:
            raise InvalidParameterError(
                f"Kanal {channel} ist im {net['band_ghz']}-GHz-Band dieser Box nicht erlaubt "
                f"(möglich: {', '.join(map(str, possible))}; 0 = automatisch)."
            )
        base: dict[str, Any] = {
            "service": service,
            "band_ghz": net["band_ghz"],
            "requested_channel": channel,
            "requested": "auto" if channel == 0 else f"Kanal {channel}",
            "before": {"channel": before["channel"], "auto_channel": before["auto_channel"]},
        }
        warnings: list[str] = []
        if not possible:
            warnings.append("Die Box nennt keine möglichen Kanäle – Kanal ungeprüft gesendet.")
        if channel in DFS_CHANNELS:
            warnings.append(
                "DFS-Kanal (Radar-Erkennung): die Box prüft vor dem Senden bis zu 10 min auf Radar, bei Radar "
                "wechselt sie selbst den Kanal."
            )
        if channel == 0 and before["auto_channel"] is True:
            return {**base, "after": base["before"], "changed": False, "verified": True, "warnings": warnings}
        if channel != 0 and before["channel"] == channel and before["auto_channel"] is not True:
            return {**base, "after": base["before"], "changed": False, "verified": True, "warnings": warnings}

        self.tr064.call(service, "SetChannel", NewChannel=channel)
        after = before
        verified: bool | None = False
        for i in range(attempts):
            after = self.channel_info(service)
            if channel == 0:
                verified = True if after["auto_channel"] is True else (None if after["auto_channel"] is None else False)
            else:
                verified = after["channel"] == channel and after["auto_channel"] is not True
            if verified:
                break
            if i < attempts - 1:
                self.wlan._sleep(wait)
        result: dict[str, Any] = {
            **base,
            "after": {"channel": after["channel"], "auto_channel": after["auto_channel"]},
            "changed": bool(verified),
            "verified": bool(verified),
            "warnings": warnings,
            "note": "Geräte in diesem Band verbinden sich kurz neu. Das Gast-WLAN im selben Band nutzt denselben "
            "Kanal.",
        }
        if verified is None:
            result["note"] = (
                "Automatische Kanalwahl gesendet, die Box meldet aber keinen Autokanal-Status – in der Web-UI "
                "unter WLAN > Funkkanal prüfen."
            )
        elif not verified:
            result["note"] = (
                "Die Box meldet nach dem Schreiben einen anderen Kanal – nicht (oder noch nicht) übernommen "
                "(DFS-Wartezeit, Zusatzbestätigung/2FA oder Kanal von der Box verworfen)."
            )
        return result
