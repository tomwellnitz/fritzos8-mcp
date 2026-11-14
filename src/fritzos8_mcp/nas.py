"""NAS (FRITZ!Box storage): protocol status, shared links, media, backup-target check, protocol writes.

Own implementation after the official AVM/FRITZ! TR-064 documents (2025-08):

- ``X_AVM-DE_Storage1`` (TR-064_Storage.pdf): ``GetInfo`` (FTP/SMB/FTP-WAN), ``GetUserInfo``
  ("ftpuser"), ``SetSMBServer``, ``SetFTPServer``, ``SetFTPServerWAN``. The service reports **no
  capacity** (used/free/total) – free space is therefore always ``unknown``.
- ``X_AVM-DE_Filelinks1`` (TR-064_Filelinks.pdf): ``GetNumberOfFilelinkEntries``,
  ``GetGenericFilelinkEntry``. ``NewID``/``NewUrl`` are bearer tokens (whoever has the link can
  download) and are never returned.
- ``X_AVM-DE_WebDAVClient1`` (TR-064_WebDAV.pdf): ``GetInfo`` – only enabled, host name and
  mount point are returned (no account name, no URL path/query).
- ``X_AVM-DE_Media1`` (TR-064_Media.pdf, DVB-C on cable boxes) and ``X_AVM-DE_UPnP1:GetInfo``
  (media server).

No file access to the NAS (list/download) – deliberately not built.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from .errors import FritzError, InvalidParameterError
from .tr064 import Tr064Client
from .util import truthy

STORAGE = "X_AVM-DE_Storage1"
FILELINKS = "X_AVM-DE_Filelinks1"
WEBDAV = "X_AVM-DE_WebDAVClient1"
MEDIA = "X_AVM-DE_Media1"
UPNP = "X_AVM-DE_UPnP1"

MAX_FILELINKS = 100
DEFAULT_MIN_FREE_GB = 50.0
PROTOCOLS = ("smb", "ftp")

CAPACITY_NOTE = (
    "Belegter/freier Speicher ist per TR-064 nicht lesbar (X_AVM-DE_Storage liefert keine Kapazität). "
    "Web-Oberfläche: Heimnetz > USB / Speicher bzw. FRITZ!NAS."
)

# Bearer token in a file link URL (e.g. /nas/filelink.lua?id=<hex>) – never shown.
_FILELINK_TOKEN = re.compile(r"(filelink\.lua\?id=)[0-9A-Za-z]+", re.I)


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _host_only(url: Any) -> str | None:
    """Only the host name of a URL: no user info, path, query (may carry account data)."""
    text = str(url or "").strip()
    if not text:
        return None
    parsed = urlparse(text if "://" in text else f"//{text}")
    return parsed.hostname or None


def parse_storage_info(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "smb": {"enabled": truthy(r.get("NewSMBEnable"))},
        "ftp": {"enabled": truthy(r.get("NewFTPEnable")), "status": r.get("NewFTPStatus") or None},
        "ftp_internet": {
            "enabled": truthy(r.get("NewFTPWANEnable")),
            "ssl_only": truthy(r.get("NewFTPWANSSLOnly")),
            "port": _int(r.get("NewFTPWANPort")),
        },
    }


def parse_filelink(e: dict[str, Any], index: int) -> dict[str, Any]:
    """Whitelist of a file link entry – without ID, URL and creator (ID/URL grant download access)."""
    path = _FILELINK_TOKEN.sub(r"\1***", str(e.get("NewPath") or ""))
    name = path.rstrip("/").rsplit("/", 1)[-1] if path else None
    return {
        "index": index,
        "name": name or None,
        "path": path or None,
        "is_directory": truthy(e.get("NewIsDirectory")),
        "valid": truthy(e.get("NewValid")),
        "expire_days": _int(e.get("NewExpire")),
        "expire_date": e.get("NewExpireDate") or None,
        "downloads": _int(e.get("NewAccessCount")),
        "download_limit": _int(e.get("NewAccessCountLimit")),
    }


def _overall(checks: list[dict[str, Any]]) -> str:
    known = [c["status"] for c in checks if c["status"] != "unknown"]
    for level in ("fail", "warn"):
        if level in known:
            return level
    return "ok" if known else "unknown"


class NasClient:
    def __init__(self, tr064: Tr064Client, sleep: Callable[[float], None] = time.sleep) -> None:
        self.tr064 = tr064
        self._sleep = sleep

    # ---------------------------------------------------------------- read

    def storage_info(self) -> dict[str, Any]:
        return parse_storage_info(self.tr064.call(STORAGE, "GetInfo"))

    def shared_links(self) -> dict[str, Any]:
        n = self.tr064.call(FILELINKS, "GetNumberOfFilelinkEntries")
        count = _int(n.get("NewNumberOfEntries")) or 0
        links = []
        for idx in range(min(count, MAX_FILELINKS)):
            e = self.tr064.try_call(FILELINKS, "GetGenericFilelinkEntry", NewIndex=idx)
            if e is None:  # 713 invalid array index = end of list
                break
            links.append(parse_filelink(e, idx))
        return {
            "available": True,
            "count": count,
            "links": links,
            "truncated": count > MAX_FILELINKS,
            "note": "Link-IDs/URLs sind Zugangs-Token und werden nie ausgegeben.",
        }

    def status(self) -> dict[str, Any]:
        out: dict[str, Any] = {}

        def section(name: str, fn: Callable[[], dict[str, Any]]) -> None:
            try:
                out[name] = fn()
            except FritzError as exc:
                out[name] = {"available": False, "error": exc.to_dict()}

        try:
            out["protocols"] = self.storage_info()
            out["available"] = True
        except FritzError as exc:
            out["available"] = False
            out["protocols"] = {"available": False, "error": exc.to_dict()}

        def ftpuser() -> dict[str, Any]:
            r = self.tr064.call(STORAGE, "GetUserInfo")
            enabled = truthy(r.get("NewEnable"))
            # Username is fixed ("ftpuser", per AVM doc) and not returned; there is no password field.
            return {
                "available": True,
                "enabled": enabled,
                "read_only": truthy(r.get("NewX_AVM-DE_NetworkAccessReadOnly")),
                "note": "Alter Standard-Benutzer 'ftpuser' (für FTP-Clients ohne FRITZ!Box-Benutzer).",
            }

        def webdav() -> dict[str, Any]:
            r = self.tr064.call(WEBDAV, "GetInfo")
            return {
                "available": True,
                "enabled": truthy(r.get("NewEnable")),
                "host": _host_only(r.get("NewHostURL")),
                "mountpoint": r.get("NewMountpointName") or None,
                "note": "Online-Speicher (WebDAV-Client der Box); Kontoname und Zugangsdaten werden nicht ausgegeben.",
            }

        def media() -> dict[str, Any]:
            data: dict[str, Any] = {}
            upnp = self.tr064.try_call(UPNP, "GetInfo")
            data["media_server"] = truthy(upnp.get("NewUPnPMediaServer")) if upnp is not None else None
            dvbc = self.tr064.try_call(MEDIA, "GetInfo")
            if dvbc is None:
                data["dvbc"] = {"available": False, "note": "kein DVB-C (nur FRITZ!Box Cable)"}
            else:
                data["dvbc"] = {
                    "available": True,
                    "enabled": truthy(dvbc.get("NewDVBCEnabled")),
                    "station_search": dvbc.get("NewStationSearchStatus") or None,
                    "search_progress_pct": _int(dvbc.get("NewSearchProgress")),
                }
            return data

        section("ftpuser", ftpuser)
        out["capacity"] = {"available": False, "status": "unknown", "note": CAPACITY_NOTE}
        section("shared_links", self.shared_links)
        section("online_storage", webdav)
        section("media", media)
        return out

    def assessments(self, status: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Security assessments in the format of ``security_check`` (check/status/summary/details).

        Meant to be merged into ``security_check`` later (stage 4 owns that tool)."""
        st = status if status is not None else self.status()
        checks: list[dict[str, Any]] = []
        protocols = st.get("protocols") or {}
        wan = protocols.get("ftp_internet")
        if not isinstance(wan, dict):
            checks.append(
                {"check": "nas_internet", "status": "unknown", "summary": "NAS-Status nicht lesbar", "details": {}}
            )
        elif not wan["enabled"]:
            checks.append(
                {"check": "nas_internet", "status": "ok", "summary": "FTP aus dem Internet aus", "details": wan}
            )
        elif not wan["ssl_only"]:
            checks.append(
                {
                    "check": "nas_internet",
                    "status": "warn",
                    "summary": "FTP aus dem Internet aktiv und auch UNVERSCHLÜSSELT erlaubt",
                    "details": wan,
                }
            )
        else:
            checks.append(
                {
                    "check": "nas_internet",
                    "status": "warn",
                    "summary": "FTP aus dem Internet aktiv (nur verschlüsselt)",
                    "details": wan,
                }
            )
        links = st.get("shared_links") or {}
        if links.get("available"):
            open_links = [lk for lk in links["links"] if lk["valid"]]
            unlimited = [lk for lk in open_links if not lk.get("expire_date") or lk.get("expire_days") == 0]
            if open_links:
                summary = f"{len(open_links)} gültige Freigabe-Link(s) ins Internet"
                if unlimited:
                    summary += f", davon {len(unlimited)} ohne erkennbares Ablaufdatum"
                checks.append(
                    {
                        "check": "nas_links",
                        "status": "warn",
                        "summary": summary,
                        "details": {"count": len(open_links), "paths": [lk["path"] for lk in open_links]},
                    }
                )
            else:
                checks.append(
                    {"check": "nas_links", "status": "ok", "summary": "keine gültigen Freigabe-Links", "details": {}}
                )
        else:
            checks.append(
                {"check": "nas_links", "status": "unknown", "summary": "Freigabe-Links nicht lesbar", "details": {}}
            )
        return checks

    # ---------------------------------------------------------------- backup target

    def backup_target_check(self, share: str | None = None, min_free_gb: float = DEFAULT_MIN_FREE_GB) -> dict[str, Any]:
        if min_free_gb < 0:
            raise InvalidParameterError("min_free_gb darf nicht negativ sein.")
        checks: list[dict[str, Any]] = []

        def add(name: str, status: str, summary: str, recommendation: str | None = None, **details: Any) -> None:
            item: dict[str, Any] = {"check": name, "status": status, "summary": summary, "details": details}
            if recommendation:
                item["recommendation"] = recommendation
            checks.append(item)

        try:
            info: dict[str, Any] | None = self.storage_info()
        except FritzError as exc:
            info = None
            add(
                "speicher",
                "fail",
                "NAS-Funktion (X_AVM-DE_Storage) nicht lesbar",
                "Prüfen, ob die Box eine NAS-Funktion hat und der Benutzer das Recht 'NAS-Inhalte' besitzt.",
                error=exc.to_dict(),
            )

        if info is not None:
            smb = info["smb"]["enabled"]
            if smb:
                add("smb", "ok", "SMB (Heimnetzfreigabe) ist aktiv")
            else:
                add(
                    "smb",
                    "fail",
                    "SMB ist aus – Backup-Programme (Time Machine, Windows-Sicherung) erreichen die NAS nicht",
                    "SMB einschalten: set_nas_protocol(protocol='smb', enabled=true) oder Web-UI Heimnetz > "
                    "USB / Speicher > Heimnetzfreigabe.",
                )
            ftp_status = str(info["ftp"]["status"] or "")
            if ftp_status.lower() == "error":
                add(
                    "speicher",
                    "warn",
                    "Der NAS-Dienst meldet einen Fehler (FTPStatus=Error) – Speicher evtl. nicht eingehängt",
                    "USB-Speicher/internen Speicher in der Web-UI prüfen.",
                    ftp_status=ftp_status,
                )
            else:
                add(
                    "speicher",
                    "ok",
                    "NAS-Dienst erreichbar",
                    None,
                    ftp_status=ftp_status or None,
                    note="Ob ein Datenträger eingehängt ist, liefert TR-064 nicht direkt.",
                )
            wan = info["ftp_internet"]
            if not wan["enabled"]:
                add("internet_ftp", "ok", "FTP aus dem Internet ist aus (empfohlen für ein Backup-Ziel)")
            else:
                add(
                    "internet_ftp",
                    "warn",
                    "FTP aus dem Internet ist aktiv"
                    + ("" if wan["ssl_only"] else " und erlaubt unverschlüsselte Anmeldungen"),
                    "Für ein Backup-Ziel im Heimnetz Internet-FTP ausschalten (set_nas_internet_access_plan "
                    "mit enabled=false).",
                    ssl_only=wan["ssl_only"],
                    port=wan["port"],
                )

        add(
            "freier_speicher",
            "unknown",
            f"Freier Platz nicht per TR-064 lesbar (Schwelle {min_free_gb:g} GB nicht prüfbar)",
            "Freien Platz in der Web-UI (Heimnetz > USB / Speicher) bzw. im Backup-Programm prüfen.",
            min_free_gb=min_free_gb,
        )
        if share:
            add(
                "freigabe",
                "unknown",
                f"Freigabe '{share}' per TR-064 nicht prüfbar",
                "Freigabenamen im Finder/Explorer prüfen (Standard der FRITZ!Box-NAS: FRITZ.NAS).",
                share=share,
            )

        overall = _overall(checks)
        unverified = [c["check"] for c in checks if c["status"] == "unknown"]
        return {
            "overall": overall,
            "complete": not unverified,
            "unverified": unverified,
            "checks": checks,
            "recommendations": [c["recommendation"] for c in checks if c["status"] != "ok" and "recommendation" in c],
            "note": "overall bewertet nur die prüfbaren Punkte; 'unverified' muss man selbst prüfen.",
        }

    # ---------------------------------------------------------------- write

    def _read_back(self, fn: Callable[[], Any], expected: Any, attempts: int = 3) -> Any:
        value = None
        for i in range(attempts):
            try:
                value = fn()
            except FritzError:
                value = None
            if value == expected:
                return value
            if i < attempts - 1:
                self._sleep(1.0)
        return value

    def set_protocol(self, protocol: str, enabled: bool) -> dict[str, Any]:
        proto = (protocol or "").strip().lower()
        if proto not in PROTOCOLS:
            raise InvalidParameterError("protocol muss 'smb' oder 'ftp' sein.")
        before = self.storage_info()
        base: dict[str, Any] = {"protocol": proto, "enabled": enabled}
        if before[proto]["enabled"] == enabled:
            return {**base, "changed": False, "verified": True}
        if proto == "smb":
            self.tr064.call(STORAGE, "SetSMBServer", NewSMBEnable=1 if enabled else 0)
        else:
            self.tr064.call(STORAGE, "SetFTPServer", NewFTPEnable=1 if enabled else 0)
        after = self._read_back(lambda: self.storage_info()[proto]["enabled"], enabled)
        result: dict[str, Any] = {**base, "changed": True, "read_back": after, "verified": after == enabled}
        if after is None:
            result["note"] = "Schreiben angenommen, Zustand aber nicht rücklesbar – in der Web-UI prüfen."
        if proto == "ftp" and not enabled and before["ftp_internet"]["enabled"]:
            result["warning"] = (
                "FTP aus dem Internet ist weiterhin eingeschaltet (ohne lokalen FTP-Server wirkungslos) – "
                "ggf. mit set_nas_internet_access_plan(enabled=false) auch abschalten."
            )
        return result

    def set_internet(self, enabled: bool, ssl_only: bool) -> dict[str, Any]:
        self.tr064.call(
            STORAGE, "SetFTPServerWAN", NewFTPWANEnable=1 if enabled else 0, NewFTPWANSSLOnly=1 if ssl_only else 0
        )
        expected = {"enabled": enabled, "ssl_only": ssl_only}

        def current() -> dict[str, Any]:
            wan = self.storage_info()["ftp_internet"]
            return {"enabled": wan["enabled"], "ssl_only": wan["ssl_only"]}

        after = self._read_back(current, expected)
        # With FTP-WAN disabled the SSL flag is irrelevant – only the enabled state must match.
        verified = after == expected or (not enabled and isinstance(after, dict) and after["enabled"] is False)
        return {"action": "set_nas_internet_access", **expected, "read_back": after, "verified": verified}
