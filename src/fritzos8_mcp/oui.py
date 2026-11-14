"""Manufacturer lookup by MAC prefix (OUI, IEEE MA-L registry).

The registry is downloaded at runtime from the IEEE (public data,
``https://standards-oui.ieee.org/oui/oui.csv``) and cached locally for up to 30 days
(``~/.cache/fritzos8-mcp/oui.csv``). No vendor database is bundled with this project
(in particular no GPL-licensed data such as Wireshark's ``manuf``).

Without network access and without a cache the lookup simply answers ``None`` – callers
report the manufacturer as ``unknown``. Locally administered (random/private) MAC
addresses never have a manufacturer.

Set ``FRITZ_OUI_DOWNLOAD=0`` to never download (cache only).
"""

from __future__ import annotations

import csv
import io
import logging
import os
import re
import threading
import time
from collections.abc import Callable
from pathlib import Path

import httpx

from .paths import cache_dir, write_private
from .util import safe_mac

log = logging.getLogger(__name__)

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
MAX_AGE_S = 30 * 24 * 3600
_HEX6 = re.compile(r"^[0-9A-F]{6}$")

# Legal-form and filler words dropped when shortening an organisation name.
_SUFFIXES = {
    "inc",
    "incorporated",
    "ltd",
    "limited",
    "llc",
    "gmbh",
    "ag",
    "co",
    "corp",
    "corporation",
    "company",
    "kg",
    "sa",
    "srl",
    "bv",
    "nv",
    "oy",
    "ab",
    "as",
    "plc",
    "pte",
    "pty",
    "technologies",
    "technology",
    "electronics",
    "electronic",
    "international",
    "communications",
    "communication",
    "systems",
    "network",
    "networks",
    "group",
    "holdings",
    "mobile",
    "devices",
    "digital",
    "computer",
    "intelligent",
    "manufacturing",
    "industrial",
    "trading",
    "the",
    # further legal forms / company words (live finding 14.11.2026: never a vendor name on their own)
    "holding",
    "industries",
    "industry",
    "enterprise",
    "enterprises",
    "factory",
    "manufactory",
    "manufacture",
    "science",
    "sciences",
    "development",
    "information",
    "device",
    "products",
    "product",
    "solutions",
    "sas",
    "sarl",
    "spa",
    "sro",
    "kk",
    "pvt",
    "jsc",
    "ug",
    "ohg",
    "gbr",
    "mbh",
}

# Countries, regions and cities that prefix many registry names ("Shenzhen Example Technology Co., Ltd") –
# skipped; a name that consists only of them (e.g. "China") is no vendor.
_PLACES = {
    "china",
    "chinese",
    "prc",
    "taiwan",
    "hong",
    "kong",
    "hongkong",
    "korea",
    "japan",
    "germany",
    "deutschland",
    "usa",
    "us",
    "america",
    "american",
    "europe",
    "asia",
    "global",
    "shenzhen",
    "guangdong",
    "guangzhou",
    "hangzhou",
    "beijing",
    "shanghai",
    "dongguan",
    "zhejiang",
    "jiangsu",
    "fujian",
    "xiamen",
    "suzhou",
    "ningbo",
    "qingdao",
    "wuhan",
    "chengdu",
    "zhongshan",
    "zhuhai",
    "foshan",
    "huizhou",
    "tianjin",
    "nanjing",
    "anhui",
    "shandong",
    "sichuan",
    "hubei",
    "hunan",
    "jiangxi",
    "wuxi",
    "changzhou",
    "chongqing",
}

# Registry entries that do not name a manufacturer.
_PLACEHOLDER_ORGS = {"private", "ieee registration authority", "unknown", "not assigned", "reserved"}


# MA-L assignments of AVM / FRITZ! GmbH in the IEEE registry (checked 2026-11-14). Used to protect AVM devices
# (box, repeaters, Powerline) from the clean-up assistant even without a cached OUI registry. Not exhaustive –
# the downloaded registry supplements it (vendor "AVM").
AVM_OUIS = frozenset(
    {
        "00:04:0E", "00:15:0C", "00:1A:4F", "00:1C:4A", "00:1F:3F", "00:24:FE", "04:B4:FE", "08:96:D7",
        "08:B6:57", "0C:72:74", "1C:ED:6F", "24:65:11", "2C:3A:FD", "2C:91:AB", "34:31:C4", "34:81:C4",
        "34:E1:A9", "38:10:D5", "3C:37:12", "3C:A6:2F", "44:4E:6D", "48:5D:35", "50:E6:36", "5C:49:79",
        "60:B5:8D", "74:42:7F", "7C:FF:4D", "80:23:95", "98:9B:CB", "98:A9:65", "9C:C7:A6", "B0:F2:08",
        "B4:FC:7D", "BC:05:43", "C0:25:06", "C8:0E:14", "CC:CE:1E", "D0:12:CB", "D4:24:DD", "DC:15:C8",
        "DC:39:6F", "E0:08:55", "E0:28:6D", "E8:DF:70", "F0:B0:14",
    }
)  # fmt: skip


def universal_variant(mac: str) -> str:
    """MAC with the locally-administered bit cleared (``76:42:7F:…`` → ``74:42:7F:…``)."""
    m = safe_mac(mac)
    if not m:
        return ""
    return f"{int(m[:2], 16) & ~0x02 & 0xFF:02X}{m[2:]}"


# AVM derives extra interface MACs (Powerline, mesh, guest WLAN) from its own OUI by setting the locally
# administered bit and changing further low bits of the first octet – live: 7A:42:7F:… on a FRITZ!Powerline
# adapter for the AVM block 74:42:7F (0x74 ^ 0x7A = 0x0E). Octets 2–3 stay the same.
_AVM_DERIVED_MASK = 0x0E


def _derived_from_avm(mac: str) -> bool:
    first, rest = int(mac[:2], 16), mac[2:8]
    return any(oui[2:8] == rest and (first ^ int(oui[:2], 16)) & ~_AVM_DERIVED_MASK & 0xFF == 0 for oui in AVM_OUIS)


def avm_mac_kind(mac: str, db: OuiDb | None = None) -> str | None:
    """'avm' for an AVM OUI, 'avm_local' for a locally administered address derived from one, else None."""
    m = safe_mac(mac)
    if not m:
        return None
    if not is_locally_administered(m):
        hit = m[:8] in AVM_OUIS or (db is not None and (db.vendor(m) or "").upper() in {"AVM", "FRITZ!"})
        return "avm" if hit else None
    if _derived_from_avm(m):
        return "avm_local"
    if db is not None and (db.vendor(universal_variant(m)) or "").upper() in {"AVM", "FRITZ!"}:
        return "avm_local"
    return None


def is_locally_administered(mac: str) -> bool:
    """Bit 0x02 of the first octet: random/private MAC (e.g. Wi-Fi privacy address)."""
    m = safe_mac(mac)
    if not m:
        return False
    return bool(int(m[:2], 16) & 0x02)


def short_vendor(organization: str | None) -> str | None:
    """'Apple, Inc.' → 'Apple'; 'AVM Audiovisuelles Marketing und Computersysteme GmbH' → 'AVM'."""
    if not organization or organization.strip().lower() in _PLACEHOLDER_ORGS:
        return None
    words = [w for w in re.split(r"[\s,.()/&]+", organization) if w]
    # legal forms, generic company words, places and pure numbers are never the vendor ('China' → None)
    kept = [w for w in words if w.lower() not in _SUFFIXES and w.lower() not in _PLACES and not w.isdigit()]
    if not kept or len(kept[0]) < 2:
        return None
    first = kept[0]
    # 'Hon Hai' / 'Texas Instruments': keep a short second word when the first is very short.
    if len(first) <= 3 and len(kept) > 1 and not first.isupper():
        return f"{first} {kept[1]}"
    return first


def parse_oui_csv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if len(row) < 3:
            continue
        assignment = row[1].strip().upper()
        if _HEX6.match(assignment):
            out[assignment] = row[2].strip()
    return out


Fetcher = Callable[[], str]


def _default_fetch() -> str:
    response = httpx.get(OUI_URL, timeout=20.0, follow_redirects=True, headers={"User-Agent": "fritzos8-mcp"})
    response.raise_for_status()
    return response.text


class OuiDb:
    """Lazily loaded OUI → organisation map with a local, aging cache."""

    def __init__(
        self,
        cache_path: Path | None = None,
        *,
        fetch: Fetcher | None = None,
        download: bool | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.cache_path = cache_path or cache_dir() / "oui.csv"
        self._fetch = fetch or _default_fetch
        if download is None:
            download = os.environ.get("FRITZ_OUI_DOWNLOAD", "1").strip().lower() not in {"0", "false", "no", "off"}
        self._download = download
        self._now = now
        self._map: dict[str, str] | None = None
        self._source = "none"
        self._lock = threading.Lock()

    @property
    def source(self) -> str:
        """'cache', 'download', 'stale-cache' or 'none' (after the first lookup)."""
        return self._source

    def _cache_age(self) -> float | None:
        try:
            return self._now() - self.cache_path.stat().st_mtime
        except OSError:
            return None

    def _read_cache(self) -> dict[str, str] | None:
        try:
            return parse_oui_csv(self.cache_path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            return None

    def _load(self) -> dict[str, str]:
        age = self._cache_age()
        if age is not None and age < MAX_AGE_S:
            cached = self._read_cache()
            if cached:
                self._source = "cache"
                return cached
        if self._download:
            try:
                text = self._fetch()
                parsed = parse_oui_csv(text)
                if parsed:
                    write_private(self.cache_path, text.encode("utf-8"))
                    self._source = "download"
                    return parsed
                log.info("OUI-Registry: Download ohne verwertbare Einträge")
            except (httpx.HTTPError, OSError) as exc:
                log.info("OUI-Registry nicht ladbar (%s) – Hersteller bleiben unbekannt", type(exc).__name__)
        stale = self._read_cache() if age is not None else None
        if stale:
            self._source = "stale-cache"
            return stale
        self._source = "none"
        return {}

    def mapping(self) -> dict[str, str]:
        with self._lock:
            if self._map is None:
                self._map = self._load()
            return self._map

    def organization(self, mac: str) -> str | None:
        m = safe_mac(mac)
        if not m or is_locally_administered(m):
            return None
        return self.mapping().get(m.replace(":", "")[:6])

    def vendor(self, mac: str) -> str | None:
        return short_vendor(self.organization(mac))
