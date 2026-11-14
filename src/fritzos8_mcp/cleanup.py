"""Clean-up assistant for the device list (read-only analysis; writing happens via plan/execute).

Inputs: the ``/api/v0`` landevice entries (raw, all fields) and the TR-064 host list. Output:
delete candidates and rename suggestions, each with reasons. Hard rules – never proposed:
the FRITZ!Box itself, entries the box marks as not deletable, devices that are active/online
(per landevice OR per TR-064), VPN peers (entry IP inside the remote networks of a ``/api/v0/generic/vpn``
connection), AVM devices and mesh nodes (AVM OUI, the locally administered variant of an AVM OUI, a name
starting with "FRITZ!" or a node of the mesh list). Entries without a MAC are only proposed when the VPN list
could be checked, they belong to no VPN connection and they are offline. AVM devices get no rename suggestions.

Live findings 14.11.2026 (box with 98 devices): the same IP on two entries is never a reason to delete (DHCP hands
out addresses again) – only info in ``duplicates``. A name duplicate is only a delete reason for entries with a
random (locally administered) MAC, and the entry that is online / was seen last is kept. Entries with a globally
unique vendor MAC are only proposed when "last seen" is known and at least ``offline_days`` old. Names with ``--``
inside a word are remains of a lost umlaut and get no rename suggestion; registry names that are only places or
legal forms ("China") are no vendor.

"Last seen": the landevice answer is not documented. The analysis looks for a timestamp field
(``last_seen``/``lastused``/… or any ``*last*`` field holding a plausible Unix time) and reports
which field it used. If none is present, devices are only flagged as "currently offline" and
being offline alone is not a reason to delete.
"""

from __future__ import annotations

import ipaddress
import re
import time
import unicodedata
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .landevice import LanDevice
from .oui import OuiDb, avm_mac_kind, is_locally_administered
from .util import MAX_HOSTNAME_LENGTH, safe_mac

DEFAULT_OFFLINE_DAYS = 90

LAST_SEEN_KEYS = (
    "last_seen",
    "lastseen",
    "last_online",
    "lastonline",
    "last_used",
    "lastused",
    "last_connected",
    "last_activity",
    "offline_since",
)

_TRANSLIT = {"ä": "ae", "ö": "oe", "ü": "ue", "Ä": "Ae", "Ö": "Oe", "Ü": "Ue", "ß": "ss"}

# Names the box or the device made up – worth a better name.
_GENERIC_NAME = re.compile(
    r"^(|pc|pc-[\d-]+|android|android-[0-9a-f]+|unknown|unbekannt|unbenannt|esp|esp[-_][0-9a-f]+|espressif|"
    r"device|host|client|lwip\d*|dhcp|localhost|[0-9a-f]{12}|([0-9a-f]{2}[:-]){5}[0-9a-f]{2}|"
    r"(pc|host|client|device|geraet)[-_]?[0-9a-f-]+|\d+(-\d+){3})$",
    re.I,
)

# Device kinds recognisable from a name token → canonical spelling for "Hersteller-Modell".
_MODEL_HINTS = (
    "iPhone",
    "iPad",
    "MacBook",
    "iMac",
    "AppleTV",
    "Watch",
    "Galaxy",
    "Pixel",
    "Echo",
    "Kindle",
    "FireTV",
    "Chromecast",
    "Sonos",
    "Shelly",
    "Tasmota",
    "Hue",
    "Roborock",
    "Vacuum",
    "Printer",
    "Drucker",
    "TV",
    "NAS",
    "Repeater",
    "Camera",
    "Kamera",
    "Laptop",
    "Notebook",
    "Desktop",
    "Tablet",
    "Phone",
    "Switch",
    "Plug",
    "Steckdose",
    "Thermostat",
)


def normalize_name(name: str) -> str:
    """Only A–Z a–z 0–9 and '-'; umlauts transliterated; max. 63 characters."""
    text = "".join(_TRANSLIT.get(c, c) for c in (name or "").strip())
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"[\s_.,/:;+]+", "-", text)
    text = re.sub(r"[^A-Za-z0-9-]", "", text)
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return text[:MAX_HOSTNAME_LENGTH].rstrip("-")


def make_unique(name: str, taken: set[str]) -> str:
    """Append -2, -3, … if the (case-insensitive) name is already taken; registers the result."""
    lowered = {t.lower() for t in taken}
    candidate = name
    n = 2
    while candidate.lower() in lowered:
        suffix = f"-{n}"
        candidate = f"{name[: MAX_HOSTNAME_LENGTH - len(suffix)]}{suffix}"
        n += 1
    taken.add(candidate)
    return candidate


def is_generic_name(name: str, mac: str = "") -> bool:
    n = (name or "").strip()
    if _GENERIC_NAME.match(n):
        return True
    return bool(mac) and normalize_name(n).lower() == mac.replace(":", "").lower()


def model_hint(name: str) -> str | None:
    lowered = (name or "").lower().replace(" ", "").replace("-", "").replace("_", "")
    for hint in _MODEL_HINTS:
        if hint.lower() in lowered:
            return hint
    return None


def last_seen(raw: dict[str, Any], now: float) -> tuple[float | None, str | None]:
    """Find a 'last seen' Unix timestamp in an undocumented landevice entry."""
    keys = [k for k in LAST_SEEN_KEYS if k in raw] + [k for k in raw if "last" in k.lower() and k not in LAST_SEEN_KEYS]
    for key in keys:
        try:
            value = float(str(raw[key]).strip())
        except (TypeError, ValueError):
            continue
        if 1_000_000_000 <= value <= now + 86400:  # plausible Unix time (after 2001, not in the future)
            return value, key
    return None, None


# ------------------------------------------------------------------ protection rules (live finding 14.11.2026)


@dataclass
class ProtectionContext:
    """What the clean-up must never touch, besides the box's own flags.

    ``vpn_checked`` is False when the VPN list could not be read – then entries without a MAC are never proposed
    (they might be VPN peers)."""

    mesh_macs: set[str] = field(default_factory=set)
    vpn_networks: list[tuple[str, str]] = field(default_factory=list)  # (connection name, network/IP)
    vpn_names: set[str] = field(default_factory=set)
    vpn_checked: bool = False
    mesh_checked: bool = False


def mesh_node_macs(doc: dict[str, Any] | None) -> set[str]:
    """MACs of AVM mesh nodes (master/slave/meshed or AVM model) incl. their interface MACs."""
    out: set[str] = set()
    for n in (doc or {}).get("nodes") or []:
        if not isinstance(n, dict):
            continue
        infra = bool(n.get("is_meshed")) or str(n.get("mesh_role") or "").lower() in {"master", "slave"}
        avm_model = (
            str(n.get("device_model") or n.get("device_manufacturer") or "").upper().startswith(("FRITZ!", "AVM"))
        )
        if not (infra or avm_model):
            continue
        macs = [n.get("device_mac_address")] + [
            i.get("mac_address") for i in n.get("node_interfaces") or [] if isinstance(i, dict)
        ]
        out.update(m for m in (safe_mac(x) for x in macs) if m)
    return out


def vpn_context(vpn: dict[str, Any] | None) -> tuple[list[tuple[str, str]], set[str]]:
    nets: list[tuple[str, str]] = []
    names: set[str] = set()
    for c in (vpn or {}).get("connections") or []:
        name = str(c.get("name") or "VPN")
        names.add(name.strip().lower())
        for net in c.get("remote_networks") or []:
            nets.append((name, str(net)))
        if c.get("remote_ip"):
            nets.append((name, str(c["remote_ip"])))
    return nets, names


def _ip_in(ip: str, network: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.strip())
        net = ipaddress.ip_network(network.strip().split()[0], strict=False)
    except ValueError:
        return False
    return addr.version == net.version and addr in net


def vpn_peer(dev: LanDevice, ctx: ProtectionContext) -> str | None:
    if dev.ip:
        for name, net in ctx.vpn_networks:
            if _ip_in(dev.ip, net):
                return f"VPN-Gegenstelle (IP {dev.ip} liegt im entfernten Netz {net} der VPN-Verbindung „{name}“)"
    if dev.display_name.strip().lower() in ctx.vpn_names:
        return f"VPN-Gegenstelle (Name wie die VPN-Verbindung „{dev.display_name}“)"
    return None


def avm_device(dev: LanDevice, ctx: ProtectionContext, oui: OuiDb | None) -> str | None:
    mac = safe_mac(dev.mac)
    if mac and mac in ctx.mesh_macs:
        return "AVM-Gerät/Mesh-Knoten (steht in der Mesh-Liste)"
    kind = avm_mac_kind(mac, oui) if mac else None
    if kind == "avm":
        return "AVM-Gerät (MAC aus einem AVM-Adressblock)"
    if kind == "avm_local":
        return "AVM-Gerät (lokal administrierte Variante einer AVM-MAC, z. B. Powerline/Mesh) – keine Zufalls-MAC"
    if re.match(r"^\s*fritz\s*!", dev.display_name, re.I) or re.match(r"^\s*fritz\s*!", dev.name, re.I):
        return "AVM-Gerät (Name „FRITZ!…“)"
    return None


def protection_reason(
    dev: LanDevice, ctx: ProtectionContext, oui: OuiDb | None, *, recently_seen: bool = False
) -> str | None:
    """Reason why an entry must never be deleted (beyond the box flags and online state), else None."""
    vpn = vpn_peer(dev, ctx)
    if vpn:
        return vpn + " – VPN-Peers werden nie gelöscht"
    avm = avm_device(dev, ctx, oui)
    if avm:
        return avm + " – AVM-Geräte werden nie gelöscht"
    if not safe_mac(dev.mac):
        if not ctx.vpn_checked:
            return "Eintrag ohne MAC und VPN-Liste nicht lesbar – könnte eine VPN-Gegenstelle sein"
        if recently_seen:
            return "Eintrag ohne MAC, heute noch gesehen – nur offline Einträge ohne MAC werden vorgeschlagen"
    return None


# ------------------------------------------------------------------ delete rules shared by report and plan

# FRITZ!OS default access profile ("Standard") – not worth a warning.
_DEFAULT_PROFILES = {"", "0", "none", "null", "filtprof1"}

# "--" between letters: the box replaced an umlaut by two dashes ("K--chen-Wand" from "Küchen-Wand").
_LOST_UMLAUT = re.compile(r"[A-Za-z]--[a-z]")


def offline_days_of(raw: dict[str, Any], now: float) -> int | None:
    ts, _ = last_seen(raw, now)
    return None if ts is None else int((now - ts) // 86400)


def has_global_mac(dev: LanDevice) -> bool:
    """Globally unique (OUI) MAC: valid and not locally administered."""
    return bool(safe_mac(dev.mac)) and not is_locally_administered(dev.mac)


def access_profile(raw: dict[str, Any] | None) -> tuple[str, str] | None:
    """(field, value) of a non-default parental-control profile in an (undocumented) landevice entry."""
    for key, value in (raw or {}).items():
        lk = key.lower()
        # Nur echte Profil-Felder: live (FRITZ!OS 8.25/8.26) gibt es z. B. `kisi_state_hide` – ein Anzeige-Flag,
        # kein Profil; ein Treffer auf bloßes "kisi" erzeugte bei jedem Eintrag eine falsche Warnung.
        if "profile" in lk and not isinstance(value, dict | list):
            text = str(value or "").strip()
            if text.lower() not in _DEFAULT_PROFILES:
                return key, text
    return None


def loss_note(dev: LanDevice, raw: dict[str, Any] | None) -> str | None:
    """What deleting the entry loses beyond the entry itself (fixed IP, access profile)."""
    parts: list[str] = []
    if dev.static_dhcp:
        parts.append(f"die feste IP-Zuweisung ({dev.ip or 'ohne IP'})")
    prof = access_profile(raw)
    if prof:
        parts.append(f"das Kindersicherungsprofil ({prof[0]}={prof[1]})")
    if not parts:
        return None
    return "Achtung: Löschen entfernt auch " + " und ".join(parts) + " sowie den Namen"


def age_block(dev: LanDevice, days: int | None, offline_days: int) -> str | None:
    """Entries with a globally unique vendor MAC are only deleted when 'last seen' is known and old enough."""
    if not has_global_mac(dev):
        return None
    if days is None:
        return (
            "global eindeutige Hersteller-MAC und 'zuletzt online' unbekannt – solche Einträge werden nur nach "
            f"mindestens {offline_days} Tagen offline vorgeschlagen (feste IP, Name und Profil gingen verloren)"
        )
    if days < offline_days:
        return (
            f"global eindeutige Hersteller-MAC, zuletzt vor {days} Tagen online (Grenze {offline_days}) – "
            "noch kein Löschgrund"
        )
    return None


def _keeper(group: list[LanDevice], days: dict[str, int | None], online: set[str]) -> LanDevice:
    """Entry of a duplicate group to keep: online, else seen last, else fixed IP, else with a friendly name."""
    hits = [d for d in group if d.uid in online]
    if hits:
        return hits[0]
    known = [d for d in group if days.get(d.uid) is not None]
    if known:
        return min(known, key=lambda d: days[d.uid] or 0)
    for pred in (lambda d: d.static_dhcp, lambda d: bool(d.friendly_name)):
        hits = [d for d in group if pred(d)]
        if hits:
            return hits[0]
    return group[0]


def name_duplicates(
    devices: list[LanDevice], days: dict[str, int | None], online: set[str]
) -> list[tuple[str, list[LanDevice], LanDevice]]:
    """Groups of entries with the same display name: (name, entries, entry to keep)."""
    groups: dict[str, list[LanDevice]] = defaultdict(list)
    for d in devices:
        key = d.display_name.strip().lower()
        if key and key != d.mac.lower():
            groups[key].append(d)
    return [(k, g, _keeper(g, days, online)) for k, g in groups.items() if len(g) >= 2]


def duplicate_keeper_block(
    dev: LanDevice, devices: list[LanDevice], days: dict[str, int | None], online: set[str]
) -> str | None:
    """A random-MAC entry that is the newest of its name duplicates is kept (its older copies go)."""
    if has_global_mac(dev) or not safe_mac(dev.mac):
        return None
    for _name, group, keep in name_duplicates(devices, days, online):
        others = [d for d in group if d.uid != dev.uid and is_locally_administered(d.mac)]
        if keep.uid == dev.uid and others:
            return (
                f"neuester Eintrag der Duplikatgruppe „{dev.display_name}“ (zufällige MAC) – wird behalten, "
                f"vorgeschlagen werden die älteren ({', '.join(d.uid for d in others)})"
            )
    return None


def analyze(
    raw_entries: Iterable[dict[str, Any]],
    hosts: Iterable[dict[str, Any]],
    oui: OuiDb | None,
    *,
    box_ips: set[str] | None = None,
    offline_days: int = DEFAULT_OFFLINE_DAYS,
    now: float | None = None,
    context: ProtectionContext | None = None,
) -> dict[str, Any]:
    t = time.time() if now is None else now
    ctx = context or ProtectionContext()
    raws = list(raw_entries)
    devices = [LanDevice.from_raw(r) for r in raws]
    box_ips = box_ips or set()
    active_by_tr064 = {safe_mac(h.get("mac")) for h in hosts if h.get("active") and safe_mac(h.get("mac"))}
    seen_field: str | None = None

    info: dict[str, dict[str, Any]] = {}
    online_uids: set[str] = set()
    for raw, d in zip(raws, devices, strict=True):
        ts, key = last_seen(raw, t)
        if key:
            seen_field = seen_field or key
        days = None if ts is None else int((t - ts) // 86400)
        online = d.active or d.online or bool(d.mac and d.mac in active_by_tr064)
        if online:
            online_uids.add(d.uid)
        protected = None
        if not d.deleteable:
            protected = "von der FRITZ!Box als nicht löschbar markiert (z. B. die Box selbst)"
        elif d.ip and d.ip in box_ips:
            protected = "die FRITZ!Box selbst"
        elif online:
            protected = "aktiv/online"
        else:
            protected = protection_reason(d, ctx, oui, recently_seen=days == 0)
        avm = avm_device(d, ctx, oui) is not None
        info[d.uid] = {
            "device": d,
            "raw": raw,
            "avm": avm,
            "online": online,
            # LA variants of AVM OUIs are AVM interface addresses, not privacy/random MACs
            "random_mac": is_locally_administered(d.mac) and not avm,
            "last_seen": ts,
            "offline_days": days,
            "protected": protected,
        }
    days_by_uid = {uid: i["offline_days"] for uid, i in info.items()}

    reasons: dict[str, list[str]] = defaultdict(list)

    def flag(uid: str, reason: str) -> None:
        if reason not in reasons[uid]:
            reasons[uid].append(reason)

    for uid, i in info.items():
        dev: LanDevice = i["device"]
        if i["random_mac"]:
            flag(uid, "zufällige/private MAC (lokal administriert) – der Eintrag entsteht bei jedem Adresswechsel neu")
        if not safe_mac(dev.mac):
            flag(uid, "Eintrag ohne gültige MAC-Adresse")
        if i["offline_days"] is not None and i["offline_days"] >= offline_days:
            flag(uid, f"seit {i['offline_days']} Tagen nicht mehr online (Grenze {offline_days})")
        # only for devices that really are offline (live finding: was shown for online devices with a fixed IP)
        if dev.static_dhcp and not i["online"] and (i["random_mac"] or (i["offline_days"] or 0) >= offline_days):
            flag(uid, f"verwaiste feste IP-Zuweisung ({dev.ip or 'ohne IP'}) an einem offline/zufälligen Gerät")

    # duplicates. Same IP: info only – DHCP hands addresses out again, an offline device whose former IP another
    # device has now is no duplicate. Same name: only entries with a random MAC are proposed (the device shows up
    # again with a new private MAC); the entry that is online / was seen last is kept.
    duplicates: list[dict[str, Any]] = []
    for name, group, keep in name_duplicates(devices, days_by_uid, online_uids):
        proposed = [d for d in group if d.uid != keep.uid and info[d.uid]["random_mac"]]
        for d in proposed:
            flag(d.uid, f"Duplikat (gleiche Bezeichnung wie {keep.uid}, zufällige MAC – Gerät mit neuer Privat-MAC)")
        if proposed and info[keep.uid]["random_mac"] and not info[keep.uid]["protected"]:
            info[keep.uid]["protected"] = duplicate_keeper_block(keep, devices, days_by_uid, online_uids)
        duplicates.append(
            {
                "by": "name",
                "value": name,
                "keep": keep.uid,
                "severity": "delete_candidates" if proposed else "info",
                **(
                    {}
                    if proposed
                    else {"note": "Kein Löschgrund: gleiche Bezeichnung, aber global eindeutige Hersteller-MACs."}
                ),
                "entries": [{"uid": d.uid, "mac": d.mac, "name": d.display_name, "online": d.online} for d in group],
            }
        )
    by_ip: dict[str, list[LanDevice]] = defaultdict(list)
    for d in devices:
        if d.ip:
            by_ip[d.ip].append(d)
    for ip, group in by_ip.items():
        if len(group) < 2:
            continue
        duplicates.append(
            {
                "by": "ip",
                "value": ip,
                "severity": "info",
                "note": "Nur Hinweis, kein Löschgrund: DHCP vergibt IP-Adressen neu.",
                "entries": [{"uid": d.uid, "mac": d.mac, "name": d.display_name, "online": d.online} for d in group],
            }
        )

    # globally unique vendor MAC: never deleted on an unknown or too young 'last seen'
    for uid in reasons:
        i = info[uid]
        if not i["protected"]:
            i["protected"] = age_block(i["device"], i["offline_days"], offline_days)

    delete_candidates: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for uid, rs in reasons.items():
        i = info[uid]
        d = i["device"]
        entry = {
            "uid": d.uid,
            "mac": d.mac,
            "name": d.display_name,
            "ip": d.ip or None,
            "static_dhcp": d.static_dhcp,
            "last_seen_days": i["offline_days"],
            "reasons": rs,
        }
        if i["protected"]:
            skipped.append({**entry, "not_proposed_because": i["protected"]})
        else:
            note = loss_note(d, i["raw"])
            if note:
                entry["reasons"] = [*rs, note]
            delete_candidates.append({**entry, "action": "delete"})

    offline_unknown_age = [
        {"uid": i["device"].uid, "mac": i["device"].mac, "name": i["device"].display_name}
        for i in info.values()
        if not i["protected"] and i["last_seen"] is None and i["device"].uid not in reasons
    ]

    # rename suggestions
    taken = {d.display_name for d in devices if d.display_name}
    renames: list[dict[str, Any]] = []
    rename_skipped: list[dict[str, Any]] = []
    candidate_uids = {c["uid"] for c in delete_candidates}
    for d in devices:
        if not d.deleteable or d.uid in candidate_uids or not safe_mac(d.mac) or info[d.uid]["avm"]:
            continue  # AVM devices keep their names (e.g. "FRITZ!Powerline 510E")
        current = d.display_name
        organization = oui.organization(d.mac) if oui else None
        vendor = oui.vendor(d.mac) if oui else None
        why: str | None = None
        base: str | None = None
        skip: str | None = None
        if _LOST_UMLAUT.search(current):
            skip = (
                "„--“ im Wort ist der Rest eines verlorenen Umlauts – ursprünglicher Umlaut nicht rekonstruierbar, "
                "bitte von Hand benennen"
            )
        elif is_generic_name(current, d.mac) and organization and not vendor:
            skip = f"Hersteller laut OUI-Register nicht verwertbar („{organization}“ – nur Ort/Rechtsform)"
        if skip:
            rename_skipped.append({"uid": d.uid, "mac": d.mac, "current": current, "reason": skip})
            continue
        if is_generic_name(current, d.mac):
            hint = model_hint(current) or "Geraet"
            base = normalize_name(f"{vendor or 'Unbekannt'}-{hint}")
            why = "nichtssagender Name" + (f"; Hersteller laut MAC: {vendor}" if vendor else "; Hersteller unbekannt")
        elif normalize_name(current) != current:
            base = normalize_name(current)
            why = "Name enthält Zeichen außerhalb A–Z a–z 0–9 - (Umlaute/Leerzeichen/Sonderzeichen)"
        if not base or not why:
            continue
        taken.discard(current)
        suggestion = make_unique(base, taken)
        if suggestion == current:
            continue
        renames.append(
            {
                "uid": d.uid,
                "mac": d.mac,
                "current": current,
                "suggested": suggestion,
                "vendor": vendor or ("random" if is_locally_administered(d.mac) else "unknown"),
                "reason": why,
                "action": "rename",
            }
        )

    return {
        "devices_total": len(devices),
        "delete_candidates": delete_candidates,
        "rename_suggestions": renames,
        "rename_not_proposed": rename_skipped,
        "duplicates": duplicates,
        "offline_age_unknown": offline_unknown_age,
        "not_proposed": skipped,
        "last_seen_field": seen_field,
        "offline_days_threshold": offline_days,
        "vendor_source": oui.source if oui else "none",
        "protection": {
            "vpn_list_checked": ctx.vpn_checked,
            "mesh_list_checked": ctx.mesh_checked,
            "rules": "nie vorgeschlagen: Box selbst, nicht löschbare, aktive/online Einträge, VPN-Gegenstellen, "
            "AVM-Geräte/Mesh-Knoten (auch lokal administrierte AVM-MACs); ohne MAC nur offline und ohne VPN-Bezug; "
            "global eindeutige Hersteller-MACs nur bei bekanntem 'zuletzt online' ab der Grenze; gleiche IP ist nie "
            "ein Löschgrund, gleiche Bezeichnung nur bei zufälliger MAC (der neueste Eintrag bleibt)",
        },
        "naming_scheme": "Typ-Raum (z. B. Drucker-Buero) oder Hersteller-Modell (z. B. Apple-iPhone); "
        "nur A–Z a–z 0–9 -",
        "note": (
            "Nur Vorschläge – nichts wurde geändert. Auswahl per devices_cleanup_plan übernehmen. "
            + (
                f"'Zuletzt online' aus Feld '{seen_field}'."
                if seen_field
                else "Die Box liefert kein 'zuletzt online'-Feld: Offline-Geräte stehen nur in "
                "offline_age_unknown und werden allein deshalb nicht zum Löschen vorgeschlagen."
            )
        ),
    }
