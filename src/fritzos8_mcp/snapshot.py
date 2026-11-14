"""Configuration snapshots (local JSON files) and a structured change comparison.

A snapshot collects readable *settings* – no measurements or counters (uptime, temperatures,
client counts, current IPs of dynamic devices, auto-selected WLAN channels). It is redacted
before it is written and never contains keys, passwords or session ids.

Storage: ``<state>/<box-host>/snapshots/<UTC time>.json`` with ``<state>`` =
``~/.local/state/fritzos8-mcp`` (``FRITZ_STATE_DIR``/``XDG_STATE_HOME``); directories 0700,
files 0600. Retention: the newest ``FRITZ_SNAPSHOT_KEEP`` (default 30) per box.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .errors import AuthError, ConfirmationRequiredError, FritzError, InvalidParameterError, NotFoundError
from .paths import ensure_private_dir, safe_component, write_private
from .redact import is_secret_field, redact_obj

if TYPE_CHECKING:
    from .service import FritzService

SCHEMA = 1
DEFAULT_KEEP = 30
MAX_HOSTFILTER_LOOKUPS = 256
MAX_SUMMARY_LINES = 60
_ID = re.compile(r"^\d{8}T\d{6}Z(-\d+)?$")

# Never treated as a change, even if an older snapshot contains them.
VOLATILE_KEYS = frozenset(
    {
        "uptime_s",
        "uptime",
        "clients",
        "temperature_c",
        "humidity_pct",
        "power",
        "energy_wh",
        "time_remaining_min",
        "last_seen",
        "active",
        "online",
        "channel",
        "external_ipv4",
        "external_ipv6",
    }
)

KEYED = ("landevices", "static_ips", "port_forwards", "wlan", "smarthome", "internet_blocks", "security")
FLAT = ("system", "firmware", "wan", "dns")


# ------------------------------------------------------------------ collection


def _strip_secrets(obj: Any) -> Any:
    """Drop (not only mask) fields whose names look like secrets."""
    if isinstance(obj, dict):
        return {k: _strip_secrets(v) for k, v in obj.items() if not (isinstance(k, str) and is_secret_field(k))}
    if isinstance(obj, list):
        return [_strip_secrets(v) for v in obj]
    return obj


def _section(fn: Callable[[], Any]) -> Any:
    try:
        return fn()
    except (AuthError, ConfirmationRequiredError):
        raise
    except FritzError as exc:
        return {"_error": exc.to_dict()}


def _pick(d: dict[str, Any], keys: Iterable[str]) -> dict[str, Any]:
    return {k: d.get(k) for k in keys}


def collect(svc: FritzService) -> dict[str, Any]:
    """Read all settings that make up a snapshot. Each section fails independently."""

    def system() -> dict[str, Any]:
        return _pick(svc.tr064.system_info(), ("model", "software_version", "hardware_version", "manufacturer"))

    def firmware() -> dict[str, Any]:
        f = svc.diag.firmware_status()
        return _pick(f, ("installed", "update_available", "available_version", "auto_update_mode"))

    def wan() -> dict[str, Any]:
        w = svc.tr064.wan_status()
        return {
            "service": w.get("connection", {}).get("service"),
            "access_type": (w.get("link") or {}).get("access_type"),
            "public_ipv4": bool(w.get("external_ipv4")),
        }

    def dns() -> dict[str, Any]:
        d = svc.dns.settings()
        web = d.get("web_settings") or {}
        web = {
            k: v for k, v in web.items() if k not in {"fields_present", "fields_missing", "note", "verified_endpoint"}
        }
        return {"lan_dhcp_dns": (d.get("lan_dhcp") or {}).get("dns_servers"), "web_settings": web}

    def wlan() -> dict[str, Any]:
        out: dict[str, Any] = {}
        for n in svc.wlan.networks():
            entry = _pick(n, ("ssid", "enabled", "band_ghz", "standard", "security", "encrypted", "guest"))
            extra = n.get("guest_extra") or {}
            if extra:
                entry["guest_extra"] = _pick(
                    extra, ("timeout_active", "timeout_min", "user_isolation", "no_forced_off")
                )
            out[str(n["service"])] = entry
        return out

    def port_forwards() -> dict[str, Any]:
        return {
            f"{m.get('protocol')}/{m.get('external_port')}": _pick(
                m, ("internal_client", "internal_port", "enabled", "description")
            )
            for m in svc.diag.port_mappings()
        }

    def security() -> dict[str, Any]:
        report = svc.security_check()
        out: dict[str, Any] = {}
        for c in report.get("checks", []):
            if c["check"] in {"portfreigaben", "firmware"}:  # covered by own sections
                out[c["check"]] = {"status": c["status"]}
                continue
            details = {k: v for k, v in (c.get("details") or {}).items() if k not in VOLATILE_KEYS}
            out[c["check"]] = {"status": c["status"], "details": details}
        return out

    landevices_cache: list[Any] = []

    def devices() -> list[Any]:
        if not landevices_cache:
            landevices_cache.extend(svc.landevices.list())
        return landevices_cache

    def landevices() -> dict[str, Any]:
        out: dict[str, Any] = {}
        macs = [d.mac for d in devices()]
        for d in devices():
            key = d.mac if d.mac and macs.count(d.mac) == 1 else f"{d.mac or 'ohne-mac'}#{d.uid}"
            entry: dict[str, Any] = {"name": d.name, "friendly_name": d.friendly_name, "static_dhcp": d.static_dhcp}
            if d.static_dhcp:
                entry["ip"] = d.ip
            out[key] = entry
        return out

    def static_ips() -> dict[str, Any]:
        return {d.mac or d.uid: {"name": d.display_name, "ip": d.ip} for d in devices() if d.static_dhcp}

    def internet_blocks() -> dict[str, Any]:
        out: dict[str, Any] = {}
        hosts = [h for h in svc.resolver.hosts() if h.ip][:MAX_HOSTFILTER_LOOKUPS]
        for h in hosts:
            r = svc.tr064.try_call("X_AVM-DE_HostFilter1", "GetWANAccessByIP", NewIPv4Address=h.ip)
            if r is None:
                if not out:  # service missing altogether
                    raise NotFoundError("X_AVM-DE_HostFilter1 nicht verfügbar.")
                continue
            if str(r.get("NewDisallow") or "0").strip() in {"1", "true"}:
                out[h.mac or h.ip] = {"name": h.name, "ip": h.ip}
        return out

    def smarthome() -> dict[str, Any]:
        return {
            str(d["ain"]): _pick(d, ("name", "kind", "product", "type", "functions", "firmware"))
            for d in svc.smarthome.list_devices()
        }

    sections = {
        "system": _section(system),
        "firmware": _section(firmware),
        "wan": _section(wan),
        "dns": _section(dns),
        "wlan": _section(wlan),
        "port_forwards": _section(port_forwards),
        "security": _section(security),
        "landevices": _section(landevices),
        "static_ips": _section(static_ips),
        "internet_blocks": _section(internet_blocks),
        "smarthome": _section(smarthome),
    }
    return sections


def build(svc: FritzService, label: str | None, secrets: Iterable[str] = ()) -> dict[str, Any]:
    snap = {
        "schema": SCHEMA,
        "created": datetime.now(UTC).isoformat(timespec="seconds"),
        "label": (label or "").strip()[:100] or None,
        "box": svc.box_host,
        "sections": collect(svc),
    }
    # Redaction BEFORE anything is written: drop secret-named fields, mask known secrets/SIDs.
    return redact_obj(_strip_secrets(snap), list(secrets))  # type: ignore[no-any-return]


# ------------------------------------------------------------------ storage


class SnapshotStore:
    def __init__(self, root: Path, box_host: str, keep: int = DEFAULT_KEEP, now: Callable[[], float] = time.time):
        self.dir = root / safe_component(box_host) / "snapshots"
        self.keep = max(1, keep)
        self._now = now

    def _path(self, snap_id: str) -> Path:
        if not _ID.match(snap_id or ""):
            raise InvalidParameterError(f'Ungültige Schnappschuss-ID "{snap_id}" – siehe snapshot_list.')
        return self.dir / f"{snap_id}.json"

    def ids(self) -> list[str]:
        if not self.dir.is_dir():
            return []
        return sorted(p.stem for p in self.dir.glob("*.json") if _ID.match(p.stem))

    def save(self, snap: dict[str, Any]) -> str:
        ensure_private_dir(self.dir.parent.parent)
        ensure_private_dir(self.dir.parent)
        ensure_private_dir(self.dir)
        base = datetime.fromtimestamp(self._now(), UTC).strftime("%Y%m%dT%H%M%SZ")
        snap_id, n = base, 2
        while (self.dir / f"{snap_id}.json").exists():
            snap_id, n = f"{base}-{n}", n + 1
        write_private(self.dir / f"{snap_id}.json", json.dumps(snap, ensure_ascii=False, indent=1).encode("utf-8"))
        self.prune()
        return snap_id

    def prune(self) -> list[str]:
        ids = self.ids()
        removed = ids[: max(0, len(ids) - self.keep)]
        for snap_id in removed:
            (self.dir / f"{snap_id}.json").unlink(missing_ok=True)
        return removed

    def load(self, snap_id: str) -> dict[str, Any]:
        path = self._path(snap_id)
        try:
            data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise NotFoundError(f"Schnappschuss {snap_id} nicht gefunden – siehe snapshot_list.") from None
        except (OSError, ValueError):
            raise FritzError(f"Schnappschuss {snap_id} ist nicht lesbar.") from None
        return data

    def latest(self) -> str | None:
        ids = self.ids()
        return ids[-1] if ids else None

    def listing(self) -> list[dict[str, Any]]:
        out = []
        for snap_id in reversed(self.ids()):
            try:
                data = self.load(snap_id)
                out.append({"id": snap_id, "created": data.get("created"), "label": data.get("label")})
            except FritzError:
                out.append({"id": snap_id, "created": None, "label": None, "error": "nicht lesbar"})
        return out


# ------------------------------------------------------------------ diff


def _flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if k in VOLATILE_KEYS:
                continue
            out.update(_flatten(v, f"{prefix}.{k}" if prefix else str(k)))
        return out
    return {prefix: obj}


def _field_changes(a: Any, b: Any) -> list[dict[str, Any]]:
    fa, fb = _flatten(a), _flatten(b)
    return [
        {"field": k, "before": fa.get(k), "after": fb.get(k)}
        for k in sorted(set(fa) | set(fb))
        if fa.get(k) != fb.get(k)
    ]


def _fmt(v: Any) -> str:
    if v is None or v == "":
        return "–"
    if isinstance(v, list):
        return ", ".join(str(x) for x in v) or "–"
    return str(v)


def _describe(category: str, kind: str, key: str, before: Any, after: Any, changes: list[dict[str, Any]]) -> str:
    item = after if kind == "neu" else before
    item = item if isinstance(item, dict) else {}
    if category == "port_forwards":
        target = f"{item.get('internal_client')}:{item.get('internal_port')}"
        if kind == "neu":
            return f"neue Portfreigabe {key} → {target}"
        if kind == "entfernt":
            return f"Portfreigabe {key} → {target} entfernt"
        return f"Portfreigabe {key} geändert ({', '.join(c['field'] for c in changes)})"
    if category == "landevices":
        name = item.get("friendly_name") or item.get("name") or "ohne Namen"
        if kind == "neu":
            return f"unbekanntes/neues Gerät {name} ({key})"
        if kind == "entfernt":
            return f"Gerät {name} ({key}) nicht mehr in der Liste"
        return f"Gerät {key}: " + "; ".join(f"{c['field']} {_fmt(c['before'])} → {_fmt(c['after'])}" for c in changes)
    if category == "static_ips":
        verb = {"neu": "neue feste IP", "entfernt": "feste IP aufgehoben", "geändert": "feste IP geändert"}[kind]
        return f"{verb}: {item.get('name') or key} {item.get('ip') or ''}".strip()
    if category == "internet_blocks":
        verb = {"neu": "Internet gesperrt", "entfernt": "Internetsperre aufgehoben", "geändert": "Sperre geändert"}[
            kind
        ]
        return f"{verb}: {item.get('name') or key}"
    if category == "smarthome":
        verb = {"neu": "neues Smart-Home-Gerät", "entfernt": "Smart-Home-Gerät entfernt", "geändert": "geändert"}[kind]
        return f"{verb}: {item.get('name') or key} ({key})"
    if category == "security" and kind == "geändert":
        parts = [f"{c['field']} {_fmt(c['before'])} → {_fmt(c['after'])}" for c in changes]
        return f"Sicherheit {key}: " + "; ".join(parts)
    if category == "wlan" and kind == "geändert":
        parts = [f"{c['field']} {_fmt(c['before'])} → {_fmt(c['after'])}" for c in changes]
        return f"WLAN {key}: " + "; ".join(parts)
    return f"{category} {key} {kind}"


def _flat_line(category: str, change: dict[str, Any]) -> str:
    field = change["field"]
    if category == "dns":
        label = "DNSv6" if "ipv6" in field.lower() else "DNS"
        return f"{label} geändert: {field} {_fmt(change['before'])} → {_fmt(change['after'])}"
    if category == "firmware" and field == "installed":
        return f"FRITZ!OS aktualisiert: {_fmt(change['before'])} → {_fmt(change['after'])}"
    return f"{category} geändert: {field} {_fmt(change['before'])} → {_fmt(change['after'])}"


def diff(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    sa, sb = a.get("sections") or {}, b.get("sections") or {}
    result: dict[str, Any] = {"changed": {}, "added": {}, "removed": {}, "not_comparable": []}
    lines: list[str] = []
    for category in KEYED + FLAT:
        ca, cb = sa.get(category), sb.get(category)
        if ca is None and cb is None:
            continue
        if not isinstance(ca, dict) or not isinstance(cb, dict) or "_error" in ca or "_error" in cb:
            result["not_comparable"].append(category)
            continue
        if category in FLAT:
            changes = _field_changes(ca, cb)
            if changes:
                result["changed"][category] = changes
                lines.extend(_flat_line(category, c) for c in changes)
            continue
        added = {k: cb[k] for k in sorted(set(cb) - set(ca))}
        removed = {k: ca[k] for k in sorted(set(ca) - set(cb))}
        changed = {}
        for k in sorted(set(ca) & set(cb)):
            ch = _field_changes(ca[k], cb[k])
            if ch:
                changed[k] = ch
        if added:
            result["added"][category] = added
            lines.extend(_describe(category, "neu", k, None, v, []) for k, v in added.items())
        if removed:
            result["removed"][category] = removed
            lines.extend(_describe(category, "entfernt", k, v, None, []) for k, v in removed.items())
        if changed:
            result["changed"][category] = changed
            lines.extend(_describe(category, "geändert", k, ca[k], cb[k], ch) for k, ch in changed.items())
    total = len(lines)
    result["summary"] = lines[:MAX_SUMMARY_LINES]
    if total > MAX_SUMMARY_LINES:
        result["summary"].append(f"… und {total - MAX_SUMMARY_LINES} weitere Änderungen (siehe Details)")
    result["change_count"] = total
    result["ignored"] = sorted(VOLATILE_KEYS)
    return result
