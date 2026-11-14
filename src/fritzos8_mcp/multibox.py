"""Overview and comparison across several FRITZ!Boxes in one server instance."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from .errors import FritzError, InvalidParameterError

if TYPE_CHECKING:
    from .service import FritzService

ASPECTS = ("dns", "security", "firmware", "wlan", "system", "wan")


def _try(fn: Callable[[], Any]) -> Any:
    try:
        return fn()
    except FritzError as exc:
        return {"_error": exc.to_dict()}


def _ok(value: Any) -> bool:
    return not (isinstance(value, dict) and "_error" in value)


def overview(services: Mapping[str, FritzService]) -> dict[str, Any]:
    boxes = []
    for name, svc in services.items():
        info = _try(svc.tr064.system_info)
        fw = _try(svc.diag.firmware_status)
        wan = _try(svc.tr064.wan_connection_status)
        sec = _try(svc.security_check)
        entry: dict[str, Any] = {
            "box": name,
            "host": svc.box_host,
            "reachable": _ok(info),
            "model": info.get("model") if _ok(info) else None,
            "firmware": info.get("software_version") if _ok(info) else None,
            "update_available": fw.get("update_available") if _ok(fw) else None,
            "online": (wan.get("status") == "Connected") if _ok(wan) else None,
        }
        if _ok(sec):
            entry["security"] = {
                "overall": sec.get("overall"),
                "score": sec.get("score"),
                "warnings": [c["check"] for c in sec.get("checks", []) if c.get("status") == "warn"],
            }
        else:
            entry["security"] = {"overall": "unknown", "error": sec["_error"]}
        errors = {k: v["_error"] for k, v in (("system", info), ("firmware", fw), ("wan", wan)) if not _ok(v)}
        if errors:
            entry["errors"] = errors
        boxes.append(entry)
    return {"count": len(boxes), "boxes": boxes}


def _aspect(svc: FritzService, aspect: str) -> Any:
    if aspect == "dns":
        d = svc.dns.settings()
        web = d.get("web_settings") or {}
        return {
            "lan_dhcp_dns": (d.get("lan_dhcp") or {}).get("dns_servers"),
            "internet_ipv4": web.get("internet_ipv4"),
            "internet_ipv6": web.get("internet_ipv6"),
            "dns_over_tls": web.get("dns_over_tls"),
            "home_ipv6_dns": web.get("home_ipv6_dns"),
        }
    if aspect == "security":
        sec = svc.security_check()
        return {
            "overall": sec.get("overall"),
            "score": sec.get("score"),
            **{c["check"]: c["status"] for c in sec["checks"]},
        }
    if aspect == "firmware":
        f = svc.diag.firmware_status()
        return {
            k: f.get(k) for k in ("model", "installed", "update_available", "available_version", "auto_update_mode")
        }
    if aspect == "wlan":
        return {
            n["service"]: {k: n.get(k) for k in ("ssid", "enabled", "band_ghz", "standard", "security", "guest")}
            for n in svc.wlan.networks()
        }
    if aspect == "system":
        i = svc.tr064.system_info()
        return {k: i.get(k) for k in ("model", "software_version", "hardware_version")}
    w = svc.tr064.wan_status()
    return {
        "access_type": (w.get("link") or {}).get("access_type"),
        "status": w["connection"].get("status"),
        "public_ipv4": bool(w.get("external_ipv4")),
        "ipv6": bool(w.get("external_ipv6")),
    }


def _flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            out.update(_flatten(v, f"{prefix}.{k}" if prefix else str(k)))
        return out
    return {prefix: obj}


def compare(services: Mapping[str, FritzService], aspect: str) -> dict[str, Any]:
    if aspect not in ASPECTS:
        raise InvalidParameterError(f'Unbekannter Aspekt "{aspect}" – erlaubt: {", ".join(ASPECTS)}.')
    values: dict[str, Any] = {}
    for name, svc in services.items():

        def read(svc: FritzService = svc) -> Any:
            return _aspect(svc, aspect)

        values[name] = _try(read)
    flat = {name: _flatten(v) for name, v in values.items() if _ok(v)}
    keys = sorted({k for f in flat.values() for k in f})
    differences = {
        k: {name: f.get(k) for name, f in flat.items()}
        for k in keys
        if len({repr(f.get(k)) for f in flat.values()}) > 1
    }
    return {
        "aspect": aspect,
        "boxes": values,
        "differences": differences,
        "identical": not differences and len(flat) == len(values),
        "note": "Bei nur einer konfigurierten Box gibt es nichts zu vergleichen." if len(values) < 2 else None,
    }
