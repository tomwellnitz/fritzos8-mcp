"""Stage 8.6 – "FRITZ as Code": a desired state per box as YAML, drift detection against the live box and a plan →
token → execute path that applies only the supported keys through the existing write tools (each with read-back).

Desired state (version 1) – every key is optional, only listed values are checked::

    version: 1
    guest_wifi: false                    # Gast-WLAN an/aus
    wlan_channels: {"2.4": 0, "5": 36}   # 0 = automatische Kanalwahl
    lan_eee: {all: off}                  # Port-Label oder "all" → auto/off
    static_ip: {"AA:BB:CC:DD:EE:01": true}
    internet_access: {"AA:BB:CC:DD:EE:02": false}   # false = gesperrt
    parental_profile: {"AA:BB:CC:DD:EE:02": filtprof3}
    tam: {0: true}                       # Anrufbeantworter je Index
    dns_dhcp: ["192.0.2.53"]             # nur Vergleich (DNS schreiben ist nicht gebaut, Stufe 7.2)
    port_forwards:                       # nur Vergleich (Portfreigaben haben eigene critical-Tools)
      - {protocol: TCP, external_port: 443, internal_port: 443, ip: 192.0.2.10}

Specs come inline (``spec``) or as a file name inside ``FRITZ_CODE_DIR`` (default ``<state dir>/desired``) – no
arbitrary paths. ``yaml.safe_load`` only. Applying is critical (plan/execute + elicitation): the plan binds the exact
action list server-side; execute re-checks every action (already in the desired state → ``unchanged``) and never
stops at the first error. The box itself and this server's machine stay protected by the write tools themselves.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import yaml
from pydantic import Field

from .errors import AuthError, ConfirmationRequiredError, FritzError, InvalidParameterError
from .nasremote import ToolDecorator
from .paths import ensure_private_dir, state_dir, write_private
from .security import Tier
from .toolargs import DESTRUCTIVE, READ, BoxArg, TokenArg
from .util import normalize_mac, safe_mac
from .wlan import normalize_band

if TYPE_CHECKING:
    from .service import FritzService

SUPPORTED_KEYS = (
    "version",
    "box",
    "guest_wifi",
    "wlan_channels",
    "lan_eee",
    "static_ip",
    "internet_access",
    "parental_profile",
    "tam",
    "dns_dhcp",
    "port_forwards",
)
COMPARE_ONLY = {"dns_dhcp": "DNS schreiben ist nicht gebaut (Stufe 7.2)", "port_forwards": "eigene critical-Tools"}
MAX_SPEC_BYTES = 64_000
MAX_ACTIONS = 50
_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}\.(ya?ml|json)$")


def code_dir(environ: dict[str, str] | None = None) -> Path:
    env = os.environ if environ is None else environ
    return Path(env["FRITZ_CODE_DIR"]).expanduser() if env.get("FRITZ_CODE_DIR") else state_dir() / "desired"


def load_spec(spec: str | None, name: str | None, base: Path | None = None) -> dict[str, Any]:
    if bool(spec) == bool(name):
        raise InvalidParameterError("Genau eins angeben: spec (YAML-Text) oder name (Datei in FRITZ_CODE_DIR).")
    if name:
        if not _NAME.match(name):
            raise InvalidParameterError("name: nur ein Dateiname (a–z 0–9 . _ -) mit .yaml/.yml/.json, kein Pfad.")
        path = (base or code_dir()) / name
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            raise InvalidParameterError(f"Datei {name} nicht lesbar (Verzeichnis FRITZ_CODE_DIR).") from None
    else:
        text = spec or ""
    if len(text.encode("utf-8")) > MAX_SPEC_BYTES:
        raise InvalidParameterError("Sollzustand zu groß (max. 64 KB).")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (Zeile {mark.line + 1})" if mark is not None else ""
        raise InvalidParameterError(f"Sollzustand ist kein gültiges YAML{where}.") from None
    if not isinstance(data, dict):
        raise InvalidParameterError("Sollzustand muss ein YAML-Objekt (Schlüssel: Wert) sein.")
    unknown = sorted(set(map(str, data)) - set(SUPPORTED_KEYS))
    if unknown:
        raise InvalidParameterError(
            f"Unbekannte Schlüssel: {', '.join(unknown)}.", hint=f"Unterstützt: {', '.join(SUPPORTED_KEYS)}"
        )
    if data.get("version", 1) != 1:
        raise InvalidParameterError("Nur version: 1 wird unterstützt.")
    return data


def _mac_map(value: Any, key: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvalidParameterError(f"{key}: erwartet MAC → Wert.")
    return {normalize_mac(str(mac)): v for mac, v in value.items()}


class FritzCode:
    def __init__(self, service: FritzService, environ: dict[str, str] | None = None) -> None:
        self.svc = service
        self.environ = environ

    # ------------------------------------------------------------ diff per key

    def _guest(self, want: Any) -> list[dict[str, Any]]:
        if not isinstance(want, bool):
            raise InvalidParameterError("guest_wifi: true oder false.")
        current = (self.svc.wlan.guest() or {}).get("enabled")
        return [self._action("guest_wifi", "Gast-WLAN", current, want, {"enabled": want})]

    def _channels(self, want: Any) -> list[dict[str, Any]]:
        if not isinstance(want, dict):
            raise InvalidParameterError('wlan_channels: Band → Kanal, z. B. {"2.4": 0}.')
        radios = {r["band_ghz"]: r for r in self.svc.wlan_cfg.radios()}
        out = []
        for band_raw, ch in want.items():
            band = normalize_band(str(band_raw))
            if not isinstance(ch, int) or ch < 0:
                raise InvalidParameterError(f"wlan_channels.{band_raw}: Kanal als Zahl, 0 = automatisch.")
            r = radios.get(band) or {}
            current = 0 if r.get("auto_channel") else r.get("channel")
            out.append(self._action("wlan_channel", f"WLAN {band} GHz", current, ch, {"band": band, "channel": ch}))
        return out

    def _eee(self, want: Any) -> list[dict[str, Any]]:
        if not isinstance(want, dict):
            raise InvalidParameterError("lan_eee: Port-Label oder all → auto/off.")
        ports = self.svc.connectivity.lan.ports()
        out = []
        for port, mode_raw in want.items():
            mode = "off" if mode_raw is False else str(mode_raw).lower()
            if mode not in ("auto", "off"):
                raise InvalidParameterError(f"lan_eee.{port}: auto oder off.")
            label = str(port)
            matched = ports if label.lower() == "all" else [p for p in ports if str(p.get("label")) == label]
            current_modes = {str(p.get("eee_mode")) for p in matched if p.get("eee_supported", True)}
            current = current_modes.pop() if len(current_modes) == 1 else ("gemischt" if current_modes else None)
            out.append(self._action("lan_eee", f"EEE {label}", current, mode, {"port": label, "mode": mode}))
        return out

    def _static(self, want: Any) -> list[dict[str, Any]]:
        devices = {safe_mac(d.mac): d for d in self.svc.landevices.list()}
        out = []
        for mac, flag in _mac_map(want, "static_ip").items():
            if not isinstance(flag, bool):
                raise InvalidParameterError(f"static_ip.{mac}: true oder false.")
            dev = devices.get(mac)
            current = dev.static_dhcp if dev else None
            label = f"feste IP {dev.display_name if dev else mac}"
            act = self._action("static_ip", label, current, flag, {"mac": mac, "enabled": flag})
            if dev is None:
                act.update(applicable=False, reason="Gerät nicht in der Geräteliste")
            out.append(act)
        return out

    def _internet(self, want: Any) -> list[dict[str, Any]]:
        out = []
        for mac, allowed in _mac_map(want, "internet_access").items():
            if not isinstance(allowed, bool):
                raise InvalidParameterError(f"internet_access.{mac}: true (erlaubt) oder false (gesperrt).")
            st = self.svc.internet_access_status(mac, None)
            blocked = st.get("blocked")
            current = None if blocked is None else not blocked
            out.append(
                self._action(
                    "internet_access",
                    f"Internet {st.get('name') or mac}",
                    current,
                    allowed,
                    {"mac": mac, "allowed": allowed},
                )
            )
        return out

    def _parental(self, want: Any) -> list[dict[str, Any]]:
        out = []
        for mac, profile in _mac_map(want, "parental_profile").items():
            st = self.svc.parental.parental_device_status(mac, None)
            current = (st.get("profile") or {}).get("id")
            out.append(
                self._action(
                    "parental_profile",
                    f"Profil {st.get('name') or mac}",
                    current,
                    str(profile),
                    {"mac": mac, "profile_id": str(profile)},
                )
            )
        return out

    def _tam(self, want: Any) -> list[dict[str, Any]]:
        if not isinstance(want, dict):
            raise InvalidParameterError("tam: Index → true/false.")
        machines = {m.get("index"): m for m in self.svc.tam_list().get("machines") or []}
        out = []
        for idx_raw, flag in want.items():
            idx = int(idx_raw)
            m = machines.get(idx) or {}
            out.append(
                self._action(
                    "tam",
                    _tam_label(m.get("name"), idx),
                    m.get("enabled"),
                    bool(flag),
                    {"index": idx, "enabled": bool(flag)},
                )
            )
        return out

    def _dns(self, want: Any) -> list[dict[str, Any]]:
        wanted = [str(x) for x in (want if isinstance(want, list) else [want])]
        current = self.svc.get_lan_dns().get("dns_servers")
        act = self._action("dns_dhcp", "DNS per DHCP", current, wanted, {})
        act.update(applicable=False, reason=COMPARE_ONLY["dns_dhcp"])
        return [act]

    def _ports(self, want: Any) -> list[dict[str, Any]]:
        if not isinstance(want, list):
            raise InvalidParameterError("port_forwards: Liste von {protocol, external_port, internal_port, ip}.")

        def key(m: dict[str, Any]) -> tuple[str, int, int, str]:
            return (
                str(m.get("protocol") or "").upper(),
                int(m.get("external_port") or 0),
                int(m.get("internal_port") or m.get("external_port") or 0),
                str(m.get("ip") or m.get("internal_client") or ""),
            )

        live = {key(m) for m in self.svc.list_port_forwards().get("port_forwards") or [] if m.get("enabled")}
        desired = {key(m) for m in want if isinstance(m, dict)}
        out = []
        for k in sorted(desired - live):
            out.append(
                {
                    **self._action(
                        "port_forward", f"Portfreigabe {k[0]} {k[1]}→{k[3]}:{k[2]}", "fehlt", "vorhanden", {}
                    ),
                    "applicable": False,
                    "reason": COMPARE_ONLY["port_forwards"],
                }
            )
        for k in sorted(live - desired):
            out.append(
                {
                    **self._action(
                        "port_forward",
                        f"Portfreigabe {k[0]} {k[1]}→{k[3]}:{k[2]}",
                        "vorhanden",
                        "nicht im Sollzustand",
                        {},
                    ),
                    "applicable": False,
                    "reason": COMPARE_ONLY["port_forwards"],
                }
            )
        return out

    @staticmethod
    def _action(kind: str, label: str, current: Any, desired: Any, args: dict[str, Any]) -> dict[str, Any]:
        return {
            "kind": kind,
            "target": label,
            "current": current,
            "desired": desired,
            "in_sync": current == desired,
            "applicable": True,
            "args": args,
        }

    # ------------------------------------------------------------ public

    def drift(self, spec: str | None = None, name: str | None = None) -> dict[str, Any]:
        data = load_spec(spec, name, code_dir(self.environ))
        handlers: dict[str, Callable[[Any], list[dict[str, Any]]]] = {
            "guest_wifi": self._guest,
            "wlan_channels": self._channels,
            "lan_eee": self._eee,
            "static_ip": self._static,
            "internet_access": self._internet,
            "parental_profile": self._parental,
            "tam": self._tam,
            "dns_dhcp": self._dns,
            "port_forwards": self._ports,
        }
        items: list[dict[str, Any]] = []
        errors: dict[str, Any] = {}
        for key, handler in handlers.items():
            if key not in data:
                continue
            try:
                items.extend(handler(data[key]))
            except (AuthError, ConfirmationRequiredError):
                raise
            except FritzError as exc:
                errors[key] = exc.to_dict()
        drift = [i for i in items if not i["in_sync"]]
        return {
            "checked": len(items),
            "in_sync": len(items) - len(drift),
            "drift": drift,
            "applicable": [i for i in drift if i["applicable"]],
            "not_applicable": [i for i in drift if not i["applicable"]],
            "errors": errors,
            "verdict": "Box entspricht dem Sollzustand" if not drift and not errors else f"{len(drift)} Abweichung(en)",
        }

    def plan(self, spec: str | None = None, name: str | None = None) -> dict[str, Any]:
        self.svc.gate.require(Tier.CRITICAL)
        d = self.drift(spec, name)
        actions = [
            {"kind": a["kind"], "target": a["target"], "args": a["args"], "desired": a["desired"]}
            for a in d["applicable"]
        ][:MAX_ACTIONS]
        out: dict[str, Any] = {**d, "actions": actions}
        if not actions:
            out["note"] = "Nichts anzuwenden." + (
                " Nicht anwendbare Abweichungen siehe not_applicable." if d["not_applicable"] else ""
            )
            return out
        token = self.svc.plans.issue("fritz_apply", {}, payload=actions)
        warnings = []
        if any(a["kind"] in ("wlan_channel", "guest_wifi") for a in actions):
            warnings.append("WLAN-Änderungen trennen verbundene Geräte kurz.")
        if any(a["kind"] == "internet_access" and a["args"]["allowed"] is False for a in actions):
            warnings.append("Mindestens ein Gerät wird für das Internet gesperrt.")
        if any(a["kind"] == "lan_eee" for a in actions):
            warnings.append("EEE-Änderungen handeln LAN-Links neu aus (kurze Unterbrechung).")
        out.update(
            {
                "consequence": f"{len(actions)} Einstellung(en) werden auf den Sollzustand gesetzt: "
                + "; ".join(f"{a['target']} → {a['desired']}" for a in actions[:10]),
                "warnings": warnings,
                "token": token,
                "token_valid_s": int(self.svc.plans.ttl),
                "execute_with": {"tool": "fritz_apply_execute"},
            }
        )
        return out

    def execute(self, token: str) -> dict[str, Any]:
        self.svc.gate.require(Tier.CRITICAL)
        actions = self.svc.plans.redeem_payload(token, "fritz_apply") or []
        results = []
        for a in actions:
            args = a["args"]
            try:
                r = self._apply(a["kind"], args)
                results.append(
                    {
                        "target": a["target"],
                        "ok": True,
                        "verified": bool(r.get("verified")),
                        "changed": r.get("changed", True),
                        "result": r,
                    }
                )
            except AuthError:
                raise
            except FritzError as exc:
                results.append({"target": a["target"], "ok": False, "verified": False, "error": exc.to_dict()})
        return {
            "applied": sum(1 for r in results if r["ok"]),
            "verified": sum(1 for r in results if r["verified"]),
            "failed": [r["target"] for r in results if not r["ok"] or not r["verified"]],
            "results": results,
            "note": "Jede Aktion wurde über das jeweilige Schreib-Tool ausgeführt und zurückgelesen; verified=false "
            "heißt: nicht als Erfolg werten. Erneutes fritz_drift zeigt den Stand.",
        }

    def _apply(self, kind: str, a: dict[str, Any]) -> dict[str, Any]:
        s = self.svc
        if kind == "guest_wifi":
            return s.set_guest_wifi(a["enabled"])
        if kind == "wlan_channel":
            return s.set_wlan_channel(a["band"], a["channel"])
        if kind == "lan_eee":
            return s.connectivity.set_lan_eee(a["port"], a["mode"])
        if kind == "static_ip":
            return s.set_static_ip(a["mac"], None, a["enabled"])
        if kind == "internet_access":
            return s.set_internet_access(a["mac"], a["allowed"])
        if kind == "parental_profile":
            return s.parental.set_parental_profile(a["mac"], a["profile_id"])
        if kind == "tam":
            return s.set_tam_enabled(a["index"], a["enabled"])
        raise InvalidParameterError(f"Aktion {kind} ist nicht anwendbar.")

    def export(self, save_as: str | None = None) -> dict[str, Any]:
        """Current state of the supported keys as a YAML desired state (starting point for editing)."""
        s = self.svc
        data: dict[str, Any] = {"version": 1}
        errors: dict[str, Any] = {}

        def part(key: str, fn: Callable[[], Any]) -> None:
            try:
                value = fn()
                if value not in (None, {}, []):
                    data[key] = value
            except (AuthError, ConfirmationRequiredError):
                raise
            except FritzError as exc:
                errors[key] = exc.to_dict()

        part("guest_wifi", lambda: (s.wlan.guest() or {}).get("enabled"))
        part(
            "wlan_channels",
            lambda: {
                r["band_ghz"]: 0 if r.get("auto_channel") else r.get("channel")
                for r in s.wlan_cfg.radios()
                if r.get("band_ghz")
            },
        )
        part(
            "static_ip",
            lambda: {safe_mac(d.mac): True for d in s.landevices.list() if d.static_dhcp and safe_mac(d.mac)},
        )
        part("tam", lambda: {m["index"]: bool(m["enabled"]) for m in s.tam_list().get("machines") or []})
        part("dns_dhcp", lambda: s.get_lan_dns().get("dns_servers"))
        text = yaml.safe_dump(data, allow_unicode=True, sort_keys=False)
        out: dict[str, Any] = {
            "yaml": text,
            "errors": errors,
            "note": "Nur unterstützte Schlüssel; Internetsperren/Profile/EEE bei Bedarf ergänzen.",
        }
        if save_as:
            if not _NAME.match(save_as):
                raise InvalidParameterError("save_as: nur ein Dateiname mit .yaml/.yml.")
            base = ensure_private_dir(code_dir(self.environ))
            write_private(base / save_as, text.encode("utf-8"))
            out["saved_to"] = str(base / save_as)
        return out


Spec = Annotated[str | None, Field(description="Sollzustand als YAML-Text (alternativ name)")]
Name = Annotated[str | None, Field(description="Dateiname im Verzeichnis FRITZ_CODE_DIR, z. B. heim.yaml")]


def register_code_tools(tool: ToolDecorator, svc: Callable[[str | None], FritzCode]) -> None:
    @tool(Tier.READ, READ)
    def fritz_drift(spec: Spec = None, name: Name = None, box: BoxArg = None) -> dict[str, Any]:
        """FRITZ as Code: vergleicht einen Sollzustand (YAML: guest_wifi, wlan_channels, lan_eee, static_ip,
        internet_access, parental_profile, tam, dns_dhcp, port_forwards) mit der Box und listet Abweichungen
        (anwendbar bzw. nur Vergleich). Ändert nichts."""
        return svc(box).drift(spec, name)

    @tool(Tier.READ, READ)
    def fritz_export(
        save_as: Annotated[str | None, Field(description="Optional als Datei in FRITZ_CODE_DIR speichern")] = None,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """FRITZ as Code: erzeugt aus dem aktuellen Stand einen Sollzustand (YAML) als Ausgangspunkt; optional lokal
        gespeichert (0600). Ändert an der Box nichts."""
        return svc(box).export(save_as)

    @tool(Tier.CRITICAL, READ)
    def fritz_apply_plan(spec: Spec = None, name: Name = None, box: BoxArg = None) -> dict[str, Any]:
        """FRITZ as Code: plant das Anwenden der anwendbaren Abweichungen (Vorschau je Einstellung, Warnungen) und gibt
        ein einmaliges Token (5 min). Ändert nichts."""
        return svc(box).plan(spec, name)

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def fritz_apply_execute(token: TokenArg, box: BoxArg = None) -> dict[str, Any]:
        """FRITZ as Code: wendet den geplanten Sollzustand an (über die Schreib-Tools, je Aktion zurückgelesen,
        bricht bei Fehlern nicht ab). Nur nach ausdrücklicher Zustimmung."""
        return svc(box).execute(token)


def _tam_label(name: object, idx: object) -> str:
    """Anzeigename eines Anrufbeantworters ohne Doppelung (Box-Standardname ist oft schon 'Anrufbeantworter')."""
    n = str(name).strip() if name else ""
    if not n:
        return f"Anrufbeantworter {idx}"
    return n if "anrufbeantworter" in n.lower() else f"Anrufbeantworter {n}"
