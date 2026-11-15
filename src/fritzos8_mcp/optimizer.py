"""Stage 10.2 – network optimizer: suggestions from the live state and the measurement series → plan → execution only
through the existing write tools (with their read-back) → effect measured afterwards (before/after comparison).

Suggestions (``network_optimizer_suggest``, read):

* **WLAN channel** – a fixed 2.4 GHz channel outside 1/6/11/13 overlaps two neighbours → automatic channel (or the
  nearest non-overlapping channel). With frequent device drops in the measurement series (stage 10.1) a fixed channel
  on any band is a candidate for the automatic channel selection. Executed via ``set_wlan_channel``.
* **EEE** – Raspberry Pi with EEE (known link-flapping bug) or LAN link flapping in the event log on a port with EEE
  → EEE off. Executed via ``set_lan_eee`` (may act box-wide on some models – said in the plan).
* **Band steering** – many clients on 2.4 GHz while 5 GHz is idle; band steering is not writable via TR-064 →
  manual recommendation (Web-UI path).
* **Repeater** – weak mesh backbone (rate/signal) → manual recommendation (move closer, LAN/Powerline uplink).

Executing (``network_optimizer_apply_plan/_execute``, critical): the actions are bound to the token server-side;
each one runs through the curated write method (gate, guard, read-back) – never a raw call. Every applied change is
recorded in ``<state>/<box>/optimizer.json`` (0600) with time, kind and the affected devices.

Effect (``network_optimizer_effect``, read): compares the measurement series in equal windows before and after the
change – device drops per day (all devices / affected devices), reconnects per day, average active devices and
throughput. Too little data after the change → ``insufficient_data``; the verdict is a hint, not proof (other
causes are possible).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from .errors import FritzError, InvalidParameterError, PlanError
from .history import HistoryStore
from .nasremote import ToolDecorator
from .netinfo import parse_mesh
from .paths import ensure_private_dir, safe_component, state_dir, write_private
from .quality import is_raspberry_pi, mesh_clients
from .security import Tier
from .toolargs import DESTRUCTIVE, READ, BoxArg, TokenArg
from .util import decimal_int, safe_mac

if TYPE_CHECKING:
    from .service import FritzService

NON_OVERLAPPING_24 = (1, 6, 11)
MESH_RATE_WARN_MBIT = 100
SIGNAL_WEAK_DBM = -75
BAND_STEERING_RATIO = 2.0
BAND_STEERING_MIN_CLIENTS = 8
DROPS_PER_DAY_HIGH = 10.0
EFFECT_CHANGE_PCT = 30.0
MAX_ACTIONS = 5


def _nearest_channel(current: int, possible: list[int]) -> int | None:
    candidates = [c for c in NON_OVERLAPPING_24 if not possible or c in possible]
    return min(candidates, key=lambda c: (abs(c - current), c)) if candidates else None


class NetworkOptimizer:
    def __init__(
        self,
        svc: FritzService,
        *,
        now: Callable[[], float] = time.time,
        state_root: Path | None = None,
        store: Callable[[], HistoryStore] | None = None,
    ) -> None:
        self.svc = svc
        self.now = now
        self._state_root = state_root
        self._store = store

    # ------------------------------------------------------------ local state

    @property
    def _path(self) -> Path:
        base = ensure_private_dir((self._state_root or state_dir()) / safe_component(self.svc.box_host))
        return base / "optimizer.json"

    def _changes(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        return [c for c in data.get("changes") or [] if isinstance(c, dict)] if isinstance(data, dict) else []

    def _save_changes(self, changes: list[dict[str, Any]]) -> None:
        write_private(self._path, json.dumps({"changes": changes[-200:]}, ensure_ascii=False, indent=1).encode())

    def store(self) -> HistoryStore:
        if self._store is not None:
            return self._store()
        return HistoryStore.for_box(self.svc.box_host, self._state_root)

    # ------------------------------------------------------------ suggestions

    def suggest(self, days: float = 7) -> dict[str, Any]:
        if not 1 <= days <= 90:
            raise InvalidParameterError("days muss zwischen 1 und 90 liegen.")
        sources: dict[str, Any] = {}

        def load(name: str, fn: Callable[[], Any]) -> Any:
            try:
                value = fn()
                sources[name] = "ok"
                return value
            except FritzError as exc:
                sources[name] = exc.to_dict()
                return None

        radios = load("wlan", self.svc.wlan_cfg.radios) or []
        ports = load("lan_ports", self.svc.connectivity.lan.ports) or []
        mesh_doc = load("mesh", self.svc.netinfo.mesh_document)
        log = load("log", lambda: self.svc.diag.system_log(300))
        drops = load("history", lambda: self._drop_stats(days)) or {}

        suggestions: list[dict[str, Any]] = []
        suggestions += self._channel_suggestions(radios, drops)
        suggestions += self._eee_suggestions(ports, mesh_doc, log, drops)
        suggestions += self._band_steering(radios)
        if isinstance(mesh_doc, dict):
            suggestions += self._repeater(mesh_doc)
        return {
            "suggestions": suggestions,
            "actionable": [s["id"] for s in suggestions if s["actionable"]],
            "history": drops or {"available": False},
            "sources": sources,
            "next_step": "Ausführbare Vorschläge (actionable) mit network_optimizer_apply_plan(ids=[…]) planen; danach "
            "die Wirkung nach einigen Stunden/Tagen mit network_optimizer_effect prüfen. Manuelle Vorschläge "
            "(actionable=false) sind über TR-064/dokumentierte Schnittstellen nicht schreibbar.",
            "note": "Faustregeln – Vorschläge, keine Diagnose. Eine Änderung verbindet WLAN-Geräte kurz neu.",
        }

    def _drop_stats(self, days: float) -> dict[str, Any]:
        end = self.now()
        start = end - days * 86400
        events = self.store().events(start, end)
        offline = [e for e in events if e[1] == "device_offline"]
        if not events:
            return {"available": False, "note": "Keine Messreihe – fritzos8-collector laufen lassen."}
        span_days = max((end - events[0][0]) / 86400, 1 / 24)
        per_mac: dict[str, int] = {}
        for _, _, mac in offline:
            per_mac[mac] = per_mac.get(mac, 0) + 1
        return {
            "available": True,
            "days": round(span_days, 2),
            "drops_per_day": round(len(offline) / span_days, 2),
            "drops_by_mac": dict(sorted(per_mac.items(), key=lambda kv: -kv[1])[:20]),
        }

    @staticmethod
    def _suggestion(
        sid: str,
        kind: str,
        title: str,
        reason: str,
        *,
        action: dict[str, Any] | None = None,
        manual: str | None = None,
        warnings: list[str] | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "id": sid,
            "kind": kind,
            "title": title,
            "reason": reason,
            "actionable": action is not None,
            "action": action,
            "manual_steps": manual,
            "warnings": warnings or [],
            "evidence": evidence or {},
        }

    def _channel_suggestions(self, radios: list[dict[str, Any]], drops: dict[str, Any]) -> list[dict[str, Any]]:
        out = []
        many_drops = (drops.get("drops_per_day") or 0) >= DROPS_PER_DAY_HIGH
        for r in radios:
            band = r.get("band_ghz")
            ch = r.get("channel")
            if not r.get("enabled") or r.get("auto_channel") or not isinstance(ch, int) or ch <= 0:
                continue
            band_s = str(band)
            possible = [c for c in map(decimal_int, r.get("possible_channels") or []) if c is not None]
            warnings = ["WLAN-Geräte in diesem Band verbinden sich beim Kanalwechsel kurz neu."]
            if band_s in ("2.4", "2") and ch not in (*NON_OVERLAPPING_24, 13):
                nearest = _nearest_channel(ch, possible)
                out.append(
                    self._suggestion(
                        f"wlan_channel:{band_s}",
                        "wlan_channel",
                        f"2,4-GHz-Kanal {ch} überlappt die Nachbarkanäle – automatische Kanalwahl",
                        "Im 2,4-GHz-Band überlappen sich nur 1, 6, 11 (13) nicht; ein Kanal dazwischen stört zwei "
                        "Nachbarnetze und wird von beiden gestört.",
                        action={"tool": "set_wlan_channel", "band": band_s, "channel": 0},
                        warnings=[*warnings, f"Alternative von Hand: Kanal {nearest} (nicht überlappend)."]
                        if nearest
                        else warnings,
                        evidence={"channel": ch, "possible_channels": possible, "clients": r.get("clients")},
                    )
                )
            elif many_drops:
                out.append(
                    self._suggestion(
                        f"wlan_channel:{band_s}",
                        "wlan_channel",
                        f"Fester Kanal {ch} ({band_s} GHz) bei häufigen Geräteabbrüchen – automatische Kanalwahl",
                        f"Die Messreihe zeigt {drops.get('drops_per_day')} Geräteabbrüche pro Tag; die automatische "
                        "Kanalwahl weicht Störern selbst aus.",
                        action={"tool": "set_wlan_channel", "band": band_s, "channel": 0},
                        warnings=warnings,
                        evidence={"channel": ch, "drops_per_day": drops.get("drops_per_day")},
                    )
                )
        return out

    def _eee_suggestions(
        self, ports: list[dict[str, Any]], mesh_doc: Any, log: Any, drops: dict[str, Any]
    ) -> list[dict[str, Any]]:
        from .doctor import NetworkDoctor

        by_label = {str(p.get("label")): p for p in ports}
        out: dict[str, dict[str, Any]] = {}
        clients = mesh_clients(mesh_doc) if isinstance(mesh_doc, dict) else []
        drops_by_mac: dict[str, int] = drops.get("drops_by_mac") or {}
        for c in clients:
            if c.get("connection") != "lan" or not is_raspberry_pi(c.get("mac")):
                continue
            port = by_label.get(str(c.get("lan_port") or ""))
            if not port or not port.get("eee_supported") or port.get("eee_mode") != "auto":
                continue
            mac = safe_mac(c.get("mac")) or str(c.get("mac"))
            label = str(port["label"])
            out[label] = self._suggestion(
                f"lan_eee:{label}",
                "lan_eee",
                f"EEE an {label} abschalten (Raspberry Pi {c.get('name') or mac})",
                "Bekannter Fehler: Raspberry Pi (v. a. Pi 5) mit Energy Efficient Ethernet → Link-Flapping, "
                "Paketverlust, DNS-Aussetzer.",
                action={"tool": "set_lan_eee", "port": label, "mode": "off", "macs": [mac]},
                warnings=["Auf manchen Modellen wirkt EEE box-weit (alle Ports) – set_lan_eee meldet das."],
                evidence={"mac": mac, "drops_in_history": drops_by_mac.get(mac)},
            )
        flaps: list[dict[str, Any]] = []

        def add(severity: str, area: str, finding: str, *_: Any, **ev: Any) -> None:
            flaps.append({"finding": finding, **ev})

        if isinstance(log, dict):
            NetworkDoctor._lan_log(log, add)
        for f in flaps:
            label = str(f.get("port") or "")
            if label not in by_label or label in out:
                continue
            port = by_label[label]
            if port.get("eee_mode") != "auto" or not port.get("eee_supported"):
                continue
            out[label] = self._suggestion(
                f"lan_eee:{label}",
                "lan_eee",
                f"EEE an {label} abschalten (Link-Flapping im Ereignisprotokoll)",
                "Häufige Link-Wechsel an einem Port mit EEE deuten auf eine EEE-Inkompatibilität der Gegenstelle.",
                action={"tool": "set_lan_eee", "port": label, "mode": "off", "macs": []},
                warnings=["Auf manchen Modellen wirkt EEE box-weit (alle Ports) – set_lan_eee meldet das."],
                evidence={"log": f.get("finding")},
            )
        return list(out.values())

    def _band_steering(self, radios: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_band = {str(r.get("band_ghz")): r for r in radios if r.get("enabled")}
        low, high = by_band.get("2.4"), by_band.get("5")
        if not low or not high:
            return []
        c24, c5 = int(low.get("clients") or 0), int(high.get("clients") or 0)
        if c24 < BAND_STEERING_MIN_CLIENTS or c24 < BAND_STEERING_RATIO * max(c5, 1):
            return []
        same_ssid = bool(low.get("ssid")) and low.get("ssid") == high.get("ssid")
        return [
            self._suggestion(
                "band_steering",
                "band_steering",
                f"{c24} Geräte im 2,4-GHz-Band, nur {c5} im 5-GHz-Band – Bandsteuerung prüfen",
                "Viele Geräte im langsameren, stärker gestörten 2,4-GHz-Band; die Bandsteuerung lenkt fähige Geräte "
                "ins 5-GHz-Band. Per TR-064 nicht schreibbar.",
                manual="Web-UI: WLAN > Funkkanal > Funkkanal-Einstellungen anpassen > „Band Steering“ aktivieren"
                + ("" if same_ssid else "; dafür beide Bänder mit gleichem Namen (SSID) betreiben"),
                evidence={"clients_24": c24, "clients_5": c5, "same_ssid": same_ssid},
            )
        ]

    def _repeater(self, mesh_doc: dict[str, Any]) -> list[dict[str, Any]]:
        out = []
        for link in parse_mesh(mesh_doc).get("backbone", []):
            rate = link.get("rate_down_mbit")
            signal = link.get("signal_dbm")
            weak = (rate is not None and rate < MESH_RATE_WARN_MBIT) or (
                signal is not None and signal < SIGNAL_WEAK_DBM
            )
            if not weak:
                continue
            out.append(
                self._suggestion(
                    f"repeater:{link.get('from')}-{link.get('to')}",
                    "repeater",
                    f"Mesh-Anbindung {link.get('from')} ↔ {link.get('to')} schwach",
                    f"{rate if rate is not None else '?'} Mbit/s, {signal if signal is not None else '?'} dBm – "
                    "der Repeater gibt höchstens diese Rate an seine Geräte weiter.",
                    manual="Repeater etwa auf halbe Strecke zwischen Box und Funkloch setzen (Sichtlinie, keine "
                    "Betonwand/Fußbodenheizung dazwischen) oder per LAN/Powerline anbinden (LAN-Brücke).",
                    evidence={"link": link},
                )
            )
        return out

    # ------------------------------------------------------------ plan / execute

    def plan(self, ids: list[str]) -> dict[str, Any]:
        self.svc.gate.require(Tier.CRITICAL)
        wanted = [i.strip() for i in ids if i and i.strip()]
        if not wanted or len(wanted) > MAX_ACTIONS:
            raise InvalidParameterError(f"1–{MAX_ACTIONS} Vorschlags-IDs aus network_optimizer_suggest angeben.")
        current = {s["id"]: s for s in self.suggest()["suggestions"]}
        actions = []
        for sid in wanted:
            s = current.get(sid)
            if s is None:
                raise InvalidParameterError(
                    f'Vorschlag "{sid}" ist (nicht mehr) aktuell.', hint="network_optimizer_suggest neu aufrufen."
                )
            if not s["actionable"]:
                raise InvalidParameterError(f'Vorschlag "{sid}" ist nur manuell umsetzbar: {s["manual_steps"]}')
            actions.append({"id": sid, "kind": s["kind"], "title": s["title"], "action": s["action"]})
        token = self.svc.plans.issue("network_optimize", {}, payload=actions)
        warnings = sorted({w for sid in wanted for w in current[sid]["warnings"]})
        return {
            "action": "network_optimize",
            "actions": actions,
            "consequence": "; ".join(a["title"] for a in actions)
            + ". Jede Änderung läuft über das zugehörige Schreib-Tool (Rücklesen) und wird lokal protokolliert, "
            "damit network_optimizer_effect die Wirkung messen kann.",
            "warnings": warnings,
            "token": token,
            "token_valid_s": int(self.svc.plans.ttl),
        }

    def _apply(self, action: dict[str, Any]) -> dict[str, Any]:
        tool = action.get("tool")
        if tool == "set_wlan_channel":
            return self.svc.set_wlan_channel(str(action["band"]), int(action["channel"]))
        if tool == "set_lan_eee":
            return self.svc.connectivity.set_lan_eee(str(action["port"]), str(action["mode"]))
        raise InvalidParameterError(f"Unbekannte Optimierer-Aktion {tool}.")

    def execute(self, token: str) -> dict[str, Any]:
        self.svc.gate.require(Tier.CRITICAL)
        actions = self.svc.plans.redeem_payload(token, "network_optimize")
        if not isinstance(actions, list) or not actions:
            raise PlanError("Plan enthält keine Aktionen – erst neu planen.")
        changes = self._changes()
        results = []
        for a in actions:
            entry: dict[str, Any] = {"id": a["id"], "title": a["title"]}
            try:
                r = self._apply(a["action"])
                entry.update({"result": r, "verified": bool(r.get("verified"))})
            except FritzError as exc:
                entry.update({"error": exc.to_dict(), "verified": False})
            results.append(entry)
            if entry.get("verified") or entry.get("result", {}).get("changed"):
                ts = self.now()
                changes.append(
                    {
                        "change_id": f"{int(ts)}-{a['id']}",
                        "ts": ts,
                        "suggestion": a["id"],
                        "kind": a["kind"],
                        "title": a["title"],
                        "action": {k: v for k, v in a["action"].items() if k != "macs"},
                        "macs": a["action"].get("macs") or [],
                        "verified": entry["verified"],
                    }
                )
        self._save_changes(changes)
        return {
            "results": results,
            "applied": sum(1 for r in results if r.get("verified")),
            "next_step": "Wirkung frühestens nach einigen Stunden mit network_optimizer_effect prüfen (die Messreihe "
            "muss weiterlaufen).",
            "note": "verified=false heißt: nicht als Erfolg werten.",
        }

    # ------------------------------------------------------------ effect

    def effect(self, change_id: str | None = None, hours: float = 24) -> dict[str, Any]:
        if not 1 <= hours <= 24 * 30:
            raise InvalidParameterError("hours muss zwischen 1 und 720 liegen.")
        changes = self._changes()
        if not changes:
            return {"changes": [], "note": "Noch keine Änderung über den Optimierer ausgeführt."}
        if change_id:
            change = next((c for c in changes if c.get("change_id") == change_id), None)
            if change is None:
                raise InvalidParameterError(
                    f'Änderung "{change_id}" unbekannt.', hint=", ".join(c["change_id"] for c in changes[-10:])
                )
        else:
            change = changes[-1]
        ts = float(change["ts"])
        now = self.now()
        window = hours * 3600
        after_end = min(ts + window, now)
        store = self.store()
        before = self._window_stats(store, ts - window, ts, change.get("macs") or [])
        after = self._window_stats(store, ts, after_end, change.get("macs") or [])
        verdict, details = self._verdict(before, after, window)
        return {
            "change": {k: v for k, v in change.items() if k != "ts"} | {"at": _iso(ts)},
            "window_hours": hours,
            "before": before,
            "after": after,
            "verdict": verdict,
            "details": details,
            "recent_changes": [c["change_id"] for c in changes[-10:]],
            "note": "Vorher/nachher-Vergleich gleich langer Fenster aus der lokalen Messreihe – ein Hinweis, kein "
            "Beweis (Nutzung, Uhrzeit und Störer ändern sich auch).",
        }

    @staticmethod
    def _window_stats(store: HistoryStore, start: float, end: float, macs: list[str]) -> dict[str, Any]:
        span_h = max(0.0, (end - start) / 3600)
        runs = [r for r in store.runs(start, end) if r[1]]
        events = store.events(start, end)
        days = max(span_h / 24, 1e-9)
        offline = [e for e in events if e[1] == "device_offline"]
        reconnects = [e for e in events if e[1] in ("wan_reconnect", "wan_down", "dsl_resync")]

        def avg(metric: str) -> float | None:
            values = [v for _, v in store.series(metric, start, end)]
            return round(sum(values) / len(values), 2) if values else None

        stats: dict[str, Any] = {
            "from": _iso(start),
            "to": _iso(end),
            "hours": round(span_h, 1),
            "measurements": len(runs),
            "drops_per_day": round(len(offline) / days, 2),
            "reconnects_per_day": round(len(reconnects) / days, 2),
            "hosts_active_avg": avg("hosts.active"),
            "throughput_down_avg_mbit_s": avg("throughput.down_mbit_s"),
        }
        if macs:
            wanted = {m.upper() for m in macs}
            stats["affected_drops_per_day"] = round(sum(1 for e in offline if e[2].upper() in wanted) / days, 2)
        return stats

    @staticmethod
    def _verdict(before: dict[str, Any], after: dict[str, Any], window: float) -> tuple[str, list[str]]:
        if after["measurements"] < 3 or after["hours"] < window / 3600 / 2:
            return "insufficient_data", ["Nach der Änderung noch zu wenig Messungen (mind. halbes Fenster, 3 Werte)."]
        if before["measurements"] < 3:
            return "insufficient_data", ["Vor der Änderung zu wenig Messungen – kein Vergleich möglich."]
        details: list[str] = []
        score = 0
        key = "affected_drops_per_day" if "affected_drops_per_day" in before else "drops_per_day"
        for metric, label in ((key, "Geräteabbrüche/Tag"), ("reconnects_per_day", "Neuverbindungen/Tag")):
            b, a = float(before.get(metric) or 0), float(after.get(metric) or 0)
            if b == a:
                continue
            change = (a - b) / max(b, 1.0) * 100
            if abs(change) >= EFFECT_CHANGE_PCT:
                score += -1 if change < 0 else 1
                details.append(f"{label}: {b} → {a} ({'−' if change < 0 else '+'}{abs(round(change))} %)")
        if score < 0:
            return "improved", details
        if score > 0:
            return "worse", details
        return "unchanged", details or ["Keine deutliche Änderung (Schwelle ±30 %)."]


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts))


IdsArg = Annotated[list[str], Field(description="IDs ausführbarer Vorschläge aus network_optimizer_suggest (1–5)")]


def register_optimizer_tools(tool: ToolDecorator, svc: Callable[[str | None], NetworkOptimizer]) -> None:
    @tool(Tier.READ, READ)
    def network_optimizer_suggest(
        days: Annotated[float, Field(description="Messreihe der letzten N Tage berücksichtigen", ge=1, le=90)] = 7,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Netz-Optimierer, Schritt 1 (nur lesend): Vorschläge aus WLAN-Einstellungen, LAN-Ports, Mesh,
        Ereignisprotokoll und Messreihe – WLAN-Kanal (überlappend/fest bei vielen Abbrüchen), EEE aus (Raspberry Pi,
        Link-Flapping), Bandsteuerung und Repeater-Standort (nur manuell). actionable = über bestehende
        Schreib-Tools umsetzbar."""
        return svc(box).suggest(days)

    @tool(Tier.CRITICAL, READ)
    def network_optimizer_apply_plan(ids: IdsArg, box: BoxArg = None) -> dict[str, Any]:
        """Netz-Optimierer, Schritt 2: plant ausgewählte Vorschläge (Aktionen serverseitig an das Token gebunden),
        zeigt Folgen und Warnungen + Token (5 min)."""
        return svc(box).plan(ids)

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def network_optimizer_apply_execute(token: TokenArg, box: BoxArg = None) -> dict[str, Any]:
        """Netz-Optimierer, Schritt 3: führt den Plan über die bestehenden Schreib-Tools aus (set_wlan_channel,
        set_lan_eee – jeweils mit Rücklesen) und protokolliert die Änderung lokal für den Vorher/nachher-Vergleich.
        Nur nach ausdrücklicher Zustimmung."""
        return svc(box).execute(token)

    @tool(Tier.READ, READ)
    def network_optimizer_effect(
        change_id: Annotated[
            str | None, Field(description="Änderung (change_id); Standard: die letzte über den Optimierer")
        ] = None,
        hours: Annotated[float, Field(description="Fensterlänge vorher/nachher in Stunden", ge=1, le=720)] = 24,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Netz-Optimierer, Schritt 4 (nur lesend, lokale Messreihe): Wirkung einer Änderung im Vorher/nachher-
        Vergleich – Geräteabbrüche pro Tag (betroffene Geräte), Neuverbindungen, aktive Geräte, Durchsatz;
        Urteil improved/worse/unchanged/insufficient_data."""
        return svc(box).effect(change_id, hours)
