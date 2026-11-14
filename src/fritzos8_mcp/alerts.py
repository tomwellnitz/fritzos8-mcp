"""Stage 8.3 – alarms with debouncing and optional notifications (Home Assistant webhook, ntfy, Telegram).

Checks (each fails independently): new devices (host change counter → host list vs. known MACs), configuration
drift (last snapshot vs. live, opt-in because it reads a lot), LAN link flapping (event log), line thresholds
(stage 8.9 findings), smart home battery low, firmware/device updates available (stage 8.11), anomalies in the
measurement series (stage 10.1) and pluggable extra
checks (e.g. telephony registration, stage 8.10).

Debouncing: state in ``<state dir>/<box>/alarms.json`` (0600). An alarm is notified when it appears; while it stays
active it is repeated at most every ``FRITZ_ALERT_REPEAT_H`` hours (default 24). An alarm that disappears and comes
back within that window is not notified again ("reappeared"). New devices are one-shot: once reported, the MAC is
known. The first run only learns the known devices (no flood of "new device" alarms).

Notification channels come only from the environment and are never output (URLs/tokens are secrets):
``FRITZ_ALERT_WEBHOOK`` (e.g. Home Assistant webhook URL), ``FRITZ_ALERT_NTFY`` (topic URL),
``FRITZ_ALERT_TELEGRAM_TOKEN`` + ``FRITZ_ALERT_TELEGRAM_CHAT``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import httpx
from mcp.types import ToolAnnotations
from pydantic import Field

from .errors import AuthError, ConfirmationRequiredError, FritzError
from .nasremote import ToolDecorator
from .paths import ensure_private_dir, safe_component, state_dir, write_private
from .security import Tier
from .toolargs import BoxArg

if TYPE_CHECKING:
    from .service import FritzService

log = logging.getLogger(__name__)

DEFAULT_REPEAT_H = 24.0
ALERT_ENV_SECRETS = ("FRITZ_ALERT_WEBHOOK", "FRITZ_ALERT_NTFY", "FRITZ_ALERT_TELEGRAM_TOKEN")
_NOTIFY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=True)

Poster = Callable[[str, dict[str, Any] | None, str | None, dict[str, str]], int]


@dataclass
class Alarm:
    key: str
    type: str
    severity: str  # info / warn / critical
    message: str
    details: dict[str, Any] = field(default_factory=dict)


def alert_secrets(environ: Mapping[str, str] | None = None) -> tuple[str, ...]:
    """Values that must be redacted everywhere (notification URLs/tokens, MQTT broker password)."""
    from .mqttbridge import mqtt_secrets  # stage 10.3: the MQTT broker password is a secret as well

    env = os.environ if environ is None else environ
    return tuple(v for k in ALERT_ENV_SECRETS if (v := (env.get(k) or "").strip())) + mqtt_secrets(env)


def http_post(url: str, payload: dict[str, Any] | None, text: str | None, headers: dict[str, str]) -> int:
    response = httpx.post(
        url, json=payload, content=text.encode("utf-8") if text is not None else None, headers=headers, timeout=10
    )
    return response.status_code


class Notifier:
    def __init__(self, environ: Mapping[str, str] | None = None, post: Poster = http_post) -> None:
        env = os.environ if environ is None else environ
        self.webhook = (env.get("FRITZ_ALERT_WEBHOOK") or "").strip()
        self.ntfy = (env.get("FRITZ_ALERT_NTFY") or "").strip()
        self.tg_token = (env.get("FRITZ_ALERT_TELEGRAM_TOKEN") or "").strip()
        self.tg_chat = (env.get("FRITZ_ALERT_TELEGRAM_CHAT") or "").strip()
        self.post = post

    @property
    def channels(self) -> list[str]:
        out = []
        if self.webhook:
            out.append("webhook")
        if self.ntfy:
            out.append("ntfy")
        if self.tg_token and self.tg_chat:
            out.append("telegram")
        return out

    def send(self, box: str, alarms: list[Alarm]) -> dict[str, str]:
        if not alarms:
            return {}
        text = "\n".join(f"[{a.severity}] {a.message}" for a in alarms)
        title = f"FRITZ!Box {box}: {len(alarms)} Alarm(e)"
        result: dict[str, str] = {}

        def attempt(name: str, fn: Callable[[], int]) -> None:
            try:
                status = fn()
                result[name] = "ok" if 200 <= status < 300 else f"HTTP {status}"
            except Exception as exc:  # never leak the URL/token: only the exception type
                result[name] = f"fehlgeschlagen ({type(exc).__name__})"

        if self.webhook:
            payload = {"box": box, "title": title, "alarms": [asdict(a) for a in alarms]}
            attempt("webhook", lambda: self.post(self.webhook, payload, None, {}))
        if self.ntfy:
            attempt("ntfy", lambda: self.post(self.ntfy, None, text, {"Title": title, "Tags": "warning"}))
        if self.tg_token and self.tg_chat:
            url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
            attempt("telegram", lambda: self.post(url, {"chat_id": self.tg_chat, "text": f"{title}\n{text}"}, None, {}))
        return result


class AlarmState:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def save(self, data: dict[str, Any]) -> None:
        write_private(self.path, json.dumps(data, ensure_ascii=False, indent=1).encode("utf-8"))


class AlarmService:
    def __init__(
        self,
        service: FritzService,
        *,
        now: Callable[[], float] = time.time,
        notifier: Notifier | None = None,
        state_root: Path | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self.service = service
        self.now = now
        self._notifier = notifier
        self._state_root = state_root
        env = os.environ if environ is None else environ
        try:
            self.repeat_s = float(env.get("FRITZ_ALERT_REPEAT_H") or DEFAULT_REPEAT_H) * 3600
        except ValueError:
            self.repeat_s = DEFAULT_REPEAT_H * 3600
        self.extra_checks: list[tuple[str, Callable[[], list[Alarm]]]] = []

    @property
    def notifier(self) -> Notifier:
        return self._notifier or Notifier()

    @property
    def state(self) -> AlarmState:
        base = ensure_private_dir((self._state_root or state_dir()) / safe_component(self.service.box_host))
        return AlarmState(base / "alarms.json")

    def active(self) -> list[dict[str, Any]]:
        """Alarms active at the last check (local state only – no box access)."""
        st = self.state.load()
        return [
            {"key": k, "type": v.get("type"), "severity": v.get("severity"), "message": v.get("message")}
            for k, v in (st.get("active") or {}).items()
        ]

    # ------------------------------------------------------------ checks

    def _new_devices(self, st: dict[str, Any]) -> list[Alarm]:
        tr = self.service.tr064
        counter = tr.change_counter()
        known = set(st.get("known_macs") or [])
        if counter is not None and known and st.get("change_counter") == counter:
            return []
        hosts = {h["mac"].upper(): h for h in tr.list_hosts() if h.get("mac")}
        st["change_counter"] = counter
        if not known:  # first run: learn, do not alarm
            st["known_macs"] = sorted(hosts)
            return []
        out = []
        for mac in sorted(set(hosts) - known):
            h = hosts[mac]
            guest = " im Gastnetz" if h.get("guest") else ""
            out.append(
                Alarm(
                    f"new_device:{mac}",
                    "new_device",
                    "warn",
                    f"Neues Gerät{guest}: {h.get('name') or '?'} ({mac}, {h.get('ip') or 'ohne IP'})",
                    {"mac": mac, "name": h.get("name"), "ip": h.get("ip"), "guest": bool(h.get("guest"))},
                )
            )
        st["known_macs"] = sorted(known | set(hosts))
        return out

    def _drift(self) -> list[Alarm]:
        if self.service.snapshots.latest() is None:
            return []
        diff = self.service.snapshot_diff()
        if not diff.get("change_count"):
            return []
        summary = diff.get("summary") or []
        return [
            Alarm(
                "config_drift:" + hashlib.sha256("\n".join(summary).encode("utf-8")).hexdigest()[:12],
                "config_drift",
                "warn",
                f"Konfiguration weicht vom letzten Schnappschuss ab ({diff['change_count']} Änderung(en)): "
                + "; ".join(summary[:3]),
                {"summary": summary[:20], "snapshot": diff.get("a")},
            )
        ]

    def _flapping(self) -> list[Alarm]:
        from .doctor import NetworkDoctor

        found: list[Alarm] = []

        def add(severity: str, area: str, finding: str, *_: Any, **ev: Any) -> None:
            found.append(Alarm(f"link_flapping:{ev.get('port', finding)}", "link_flapping", severity, finding, ev))

        NetworkDoctor._lan_log(self.service.diag.system_log(200), add)
        return found

    def _line(self) -> list[Alarm]:
        report = self.service.line.diagnose()
        return [
            Alarm(f"line:{f['area']}:{f['finding'][:40]}", "line", f["severity"], f["finding"], f.get("evidence") or {})
            for f in report.get("findings") or []
            if f.get("severity") in ("warn", "critical")
        ]

    def _battery(self) -> list[Alarm]:
        out = []
        for d in self.service.smarthome.list_devices():
            thermo = d.get("thermostat") or {}
            low = d.get("battery_low") or thermo.get("battery_low")
            if low:
                pct = d.get("battery_pct") if d.get("battery_pct") is not None else thermo.get("battery_pct")
                out.append(
                    Alarm(
                        f"battery:{d.get('ain')}",
                        "battery_low",
                        "warn",
                        f"Batterie schwach: {d.get('name') or d.get('ain')}"
                        + (f" ({pct} %)" if pct is not None else ""),
                        {"ain": d.get("ain"), "battery_pct": pct},
                    )
                )
        return out

    def _updates(self) -> list[Alarm]:
        overview = self.service.devices.updates_overview()
        return [
            Alarm(f"update:{text}", "update_available", "info", f"Update verfügbar – {text}")
            for text in overview["summary"]["updates_available"]
        ]

    def _anomalies(self) -> list[Alarm]:
        """Stage 10.1: creeping degradation from the local measurement series (no box access)."""
        return [
            Alarm(
                f"anomaly:{f['kind']}",
                "anomaly",
                f["severity"],
                f["finding"],
                f.get("evidence") or {},
            )
            for f in self.service.anomalies.findings()
            if f.get("severity") in ("warn", "critical")
        ]

    def check(self, notify: bool = False, include_drift: bool = False) -> dict[str, Any]:
        store = self.state
        st = store.load()
        now = self.now()
        checks: list[tuple[str, Callable[[], list[Alarm]]]] = [
            ("new_devices", lambda: self._new_devices(st)),
            ("link_flapping", self._flapping),
            ("line", self._line),
            ("battery", self._battery),
            ("updates", self._updates),
            ("anomalies", self._anomalies),
            *self.extra_checks,
        ]
        if include_drift:
            checks.append(("config_drift", self._drift))
        current: dict[str, Alarm] = {}
        sources: dict[str, Any] = {}
        for name, fn in checks:
            try:
                for alarm in fn():
                    current[alarm.key] = alarm
                sources[name] = "ok"
            except (AuthError, ConfirmationRequiredError):
                raise
            except FritzError as exc:
                sources[name] = exc.to_dict()

        active: dict[str, Any] = st.get("active") or {}
        resolved_recent: dict[str, float] = {
            k: v for k, v in (st.get("resolved") or {}).items() if now - v < self.repeat_s
        }
        to_notify: list[Alarm] = []
        report: list[dict[str, Any]] = []
        for key, alarm in current.items():
            prev = active.get(key)
            if prev is None:
                status = "reappeared" if key in resolved_recent else "new"
                entry: dict[str, Any] = {"first_seen": now, "last_notified": None}
            else:
                status = "active"
                entry = prev
            last = entry.get("last_notified")
            # never notified yet (and not just flapping back) or repeat interval elapsed
            due = (last is None and status != "reappeared") or (last is not None and now - float(last) >= self.repeat_s)
            if notify and due:
                to_notify.append(alarm)
                entry["last_notified"] = now
            active[key] = {**entry, "type": alarm.type, "severity": alarm.severity, "message": alarm.message}
            resolved_recent.pop(key, None)
            report.append({**asdict(alarm), "status": status, "first_seen": _iso(float(entry["first_seen"]))})
        resolved = []
        for key in [k for k in active if k not in current]:
            gone = active.pop(key)
            if not key.startswith("new_device:"):
                resolved.append({"key": key, "message": gone.get("message")})
            resolved_recent[key] = now
        st["active"] = active
        st["resolved"] = resolved_recent
        notifications: dict[str, Any] = {}
        if notify:
            notifier = self.notifier
            if not notifier.channels:
                notifications = {"note": "Kein Benachrichtigungskanal konfiguriert (FRITZ_ALERT_*)."}
            elif to_notify:
                notifications = notifier.send(self.service.box_host, to_notify)
            else:
                notifications = {"note": "Nichts Neues – keine Benachrichtigung (Entprellung)."}
        # new devices are one-shot: forget them once reported, the MAC is now known
        st["active"] = {k: v for k, v in st["active"].items() if not k.startswith("new_device:")}
        store.save(st)
        order = {"critical": 0, "warn": 1, "info": 2}
        report.sort(key=lambda a: (order.get(a["severity"], 3), a["type"]))
        return {
            "alarms": report,
            "count": len(report),
            "new": sum(1 for a in report if a["status"] == "new"),
            "resolved": resolved,
            "sources": sources,
            "notified": [a.key for a in to_notify],
            "notifications": notifications,
            "channels": self.notifier.channels,
            "repeat_hours": round(self.repeat_s / 3600, 1),
            "note": "Entprellt: ein Alarm wird beim Auftreten gemeldet und höchstens alle repeat_hours wiederholt. "
            "Neue Geräte werden einmal gemeldet; der erste Lauf lernt nur die vorhandenen Geräte.",
        }


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts))


def register_alert_tools(tool: ToolDecorator, svc: Callable[[str | None], AlarmService]) -> None:
    @tool(Tier.READ, _NOTIFY)
    def alarms_check(
        notify: Annotated[
            bool, Field(description="Neue Alarme an die konfigurierten Kanäle senden (HA-Webhook, ntfy, Telegram)")
        ] = False,
        include_drift: Annotated[
            bool, Field(description="Auch Konfig-Abweichung zum letzten Schnappschuss prüfen (liest viel)")
        ] = False,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Alarme prüfen (nur lesend an der Box): neue Geräte, Link-Flapping, Leitungs-Grenzwerte, Batterie schwach,
        Updates verfügbar, Anomalien der Messreihe (schleichende Verschlechterung), optional Konfig-Abweichung;
        entprellt (Zustand lokal). Mit notify=true gehen NEUE Alarme
        an die per Umgebung konfigurierten Kanäle – deren URLs/Tokens werden nie ausgegeben."""
        return svc(box).check(notify, include_drift)
