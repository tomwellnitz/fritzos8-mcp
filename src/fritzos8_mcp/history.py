"""Stage 8.1 – Messreihe: periodic samples of line/WAN/throughput/device values in a local SQLite file, plus the
MCP tools to query and summarise them.

* ``Sampler.collect()`` reads a handful of cheap TR-064 values (WAN status, DSL values/error counters, online
  monitor, host change counter; the host list only when the change counter moved) and returns metrics + events.
  Extra samplers (e.g. line diagnostics of stage 8.9) can be plugged in via ``extra``.
* ``HistoryStore`` keeps ``samples(ts, metric, value)``, ``events(ts, kind, detail)`` and ``runs(ts, ok, …)`` in
  ``<state dir>/<box>/history.sqlite`` (directory 0700, file 0600). Retention: ``FRITZ_HISTORY_DAYS`` (default 30).
  Failed runs are stored as runs too, so gaps show up as gaps and not as flat lines.
* ``fritzos8-collector`` (console script) runs ``collect`` for every configured box every
  ``FRITZ_HISTORY_INTERVAL`` seconds (default 300) – always read-only, whatever FRITZ_ALLOW_* says. With
  ``FRITZ_MQTT_HOST`` it also publishes the values and alarms to Home Assistant (stage 10.3, ``mqttbridge``).

Nothing secret is stored: only numbers, connection states and device names/MACs for online/offline events
(personal data of the owner, local file only).
"""

from __future__ import annotations

import contextlib
import itertools
import logging
import os
import sqlite3
import statistics
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from .errors import AuthError, FritzError, InvalidParameterError
from .nasremote import ToolDecorator
from .paths import ensure_private_dir, safe_component, state_dir
from .security import Tier
from .toolargs import READ, BoxArg

if TYPE_CHECKING:
    from .service import FritzService

log = logging.getLogger(__name__)

DEFAULT_INTERVAL_S = 300
DEFAULT_RETENTION_DAYS = 30
MAX_POINTS = 500
GAP_FACTOR = 2.5  # a pause longer than 2.5 × the usual interval counts as a gap

# DSL error counters (GetStatisticsTotal without "New") that become metrics dsl.err.<name>
DSL_ERROR_COUNTERS = ("CRCErrors", "FECErrors", "ATUCCRCErrors", "ATUCFECErrors", "ErroredSecs", "SeverelyErroredSecs")


@dataclass
class Sample:
    ts: float
    metrics: dict[str, float] = field(default_factory=dict)
    events: list[tuple[str, str]] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)


def _num(value: Any) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


# ------------------------------------------------------------------ storage


class HistoryStore:
    def __init__(self, path: Path, retention_days: float = DEFAULT_RETENTION_DAYS) -> None:
        self.path = path
        self.retention_days = retention_days
        self._lock = threading.Lock()

    @classmethod
    def for_box(cls, box_host: str, root: Path | None = None, environ: dict[str, str] | None = None) -> HistoryStore:
        env = os.environ if environ is None else environ
        days = _num(env.get("FRITZ_HISTORY_DAYS")) or DEFAULT_RETENTION_DAYS
        base = ensure_private_dir((root or state_dir()) / safe_component(box_host))
        return cls(base / "history.sqlite", days)

    @contextlib.contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            new = not self.path.exists()
            ensure_private_dir(self.path.parent)
            con = sqlite3.connect(self.path)
            try:
                if new:
                    self.path.chmod(0o600)
                con.executescript(
                    "CREATE TABLE IF NOT EXISTS samples (ts REAL NOT NULL, metric TEXT NOT NULL, value REAL NOT NULL,"
                    " PRIMARY KEY (ts, metric));"
                    "CREATE TABLE IF NOT EXISTS events (ts REAL NOT NULL, kind TEXT NOT NULL, detail TEXT);"
                    "CREATE TABLE IF NOT EXISTS runs (ts REAL PRIMARY KEY, ok INTEGER NOT NULL, duration_s REAL,"
                    " error TEXT);"
                    "CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT);"
                    "CREATE INDEX IF NOT EXISTS samples_metric ON samples (metric, ts);"
                )
                yield con
                con.commit()
            finally:
                con.close()

    def save(self, sample: Sample, ok: bool, duration_s: float, error: str | None = None) -> None:
        with self._db() as con:
            con.executemany(
                "INSERT OR REPLACE INTO samples VALUES (?, ?, ?)",
                [(sample.ts, k, v) for k, v in sample.metrics.items()],
            )
            con.executemany("INSERT INTO events VALUES (?, ?, ?)", [(sample.ts, k, d) for k, d in sample.events])
            con.execute("INSERT OR REPLACE INTO runs VALUES (?, ?, ?, ?)", (sample.ts, int(ok), duration_s, error))
            cutoff = sample.ts - self.retention_days * 86400
            for table in ("samples", "events", "runs"):
                con.execute(f"DELETE FROM {table} WHERE ts < ?", (cutoff,))  # noqa: S608 - fixed table names

    def get_state(self, key: str) -> str | None:
        with self._db() as con:
            row = con.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row[0])

    def set_state(self, key: str, value: str) -> None:
        with self._db() as con:
            con.execute("INSERT OR REPLACE INTO state VALUES (?, ?)", (key, value))

    def metrics(self) -> list[str]:
        with self._db() as con:
            return [r[0] for r in con.execute("SELECT DISTINCT metric FROM samples ORDER BY metric")]

    def series(self, metric: str, start: float, end: float) -> list[tuple[float, float]]:
        with self._db() as con:
            rows = con.execute(
                "SELECT ts, value FROM samples WHERE metric = ? AND ts BETWEEN ? AND ? ORDER BY ts",
                (metric, start, end),
            ).fetchall()
        return [(float(t), float(v)) for t, v in rows]

    def events(self, start: float, end: float, kind: str | None = None) -> list[tuple[float, str, str]]:
        sql = "SELECT ts, kind, detail FROM events WHERE ts BETWEEN ? AND ?"
        args: list[Any] = [start, end]
        if kind:
            sql += " AND kind = ?"
            args.append(kind)
        with self._db() as con:
            return [(float(t), str(k), str(d or "")) for t, k, d in con.execute(sql + " ORDER BY ts", args)]

    def runs(self, start: float, end: float) -> list[tuple[float, bool, str | None]]:
        with self._db() as con:
            rows = con.execute("SELECT ts, ok, error FROM runs WHERE ts BETWEEN ? AND ? ORDER BY ts", (start, end))
            return [(float(t), bool(ok), e) for t, ok, e in rows]


# ------------------------------------------------------------------ sampling


# Live 7583/8.26: die Sync-Rate schwankt ohne Resync um wenige 100 kbit/s (Ratenanpassung, < 0,1 %).
# Als Resync zählt nur eine deutliche Änderung oder eine Änderung zusammen mit einer Neuverbindung.
RESYNC_MIN_CHANGE = 0.01


# Box-Laufzeit (DeviceInfo NewUpTime): weicht sie um mehr als das ab, gilt das als Neustart. Der Abgleich
# mit der verstrichenen Zeit erkennt auch Neustarts, die in eine Messlücke fallen.
REBOOT_TOLERANCE_S = 600


def _is_resync(last: str, sync: str, events: list[tuple[str, str]]) -> bool:
    if any(kind in ("wan_reconnect", "wan_down", "wan_up") for kind, _ in events):
        return True
    try:
        pairs = list(zip((float(x) for x in last.split("/")), (float(x) for x in sync.split("/")), strict=True))
    except ValueError:
        return True  # unlesbarer Vorwert: lieber melden als verschlucken
    return any(old <= 0 or abs(new - old) / old > RESYNC_MIN_CHANGE for old, new in pairs)


class Sampler:
    """Reads one sample from a box. Every part is optional – a missing part is an error entry, not a failure."""

    def __init__(
        self,
        service: FritzService,
        store: HistoryStore,
        *,
        now: Callable[[], float] = time.time,
        extra: list[Callable[[], dict[str, float]]] | None = None,
    ) -> None:
        self.service = service
        self.store = store
        self.now = now
        self.extra = extra or []

    def _part(self, sample: Sample, name: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except AuthError:
            raise
        except FritzError as exc:
            sample.errors[name] = str(exc)

    def collect(self) -> Sample:
        sample = Sample(ts=self.now())
        tr = self.service.tr064

        def system() -> None:
            uptime = _num(tr.system_info().get("uptime_s"))
            if uptime is None:
                return
            sample.metrics["box.uptime_s"] = uptime
            last = _num(self.store.get_state("box.uptime_s"))
            last_ts = _num(self.store.get_state("box.uptime_ts"))
            if last is not None and last_ts is not None:
                expected = last + max(0.0, sample.ts - last_ts)
                if uptime < expected - REBOOT_TOLERANCE_S:
                    sample.events.append(("box_reboot", f"FRITZ!Box neu gestartet (läuft seit {int(uptime)} s)"))
            self.store.set_state("box.uptime_s", str(uptime))
            self.store.set_state("box.uptime_ts", str(sample.ts))

        def wan() -> None:
            st = tr.wan_connection_status()
            connected = st.get("status") == "Connected"
            sample.metrics["wan.connected"] = 1.0 if connected else 0.0
            uptime = _num(st.get("uptime_s"))
            if uptime is not None:
                sample.metrics["wan.uptime_s"] = uptime
                last = _num(self.store.get_state("wan.uptime_s"))
                if last is not None and uptime < last:
                    sample.events.append(("wan_reconnect", f"Verbindung neu aufgebaut (Laufzeit {int(uptime)} s)"))
                self.store.set_state("wan.uptime_s", str(uptime))
            last_conn = self.store.get_state("wan.connected")
            if last_conn is not None and last_conn != str(connected):
                sample.events.append(("wan_up" if connected else "wan_down", str(st.get("status"))))
            self.store.set_state("wan.connected", str(connected))

        def dsl() -> None:
            d = self.service.diag.dsl_info()
            if not d.get("available"):
                return
            for key, metric in (
                ("down_kbps", "dsl.down_kbps"),
                ("up_kbps", "dsl.up_kbps"),
                ("snr_down_db", "dsl.snr_down_db"),
                ("snr_up_db", "dsl.snr_up_db"),
                ("attenuation_down_db", "dsl.attenuation_down_db"),
            ):
                v = _num(d.get(key))
                if v is not None:
                    sample.metrics[metric] = v
            errors = d.get("errors_total") or {}
            for name in DSL_ERROR_COUNTERS:
                v = _num(errors.get(name))
                if v is not None:
                    sample.metrics[f"dsl.err.{name}"] = v
            sync = f"{d.get('down_kbps')}/{d.get('up_kbps')}"
            last = self.store.get_state("dsl.sync")
            if last is not None and last != sync and _is_resync(last, sync, sample.events):
                sample.events.append(("dsl_resync", f"Sync-Rate {last} → {sync} kbit/s"))
            self.store.set_state("dsl.sync", sync)

        def throughput() -> None:
            mon = self.service.netinfo.online_monitor().get("throughput") or {}
            if not mon.get("available"):
                return
            for direction in ("down", "up"):
                v = _num((mon.get(direction) or {}).get("avg_mbit_s"))
                if v is not None:
                    sample.metrics[f"throughput.{direction}_mbit_s"] = v

        def hosts() -> None:
            counter = tr.change_counter()
            if counter is not None:
                sample.metrics["hosts.change_counter"] = float(counter)
            last = self.store.get_state("hosts.change_counter")
            if counter is not None and last == str(counter):
                active = _num(self.store.get_state("hosts.active"))
                if active is not None:
                    sample.metrics["hosts.active"] = active
                return
            current = {h["mac"]: h.get("name") or h["mac"] for h in tr.list_hosts() if h.get("active") and h.get("mac")}
            sample.metrics["hosts.active"] = float(len(current))
            previous = set((self.store.get_state("hosts.active_macs") or "").split(",")) - {""}
            if previous:
                for mac in sorted(set(current) - previous):
                    sample.events.append(("device_online", f"{current[mac]} ({mac})"))
                for mac in sorted(previous - set(current)):
                    sample.events.append(("device_offline", mac))
            self.store.set_state("hosts.active_macs", ",".join(sorted(current)))
            self.store.set_state("hosts.active", str(len(current)))
            if counter is not None:
                self.store.set_state("hosts.change_counter", str(counter))

        self._part(sample, "system", system)
        self._part(sample, "wan", wan)
        self._part(sample, "dsl", dsl)
        self._part(sample, "throughput", throughput)
        self._part(sample, "hosts", hosts)
        for i, fn in enumerate(self.extra):
            self._part(sample, f"extra{i}", lambda fn=fn: sample.metrics.update(fn()))  # type: ignore[misc]
        return sample

    def run_once(self) -> dict[str, Any]:
        start = time.monotonic()
        try:
            sample = self.collect()
        except FritzError as exc:
            sample = Sample(ts=self.now(), errors={"run": str(exc)})
            self.store.save(sample, ok=False, duration_s=time.monotonic() - start, error=str(exc))
            return {"ok": False, "ts": sample.ts, "error": exc.to_dict()}
        ok = bool(sample.metrics)
        error = None if ok else "; ".join(f"{k}: {v}" for k, v in sample.errors.items()) or "keine Werte"
        self.store.save(sample, ok=ok, duration_s=time.monotonic() - start, error=error)
        return {
            "ok": ok,
            "ts": sample.ts,
            "metrics": sample.metrics,
            "events": [{"kind": k, "detail": d} for k, d in sample.events],
            "errors": sample.errors,
            "duration_s": round(time.monotonic() - start, 2),
        }


# ------------------------------------------------------------------ analysis


def find_gaps(runs: list[tuple[float, bool, str | None]], start: float, end: float) -> dict[str, Any]:
    ok_ts = [t for t, ok, _ in runs if ok]
    deltas = [b - a for a, b in itertools.pairwise(ok_ts)]
    interval = statistics.median(deltas) if deltas else None
    gaps: list[dict[str, Any]] = []
    if interval:
        limit = interval * GAP_FACTOR
        for a, b in itertools.pairwise(ok_ts):
            if b - a > limit:
                gaps.append({"from": _iso(a), "to": _iso(b), "minutes": round((b - a) / 60, 1)})
    failed = [{"at": _iso(t), "error": e} for t, ok, e in runs if not ok]
    covered = None
    if interval and ok_ts:
        covered = min(100.0, round(len(ok_ts) * interval / max(end - start, interval) * 100, 1))
    return {
        "interval_s": None if interval is None else round(interval),
        "gaps": gaps,
        "failed_runs": failed[-20:],
        "failed_count": len(failed),
        "coverage_pct": covered,
    }


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts))


def _downsample(points: list[tuple[float, float]], limit: int = MAX_POINTS) -> list[tuple[float, float]]:
    if len(points) <= limit:
        return points
    step = len(points) / limit
    return [points[int(i * step)] for i in range(limit)]


class HistoryService:
    def __init__(self, sampler_factory: Callable[[], Sampler], now: Callable[[], float] = time.time) -> None:
        self._factory = sampler_factory
        self.now = now

    @property
    def sampler(self) -> Sampler:
        return self._factory()

    def collect(self) -> dict[str, Any]:
        return self.sampler.run_once()

    def _window(self, hours: float) -> tuple[float, float]:
        if not 0 < hours <= 24 * 366:
            raise InvalidParameterError("hours muss zwischen 0 und 8784 liegen.")
        end = self.now()
        return end - hours * 3600, end

    def query(self, metric: str, hours: float = 24) -> dict[str, Any]:
        store = self.sampler.store
        start, end = self._window(hours)
        known = store.metrics()
        if metric not in known:
            raise InvalidParameterError(
                f'Unbekannte Messgröße "{metric}".', hint=f"Vorhanden: {', '.join(known) or '– (noch keine Daten)'}"
            )
        points = store.series(metric, start, end)
        values = [v for _, v in points]
        return {
            "metric": metric,
            "from": _iso(start),
            "to": _iso(end),
            "count": len(points),
            "min": min(values) if values else None,
            "max": max(values) if values else None,
            "avg": round(statistics.fmean(values), 3) if values else None,
            "points": [{"t": _iso(t), "v": v} for t, v in _downsample(points)],
            "downsampled": len(points) > MAX_POINTS,
            **{"gaps": find_gaps(store.runs(start, end), start, end)["gaps"]},
        }

    def summary(self, hours: float = 24) -> dict[str, Any]:
        store = self.sampler.store
        start, end = self._window(hours)
        metrics: dict[str, Any] = {}
        for metric in store.metrics():
            values = [v for _, v in store.series(metric, start, end)]
            if not values:
                continue
            entry: dict[str, Any] = {
                "last": values[-1],
                "min": min(values),
                "max": max(values),
                "avg": round(statistics.fmean(values), 3),
            }
            if metric.startswith("dsl.err."):
                # counters: growth within the window (a reset by resync shows as negative step → ignored)
                entry["increase"] = sum(max(0.0, b - a) for a, b in itertools.pairwise(values))
            metrics[metric] = entry
        events = store.events(start, end)
        counts: dict[str, int] = {}
        for _, kind, _ in events:
            counts[kind] = counts.get(kind, 0) + 1
        return {
            "path": str(store.path),
            "from": _iso(start),
            "to": _iso(end),
            "metrics": metrics,
            "event_counts": counts,
            "recent_events": [{"t": _iso(t), "kind": k, "detail": d} for t, k, d in events[-30:]],
            "collection": find_gaps(store.runs(start, end), start, end),
            "note": "Werte stammen aus dem lokalen Collector (fritzos8-collector) bzw. history_collect. "
            "Lücken = in dieser Zeit wurde nicht gemessen; keine Daten bedeutet nicht 'alles gut'.",
        }


Hours = Annotated[float, Field(description="Zeitraum in Stunden rückwärts ab jetzt (Standard 24)", gt=0, le=8784)]


def register_history_tools(tool: ToolDecorator, svc: Callable[[str | None], HistoryService]) -> None:
    @tool(Tier.READ, READ)
    def history_collect(box: BoxArg = None) -> dict[str, Any]:
        """Nimmt jetzt einen Messpunkt der Messreihe auf (WAN-Status/Laufzeit, DSL-Raten/SNR/Fehlerzähler,
        Durchsatz, Geräteanzahl über den Änderungszähler) und speichert ihn NUR LOKAL (SQLite 0600). Ändert an der
        Box nichts. Für regelmäßige Messung den Collector fritzos8-collector laufen lassen."""
        return svc(box).collect()

    @tool(Tier.READ, READ)
    def history_query(
        metric: Annotated[str, Field(description="Messgröße, z. B. dsl.snr_down_db (Liste: history_summary)")],
        hours: Hours = 24,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Zeitreihe einer Messgröße aus der lokalen Messreihe: Punkte (höchstens 500, sonst ausgedünnt),
        min/max/avg und Messlücken im Zeitraum."""
        return svc(box).query(metric, hours)

    @tool(Tier.READ, READ)
    def history_summary(hours: Hours = 24, box: BoxArg = None) -> dict[str, Any]:
        """Zusammenfassung der lokalen Messreihe: je Messgröße last/min/max/avg (Fehlerzähler mit Zuwachs),
        Ereignisse (Box-Neustarts, Neuverbindungen, DSL-Resyncs, Geräte online/offline), Messintervall, Lücken,
        Abdeckung in %."""
        return svc(box).summary(hours)


# ------------------------------------------------------------------ collector daemon


def collector_main() -> None:  # pragma: no cover - thin CLI wrapper, logic is tested via Sampler
    """``fritzos8-collector [--once]``: collect for all boxes every FRITZ_HISTORY_INTERVAL seconds (read-only)."""
    import sys
    from dataclasses import replace

    from . import config as config_mod
    from .errors import ConfigError
    from .redact import RedactingFilter

    try:
        configs = [replace(c, allow_write=False, allow_critical=False) for c in config_mod.load_all()]
    except ConfigError as exc:
        print(f"fritzos8-collector: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    handler = logging.StreamHandler(sys.stderr)
    from .alerts import alert_secrets

    handler.addFilter(RedactingFilter(tuple(s for c in configs for s in c.secrets) + alert_secrets()))
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    interval = max(30.0, _num(os.environ.get("FRITZ_HISTORY_INTERVAL")) or DEFAULT_INTERVAL_S)

    from .server import create_services

    services = create_services(configs)
    once = "--once" in sys.argv[1:]
    from .mqttbridge import MqttBridge, MqttSettings  # stage 10.3: Home Assistant via MQTT discovery

    try:
        mqtt_settings = MqttSettings.from_env()
    except ConfigError as exc:
        print(f"fritzos8-collector: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    bridge = MqttBridge(mqtt_settings) if mqtt_settings else None
    devices: dict[str, dict[str, Any]] = {}
    alerts = (os.environ.get("FRITZ_ALERTS_IN_COLLECTOR") or "").strip().lower() in {"1", "true", "yes", "on"}
    while True:
        started = time.monotonic()
        for name, service in services.items():
            r = service.history.collect()
            expired = service.guest.enforce_expiry()  # stage 8.4: end an expired guest WLAN session
            if expired is not None:
                log.info("%s: Gast-WLAN-Sitzung abgelaufen – abgeschaltet: %s", name, expired.get("verified"))
            alarm_list: list[dict[str, Any]] | None = None
            if alerts:  # stage 8.3: FRITZ_ALERTS_IN_COLLECTOR=1 → check + notify after each measurement
                try:
                    a = service.alarms.check(notify=True)
                    alarm_list = a["alarms"]
                    log.info("%s: %d Alarm(e), %d gemeldet", name, a["count"], len(a["notified"]))
                except FritzError as exc:
                    log.warning("%s: Alarmprüfung fehlgeschlagen: %s", name, exc)
            if bridge is not None:
                if name not in devices:
                    try:
                        info = service.system_info()
                        devices[name] = {"model": info.get("model"), "firmware": info.get("software_version")}
                    except FritzError:
                        devices[name] = {}
                if alarm_list is None:
                    alarm_list = service.alarms.active()  # last known state, no box access
                m = bridge.publish(name, r, alarm_list, devices[name])
                if not m["ok"]:
                    log.warning("%s: MQTT nicht erreichbar (%s) – Messung bleibt lokal gespeichert", name, m["error"])
            log.info(
                "%s: %s, %d Werte, %d Ereignisse",
                name,
                "ok" if r["ok"] else "Fehler",
                len(r.get("metrics") or {}),
                len(r.get("events") or []),
            )
        if once:
            if bridge is not None:
                bridge.close()
            return
        time.sleep(max(1.0, interval - (time.monotonic() - started)))
