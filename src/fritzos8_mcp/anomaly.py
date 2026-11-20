"""Stage 10.1 – anomaly detection on the local measurement series (stage 8.1): creeping degradation that a single
snapshot cannot show.

Compares a *recent* window (default the last 24 h) with a *baseline* (the days before, default 14 days back) and
fits trends over the whole window. Reads only the local SQLite file – never the box.

Checks (each conservative, phrased as "deutet auf …"):

* ``snr_trend`` – DSL noise margin falls steadily (linear fit, dB/day) or the recent median is clearly below the
  baseline median; with a projection when the warn threshold of the network doctor (6 dB) would be reached.
* ``sync_rate`` – the recent median sync rate is clearly below the baseline (line was resynced lower).
* ``error_rate`` – a DSL error counter grows much faster than in the baseline (counter resets are ignored).
* ``reconnects`` – reconnects/resyncs/WAN-down events are more frequent than in the baseline.
* ``device_drops`` – devices go offline more often than usual (all devices and per device).
* ``device_flapping`` – a device drops out briefly (back within minutes) several times a day on several days. This
  is chronic, not a change, so the baseline comparison above would never flag it. Devices that drop at the same
  moments are reported together (common switch/port/power supply – or all idle at once).

Too little data is reported as such (``status: insufficient_data``) – never as "alles gut".
"""

from __future__ import annotations

import itertools
import statistics
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from .errors import InvalidParameterError
from .nasremote import ToolDecorator
from .security import Tier
from .toolargs import READ, BoxArg

if TYPE_CHECKING:
    from .history import HistoryStore

DAY = 86400.0

# Documented thresholds (returned with every report).
ANOMALY_THRESHOLDS: dict[str, Any] = {
    "min_baseline_hours": 24,
    "min_points_trend": 12,
    "snr_slope_warn_db_per_day": -0.15,
    "snr_total_drop_warn_db": 1.0,
    "snr_median_drop_warn_db": 1.5,
    "snr_warn_level_db": 6.0,  # network doctor: dsl_snr_margin_warn_db
    "snr_projection_days": 14,
    "sync_rate_drop_ratio": 0.9,
    "error_rate_factor": 3.0,
    # minimum growth within the recent window before a counter is worth a finding
    "error_min_increase": {
        "CRCErrors": 100,
        "ATUCCRCErrors": 100,
        "FECErrors": 10000,
        "ATUCFECErrors": 10000,
        "ErroredSecs": 10,
        "SeverelyErroredSecs": 5,
    },
    "reconnect_min_recent": 3,
    "reconnect_factor": 2.0,
    "device_drops_min_recent": 10,
    "device_drops_factor": 2.0,
    "device_drop_single_min": 4,
    "device_drop_single_factor": 3.0,
    "device_flap_max_minutes": 15,
    "device_flap_min_per_day": 3,
    "device_flap_min_days": 2,
    "device_flap_together_ratio": 0.8,
}

RECONNECT_EVENTS = ("wan_reconnect", "dsl_resync", "wan_down")


def _median(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def _increase(points: list[tuple[float, float]]) -> float:
    """Growth of a counter; a negative step (reset by resync/reboot) is ignored."""
    return sum(max(0.0, b[1] - a[1]) for a, b in itertools.pairwise(points))


def _span_h(points: list[tuple[float, float]]) -> float:
    return (points[-1][0] - points[0][0]) / 3600 if len(points) > 1 else 0.0


class AnomalyDetector:
    def __init__(self, store: Callable[[], HistoryStore], now: Callable[[], float] = time.time) -> None:
        self._store = store
        self.now = now

    # ------------------------------------------------------------ public

    def detect(self, days: float = 14, recent_hours: float = 24) -> dict[str, Any]:
        if not 1 <= days <= 366:
            raise InvalidParameterError("days muss zwischen 1 und 366 liegen.")
        if not 1 <= recent_hours <= 24 * 7 or recent_hours >= days * 24:
            raise InvalidParameterError("recent_hours muss zwischen 1 und 168 liegen und kürzer als days sein.")
        store = self._store()
        end = self.now()
        start = end - days * DAY
        split = end - recent_hours * 3600
        findings: list[dict[str, Any]] = []
        checks: dict[str, str] = {}

        def run(name: str, fn: Callable[[], str]) -> None:
            checks[name] = fn()

        known = set(store.metrics())
        run("snr_trend", lambda: self._snr(store, known, start, split, end, findings))
        run("sync_rate", lambda: self._sync(store, known, start, split, end, findings))
        run("error_rate", lambda: self._errors(store, known, start, split, end, recent_hours, findings))
        events = store.events(start, end)
        run("reconnects", lambda: self._reconnects(events, start, split, end, findings))
        run("device_drops", lambda: self._devices(events, start, split, end, findings))
        run("device_flapping", lambda: self._flapping(events, end, findings))
        evaluated = [k for k, v in checks.items() if v != "insufficient_data"]
        status = "insufficient_data" if not evaluated else ("anomalies" if findings else "ok")
        return {
            "status": status,
            "window": {"days": days, "recent_hours": recent_hours},
            "findings": findings,
            "checks": checks,
            "thresholds": ANOMALY_THRESHOLDS,
            "note": "Vergleicht die letzten recent_hours mit den Tagen davor (lokale Messreihe, keine Box-Abfrage). "
            "Ohne genügend Messdaten (fritzos8-collector) gibt es keine Aussage – 'insufficient_data' heißt nicht "
            "'alles gut'.",
        }

    def findings(self) -> list[dict[str, Any]]:
        """Findings for the network doctor / alarms (default window)."""
        return list(self.detect()["findings"])

    # ------------------------------------------------------------ checks

    @staticmethod
    def _finding(
        severity: str, kind: str, finding: str, cause: str, recommendation: str, **evidence: Any
    ) -> dict[str, Any]:
        return {
            "severity": severity,
            "area": "trend",
            "kind": kind,
            "finding": finding,
            "likely_cause": cause,
            "recommendation": recommendation,
            "evidence": evidence,
        }

    def _snr(
        self,
        store: HistoryStore,
        known: set[str],
        start: float,
        split: float,
        end: float,
        out: list[dict[str, Any]],
    ) -> str:
        t = ANOMALY_THRESHOLDS
        evaluated = False
        for metric, label in (("dsl.snr_down_db", "Downstream"), ("dsl.snr_up_db", "Upstream")):
            if metric not in known:
                continue
            points = store.series(metric, start, end)
            baseline = [v for ts, v in points if ts < split]
            recent = [v for ts, v in points if ts >= split]
            if len(points) < t["min_points_trend"] or _span_h(points) < t["min_baseline_hours"] or not recent:
                continue
            evaluated = True
            xs = [(ts - points[0][0]) / DAY for ts, _ in points]
            ys = [v for _, v in points]
            if len(set(xs)) < 2:
                continue
            slope, _ = statistics.linear_regression(xs, ys)
            fitted_drop = -slope * xs[-1]
            current = statistics.median(recent)
            base_med = _median(baseline)
            median_drop = (base_med - current) if base_med is not None else 0.0
            trend_bad = slope <= t["snr_slope_warn_db_per_day"] and fitted_drop >= t["snr_total_drop_warn_db"]
            if not trend_bad and median_drop < t["snr_median_drop_warn_db"]:
                continue
            days_to_warn = None
            if slope < 0 and current > t["snr_warn_level_db"]:
                days_to_warn = round((current - t["snr_warn_level_db"]) / -slope, 1)
            severity = (
                "warn"
                if (days_to_warn is not None and days_to_warn <= t["snr_projection_days"])
                or median_drop >= t["snr_median_drop_warn_db"]
                else "info"
            )
            text = f"Störabstandsmarge {label} sinkt schleichend: {round(slope * 7, 2)} dB/Woche"
            if base_med is not None:
                text += f", Median {round(base_med, 1)} → {round(current, 1)} dB"
            if days_to_warn is not None and days_to_warn <= t["snr_projection_days"]:
                text += f" – bei diesem Trend in ca. {days_to_warn} Tagen unter {t['snr_warn_level_db']} dB"
            out.append(
                self._finding(
                    severity,
                    f"snr_trend:{metric}",
                    text,
                    "Deutet auf eine sich verschlechternde Leitung (Feuchtigkeit/Korrosion an Dose oder Kabel, neue "
                    "Störquelle, Nachbaranschlüsse) – noch bevor es zu Abbrüchen kommt.",
                    "Verkabelung zwischen Dose und Box prüfen (möglichst kurz, kein Verlängerungskabel), Verlauf "
                    "beobachten; bei anhaltendem Trend mit isp_report beim Anbieter melden.",
                    metric=metric,
                    slope_db_per_day=round(slope, 3),
                    baseline_median_db=None if base_med is None else round(base_med, 2),
                    recent_median_db=round(current, 2),
                    days_until_warn_level=days_to_warn,
                    points=len(points),
                )
            )
        return "evaluated" if evaluated else "insufficient_data"

    def _sync(
        self,
        store: HistoryStore,
        known: set[str],
        start: float,
        split: float,
        end: float,
        out: list[dict[str, Any]],
    ) -> str:
        t = ANOMALY_THRESHOLDS
        evaluated = False
        for metric, label in (("dsl.down_kbps", "Downstream"), ("dsl.up_kbps", "Upstream")):
            if metric not in known:
                continue
            points = store.series(metric, start, end)
            baseline = [(ts, v) for ts, v in points if ts < split]
            recent = [v for ts, v in points if ts >= split]
            if not recent or _span_h(baseline) < t["min_baseline_hours"]:
                continue
            evaluated = True
            base_med = statistics.median(v for _, v in baseline)
            cur = statistics.median(recent)
            if base_med > 0 and cur < base_med * t["sync_rate_drop_ratio"]:
                pct = round((1 - cur / base_med) * 100)
                out.append(
                    self._finding(
                        "warn",
                        f"sync_rate:{metric}",
                        f"Sync-Rate {label} liegt {pct} % unter dem bisherigen Median ({int(base_med)} → {int(cur)} "
                        "kbit/s)",
                        "Deutet auf eine Neusynchronisation mit schlechteren Leitungswerten (die Box wählt nach "
                        "Störungen eine robustere, langsamere Einstellung).",
                        "line_diagnostics und dsl_info prüfen; bleibt die Rate niedrig, Störung beim Anbieter melden "
                        "(isp_report).",
                        metric=metric,
                        baseline_median_kbps=round(base_med),
                        recent_median_kbps=round(cur),
                    )
                )
        return "evaluated" if evaluated else "insufficient_data"

    def _errors(
        self,
        store: HistoryStore,
        known: set[str],
        start: float,
        split: float,
        end: float,
        recent_hours: float,
        out: list[dict[str, Any]],
    ) -> str:
        t = ANOMALY_THRESHOLDS
        evaluated = False
        for name, minimum in t["error_min_increase"].items():
            metric = f"dsl.err.{name}"
            if metric not in known:
                continue
            points = store.series(metric, start, end)
            baseline = [(ts, v) for ts, v in points if ts < split]
            recent = [(ts, v) for ts, v in points if ts >= split]
            if baseline and recent:
                recent = [baseline[-1], *recent]  # growth across the boundary belongs to the recent window
            span_b = _span_h(baseline)
            if span_b < t["min_baseline_hours"] or len(recent) < 2:
                continue
            evaluated = True
            rate_b = _increase(baseline) / span_b  # per hour
            inc_r = _increase(recent)
            rate_r = inc_r / max(_span_h(recent), 1.0)
            floor = minimum / 24  # never compare against "0 per hour"
            if inc_r >= minimum and rate_r >= t["error_rate_factor"] * max(rate_b, floor):
                factor = round(rate_r / max(rate_b, floor), 1)
                out.append(
                    self._finding(
                        "warn",
                        f"error_rate:{name}",
                        f"Fehlerzähler {name} wächst {factor}× schneller als bisher (+{int(inc_r)} in "
                        f"{int(recent_hours)} h)",
                        "Deutet auf zunehmende Störungen auf der Leitung (Impulsstörungen, schlechter Kontakt) – "
                        "kann Abbrüchen und Resyncs vorausgehen.",
                        "Verkabelung prüfen, Störquellen in der Nähe (Netzteile, Dimmer) ausschließen; Verlauf mit "
                        "history_query beobachten.",
                        metric=metric,
                        baseline_per_hour=round(rate_b, 2),
                        recent_per_hour=round(rate_r, 2),
                        recent_increase=int(inc_r),
                    )
                )
        return "evaluated" if evaluated else "insufficient_data"

    @staticmethod
    def _per_day(count: int, seconds: float) -> float:
        return count / max(seconds / DAY, 1e-9)

    def _reconnects(
        self, events: list[tuple[float, str, str]], start: float, split: float, end: float, out: list[dict[str, Any]]
    ) -> str:
        t = ANOMALY_THRESHOLDS
        first = events[0][0] if events else None
        if first is None or split - first < t["min_baseline_hours"] * 3600:
            return "insufficient_data"
        base_span = split - first
        rel = [e for e in events if e[1] in RECONNECT_EVENTS]
        base = sum(1 for e in rel if e[0] < split)
        recent = sum(1 for e in rel if e[0] >= split)
        base_rate = self._per_day(base, base_span)
        recent_rate = self._per_day(recent, end - split)
        if recent >= t["reconnect_min_recent"] and recent_rate >= t["reconnect_factor"] * base_rate + 1:
            kinds: dict[str, int] = {}
            for e in rel:
                if e[0] >= split:
                    kinds[e[1]] = kinds.get(e[1], 0) + 1
            out.append(
                AnomalyDetector._finding(
                    "warn",
                    "reconnects",
                    f"Verbindungsabbrüche häufen sich: {recent} im aktuellen Zeitraum, bisher "
                    f"{round(base_rate, 1)} pro Tag",
                    "Deutet auf eine instabile Leitung oder Störung beim Anbieter.",
                    "network_doctor und line_diagnostics ausführen; für den Anbieter isp_report erstellen.",
                    recent_events=kinds,
                    baseline_per_day=round(base_rate, 2),
                    recent_per_day=round(recent_rate, 2),
                )
            )
        return "evaluated"

    def _devices(
        self, events: list[tuple[float, str, str]], start: float, split: float, end: float, out: list[dict[str, Any]]
    ) -> str:
        t = ANOMALY_THRESHOLDS
        dev = [e for e in events if e[1] in ("device_offline", "device_online")]
        first = dev[0][0] if dev else None
        if first is None or split - first < t["min_baseline_hours"] * 3600:
            return "insufficient_data"
        base_span = split - first
        names: dict[str, str] = {}
        for _, kind, detail in dev:
            if kind == "device_online" and detail.endswith(")") and " (" in detail:
                name, mac = detail[:-1].rsplit(" (", 1)
                names[mac] = name
        offline = [e for e in dev if e[1] == "device_offline"]
        base = [e for e in offline if e[0] < split]
        recent = [e for e in offline if e[0] >= split]
        base_rate = self._per_day(len(base), base_span)
        recent_rate = self._per_day(len(recent), end - split)
        if len(recent) >= t["device_drops_min_recent"] and recent_rate >= t["device_drops_factor"] * max(base_rate, 1):
            out.append(
                self._finding(
                    "warn",
                    "device_drops",
                    f"Geräte verlieren häufiger die Verbindung: {len(recent)} Abmeldungen im aktuellen Zeitraum, "
                    f"bisher {round(base_rate, 1)} pro Tag",
                    "Deutet auf ein WLAN-Problem (Kanalstörung, Repeater, Funklöcher) oder Energiesparfunktionen.",
                    "wlan_settings/mesh_overview prüfen, network_optimizer_suggest ausführen.",
                    baseline_per_day=round(base_rate, 2),
                    recent_per_day=round(recent_rate, 2),
                )
            )
        per_mac_recent: dict[str, int] = {}
        per_mac_base: dict[str, int] = {}
        for ts, _, mac in offline:
            target = per_mac_recent if ts >= split else per_mac_base
            target[mac] = target.get(mac, 0) + 1
        span_days = base_span / DAY
        flagged = []
        for mac, n in sorted(per_mac_recent.items(), key=lambda kv: -kv[1]):
            usual = per_mac_base.get(mac, 0) / max(span_days, 1e-9)
            if n >= t["device_drop_single_min"] and n >= t["device_drop_single_factor"] * max(usual, 1):
                flagged.append({"mac": mac, "name": names.get(mac), "recent": n, "usual_per_day": round(usual, 2)})
        for d in flagged[:5]:
            out.append(
                self._finding(
                    "info",
                    f"device_drops:{d['mac']}",
                    f"Gerät {d['name'] or d['mac']} verliert ungewöhnlich oft die Verbindung ({d['recent']}× statt "
                    f"sonst {d['usual_per_day']}× pro Tag)",
                    "Deutet auf schwachen Empfang am Standort des Geräts, Energiesparmodus oder einen "
                    "Kabel-/Port-Fehler.",
                    "device_connection_quality bzw. test_my_device für das Gerät ausführen.",
                    **d,
                )
            )
        return "evaluated"

    def _flapping(self, events: list[tuple[float, str, str]], end: float, out: list[dict[str, Any]]) -> str:
        t = ANOMALY_THRESHOLDS
        dev = [e for e in events if e[1] in ("device_offline", "device_online")]
        if not dev or end - dev[0][0] < t["device_flap_min_days"] * DAY:
            return "insufficient_data"
        first = dev[0][0]
        names: dict[str, str] = {}
        pending: dict[str, float] = {}  # mac → time it went offline
        drops: dict[str, list[float]] = {}  # mac → times of short drops
        for ts, kind, detail in dev:
            if kind == "device_offline":
                pending[detail] = ts
                continue
            if not (detail.endswith(")") and " (" in detail):
                continue
            name, mac = detail[:-1].rsplit(" (", 1)
            names[mac] = name
            went = pending.pop(mac, None)
            if went is not None and ts - went <= t["device_flap_max_minutes"] * 60:
                drops.setdefault(mac, []).append(went)
        flagged: dict[str, dict[str, Any]] = {}
        for mac, times in drops.items():
            per_day: dict[int, int] = {}
            for ts in times:
                day = int((ts - first) // DAY)
                per_day[day] = per_day.get(day, 0) + 1
            bad_days = sum(1 for n in per_day.values() if n >= t["device_flap_min_per_day"])
            if bad_days >= t["device_flap_min_days"]:
                days_total = max((end - first) / DAY, 1.0)
                flagged[mac] = {
                    "mac": mac,
                    "name": names.get(mac),
                    "short_drops": len(times),
                    "per_day": round(len(times) / days_total, 1),
                    "days_with_drops": bad_days,
                }
        # devices dropping at the same moments → one finding per group
        done: set[str] = set()
        for mac, d in sorted(flagged.items(), key=lambda kv: -kv[1]["short_drops"]):
            if mac in done:
                continue
            mine = set(drops[mac])
            group = [mac] + [
                other
                for other in flagged
                if other != mac
                and other not in done
                and len(mine & set(drops[other])) >= t["device_flap_together_ratio"] * min(len(mine), len(drops[other]))
            ]
            done.update(group)
            label = ", ".join(flagged[m]["name"] or m for m in group)
            together = len(group) > 1
            out.append(
                self._finding(
                    "info",
                    f"device_flapping:{mac}",
                    f"{'Geräte' if together else 'Gerät'} {label} "
                    f"{'fallen' if together else 'fällt'} regelmäßig kurz aus: {d['short_drops']}× in "
                    f"{d['days_with_drops']} Tagen, jeweils nach höchstens {t['device_flap_max_minutes']} min zurück"
                    + (" – immer gleichzeitig" if together else ""),
                    "Deutet auf kurze Unterbrechungen (Kabel, Switch, Netzteil, WLAN-Empfang) – oder darauf, dass "
                    "das Gerät zeitweise keinen Verkehr hat und die Box es kurz als inaktiv führt (häufig bei "
                    "kabelgebundenen Steuerungen)."
                    + (" Gleichzeitige Ausfälle sprechen für eine gemeinsame Ursache." if together else ""),
                    "device_connection_quality für das Gerät ausführen; prüfen, ob andere Geräte am selben "
                    "Port/Switch zur selben Zeit ausfallen. Fallen sie nicht aus, ist Leerlauf wahrscheinlicher "
                    "als ein Leitungsproblem.",
                    devices=[flagged[m] for m in group],
                )
            )
            if len(done) >= 10:
                break
        return "evaluated"


Days = Annotated[float, Field(description="Betrachteter Zeitraum in Tagen rückwärts (Standard 14)", ge=1, le=366)]
RecentHours = Annotated[
    float, Field(description="Aktueller Zeitraum in Stunden, der mit den Tagen davor verglichen wird", ge=1, le=168)
]


def register_anomaly_tools(tool: ToolDecorator, svc: Callable[[str | None], AnomalyDetector]) -> None:
    @tool(Tier.READ, READ)
    def history_anomalies(days: Days = 14, recent_hours: RecentHours = 24, box: BoxArg = None) -> dict[str, Any]:
        """Anomalie-Erkennung auf der lokalen Messreihe (keine Box-Abfrage): schleichende Verschlechterung –
        sinkende DSL-Störabstandsmarge (Trend + Prognose), niedrigere Sync-Rate, schneller wachsende Fehlerzähler,
        gehäufte Neuverbindungen, häufigere Geräteabbrüche, Geräte, die regelmäßig kurz wegfallen.
        Vergleicht die letzten recent_hours mit den Tagen davor;
        zu wenig Daten = 'insufficient_data'. Befunde erscheinen auch in network_doctor und alarms_check."""
        return svc(box).detect(days, recent_hours)
