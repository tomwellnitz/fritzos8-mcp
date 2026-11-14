"""Stage 8.2 – Störungsprotokoll: a Markdown report for the internet provider from the local measurement series
(stage 8.1): outages, reconnects, DSL resyncs, error counters, sync rate vs. contract rate, gaps.

The report only states what was measured; measurement gaps are listed as gaps, never as "no fault". Throughput
values of the online monitor are utilisation, not a speed test – for a legally relevant measurement the report
points to the Breitbandmessung of the Bundesnetzagentur. Written to ``<state dir>/<box>/reports/`` (0600) on request.
"""

from __future__ import annotations

import itertools
import time
from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from .errors import AuthError, FritzError, InvalidParameterError
from .history import find_gaps
from .nasremote import ToolDecorator
from .paths import write_private
from .security import Tier
from .toolargs import READ, BoxArg

if TYPE_CHECKING:
    from .service import FritzService

# Below this many measurements (≈ 1 h at the collector's 5-min interval) or with unknown coverage the report makes
# no statement about outages – like history_anomalies (status "insufficient_data").
MIN_SAMPLES = 12
INSUFFICIENT_TEXT = "Zu wenig Messdaten – keine Aussage möglich."

BNETZA_HINT = (
    "Für eine rechtlich verwertbare Geschwindigkeitsmessung (Minderung nach § 57 TKG): Breitbandmessung der "
    "Bundesnetzagentur (https://breitbandmessung.de, Desktop-App, Messprotokoll mit 30 Messungen an 3 Tagen)."
)


def parse_time(value: str | None, default: float) -> float:
    if not value:
        return default
    try:
        dt = datetime.fromisoformat(value.strip())
    except ValueError:
        raise InvalidParameterError(
            f'Zeitpunkt "{value}" nicht lesbar – Format z. B. 2026-11-01 oder 2026-11-01T18:00.'
        ) from None
    return dt.timestamp()


def _fmt(ts: float) -> str:
    return time.strftime("%d.%m.%Y %H:%M", time.localtime(ts))


def outages(series: list[tuple[float, float]], end: float) -> list[dict[str, Any]]:
    """Periods in which wan.connected was 0: from the first 0 sample to the next 1 sample (or the window end)."""
    out: list[dict[str, Any]] = []
    start: float | None = None
    for ts, value in series:
        if value < 0.5 and start is None:
            start = ts
        elif value >= 0.5 and start is not None:
            out.append({"from": start, "to": ts, "minutes": round((ts - start) / 60, 1), "open": False})
            start = None
    if start is not None:
        out.append({"from": start, "to": end, "minutes": round((end - start) / 60, 1), "open": True})
    return out


class IspReport:
    def __init__(self, service: FritzService, now: Callable[[], float] = time.time) -> None:
        self.service = service
        self.now = now

    def build(self, start: float, end: float) -> dict[str, Any]:
        if end <= start:
            raise InvalidParameterError("Ende muss nach dem Anfang liegen.")
        store = self.service.history.sampler.store
        connected = store.series("wan.connected", start, end)
        down = outages(connected, end)
        events = store.events(start, end)
        reconnects = [e for e in events if e[1] == "wan_reconnect"]
        resyncs = [e for e in events if e[1] == "dsl_resync"]
        collection = find_gaps(store.runs(start, end), start, end)

        errors: dict[str, float] = {}
        for metric in store.metrics():
            if metric.startswith(("dsl.err.", "fiber.resyncs")):
                values = [v for _, v in store.series(metric, start, end)]
                errors[metric] = sum(max(0.0, b - a) for a, b in itertools.pairwise(values))
        sync_down = [v for _, v in store.series("dsl.down_kbps", start, end)]
        sync_up = [v for _, v in store.series("dsl.up_kbps", start, end)]
        snr = [v for _, v in store.series("dsl.snr_down_db", start, end)]

        live: dict[str, Any] = {}
        try:
            live["system"] = self.service.system_info()
            live["rates"] = self.service.netinfo.online_monitor().get("rates") or {}
        except AuthError:
            raise
        except FritzError as exc:
            live["error"] = exc.to_dict()
        tariff = ((live.get("rates") or {}).get("tariff") or {}).get("down_mbit_s")

        data: dict[str, Any] = {
            "from": _fmt(start),
            "to": _fmt(end),
            "samples": len(connected),
            "outages": [{**o, "from": _fmt(o["from"]), "to": _fmt(o["to"])} for o in down],
            "outage_minutes": round(sum(o["minutes"] for o in down), 1),
            "reconnects": len(reconnects),
            "dsl_resyncs": len(resyncs),
            "error_increase": errors,
            "sync_down_mbit": _range(sync_down, 1000),
            "sync_up_mbit": _range(sync_up, 1000),
            "snr_down_db": _range(snr, 1),
            "tariff_down_mbit": tariff,
            "collection": collection,
            "box": {k: (live.get("system") or {}).get(k) for k in ("model", "software_version")},
        }
        sufficient = len(connected) >= MIN_SAMPLES and collection.get("coverage_pct") is not None
        data["status"] = "evaluated" if sufficient else "insufficient_data"
        if not sufficient:
            data["note"] = (
                f"{INSUFFICIENT_TEXT} {len(connected)} Messpunkt(e), mindestens {MIN_SAMPLES} mit bekanntem Intervall "
                "nötig – Messreihe mit fritzos8-collector bzw. history_collect länger laufen lassen. "
                "'insufficient_data' heißt nicht 'störungsfrei'."
            )
        if tariff and data["sync_down_mbit"]["min"] is not None:
            data["sync_vs_tariff_pct"] = round(data["sync_down_mbit"]["min"] / tariff * 100, 1)
        data["markdown"] = self.markdown(data, events)
        return data

    @staticmethod
    def markdown(d: dict[str, Any], events: list[tuple[float, str, str]]) -> str:
        insufficient = d.get("status") == "insufficient_data"
        coll = d["collection"]
        interval, coverage = coll.get("interval_s"), coll.get("coverage_pct")
        sample_line = f"- Messpunkte: {d['samples']}"
        if interval and coverage is not None:
            sample_line += f" (Intervall ca. {interval} s, Abdeckung {coverage} %)"
        else:
            sample_line += " (Intervall und Abdeckung nicht bestimmbar)"
        lines = [
            f"# Störungsprotokoll Internetanschluss – {d['from']} bis {d['to']}",
            "",
            f"Gerät: {d['box'].get('model') or 'FRITZ!Box'}"
            + (f" (FRITZ!OS {d['box']['software_version']})" if d["box"].get("software_version") else "")
            + ". Automatisch erfasst durch eine lokale Messreihe (Abfrage der FRITZ!Box per TR-064).",
            "",
        ]
        if insufficient:
            lines += [
                f"> **{INSUFFICIENT_TEXT}** Nur {d['samples']} Messpunkt(e) im Zeitraum (mindestens {MIN_SAMPLES} "
                "nötig). Ausfälle, Neuverbindungen und Messlücken lassen sich daraus nicht beurteilen.",
                "",
            ]
        lines += ["## Zusammenfassung", "", sample_line]
        if not insufficient:
            lines += [
                f"- Ausfälle der Internetverbindung: {len(d['outages'])}, zusammen {d['outage_minutes']} min",
                f"- Neuverbindungen (Verbindungsdauer zurückgesetzt): {d['reconnects']}",
                f"- DSL-Resynchronisationen (Sync-Rate geändert): {d['dsl_resyncs']}",
            ]
        sd = d["sync_down_mbit"]
        if sd["min"] is not None:
            lines.append(f"- Synchronisierte Rate Download: {sd['min']}–{sd['max']} Mbit/s (Ø {sd['avg']})")
        if d.get("tariff_down_mbit"):
            lines.append(
                f"- Vom Provider gemeldete Vertragsrate Download: {d['tariff_down_mbit']} Mbit/s"
                + (f" – minimale Sync-Rate = {d['sync_vs_tariff_pct']} % davon" if "sync_vs_tariff_pct" in d else "")
            )
        if d["snr_down_db"]["min"] is not None:
            lines.append(f"- Störabstandsmarge Download: {d['snr_down_db']['min']}–{d['snr_down_db']['max']} dB")
        if any(d["error_increase"].values()):
            lines.append(
                "- Fehlerzähler (Zuwachs): "
                + ", ".join(f"{k.split('.')[-1]} +{int(v)}" for k, v in d["error_increase"].items() if v)
            )
        lines += ["", "## Ausfälle", ""]
        if insufficient and not d["outages"]:
            lines.append(INSUFFICIENT_TEXT)
        elif d["outages"]:
            lines += ["| von | bis | Dauer (min) |", "|---|---|---|"]
            lines += [
                f"| {o['from']} | {o['to']}{' (andauernd)' if o['open'] else ''} | {o['minutes']} |"
                for o in d["outages"]
            ]
        else:
            lines.append("Keine Ausfälle gemessen (siehe Messlücken).")
        lines += ["", "## Ereignisse", ""]
        relevant = [e for e in events if e[1] in {"wan_down", "wan_up", "wan_reconnect", "dsl_resync"}]
        if relevant:
            lines += [f"- {_fmt(t)} – {detail or kind}" for t, kind, detail in relevant[-100:]]
        elif insufficient:
            lines.append(INSUFFICIENT_TEXT)
        else:
            lines.append("Keine Verbindungsereignisse.")
        lines += ["", "## Messlücken", ""]
        gaps = coll["gaps"]
        if insufficient:
            lines.append("Nicht bestimmbar (zu wenige Messpunkte, Abdeckung unbekannt).")
        elif gaps or coll["failed_count"]:
            lines += [f"- {g['from']} bis {g['to']} ({g['minutes']} min ohne Messung)" for g in gaps]
            if d["collection"]["failed_count"]:
                lines.append(f"- {d['collection']['failed_count']} Messung(en) ohne Antwort der Box")
            lines.append(
                "In Messlücken ist der Zustand unbekannt – sie sind kein Nachweis eines störungsfreien Betriebs."
            )
        else:
            lines.append("Keine.")
        lines += ["", "## Hinweis", "", BNETZA_HINT, ""]
        return "\n".join(lines)

    def report(self, date_from: str | None, date_to: str | None, save: bool) -> dict[str, Any]:
        end = parse_time(date_to, self.now())
        start = parse_time(date_from, end - 7 * 86400)
        data = self.build(start, end)
        if save:
            box = self.service.history.sampler.store.path.parent
            name = f"stoerungsprotokoll-{time.strftime('%Y%m%d-%H%M', time.localtime(start))}.md"
            path = box / "reports" / name
            write_private(path, data["markdown"].encode("utf-8"))
            data["saved_to"] = str(path)
        data["format_note"] = "Markdown; als PDF z. B. über den Druckdialog eines Markdown-Viewers bzw. pandoc."
        return data


def register_report_tools(tool: ToolDecorator, svc: Callable[[str | None], IspReport]) -> None:
    @tool(Tier.READ, READ)
    def isp_report(
        date_from: Annotated[
            str | None, Field(description="Beginn (ISO, z. B. 2026-11-01); Standard: vor 7 Tagen")
        ] = None,
        date_to: Annotated[str | None, Field(description="Ende (ISO); Standard: jetzt")] = None,
        save: Annotated[bool, Field(description="Zusätzlich lokal als Markdown-Datei speichern (0600)")] = False,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Störungsprotokoll für den Provider (Markdown) aus der lokalen Messreihe: Ausfälle mit Dauer, Neuverbindungen,
        DSL-Resyncs, Fehlerzähler, Sync-Rate vs. Vertragsrate (X_AVM-DE_TariffDataRate), Messlücken, Hinweis auf die
        Breitbandmessung der BNetzA. Braucht Daten von fritzos8-collector bzw. history_collect."""
        return svc(box).report(date_from, date_to, save)


def _range(values: list[float], divisor: float) -> dict[str, Any]:
    if not values:
        return {"min": None, "max": None, "avg": None}
    return {
        "min": round(min(values) / divisor, 1),
        "max": round(max(values) / divisor, 1),
        "avg": round(sum(values) / len(values) / divisor, 1),
    }
