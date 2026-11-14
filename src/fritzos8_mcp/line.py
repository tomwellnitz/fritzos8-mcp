"""Stage 8.9 – line diagnostics per access type (DSL, fibre, mobile, cable) – read only.

Own implementation after the AVM TR-064 documents:

* DSL (``WANDSLInterfaceConfig``): ``GetInfo``/``GetStatisticsTotal`` (as ``dsl_info``), ``X_AVM-DE_GetDSLInfo``
  (modulation, profile, link status, SNR per tone group ``SNRpsds``/``SNRpsus`` as comma list, group size
  ``SNRGds``) and ``X_AVM-DE_GetDSLDiagnoseInfo`` – the automatic cable test after ≥ 300 s without sync:
  state NONE/NO_CALIB/RUNNING/DONE_CABLE_OK/DONE_CABLE_NOK, fault distance in metres (-1 = unknown). Note the
  AVM spelling ``NewX_AVM-DE_DSLDigagnoseState`` (typo in the box), the correct spelling is read as fallback.
* Fibre (``X_AVM-DE_WANFiber``, right App): ``GetInfo`` optical levels and alarm thresholds in dBm/1000, fibre mode;
  ``GetInfoGPON`` (PON/ONU id, UNI type, GEM ports); ``GetStatistics`` (rates, resyncs, minutes in showtime,
  packet errors). Serial numbers (SFP, GPON) are not needed for a diagnosis and are not output.
* Mobile (``X_AVM-DE_WANMobileConnection``, right App): ``GetInfo`` (SIM status, PIN/PUK failure counts),
  ``GetInfoEx`` (technology, RSRP of both antennas, roaming, uptime, cell list XML),
  ``GetEnabledBandCapabilities``. IMSI, PPP user names, serial number and cell location data (cell id, TAC,
  distance) never leave this module.
* Cable (DOCSIS): AVM's TR-064 has no DOCSIS service – values are ``unknown`` (web UI: Internet > Kabel-Informationen).

Thresholds are rules of thumb (``LINE_THRESHOLDS``), returned with every report.
"""

from __future__ import annotations

import statistics
from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated, Any

from defusedxml import ElementTree as ET
from pydantic import Field

from .errors import AuthError, ConfirmationRequiredError, FritzConnectionError, FritzError
from .nasremote import ToolDecorator
from .security import Tier
from .toolargs import READ, BoxArg
from .util import truthy

if TYPE_CHECKING:
    from .diagnose import DiagnoseClient
    from .tr064 import Tr064Client

DSL = "WANDSLInterfaceConfig1"
FIBER = "X_AVM-DE_WANFiber1"
MOBILE = "X_AVM-DE_WANMobileConnection1"
MAX_SPECTRUM_POINTS = 512

LINE_THRESHOLDS: dict[str, Any] = {
    "fiber_margin_warn_db": 2.0,  # receive level closer than this to an alarm threshold → warn
    "mobile_rsrp_good_dbm": -90,
    "mobile_rsrp_fair_dbm": -100,
    "mobile_rsrp_poor_dbm": -110,
    "dsl_snr_tone_low_db": 6.0,  # share of tones below this is reported
}

CABLE_TYPES = {"cable", "docsis", "x_avm-de_cable"}
FIBER_TYPES = {"x_avm-de_fiber", "fiber", "gpon", "aon", "ethernet_fiber"}
MOBILE_TYPES = {"x_avm-de_umts", "x_avm-de_lte", "x_avm-de_mobile", "umts", "lte", "5g", "mobile"}


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _milli_dbm(value: Any) -> float | None:
    v = _int(value)
    return None if v is None else round(v / 1000, 2)


def _tone_list(value: Any) -> list[int]:
    out = []
    for part in str(value or "").split(","):
        v = _int(part)
        if v is not None:
            out.append(v)
    return out


def classify_access(access_type: Any) -> str:
    """WANAccessType of GetCommonLinkProperties / X_AVM-DE_GetAddonInfos → dsl/fiber/mobile/cable/ethernet."""
    t = str(access_type or "").strip().lower()
    if not t:
        return "unknown"
    if "dsl" in t:
        return "dsl"
    if t in CABLE_TYPES or "cable" in t or "docsis" in t:
        return "cable"
    if t in FIBER_TYPES or "fiber" in t or "pon" in t:
        return "fiber"
    if t in MOBILE_TYPES or any(k in t for k in ("umts", "lte", "mobile", "5g")):
        return "mobile"
    if "ethernet" in t:
        return "ethernet"
    return "unknown"


def rsrp_rating(rsrp: int | None) -> str:
    if rsrp is None or rsrp == 0:
        return "unknown"
    if rsrp >= LINE_THRESHOLDS["mobile_rsrp_good_dbm"]:
        return "gut"
    if rsrp >= LINE_THRESHOLDS["mobile_rsrp_fair_dbm"]:
        return "mittel"
    if rsrp >= LINE_THRESHOLDS["mobile_rsrp_poor_dbm"]:
        return "schwach"
    return "sehr schwach"


def parse_cell_list(xml: Any) -> list[dict[str, Any]]:
    """Cell list XML of GetInfoEx – only radio values, no location data (cell id, TAC, distance)."""
    text = str(xml or "").strip()
    if not text:
        return []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    cells = []
    for cell in root.iter("Cell"):
        rsrp = _int(cell.findtext("RSRP"))
        cells.append(
            {
                "connected": (cell.findtext("Connected") or "none").strip(),
                "type": (cell.findtext("CellType") or "").strip() or None,
                "provider": (cell.findtext("Provider") or "").strip() or None,
                "plmn": (cell.findtext("PLMN") or "").strip() or None,
                "rsrp_dbm": rsrp,
                "rsrq_db": _int(cell.findtext("RSRQ")),
                "rssi": _int(cell.findtext("RSSI")),
                "rating": rsrp_rating(rsrp),
            }
        )
    return cells


class LineDiagnostics:
    def __init__(self, tr064: Tr064Client, diag: DiagnoseClient) -> None:
        self.tr064 = tr064
        self.diag = diag

    # ------------------------------------------------------------ access type

    def access_type(self) -> dict[str, Any]:
        link = self.tr064.try_call("WANCommonInterfaceConfig1", "GetCommonLinkProperties") or {}
        raw = link.get("NewWANAccessType")
        addon = self.tr064.try_call("WANCommonInterfaceConfig1", "X_AVM-DE_GetAddonInfos") or {}
        raw_addon = addon.get("NewX_AVM-DE_WANAccessType")
        kind = classify_access(raw_addon) if classify_access(raw_addon) != "unknown" else classify_access(raw)
        return {"kind": kind, "wan_access_type": raw, "addon_access_type": raw_addon or None}

    # ------------------------------------------------------------ DSL

    def dsl(self, include_spectrum: bool = False) -> dict[str, Any]:
        base = self.diag.dsl_info()
        if not base.get("available"):
            return {"available": False, "note": base.get("note")}
        out: dict[str, Any] = {**base}
        info = self.tr064.try_call(DSL, "X_AVM-DE_GetDSLInfo")
        if info:
            out["link_status"] = info.get("NewLinkStatus") or None
            out["modulation"] = info.get("NewModulationType") or None
            out["profile"] = info.get("NewCurrentProfile") or None
            out["dslam_country"] = info.get("NewATURCountry") or None
            spectrum: dict[str, Any] = {}
            for direction, field, group in (("down", "NewSNRpsds", "NewSNRGds"), ("up", "NewSNRpsus", "NewSNRGus")):
                tones = _tone_list(info.get(field))
                if not tones:
                    continue
                low = sum(1 for t in tones if t < LINE_THRESHOLDS["dsl_snr_tone_low_db"])
                entry: dict[str, Any] = {
                    "groups": len(tones),
                    "group_size": _int(info.get(group)),
                    "min": min(tones),
                    "max": max(tones),
                    "avg": round(statistics.fmean(tones), 1),
                    "low_share_pct": round(low / len(tones) * 100, 1),
                }
                if include_spectrum:
                    step = max(1, len(tones) // MAX_SPECTRUM_POINTS)
                    entry["values"] = tones[::step][:MAX_SPECTRUM_POINTS]
                    entry["downsampled"] = step > 1
                spectrum[direction] = entry
            if spectrum:
                out["snr_spectrum"] = spectrum
                out["snr_spectrum_note"] = (
                    "SNR je Trägergruppe aus X_AVM-DE_GetDSLInfo (Rohwerte der Box, Einheit laut Doku nicht "
                    "angegeben – üblich dB; live prüfen)."
                )
        diag = self.tr064.try_call(DSL, "X_AVM-DE_GetDSLDiagnoseInfo")
        if diag:
            state = diag.get("NewX_AVM-DE_DSLDigagnoseState") or diag.get("NewX_AVM-DE_DSLDiagnoseState") or ""
            distance = _int(diag.get("NewX_AVM-DE_CableNokDistance"))
            out["cable_test"] = {
                "state": state or None,
                "fault_distance_m": distance if distance is not None and distance >= 0 else None,
                "signal_loss_s": _int(diag.get("NewX_AVM-DE_DSLSignalLossTime")),
                "last_diagnose_s": _int(diag.get("NewX_AVM-DE_DSLLastDiagnoseTime")),
                "dsl_active": truthy(diag.get("NewX_AVM-DE_DSLActive")),
                "dsl_sync": truthy(diag.get("NewX_AVM-DE_DSLSync")),
                "meaning": _cable_meaning(str(state), distance),
            }
        return out

    # ------------------------------------------------------------ fibre

    def fiber(self) -> dict[str, Any]:
        info = self.tr064.call(FIBER, "GetInfo")
        rx = _milli_dbm(info.get("NewOpticalSignalLevel"))
        tx = _milli_dbm(info.get("NewTransmitOpticalLevel"))
        rx_low, rx_high = (
            _milli_dbm(info.get("NewLowerOpticalThreshold")),
            _milli_dbm(info.get("NewUpperOpticalThreshold")),
        )
        tx_low = _milli_dbm(info.get("NewLowerTransmitPowerThreshold"))
        tx_high = _milli_dbm(info.get("NewUpperTransmitPowerThreshold"))
        out: dict[str, Any] = {
            "available": True,
            "mode": info.get("NewFiberMode") or None,
            "sfp_vendor": info.get("NewSFPVendor") or None,
            "sfp_part_number": info.get("NewSFPPartNumber") or None,
            "tx_wavelength_nm": _int(info.get("NewTXWaveLength")),
            "rx_dbm": rx,
            "rx_thresholds_dbm": [rx_low, rx_high],
            "rx_rating": _level_rating(rx, rx_low, rx_high),
            "tx_dbm": tx,
            "tx_thresholds_dbm": [tx_low, tx_high],
            "tx_rating": _level_rating(tx, tx_low, tx_high),
            "units": "optische Pegel in dBm (Box liefert dBm/1000)",
        }
        gpon = self.tr064.try_call(FIBER, "GetInfoGPON")
        if gpon:
            out["gpon"] = {
                "pon_id": gpon.get("NewPONId") or None,
                "onu_id": _int(gpon.get("NewONUId")),
                "uni_type": gpon.get("NewUNIType") or None,
                "gem_ports": _int(gpon.get("NewGEMPortCount")),
            }
        stats = self.tr064.try_call(FIBER, "GetStatistics")
        if stats:
            out["statistics"] = {
                "rate_down": _int(stats.get("NewConnectionRateDown")),
                "rate_up": _int(stats.get("NewConnectionRateUp")),
                "resyncs": _int(stats.get("NewResyncs")),
                "minutes_in_showtime": _int(stats.get("NewMinutesInShowtime")),
                "best_train_state": _int(stats.get("NewBestTrainState")),
                "packet_errors_received": _int(stats.get("NewPacketErrorsReceived")),
                "packet_errors_sent": _int(stats.get("NewPacketErrorsSent")),
                "rate_unit_note": "Einheit der Raten laut Doku nicht angegeben (live prüfen).",
            }
        return out

    # ------------------------------------------------------------ mobile

    def mobile(self) -> dict[str, Any]:
        info = self.tr064.call(MOBILE, "GetInfo")
        out: dict[str, Any] = {
            "available": True,
            "enabled": truthy(info.get("NewEnable")),
            "sim_status": info.get("NewStatus") or "unknown",
            "pin_failures": _int(info.get("NewPINFailureCount")),
            "puk_failures": _int(info.get("NewPUKFailureCount")),
        }
        ex = self.tr064.try_call(MOBILE, "GetInfoEx")
        if ex:
            rsrp = [_int(ex.get("NewSignalRSRP0")), _int(ex.get("NewSignalRSRP1"))]
            best = max((r for r in rsrp if r), default=None)
            out.update(
                {
                    "technology": ex.get("NewCurrentAccessTechnology") or None,
                    "roaming": truthy(ex.get("NewRoaming")),
                    "uptime_s": _int(ex.get("NewUptime")),
                    "rsrp_dbm": rsrp,
                    "rsrp_rating": rsrp_rating(best),
                    "cells": parse_cell_list(ex.get("NewCellList")),
                    "privacy_note": "IMSI, PPP-Benutzernamen, Seriennummer und Zellstandort (Cell-ID, TAC, Distanz) "
                    "werden nicht ausgegeben.",
                }
            )
        bands = self.tr064.try_call(MOBILE, "GetEnabledBandCapabilities")
        if bands:
            out["enabled_bands"] = {
                "lte": bands.get("NewBandCapabilitiesLTE") or None,
                "5g_nsa": bands.get("NewBandCapabilities5GNSA") or None,
                "5g_sa": bands.get("NewBandCapabilities5GSA") or None,
            }
        return out

    # ------------------------------------------------------------ combined

    def _section(self, fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        try:
            return fn()
        except (AuthError, ConfirmationRequiredError, FritzConnectionError):
            raise
        except FritzError as exc:
            return {"available": False, "error": exc.to_dict()}

    def diagnose(self, include_spectrum: bool = False) -> dict[str, Any]:
        access = self.access_type()
        kind = access["kind"]
        out: dict[str, Any] = {"access": access}
        # DSL needs no rights and is cheap; fibre/mobile only when the access type says so (or is unknown).
        if kind in ("dsl", "unknown"):
            out["dsl"] = self._section(lambda: self.dsl(include_spectrum))
        if kind in ("fiber", "unknown"):
            out["fiber"] = self._section(self.fiber)
        if kind in ("mobile", "unknown"):
            out["mobile"] = self._section(self.mobile)
        else:
            # a mobile fallback stick/LTE backup can exist next to DSL/cable – report it only if present
            mobile = self._section(self.mobile)
            if mobile.get("available") and mobile.get("enabled"):
                out["mobile_backup"] = mobile
        if kind == "cable":
            out["cable"] = {
                "available": False,
                "status": "unknown",
                "note": "Für Kabelanschlüsse (DOCSIS) bietet TR-064 keine Leitungswerte. Web-Oberfläche: Internet > "
                "Kabel-Informationen (Kanäle, Pegel, Fehler).",
            }
        out["findings"] = self.findings(out)
        out["thresholds"] = LINE_THRESHOLDS
        return out

    @staticmethod
    def findings(report: dict[str, Any]) -> list[dict[str, Any]]:
        """Findings in the network doctor's format (severity, area, finding, likely_cause, recommendation)."""
        out: list[dict[str, Any]] = []

        def add(severity: str, area: str, finding: str, cause: str, recommendation: str, **evidence: Any) -> None:
            out.append(
                {
                    "severity": severity,
                    "area": area,
                    "finding": finding,
                    "likely_cause": cause,
                    "recommendation": recommendation,
                    "evidence": evidence,
                }
            )

        dsl = report.get("dsl") or {}
        cable = dsl.get("cable_test") or {}
        state = str(cable.get("state") or "")
        if state.startswith("DONE_CABLE_NOK"):
            where = f" etwa {cable['fault_distance_m']} m entfernt" if cable.get("fault_distance_m") is not None else ""
            add(
                "critical",
                "dsl",
                f"DSL-Kabeltest meldet einen Leitungsfehler{where}.",
                "deutet auf eine Unterbrechung/Beschädigung der Leitung hin (Hausverkabelung oder Provider)",
                "TAE-Kabel und Dose prüfen; Ergebnis (inkl. Entfernung) dem Provider bei der Störungsmeldung nennen.",
                state=state,
                distance_m=cable.get("fault_distance_m"),
            )
        elif state == "RUNNING" or (cable and not cable.get("dsl_sync", True)):
            add(
                "warn",
                "dsl",
                "Keine DSL-Synchronisation – die Box misst gerade bzw. hat die Leitung verloren.",
                "deutet auf einen Leitungsausfall hin",
                "Einige Minuten warten und line_diagnostics erneut aufrufen (Kabeltest startet nach 5 min ohne Sync).",
                state=state or None,
            )
        spectrum = (dsl.get("snr_spectrum") or {}).get("down") or {}
        if spectrum.get("low_share_pct", 0) >= 20:
            add(
                "info",
                "dsl",
                f"{spectrum['low_share_pct']} % der Trägergruppen im Downstream mit niedrigem SNR.",
                "deutet auf frequenzabhängige Störungen hin (z. B. Einkopplungen, Brückenabgriffe)",
                "Spektrum mit include_spectrum=true ansehen; Hausverkabelung prüfen.",
                low_share_pct=spectrum["low_share_pct"],
            )

        fiber = report.get("fiber") or {}
        for direction, key in (("Empfangspegel", "rx_rating"), ("Sendepegel", "tx_rating")):
            rating = fiber.get(key)
            if rating in ("critical", "warn"):
                add(
                    "critical" if rating == "critical" else "warn",
                    "fiber",
                    f"Optischer {direction} {'außerhalb' if rating == 'critical' else 'nahe'} der Alarmschwelle.",
                    "deutet auf verschmutzte/geknickte Glasfaser, Stecker oder ein SFP-Problem hin",
                    "Glasfaserkabel auf Knicke prüfen, Stecker nicht berühren; Werte dem Provider melden.",
                    level_dbm=fiber.get("rx_dbm" if key == "rx_rating" else "tx_dbm"),
                    thresholds_dbm=fiber.get("rx_thresholds_dbm" if key == "rx_rating" else "tx_thresholds_dbm"),
                )

        for name in ("mobile", "mobile_backup"):
            mobile = report.get(name) or {}
            rating = mobile.get("rsrp_rating")
            if rating in ("schwach", "sehr schwach"):
                add(
                    "warn",
                    "mobile",
                    f"Mobilfunk-Empfang {rating} (RSRP {mobile.get('rsrp_dbm')} dBm).",
                    "deutet auf ungünstigen Standort der Box/Antenne hin",
                    "Box bzw. Antenne näher ans Fenster/höher stellen; Ausrichtung zur Basisstation ändern.",
                    rsrp_dbm=mobile.get("rsrp_dbm"),
                )
            status = str(mobile.get("sim_status") or "")
            if status.lower() in {"enter pin", "enter puk", "sim card locked", "sim card defect", "no sim card"}:
                add(
                    "critical",
                    "mobile",
                    f"SIM-Karte: {status}.",
                    "die Mobilfunkverbindung kann so nicht aufgebaut werden",
                    "In der Web-Oberfläche (Internet > Mobilfunk) PIN/SIM prüfen – PIN/PUK setzt dieser Server nie.",
                    sim_status=status,
                )
        return out

    def metrics(self) -> dict[str, float]:
        """Extra values for the measurement series (stage 8.1): optical receive level, mobile RSRP, DSL cable test."""
        out: dict[str, float] = {}
        kind = self.access_type()["kind"]
        if kind == "fiber":
            f = self.fiber()
            if f.get("rx_dbm") is not None:
                out["fiber.rx_dbm"] = float(f["rx_dbm"])
            resyncs = (f.get("statistics") or {}).get("resyncs")
            if resyncs is not None:
                out["fiber.resyncs"] = float(resyncs)
        elif kind == "mobile":
            m = self.mobile()
            best = max((r for r in m.get("rsrp_dbm") or [] if r), default=None)
            if best is not None:
                out["mobile.rsrp_dbm"] = float(best)
        return out


def _cable_meaning(state: str, distance: int | None) -> str:
    if state == "NONE":
        return "kein Kabeltest nötig bzw. Leitung synchron"
    if state == "NO_CALIB":
        return "Kabeltest konnte nicht starten (keine Kalibrierung)"
    if state == "RUNNING":
        return "Kabeltest läuft (startet nach ≥ 300 s ohne DSL-Sync)"
    if state.startswith("DONE_CABLE_OK"):
        return "Kabeltest fertig – kein Leitungsbruch erkannt"
    if state.startswith("DONE_CABLE_NOK"):
        if distance is not None and distance >= 0:
            return f"Kabeltest fertig – Leitungsfehler in etwa {distance} m"
        return "Kabeltest fertig – Leitungsfehler, Entfernung nicht bestimmbar"
    return "unbekannter Zustand"


def _level_rating(level: float | None, low: float | None, high: float | None) -> str:
    if level is None or (low is None and high is None) or (low == 0 and high == 0):
        return "unknown"
    margin = LINE_THRESHOLDS["fiber_margin_warn_db"]
    if (low is not None and level < low) or (high is not None and level > high):
        return "critical"
    if (low is not None and level - low < margin) or (high is not None and high - level < margin):
        return "warn"
    return "ok"


def register_line_tools(tool: ToolDecorator, svc: Callable[[str | None], LineDiagnostics]) -> None:
    @tool(Tier.READ, READ)
    def line_diagnostics(
        include_spectrum: Annotated[
            bool, Field(description="DSL: SNR je Trägergruppe mit ausgeben (≤ 512 Werte, sonst ausgedünnt)")
        ] = False,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Leitungsdiagnose je Anschlussart (nur lesend): DSL (Raten, SNR, Dämpfung, Fehler, Profil, SNR-Spektrum,
        automatischer Kabeltest mit Fehlerort), Glasfaser (optische Pegel gegen Alarmschwellen, GPON, Resyncs),
        Mobilfunk (Technik, RSRP-Bewertung, Zellen ohne Standortdaten, Bänder, SIM-Status), Kabel (per TR-064
        unknown). Mit Befunden (Schweregrad, Ursache, Empfehlung)."""
        return svc(box).diagnose(include_spectrum)
