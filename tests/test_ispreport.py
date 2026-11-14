"""Stage 8.2 – Störungsprotokoll from a simulated measurement series with an outage."""

from __future__ import annotations

import stat
from datetime import datetime
from pathlib import Path

import pytest

from fritzos8_mcp.errors import InvalidParameterError
from fritzos8_mcp.history import HistoryStore, Sample
from fritzos8_mcp.ispreport import IspReport, outages, parse_time
from fritzos8_mcp.landevice import LanDeviceClient

from .conftest import FakeFC, make_service

T0 = datetime(2026, 11, 1, 0, 0).timestamp()


def fill(store: HistoryStore) -> None:
    """24 h every 5 min; outage 03:00–03:45, a resync with error burst at 03:45, one measurement gap."""
    crc = 100.0
    for i in range(288):
        ts = T0 + i * 300
        if 120 <= i < 130:  # 10:00–10:50 collector was off → gap
            continue
        connected = 0.0 if 36 <= i < 45 else 1.0
        if i == 45:
            crc += 900
        events: list[tuple[str, str]] = []
        if i == 36:
            events.append(("wan_down", "Disconnected"))
        if i == 45:
            events += [("wan_up", "Connected"), ("wan_reconnect", "Verbindung neu aufgebaut"), ("dsl_resync", "x")]
        sample = Sample(
            ts=ts,
            metrics={
                "wan.connected": connected,
                "dsl.down_kbps": 100000.0 if i < 45 else 80000.0,
                "dsl.up_kbps": 40000.0,
                "dsl.snr_down_db": 9.0 if i < 45 else 6.5,
                "dsl.err.CRCErrors": crc,
            },
            events=events,
        )
        store.save(sample, ok=True, duration_s=0.2)


def report(landevices: LanDeviceClient, tmp_path: Path) -> IspReport:
    fc = FakeFC(
        {
            ("DeviceInfo1", "GetInfo"): {"NewModelName": "FRITZ!Box 7583", "NewSoftwareVersion": "164.08.26"},
            ("WANCommonInterfaceConfig1", "X_AVM-DE_GetAddonInfos"): {
                "NewX_AVM-DE_TariffDataRateDownstream": "100000000"
            },
        }
    )
    svc = make_service(landevices, fc)
    fill(svc.history.sampler.store)
    return IspReport(svc, now=lambda: T0 + 86400)


def test_outages_helper() -> None:
    assert outages([(0, 1), (300, 0), (600, 0), (900, 1)], 1000) == [
        {"from": 300, "to": 900, "minutes": 10.0, "open": False}
    ]
    assert outages([(0, 0)], 600)[0]["open"] is True


def test_report_with_simulated_outage(landevices: LanDeviceClient, tmp_path: Path) -> None:
    r = report(landevices, tmp_path).report("2026-11-01", "2026-11-02", save=False)
    assert len(r["outages"]) == 1 and r["outage_minutes"] == 45.0
    assert r["reconnects"] == 1 and r["dsl_resyncs"] == 1
    assert r["error_increase"]["dsl.err.CRCErrors"] == 900
    assert r["sync_down_mbit"] == {"min": 80.0, "max": 100.0, "avg": r["sync_down_mbit"]["avg"]}
    assert r["tariff_down_mbit"] == 100.0 and r["sync_vs_tariff_pct"] == 80.0
    assert len(r["collection"]["gaps"]) == 1
    md = r["markdown"]
    assert "# Störungsprotokoll" in md and "01.11.2026 03:00" in md and "breitbandmessung.de" in md
    assert "Messlücken" in md and "kein Nachweis" in md and "CRCErrors +900" in md


def test_report_saved_private(landevices: LanDeviceClient, tmp_path: Path) -> None:
    r = report(landevices, tmp_path).report("2026-11-01", "2026-11-02", save=True)
    path = Path(r["saved_to"])
    assert path.read_text(encoding="utf-8") == r["markdown"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_report_without_data_is_honest(landevices: LanDeviceClient) -> None:
    svc = make_service(landevices, FakeFC())
    r = IspReport(svc, now=lambda: T0).report(None, None, save=False)
    assert r["samples"] == 0 and r["outages"] == [] and r["status"] == "insufficient_data"
    assert "Zu wenig Messdaten – keine Aussage möglich" in r["markdown"] and "Keine Ausfälle" not in r["markdown"]


def test_bad_dates() -> None:
    with pytest.raises(InvalidParameterError):
        parse_time("gestern", 0)
    assert parse_time(None, 5.0) == 5.0


def test_end_before_start(landevices: LanDeviceClient) -> None:
    svc = make_service(landevices, FakeFC())
    with pytest.raises(InvalidParameterError):
        IspReport(svc).report("2026-11-02", "2026-11-01", save=False)


def test_report_with_too_few_samples_says_so(landevices: LanDeviceClient, tmp_path: Path) -> None:
    """Live finding: 1 sample → "Keine Ausfälle gemessen", "Messlücken: Keine", "Intervall ca. ? s"."""
    fc = FakeFC({("DeviceInfo1", "GetInfo"): {"NewModelName": "FRITZ!Box 7583"}})
    svc = make_service(landevices, fc)
    svc.history.sampler.store.save(
        Sample(ts=T0 + 3600, metrics={"wan.connected": 1.0}, events=[]), ok=True, duration_s=0.1
    )
    r = IspReport(svc, now=lambda: T0 + 86400).report("2026-11-01", "2026-11-02", save=False)
    assert r["status"] == "insufficient_data" and r["samples"] == 1
    md = r["markdown"]
    assert "Zu wenig Messdaten – keine Aussage möglich" in md
    assert "?" not in md
    assert "Keine Ausfälle gemessen" not in md and "\nKeine.\n" not in md
    assert "Intervall und Abdeckung nicht bestimmbar" in md


def test_report_with_enough_samples_is_evaluated(landevices: LanDeviceClient, tmp_path: Path) -> None:
    r = report(landevices, tmp_path).report("2026-11-01", "2026-11-02", save=False)
    assert r["status"] == "evaluated" and "Zu wenig Messdaten" not in r["markdown"]
