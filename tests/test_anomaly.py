"""Stage 10.1 – anomaly detection on the measurement series (synthetic local data, no box)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from fritzos8_mcp.alerts import AlarmService, Notifier
from fritzos8_mcp.anomaly import AnomalyDetector
from fritzos8_mcp.errors import InvalidParameterError
from fritzos8_mcp.history import HistoryStore, Sample
from fritzos8_mcp.landevice import LanDeviceClient

from .conftest import FakeFC, make_service

NOW = 1_800_000_000.0
H = 3600.0


def _store(tmp_path: Path) -> HistoryStore:
    return HistoryStore(tmp_path / "h.sqlite", retention_days=400)


def _fill(
    store: HistoryStore,
    days: float,
    metric_fn: Any,
    step_h: float = 1.0,
    events_fn: Any = None,
) -> None:
    t = NOW - days * 86400
    while t <= NOW:
        metrics = metric_fn(t)
        events = events_fn(t) if events_fn else []
        store.save(Sample(ts=t, metrics=metrics, events=events), ok=True, duration_s=0.1)
        t += step_h * H


def _detector(store: HistoryStore) -> AnomalyDetector:
    return AnomalyDetector(lambda: store, now=lambda: NOW)


def test_no_data_is_insufficient_not_ok(tmp_path: Path) -> None:
    r = _detector(_store(tmp_path)).detect()
    assert r["status"] == "insufficient_data"
    assert r["findings"] == []
    assert "nicht 'alles gut'" in r["note"]


def test_stable_line_is_ok(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _fill(
        store,
        10,
        lambda t: {"dsl.snr_down_db": 9.0, "dsl.down_kbps": 100000.0, "dsl.err.CRCErrors": (t - NOW) / H + 1000},
        events_fn=lambda t: [("device_online", "pc (AA:BB:CC:00:00:01)")] if t == NOW - 10 * 86400 else [],
    )
    r = _detector(store).detect()
    assert r["status"] == "ok"
    assert r["checks"]["snr_trend"] == "evaluated"
    assert r["checks"]["error_rate"] == "evaluated"


def test_snr_falling_trend_with_projection(tmp_path: Path) -> None:
    store = _store(tmp_path)
    # 10 dB falling by 0.3 dB per day → 7 dB after 10 days, warn level (6 dB) in ~3 days
    _fill(store, 10, lambda t: {"dsl.snr_down_db": 7.0 + 0.3 * (NOW - t) / 86400})
    r = _detector(store).detect()
    f = next(f for f in r["findings"] if f["kind"] == "snr_trend:dsl.snr_down_db")
    assert f["severity"] == "warn"
    assert f["area"] == "trend"
    assert f["evidence"]["slope_db_per_day"] == pytest.approx(-0.3, abs=0.01)
    assert f["evidence"]["days_until_warn_level"] == pytest.approx(3.3, abs=0.5)
    assert "unter 6.0 dB" in f["finding"]


def test_sync_rate_drop(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _fill(store, 5, lambda t: {"dsl.down_kbps": 100000.0 if t < NOW - 20 * H else 80000.0})
    r = _detector(store).detect()
    f = next(f for f in r["findings"] if f["kind"] == "sync_rate:dsl.down_kbps")
    assert f["evidence"]["baseline_median_kbps"] == 100000
    assert "20 %" in f["finding"]


def test_error_counter_acceleration_ignores_reset(tmp_path: Path) -> None:
    store = _store(tmp_path)

    def crc(t: float) -> dict[str, float]:
        hours = (t - (NOW - 5 * 86400)) / H
        if t < NOW - 24 * H:
            return {"dsl.err.CRCErrors": hours * 2}  # 2 per hour
        if abs(t - (NOW - 12 * H)) < 1:
            return {"dsl.err.CRCErrors": 0.0}  # reset (resync) must not count negative
        return {"dsl.err.CRCErrors": 240 + hours * 50}  # 50 per hour

    _fill(store, 5, crc)
    r = _detector(store).detect()
    f = next(f for f in r["findings"] if f["kind"] == "error_rate:CRCErrors")
    assert f["evidence"]["baseline_per_hour"] == pytest.approx(2, abs=0.5)
    assert f["evidence"]["recent_per_hour"] > 20


def test_reconnects_and_device_drops(tmp_path: Path) -> None:
    store = _store(tmp_path)
    start = NOW - 7 * 86400

    def events(t: float) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        if t == start:
            out.append(("device_online", "Laptop (AA:BB:CC:00:00:09)"))
        if t >= NOW - 24 * H and int((t - start) / H) % 4 == 0:
            out += [("wan_reconnect", "neu"), ("device_offline", "AA:BB:CC:00:00:09")]
        if t >= NOW - 24 * H and int((t - start) / H) % 2 == 0:
            out.append(("device_offline", "AA:BB:CC:00:00:0A"))
        return out

    _fill(store, 7, lambda t: {"wan.connected": 1.0}, events_fn=events)
    r = _detector(store).detect()
    kinds = {f["kind"]: f for f in r["findings"]}
    assert "reconnects" in kinds
    assert kinds["reconnects"]["evidence"]["recent_events"]["wan_reconnect"] >= 3
    assert "device_drops" in kinds
    single = kinds["device_drops:AA:BB:CC:00:00:09"]
    assert single["evidence"]["name"] == "Laptop"
    assert single["severity"] == "info"


def test_parameter_validation(tmp_path: Path) -> None:
    det = _detector(_store(tmp_path))
    with pytest.raises(InvalidParameterError):
        det.detect(days=0.5)
    with pytest.raises(InvalidParameterError):
        det.detect(days=1, recent_hours=24)


def _service_with_history(landevices: LanDeviceClient, tmp_path: Path) -> Any:
    svc = make_service(landevices, FakeFC())
    store = HistoryStore.for_box(svc.box_host, tmp_path / "state")
    _fill(store, 10, lambda t: {"dsl.snr_down_db": 7.0 + 0.3 * (NOW - t) / 86400})
    svc.anomalies = AnomalyDetector(lambda: store, now=lambda: NOW)
    return svc


def test_doctor_includes_trend_findings(landevices: LanDeviceClient, tmp_path: Path) -> None:
    svc = _service_with_history(landevices, tmp_path)
    report = svc.network_doctor(symptom="Internet wird seit Tagen langsamer")
    trend = [f for f in report["findings"] if f["area"] == "trend"]
    assert trend and trend[0]["relevant_to_symptom"] is True
    assert report["sources"]["anomalies"] == "ok"


def test_alarms_include_anomalies(landevices: LanDeviceClient, tmp_path: Path) -> None:
    svc = _service_with_history(landevices, tmp_path)
    alarms = AlarmService(svc, now=lambda: NOW, notifier=Notifier({}), state_root=tmp_path / "s")
    r = alarms.check()
    assert r["sources"]["anomalies"] == "ok"
    assert any(a["type"] == "anomaly" and a["key"] == "anomaly:snr_trend:dsl.snr_down_db" for a in r["alarms"])
