"""Stage 8.1 – measurement series (sampler, SQLite store, gaps, tools). Mock box only."""

from __future__ import annotations

import stat
from pathlib import Path
from typing import Any

import pytest
from fritzconnection.core.exceptions import FritzActionError, FritzConnectionException

from fritzos8_mcp.errors import InvalidParameterError
from fritzos8_mcp.history import HistoryService, HistoryStore, Sampler, find_gaps
from fritzos8_mcp.landevice import LanDeviceClient

from .conftest import FakeFC, make_service


class Clock:
    def __init__(self, t: float = 1_800_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class Box:
    def __init__(self) -> None:
        self.uptime = 1000
        self.counter = 1
        self.hosts = [
            {"NewHostName": "pc", "NewIPAddress": "192.0.2.20", "NewMACAddress": "AA:BB:CC:00:00:01", "NewActive": True}
        ]
        self.crc = 10
        self.down = 100000
        self.up = 40000

    def responses(self) -> dict[tuple[str, str], Any]:
        return {
            ("WANIPConnection1", "GetStatusInfo"): lambda: {
                "NewConnectionStatus": "Connected",
                "NewUptime": self.uptime,
            },
            ("WANDSLInterfaceConfig1", "GetInfo"): lambda: {
                "NewEnable": "1",
                "NewStatus": "Up",
                "NewDownstreamCurrRate": self.down,
                "NewUpstreamCurrRate": self.up,
                "NewDownstreamNoiseMargin": 85,
                "NewUpstreamNoiseMargin": 70,
                "NewDownstreamAttenuation": 120,
            },
            ("WANDSLInterfaceConfig1", "GetStatisticsTotal"): lambda: {"NewCRCErrors": self.crc, "NewFECErrors": 3},
            ("WANCommonInterfaceConfig1", "X_AVM-DE_GetOnlineMonitor"): {
                "Newds_current_bps": "1250000,1250000",
                "Newus_current_bps": "125000",
            },
            ("Hosts1", "X_AVM-DE_GetChangeCounter"): lambda: {"NewX_AVM-DE_ChangeCounter": self.counter},
            ("Hosts1", "X_AVM-DE_GetHostListPath"): {},
            ("Hosts1", "GetHostNumberOfEntries"): lambda: {"NewHostNumberOfEntries": len(self.hosts)},
            ("Hosts1", "GetGenericHostEntry"): lambda NewIndex: self.hosts[NewIndex],
        }


def setup(landevices: LanDeviceClient, tmp_path: Path, box: Box | None = None) -> tuple[HistoryService, Clock, Box]:
    box = box or Box()
    svc = make_service(landevices, FakeFC(box.responses()))
    clock = Clock()
    sampler = Sampler(svc, HistoryStore(tmp_path / "box" / "history.sqlite"), now=clock)
    return HistoryService(lambda: sampler, now=clock), clock, box


def test_collect_stores_metrics_private_file(landevices: LanDeviceClient, tmp_path: Path) -> None:
    hist, _, _ = setup(landevices, tmp_path)
    r = hist.collect()
    assert r["ok"] is True and r["errors"] == {}
    m = r["metrics"]
    assert m["wan.connected"] == 1.0 and m["dsl.snr_down_db"] == 8.5 and m["dsl.err.CRCErrors"] == 10
    assert m["throughput.down_mbit_s"] == 10.0 and m["hosts.active"] == 1 and m["hosts.change_counter"] == 1
    path = tmp_path / "box" / "history.sqlite"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_events_reconnect_resync_devices(landevices: LanDeviceClient, tmp_path: Path) -> None:
    hist, clock, box = setup(landevices, tmp_path)
    hist.collect()
    clock.t += 300
    box.uptime = 20  # reconnect
    box.counter = 2
    box.hosts.append(
        {"NewHostName": "handy", "NewIPAddress": "192.0.2.21", "NewMACAddress": "AA:BB:CC:00:00:02", "NewActive": True}
    )
    r = hist.collect()
    kinds = [e["kind"] for e in r["events"]]
    assert "wan_reconnect" in kinds and "device_online" in kinds
    assert any("handy" in e["detail"] for e in r["events"])
    clock.t += 300
    box.counter = 3
    box.hosts.pop(0)
    r = hist.collect()
    assert [e["kind"] for e in r["events"]] == ["device_offline"]
    s = hist.summary(hours=1)
    assert s["event_counts"] == {"wan_reconnect": 1, "device_online": 1, "device_offline": 1}


def test_small_sync_rate_drift_is_not_a_resync(landevices: LanDeviceClient, tmp_path: Path) -> None:
    # Regression (live 7583/8.26): rate adaptation by a few 100 kbit/s every 30 min was logged as "dsl_resync"
    hist, clock, box = setup(landevices, tmp_path)
    hist.collect()
    for down in (100050, 99950, 100070):  # < 1 %, uptime keeps running
        clock.t += 300
        box.uptime += 300
        box.down = down
        assert hist.collect()["events"] == []
    clock.t += 300
    box.uptime += 300
    box.down = 80000  # real drop by 20 %
    assert [e["kind"] for e in hist.collect()["events"]] == ["dsl_resync"]


def test_sync_change_with_reconnect_is_a_resync(landevices: LanDeviceClient, tmp_path: Path) -> None:
    hist, clock, box = setup(landevices, tmp_path)
    hist.collect()
    clock.t += 300
    box.uptime = 20  # reconnect
    box.down = 100010  # tiny change, but together with a reconnect
    kinds = [e["kind"] for e in hist.collect()["events"]]
    assert kinds == ["wan_reconnect", "dsl_resync"]


def test_unchanged_counter_skips_host_list(landevices: LanDeviceClient, tmp_path: Path) -> None:
    box = Box()
    fc = FakeFC(box.responses())
    svc = make_service(landevices, fc)
    clock = Clock()
    sampler = Sampler(svc, HistoryStore(tmp_path / "h.sqlite"), now=clock)
    sampler.run_once()
    before = sum(1 for c in fc.calls if c[1] == "GetGenericHostEntry")
    clock.t += 300
    r = sampler.run_once()
    assert sum(1 for c in fc.calls if c[1] == "GetGenericHostEntry") == before  # host list not read again
    assert r["metrics"]["hosts.active"] == 1.0


def test_zero_counter_does_not_skip_host_list(landevices: LanDeviceClient, tmp_path: Path) -> None:
    """Live korrigiert (7583/8.26): X_AVM-DE_GetChangeCounter bleibt 0 – darauf darf die Messreihe nicht bauen."""
    box = Box()
    box.counter = 0
    fc = FakeFC(box.responses())
    sampler = Sampler(make_service(landevices, fc), HistoryStore(tmp_path / "h.sqlite"), now=Clock())
    sampler.run_once()
    before = sum(1 for c in fc.calls if c[1] == "GetGenericHostEntry")
    r = sampler.run_once()
    assert sum(1 for c in fc.calls if c[1] == "GetGenericHostEntry") > before  # host list read again
    assert "hosts.change_counter" not in r["metrics"]


def test_missing_parts_are_errors_not_failures(landevices: LanDeviceClient, tmp_path: Path) -> None:
    box = Box()
    responses = box.responses()
    responses[("WANDSLInterfaceConfig1", "GetInfo")] = FritzActionError("x")  # cable box: no DSL
    responses[("WANCommonInterfaceConfig1", "X_AVM-DE_GetOnlineMonitor")] = FritzActionError("x")
    svc = make_service(landevices, FakeFC(responses))
    sampler = Sampler(svc, HistoryStore(tmp_path / "h.sqlite"), now=Clock())
    r = sampler.run_once()
    assert r["ok"] is True and not any(k.startswith("dsl.") for k in r["metrics"])


def test_failed_run_is_recorded_as_gap(landevices: LanDeviceClient, tmp_path: Path) -> None:
    box = Box()
    responses = box.responses()
    fc = FakeFC(responses)
    svc = make_service(landevices, fc)
    clock = Clock()
    hist = HistoryService(lambda: sampler, now=clock)
    sampler = Sampler(svc, HistoryStore(tmp_path / "h.sqlite"), now=clock)
    for _ in range(4):
        hist.collect()
        clock.t += 300
    for key in list(responses):
        responses[key] = FritzConnectionException("Read timed out")
    fc.responses = responses
    r = hist.collect()
    assert r["ok"] is False
    clock.t += 3000  # long pause
    fc.responses = box.responses()
    hist.collect()
    s = hist.summary(hours=2)
    assert s["collection"]["interval_s"] == 300 and s["collection"]["failed_count"] == 1
    assert len(s["collection"]["gaps"]) == 1 and s["collection"]["gaps"][0]["minutes"] == 55.0


def test_query_and_summary(landevices: LanDeviceClient, tmp_path: Path) -> None:
    hist, clock, box = setup(landevices, tmp_path)
    for crc in (10, 15, 2, 4):  # 2 = counter reset after resync
        box.crc = crc
        hist.collect()
        clock.t += 300
    q = hist.query("dsl.err.CRCErrors", hours=1)
    assert q["count"] == 4 and q["max"] == 15 and q["points"][0]["v"] == 10
    s = hist.summary(hours=1)
    assert s["metrics"]["dsl.err.CRCErrors"]["increase"] == 7  # 5 + 2, the reset is ignored
    with pytest.raises(InvalidParameterError) as ei:
        hist.query("gibts.nicht")
    assert "dsl.snr_down_db" in (ei.value.hint or "")
    with pytest.raises(InvalidParameterError):
        hist.summary(hours=0)


def test_retention_prunes_old_rows(tmp_path: Path) -> None:
    from fritzos8_mcp.history import Sample

    store = HistoryStore(tmp_path / "h.sqlite", retention_days=1)
    store.save(Sample(ts=1000.0, metrics={"x": 1.0}), ok=True, duration_s=0.1)
    store.save(Sample(ts=1000.0 + 2 * 86400, metrics={"x": 2.0}), ok=True, duration_s=0.1)
    assert store.series("x", 0, 10**10) == [(1000.0 + 2 * 86400, 2.0)]


def test_find_gaps_without_data() -> None:
    r = find_gaps([], 0, 100)
    assert r["interval_s"] is None and r["gaps"] == [] and r["coverage_pct"] is None


def test_service_wires_history_into_state_dir(landevices: LanDeviceClient, tmp_path: Path) -> None:
    svc = make_service(landevices, FakeFC(Box().responses()))
    r = svc.history.collect()
    assert r["ok"] is True
    assert (tmp_path / "state" / "fritz.test" / "history.sqlite").exists()
