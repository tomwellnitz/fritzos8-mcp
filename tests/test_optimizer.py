"""Stage 10.2 – network optimizer (fake service + synthetic measurement series, no box)."""

from __future__ import annotations

import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from fritzos8_mcp.errors import InvalidParameterError, PlanError, TierDisabledError
from fritzos8_mcp.history import HistoryStore, Sample
from fritzos8_mcp.optimizer import NetworkOptimizer, _nearest_channel
from fritzos8_mcp.security import Gate, PlanStore

from .test_quality import MESH_Q, PI_MAC

NOW = 1_800_000_000.0
H = 3600.0


class FakeSvc:
    def __init__(self, *, critical: bool = True, radios: list[dict[str, Any]] | None = None) -> None:
        self.box_host = "fritz.test"
        self.gate = Gate(True, critical)
        self.plans = PlanStore()
        self.applied: list[tuple[str, Any, Any]] = []
        self._radios = radios or [
            {"band_ghz": "2.4", "enabled": True, "channel": 3, "auto_channel": False, "ssid": "Heim", "clients": 12,
             "possible_channels": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]},
            {"band_ghz": "5", "enabled": True, "channel": 36, "auto_channel": False, "ssid": "Heim", "clients": 2,
             "possible_channels": [36, 40, 44, 48]},
        ]  # fmt: skip
        self.wlan_cfg = SimpleNamespace(radios=lambda: self._radios)
        ports = [
            {"label": "LAN:1", "eee_mode": "auto", "eee_supported": True},
            {"label": "LAN:2", "eee_mode": "auto", "eee_supported": True},
            {"label": "LAN:3", "eee_mode": "off", "eee_supported": True},
        ]
        log = {
            "entries": [{"message": "LAN-Anschluss 2 getrennt"}, {"message": "LAN-Anschluss 2 verbunden"}] * 4
            + [{"message": "LAN-Anschluss 3 getrennt"}] * 8
        }
        self.connectivity = SimpleNamespace(
            lan=SimpleNamespace(ports=lambda: ports),
            set_lan_eee=lambda port, mode: self._record("set_lan_eee", port, mode),
        )
        self.netinfo = SimpleNamespace(mesh_document=lambda: MESH_Q)
        self.diag = SimpleNamespace(system_log=lambda n: log)

    def _record(self, tool: str, a: Any, b: Any) -> dict[str, Any]:
        self.applied.append((tool, a, b))
        return {"changed": True, "verified": True}

    def set_wlan_channel(self, band: str, channel: int) -> dict[str, Any]:
        return self._record("set_wlan_channel", band, channel)


def _store(tmp_path: Path) -> HistoryStore:
    return HistoryStore(tmp_path / "h.sqlite", retention_days=400)


def _opt(svc: FakeSvc, store: HistoryStore, tmp_path: Path, clock: list[float]) -> NetworkOptimizer:
    return NetworkOptimizer(svc, now=lambda: clock[0], state_root=tmp_path / "state", store=lambda: store)  # type: ignore[arg-type]


def test_nearest_channel() -> None:
    assert _nearest_channel(3, list(range(1, 14))) == 1
    assert _nearest_channel(9, list(range(1, 14))) == 11
    assert _nearest_channel(4, [4, 5]) is None


def test_suggest_channel_eee_band_steering(tmp_path: Path) -> None:
    svc = FakeSvc()
    r = _opt(svc, _store(tmp_path), tmp_path, [NOW]).suggest()
    by_id = {s["id"]: s for s in r["suggestions"]}
    ch = by_id["wlan_channel:2.4"]
    assert ch["action"] == {"tool": "set_wlan_channel", "band": "2.4", "channel": 0}
    assert any("Kanal 1" in w for w in ch["warnings"])
    # Pi on LAN:1 (EEE auto) and link flapping on LAN:2; LAN:3 flaps but EEE is already off
    assert by_id["lan_eee:LAN:1"]["action"]["macs"] == [PI_MAC]
    assert "Link-Flapping" in by_id["lan_eee:LAN:2"]["title"]
    assert "lan_eee:LAN:3" not in by_id
    steering = by_id["band_steering"]
    assert steering["actionable"] is False and "Band Steering" in steering["manual_steps"]
    # 5 GHz fixed channel without many drops in the history → no suggestion
    assert "wlan_channel:5" not in by_id
    assert set(r["actionable"]) == {"wlan_channel:2.4", "lan_eee:LAN:1", "lan_eee:LAN:2"}


def test_many_drops_suggest_auto_channel_on_5ghz(tmp_path: Path) -> None:
    store = _store(tmp_path)
    for i in range(48):
        store.save(
            Sample(ts=NOW - i * H, metrics={"x": 1.0}, events=[("device_offline", "AA:BB:CC:00:00:01")]),
            ok=True,
            duration_s=0.1,
        )
    r = _opt(FakeSvc(), store, tmp_path, [NOW]).suggest()
    by_id = {s["id"]: s for s in r["suggestions"]}
    assert by_id["wlan_channel:5"]["action"]["channel"] == 0
    assert r["history"]["drops_per_day"] >= 10


def test_plan_requires_critical_and_actionable(tmp_path: Path) -> None:
    with pytest.raises(TierDisabledError):
        _opt(FakeSvc(critical=False), _store(tmp_path), tmp_path, [NOW]).plan(["wlan_channel:2.4"])
    opt = _opt(FakeSvc(), _store(tmp_path), tmp_path, [NOW])
    with pytest.raises(InvalidParameterError, match="nur manuell"):
        opt.plan(["band_steering"])
    with pytest.raises(InvalidParameterError, match="nicht mehr"):
        opt.plan(["lan_eee:LAN:9"])
    with pytest.raises(InvalidParameterError):
        opt.plan([])


def test_execute_runs_write_tools_records_and_measures_effect(tmp_path: Path) -> None:
    store = _store(tmp_path)
    svc = FakeSvc()
    clock = [NOW]
    opt = _opt(svc, store, tmp_path, clock)
    # before: the Pi drops 6×/day, afterwards once a day
    for i in range(1, 25):
        ev = [("device_offline", PI_MAC)] if i % 4 == 0 else []
        store.save(Sample(ts=NOW - i * H, metrics={"hosts.active": 10.0}, events=ev), ok=True, duration_s=0.1)
    plan = opt.plan(["lan_eee:LAN:1", "wlan_channel:2.4"])
    assert "box-weit" in " ".join(plan["warnings"])
    result = opt.execute(plan["token"])
    assert result["applied"] == 2
    assert ("set_lan_eee", "LAN:1", "off") in svc.applied
    assert ("set_wlan_channel", "2.4", 0) in svc.applied
    path = tmp_path / "state" / "fritz.test" / "optimizer.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(PlanError):
        opt.execute(plan["token"])  # one-time token

    # too early → insufficient data
    early = opt.effect(change_id=f"{int(NOW)}-lan_eee:LAN:1")
    assert early["verdict"] == "insufficient_data"

    for i in range(1, 25):
        ev = [("device_offline", PI_MAC)] if i == 12 else []
        store.save(Sample(ts=NOW + i * H, metrics={"hosts.active": 10.0}, events=ev), ok=True, duration_s=0.1)
    clock[0] = NOW + 25 * H
    eff = opt.effect(change_id=f"{int(NOW)}-lan_eee:LAN:1")
    assert eff["before"]["affected_drops_per_day"] == 6.0
    assert eff["after"]["affected_drops_per_day"] == 1.0
    assert eff["verdict"] == "improved"
    assert "Geräteabbrüche" in eff["details"][0]


def test_effect_without_changes_and_unknown_id(tmp_path: Path) -> None:
    opt = _opt(FakeSvc(), _store(tmp_path), tmp_path, [NOW])
    assert opt.effect()["changes"] == []
    plan = opt.plan(["wlan_channel:2.4"])
    opt.execute(plan["token"])
    with pytest.raises(InvalidParameterError, match="unbekannt"):
        opt.effect(change_id="nope")


def test_failed_write_is_not_recorded(tmp_path: Path) -> None:
    from fritzos8_mcp.errors import FritzError

    svc = FakeSvc()

    def boom(band: str, channel: int) -> dict[str, Any]:
        raise FritzError("SetChannel fehlgeschlagen")

    svc.set_wlan_channel = boom  # type: ignore[method-assign]
    opt = _opt(svc, _store(tmp_path), tmp_path, [NOW])
    r = opt.execute(opt.plan(["wlan_channel:2.4"])["token"])
    assert r["applied"] == 0 and r["results"][0]["verified"] is False
    assert opt.effect()["changes"] == []
