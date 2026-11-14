"""Stage 8.3 – alarms: checks, debouncing, notifications (fake poster, nothing leaves the test)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from fritzos8_mcp.alerts import Alarm, AlarmService, Notifier, alert_secrets
from fritzos8_mcp.landevice import LanDeviceClient

from .conftest import FakeFC, make_service

WEBHOOK = "https://ha.example/api/webhook/geheim-webhook-id"
NTFY = "https://ntfy.example/geheimes-topic"
TG = "123456:geheimer-bot-token"


class Clock:
    def __init__(self) -> None:
        self.t = 1_800_000_000.0

    def __call__(self) -> float:
        return self.t


class Box:
    def __init__(self) -> None:
        self.counter = 1
        self.hosts = [
            {"NewHostName": "pc", "NewIPAddress": "192.0.2.20", "NewMACAddress": "AA:BB:CC:00:00:01", "NewActive": True}
        ]
        self.log = ""

    def responses(self) -> dict[tuple[str, str], Any]:
        return {
            ("Hosts1", "X_AVM-DE_GetChangeCounter"): lambda: {"NewX_AVM-DE_ChangeCounter": self.counter},
            ("Hosts1", "X_AVM-DE_GetHostListPath"): {},
            ("Hosts1", "GetHostNumberOfEntries"): lambda: {"NewHostNumberOfEntries": len(self.hosts)},
            ("Hosts1", "GetGenericHostEntry"): lambda NewIndex: self.hosts[NewIndex],
            ("DeviceInfo1", "GetDeviceLog"): lambda: {"NewDeviceLog": self.log},
            ("UserInterface1", "GetInfo"): {"NewUpgradeAvailable": "0"},
        }


class Poster:
    def __init__(self, status: int = 200, fail: bool = False) -> None:
        self.sent: list[tuple[str, Any, Any, dict[str, str]]] = []
        self.status = status
        self.fail = fail

    def __call__(self, url: str, payload: Any, text: Any, headers: dict[str, str]) -> int:
        if self.fail:
            raise OSError(f"connect to {url} failed")
        self.sent.append((url, payload, text, headers))
        return self.status


ENV = {
    "FRITZ_ALERT_WEBHOOK": WEBHOOK,
    "FRITZ_ALERT_NTFY": NTFY,
    "FRITZ_ALERT_TELEGRAM_TOKEN": TG,
    "FRITZ_ALERT_TELEGRAM_CHAT": "42",
}


def setup(
    landevices: LanDeviceClient, tmp_path: Path, poster: Poster | None = None, env: dict[str, str] | None = None
) -> tuple[AlarmService, Box, Clock, Poster]:
    box = Box()
    svc = make_service(landevices, FakeFC(box.responses()))
    poster = poster or Poster()
    clock = Clock()
    alarms = AlarmService(
        svc,
        now=clock,
        notifier=Notifier(ENV if env is None else env, post=poster),
        state_root=tmp_path / "st",
        environ={"FRITZ_ALERT_REPEAT_H": "24"},
    )
    return alarms, box, clock, poster


def add_host(box: Box, n: int, guest: bool = False) -> None:
    box.hosts.append(
        {
            "NewHostName": f"neu{n}",
            "NewIPAddress": f"192.0.2.{100 + n}",
            "NewMACAddress": f"AA:BB:CC:00:01:{n:02d}",
            "NewActive": True,
        }
    )
    box.counter += 1


def test_first_run_learns_then_new_device_is_one_shot(landevices: LanDeviceClient, tmp_path: Path) -> None:
    alarms, box, clock, _poster = setup(landevices, tmp_path)
    r = alarms.check(notify=True)
    assert r["count"] == 0 and r["notified"] == []
    add_host(box, 1)
    clock.t += 300
    r = alarms.check(notify=True)
    assert [a["type"] for a in r["alarms"]] == ["new_device"] and r["new"] == 1
    assert "neu1" in r["alarms"][0]["message"] and r["notified"] == ["new_device:AA:BB:CC:00:01:01"]
    assert set(r["notifications"]) == {"webhook", "ntfy", "telegram"}
    clock.t += 300
    box.counter += 1  # list read again, but the device is known now
    r = alarms.check(notify=True)
    assert r["count"] == 0 and r["notified"] == []


def test_notifications_payloads_and_no_secret_in_output(landevices: LanDeviceClient, tmp_path: Path) -> None:
    alarms, box, _clock, poster = setup(landevices, tmp_path)
    alarms.check()
    add_host(box, 2)
    r = alarms.check(notify=True)
    urls = [s[0] for s in poster.sent]
    assert WEBHOOK in urls and NTFY in urls and any(TG in u for u in urls)
    webhook = next(s for s in poster.sent if s[0] == WEBHOOK)
    assert webhook[1]["alarms"][0]["type"] == "new_device"
    text = str(r)
    assert "geheim" not in text and TG not in text
    assert r["channels"] == ["webhook", "ntfy", "telegram"]


def test_failed_channel_does_not_leak_url(landevices: LanDeviceClient, tmp_path: Path) -> None:
    alarms, box, _clock, _poster = setup(landevices, tmp_path, poster=Poster(fail=True))
    alarms.check()
    add_host(box, 3)
    r = alarms.check(notify=True)
    assert r["notifications"]["webhook"] == "fehlgeschlagen (OSError)" and "geheim" not in str(r)


def test_debounce_repeat_and_reappear(landevices: LanDeviceClient, tmp_path: Path) -> None:
    alarms, _box, clock, _poster = setup(landevices, tmp_path)
    state = {"on": True}
    alarms.extra_checks.append(("test", lambda: [Alarm("x:1", "test", "warn", "Testalarm")] if state["on"] else []))
    r = alarms.check(notify=True)
    assert r["notified"] == ["x:1"]
    clock.t += 3600
    assert alarms.check(notify=True)["notified"] == []  # still active, within 24 h
    clock.t += 24 * 3600
    assert alarms.check(notify=True)["notified"] == ["x:1"]  # repeated after 24 h
    state["on"] = False
    clock.t += 60
    r = alarms.check(notify=True)
    assert r["resolved"] == [{"key": "x:1", "message": "Testalarm"}]
    state["on"] = True
    clock.t += 60
    r = alarms.check(notify=True)
    assert r["alarms"][0]["status"] == "reappeared" and r["notified"] == []  # flapping is not re-notified


def test_alarm_seen_without_notify_is_notified_later(landevices: LanDeviceClient, tmp_path: Path) -> None:
    alarms, *_ = setup(landevices, tmp_path)
    alarms.extra_checks.append(("test", lambda: [Alarm("y", "test", "warn", "später melden")]))
    assert alarms.check(notify=False)["notified"] == []
    assert alarms.check(notify=True)["notified"] == ["y"]


def test_no_channel_configured(landevices: LanDeviceClient, tmp_path: Path) -> None:
    alarms, *_ = setup(landevices, tmp_path, env={})
    alarms.extra_checks.append(("test", lambda: [Alarm("z", "test", "warn", "x")]))
    r = alarms.check(notify=True)
    assert "Kein Benachrichtigungskanal" in r["notifications"]["note"] and r["channels"] == []


def test_link_flapping_battery_and_updates(landevices: LanDeviceClient, tmp_path: Path) -> None:
    alarms, box, _clock, _poster = setup(landevices, tmp_path)
    box.log = "\n".join(
        f"14.11.26 10:{i:02d}:00 LAN-Anschluss 2 {'getrennt' if i % 2 else 'verbunden'}." for i in range(12)
    )
    alarms.service._smarthome = SimpleNamespace(  # type: ignore[assignment]
        list_devices=lambda: [
            {"ain": "09995 0000001", "name": "Heizung Bad", "thermostat": {"battery_low": True, "battery_pct": 10}}
        ]
    )
    alarms.service.tr064.fc.responses[("UserInterface1", "GetInfo")] = {  # type: ignore[attr-defined]
        "NewUpgradeAvailable": "1",
        "NewX_AVM-DE_Version": "8.30",
    }
    r = alarms.check()
    types = {a["type"] for a in r["alarms"]}
    assert {"battery_low", "update_available", "link_flapping"} <= types
    assert any("Heizung Bad (10 %)" in a["message"] for a in r["alarms"])


def test_drift_is_opt_in(landevices: LanDeviceClient, tmp_path: Path) -> None:
    alarms, *_ = setup(landevices, tmp_path)
    r = alarms.check()
    assert "config_drift" not in r["sources"]
    r = alarms.check(include_drift=True)
    assert r["sources"]["config_drift"] == "ok"  # no snapshot yet → nothing to compare


def test_alert_secrets_from_env() -> None:
    assert set(alert_secrets(ENV)) == {WEBHOOK, NTFY, TG}
    assert alert_secrets({}) == ()


@pytest.mark.parametrize("status,expected", [(200, "ok"), (500, "HTTP 500")])
def test_notifier_status(status: int, expected: str) -> None:
    n = Notifier({"FRITZ_ALERT_NTFY": NTFY}, post=Poster(status=status))
    assert n.send("box", [Alarm("a", "t", "warn", "m")]) == {"ntfy": expected}
