"""Stage 10.3 – MQTT bridge with Home Assistant discovery (fake publisher, no broker, no box)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from fritzos8_mcp.alerts import alert_secrets
from fritzos8_mcp.errors import ConfigError
from fritzos8_mcp.mqttbridge import (
    MqttBridge,
    MqttSettings,
    alarms_message,
    discovery_messages,
    mqtt_secrets,
    state_message,
)

BROKER_PW = "mqtt-Geheimnis-42"  # test value only


class FakePublisher:
    def __init__(self, settings: MqttSettings, fail: bool = False) -> None:
        self.settings = settings
        self.sent: list[tuple[str, str, bool]] = []
        self.fail = fail
        self.closed = False

    def publish(self, topic: str, payload: str, retain: bool) -> None:
        if self.fail:
            raise ConnectionRefusedError(f"broker {self.settings.host} with {self.settings.password}")
        self.sent.append((topic, payload, retain))

    def close(self) -> None:
        self.closed = True


def _settings(**kw: Any) -> MqttSettings:
    return MqttSettings(host="broker.test", user="fritz", password=BROKER_PW, **kw)


def test_settings_from_env(tmp_path: Path) -> None:
    assert MqttSettings.from_env({}) is None
    s = MqttSettings.from_env({"FRITZ_MQTT_HOST": "broker.test", "FRITZ_MQTT_TLS": "1"})
    assert s is not None and s.port == 8883 and s.tls and s.discovery_prefix == "homeassistant"
    pw = tmp_path / "pw"
    pw.write_text(BROKER_PW + "\n", encoding="utf-8")
    s = MqttSettings.from_env({"FRITZ_MQTT_HOST": "b", "FRITZ_MQTT_PASSWORD_FILE": str(pw), "FRITZ_MQTT_PORT": "1884"})
    assert s is not None and s.password == BROKER_PW and s.port == 1884
    assert BROKER_PW not in repr(s)
    with pytest.raises(ConfigError):
        MqttSettings.from_env({"FRITZ_MQTT_HOST": "b", "FRITZ_MQTT_PORT": "x"})
    with pytest.raises(ConfigError):
        MqttSettings.from_env({"FRITZ_MQTT_HOST": "b", "FRITZ_MQTT_PASSWORD": "a", "FRITZ_MQTT_PASSWORD_FILE": "f"})


def test_password_is_a_secret_everywhere() -> None:
    env = {"FRITZ_MQTT_HOST": "b", "FRITZ_MQTT_PASSWORD": BROKER_PW}
    assert mqtt_secrets(env) == (BROKER_PW,)
    assert BROKER_PW in alert_secrets(env)
    # misconfigured bridge: the password is still redacted
    assert mqtt_secrets({"FRITZ_MQTT_HOST": "b", "FRITZ_MQTT_PORT": "x", "FRITZ_MQTT_PASSWORD": BROKER_PW}) == (
        BROKER_PW,
    )
    assert mqtt_secrets({}) == ()


def test_discovery_messages_are_valid_ha_configs() -> None:
    msgs = discovery_messages(_settings(), "heim", {"model": "FRITZ!Box 7590", "firmware": "8.20"})
    topics = [t for t, _ in msgs]
    assert "homeassistant/binary_sensor/fritzos8_heim/internet/config" in topics
    assert "homeassistant/sensor/fritzos8_heim/alarms/config" in topics
    assert len(set(topics)) == len(topics)
    uids = [p["unique_id"] for _, p in msgs]
    assert len(set(uids)) == len(uids)
    snr = dict(msgs)["homeassistant/sensor/fritzos8_heim/dsl_snr_down/config"]
    assert snr["state_topic"] == "fritzos8/heim/state"
    assert snr["unit_of_measurement"] == "dB"
    assert snr["device"]["model"] == "FRITZ!Box 7590"
    assert {"topic": "fritzos8/bridge/availability"} in snr["availability"]
    blob = json.dumps(msgs)
    assert BROKER_PW not in blob


def test_box_names_are_topic_safe() -> None:
    msgs = discovery_messages(_settings(), "zweit box/#")
    assert all("#" not in t and "+" not in t and " " not in t.split("/")[2] for t, _ in msgs)


def test_state_and_alarm_messages() -> None:
    st = state_message({"ok": True, "ts": 1_800_000_000, "metrics": {"dsl.snr_down_db": 8.5, "x": "skip"}})
    assert st["dsl.snr_down_db"] == 8.5 and "x" not in st
    assert st["measured_at"][-3] == ":"  # ISO offset with colon
    al = alarms_message(
        [{"type": "new_device", "severity": "warn", "message": "Neues Gerät", "details": {"mac": "AA:BB:CC:00:00:01"}}]
    )
    assert al == {
        "count": 1,
        "problem": True,
        "alarms": [{"type": "new_device", "severity": "warn", "message": "Neues Gerät"}],
    }
    assert alarms_message([{"severity": "info", "message": "Update"}])["problem"] is False


def test_bridge_announces_once_then_publishes() -> None:
    pubs: list[FakePublisher] = []

    def factory(s: MqttSettings) -> FakePublisher:
        pubs.append(FakePublisher(s))
        return pubs[-1]

    bridge = MqttBridge(_settings(), factory)
    r1 = bridge.publish("heim", {"ok": True, "ts": 1.0, "metrics": {"hosts.active": 7}}, [])
    assert r1["ok"] and r1["announced"] > 10
    r2 = bridge.publish("heim", {"ok": False, "ts": 2.0, "metrics": {}}, None)
    assert r2 == {"ok": True, "announced": 0}
    sent = pubs[0].sent
    assert all(retain for _, _, retain in sent)
    assert ("fritzos8/heim/availability", "offline", True) in sent
    assert sum(1 for t, _, _ in sent if t == "fritzos8/heim/alarms") == 1
    bridge.close()
    assert pubs[0].closed


def test_bridge_never_raises_or_leaks_on_broker_errors(caplog: pytest.LogCaptureFixture) -> None:
    bridge = MqttBridge(_settings(), lambda s: FakePublisher(s, fail=True))
    r = bridge.publish("heim", {"ok": True, "metrics": {}}, [])
    assert r == {"ok": False, "error": "ConnectionRefusedError"}
    assert BROKER_PW not in caplog.text
    assert "heim" not in bridge._announced  # discovery is repeated after reconnect
