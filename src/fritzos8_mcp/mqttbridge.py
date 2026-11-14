"""Stage 10.3 – Home Assistant integration via MQTT: the measurement series (stage 8.1) and the alarms (stage 8.3) as
Home Assistant entities using MQTT discovery. No custom component – any MQTT broker (e.g. the Mosquitto add-on)
and the HA MQTT integration are enough.

Runs inside ``fritzos8-collector`` when ``FRITZ_MQTT_HOST`` is set: after every measurement the bridge publishes

* discovery configs (retained) once per process under ``<discovery prefix>/<component>/fritzos8_<box>/<id>/config``,
* the latest values as one JSON document ``<base>/<box>/state`` (retained),
* the alarms ``<base>/<box>/alarms`` (count + list as attributes, retained),
* availability ``<base>/<box>/availability`` (``online``/``offline``) and a bridge-wide last will
  ``<base>/bridge/availability``.

Optional dependency ``paho-mqtt`` (extra ``mqtt``). Settings only from the environment: ``FRITZ_MQTT_HOST``,
``FRITZ_MQTT_PORT`` (1883, 8883 with TLS), ``FRITZ_MQTT_USER``, ``FRITZ_MQTT_PASSWORD`` / ``FRITZ_MQTT_PASSWORD_FILE``
(secret – redacted like the box password), ``FRITZ_MQTT_TLS``, ``FRITZ_MQTT_DISCOVERY_PREFIX`` (``homeassistant``),
``FRITZ_MQTT_BASE_TOPIC`` (``fritzos8``). Nothing is ever written to the box; only values that are already in the
local measurement series leave the machine – no MACs, no device names, no secrets.
"""

from __future__ import annotations

import importlib
import json
import logging
import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from . import __version__
from .errors import ConfigError

log = logging.getLogger(__name__)

TRUTHY = {"1", "true", "yes", "on"}
_TOPIC_PART = re.compile(r"[^a-zA-Z0-9_-]")

# metric → (component, object id, name, unit, device_class, state_class, icon)
SENSORS: tuple[tuple[str, str, str, str, str | None, str | None, str | None, str | None], ...] = (
    ("wan.connected", "binary_sensor", "internet", "Internet verbunden", None, "connectivity", None, None),
    ("wan.uptime_s", "sensor", "wan_uptime", "Verbindungsdauer", "s", "duration", "measurement", None),
    ("dsl.down_kbps", "sensor", "dsl_down", "DSL Sync Downstream", "kbit/s", "data_rate", "measurement", None),
    ("dsl.up_kbps", "sensor", "dsl_up", "DSL Sync Upstream", "kbit/s", "data_rate", "measurement", None),
    ("dsl.snr_down_db", "sensor", "dsl_snr_down", "DSL Störabstand Downstream", "dB", None, "measurement", "mdi:sine-wave"),  # noqa: E501
    ("dsl.snr_up_db", "sensor", "dsl_snr_up", "DSL Störabstand Upstream", "dB", None, "measurement", "mdi:sine-wave"),
    ("dsl.attenuation_down_db", "sensor", "dsl_attenuation", "DSL Dämpfung", "dB", None, "measurement", None),
    ("dsl.err.CRCErrors", "sensor", "dsl_crc", "DSL CRC-Fehler", None, None, "total_increasing", "mdi:alert-circle"),
    ("dsl.err.FECErrors", "sensor", "dsl_fec", "DSL FEC-Fehler", None, None, "total_increasing", "mdi:alert-circle"),
    ("throughput.down_mbit_s", "sensor", "throughput_down", "Durchsatz Download", "Mbit/s", "data_rate", "measurement", None),  # noqa: E501
    ("throughput.up_mbit_s", "sensor", "throughput_up", "Durchsatz Upload", "Mbit/s", "data_rate", "measurement", None),
    ("hosts.active", "sensor", "hosts_active", "Aktive Geräte", None, None, "measurement", "mdi:devices"),
)  # fmt: skip


def _part(value: str) -> str:
    return _TOPIC_PART.sub("_", value.strip()) or "box"


@dataclass(frozen=True)
class MqttSettings:
    host: str
    port: int = 1883
    user: str = ""
    password: str = field(default="", repr=False)
    tls: bool = False
    discovery_prefix: str = "homeassistant"
    base_topic: str = "fritzos8"
    client_id: str = "fritzos8-collector"

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> MqttSettings | None:
        """None if ``FRITZ_MQTT_HOST`` is not set (bridge off)."""
        e = os.environ if environ is None else environ
        host = (e.get("FRITZ_MQTT_HOST") or "").strip()
        if not host:
            return None
        tls = (e.get("FRITZ_MQTT_TLS") or "").strip().lower() in TRUTHY
        try:
            port = int(e.get("FRITZ_MQTT_PORT") or (8883 if tls else 1883))
        except ValueError:
            raise ConfigError("FRITZ_MQTT_PORT muss eine ganze Zahl sein.") from None
        if not 1 <= port <= 65535:
            raise ConfigError("FRITZ_MQTT_PORT muss 1–65535 sein.")
        password = e.get("FRITZ_MQTT_PASSWORD") or ""
        pw_file = (e.get("FRITZ_MQTT_PASSWORD_FILE") or "").strip()
        if password and pw_file:
            raise ConfigError("Entweder FRITZ_MQTT_PASSWORD oder FRITZ_MQTT_PASSWORD_FILE setzen, nicht beides.")
        if pw_file:
            try:
                password = Path(pw_file).expanduser().read_text(encoding="utf-8").rstrip("\r\n")
            except OSError as exc:
                raise ConfigError(f"FRITZ_MQTT_PASSWORD_FILE nicht lesbar ({exc.strerror}).") from None
        return cls(
            host=host,
            port=port,
            user=(e.get("FRITZ_MQTT_USER") or "").strip(),
            password=password,
            tls=tls,
            discovery_prefix=(e.get("FRITZ_MQTT_DISCOVERY_PREFIX") or "homeassistant").strip().strip("/"),
            base_topic=(e.get("FRITZ_MQTT_BASE_TOPIC") or "fritzos8").strip().strip("/"),
        )

    @property
    def secrets(self) -> tuple[str, ...]:
        return (self.password,) if self.password else ()

    @property
    def bridge_availability(self) -> str:
        return f"{self.base_topic}/bridge/availability"

    def topic(self, box: str, leaf: str) -> str:
        return f"{self.base_topic}/{_part(box)}/{leaf}"


def mqtt_secrets(environ: Mapping[str, str] | None = None) -> tuple[str, ...]:
    """The broker password (to be redacted everywhere); empty if the bridge is not configured or misconfigured."""
    try:
        settings = MqttSettings.from_env(environ)
    except ConfigError:
        e = os.environ if environ is None else environ
        return tuple(v for v in [(e.get("FRITZ_MQTT_PASSWORD") or "")] if v)
    return settings.secrets if settings else ()


def discovery_messages(
    settings: MqttSettings, box: str, device: Mapping[str, Any] | None = None
) -> list[tuple[str, dict[str, Any]]]:
    """(topic, payload) pairs for Home Assistant MQTT discovery (retained)."""
    node = f"fritzos8_{_part(box)}"
    info = dict(device or {})
    dev = {
        "identifiers": [node],
        "name": f"FRITZ!Box {box}",
        "manufacturer": "AVM",
        "model": info.get("model") or "FRITZ!Box",
        "sw_version": info.get("firmware") or None,
        "via_device": None,
    }
    dev = {k: v for k, v in dev.items() if v is not None}
    origin = {"name": "fritzos8-mcp", "sw_version": __version__}
    availability = [
        {"topic": settings.bridge_availability},
        {"topic": settings.topic(box, "availability")},
    ]
    state_topic = settings.topic(box, "state")
    out: list[tuple[str, dict[str, Any]]] = []
    for metric, component, oid, name, unit, dclass, sclass, icon in SENSORS:
        cfg: dict[str, Any] = {
            "name": name,
            "unique_id": f"{node}_{oid}",
            "object_id": f"{node}_{oid}",
            "state_topic": state_topic,
            "value_template": "{{ value_json['" + metric + "'] if value_json['" + metric + "'] is defined else None }}",
            "availability": availability,
            "availability_mode": "all",
            "device": dev,
            "origin": origin,
        }
        if component == "binary_sensor":
            cfg["value_template"] = "{{ 'ON' if value_json['" + metric + "'] | float(0) >= 1 else 'OFF' }}"
        if unit:
            cfg["unit_of_measurement"] = unit
        if dclass:
            cfg["device_class"] = dclass
        if sclass:
            cfg["state_class"] = sclass
        if icon:
            cfg["icon"] = icon
        out.append((f"{settings.discovery_prefix}/{component}/{node}/{oid}/config", cfg))
    alarms_topic = settings.topic(box, "alarms")
    common = {"availability": availability, "availability_mode": "all", "device": dev, "origin": origin}
    out.append(
        (
            f"{settings.discovery_prefix}/sensor/{node}/alarms/config",
            {
                "name": "Alarme",
                "unique_id": f"{node}_alarms",
                "object_id": f"{node}_alarms",
                "state_topic": alarms_topic,
                "value_template": "{{ value_json.count }}",
                "json_attributes_topic": alarms_topic,
                "json_attributes_template": "{{ {'alarms': value_json.alarms} | tojson }}",
                "state_class": "measurement",
                "icon": "mdi:bell-alert",
                **common,
            },
        )
    )
    out.append(
        (
            f"{settings.discovery_prefix}/binary_sensor/{node}/problem/config",
            {
                "name": "Problem",
                "unique_id": f"{node}_problem",
                "object_id": f"{node}_problem",
                "state_topic": alarms_topic,
                "value_template": "{{ 'ON' if value_json.problem else 'OFF' }}",
                "device_class": "problem",
                **common,
            },
        )
    )
    out.append(
        (
            f"{settings.discovery_prefix}/sensor/{node}/last_measurement/config",
            {
                "name": "Letzte Messung",
                "unique_id": f"{node}_last_measurement",
                "object_id": f"{node}_last_measurement",
                "state_topic": state_topic,
                "value_template": "{{ value_json.measured_at }}",
                "device_class": "timestamp",
                "entity_category": "diagnostic",
                **common,
            },
        )
    )
    return out


def state_message(result: Mapping[str, Any]) -> dict[str, Any]:
    """The retained state document from one ``history.collect()`` result (metrics only, nothing personal)."""
    metrics = {k: v for k, v in (result.get("metrics") or {}).items() if isinstance(v, int | float)}
    ts = result.get("ts")
    measured = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(float(ts))) if isinstance(ts, int | float) else None
    if measured and len(measured) > 5:
        measured = measured[:-2] + ":" + measured[-2:]  # ISO 8601 offset with colon for HA
    return {**metrics, "measured_at": measured, "ok": bool(result.get("ok"))}


def alarms_message(alarms: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Alarm count + compact list. Problem = at least one warn/critical alarm."""
    items = [
        {"type": a.get("type"), "severity": a.get("severity"), "message": a.get("message")}
        for a in alarms
        if isinstance(a, Mapping)
    ]
    return {
        "count": len(items),
        "problem": any(a["severity"] in ("warn", "critical") for a in items),
        "alarms": items[:20],
    }


class Publisher(Protocol):
    def publish(self, topic: str, payload: str, retain: bool) -> None: ...

    def close(self) -> None: ...


class PahoPublisher:  # pragma: no cover - thin adapter around paho-mqtt, exercised live only
    def __init__(self, settings: MqttSettings) -> None:
        try:
            mqtt: Any = importlib.import_module("paho.mqtt.client")
        except ImportError:
            raise ConfigError(
                "MQTT-Brücke braucht paho-mqtt.", hint="Installieren mit: uv pip install 'fritzos8-mcp[mqtt]'"
            ) from None
        version = getattr(mqtt, "CallbackAPIVersion", None)
        self._client = (
            mqtt.Client(version.VERSION2, client_id=settings.client_id) if version else mqtt.Client(settings.client_id)
        )
        if settings.user:
            self._client.username_pw_set(settings.user, settings.password or None)
        if settings.tls:
            self._client.tls_set()
        self._client.will_set(settings.bridge_availability, "offline", qos=1, retain=True)
        self._client.connect(settings.host, settings.port, keepalive=60)
        self._client.loop_start()
        self._client.publish(settings.bridge_availability, "online", qos=1, retain=True)
        self._settings = settings

    def publish(self, topic: str, payload: str, retain: bool) -> None:
        self._client.publish(topic, payload, qos=1, retain=retain).wait_for_publish(timeout=10)

    def close(self) -> None:
        self._client.publish(self._settings.bridge_availability, "offline", qos=1, retain=True).wait_for_publish(
            timeout=5
        )
        self._client.loop_stop()
        self._client.disconnect()


class MqttBridge:
    def __init__(
        self, settings: MqttSettings, publisher_factory: Callable[[MqttSettings], Publisher] = PahoPublisher
    ) -> None:
        self.settings = settings
        self._factory = publisher_factory
        self._publisher: Publisher | None = None
        self._announced: set[str] = set()

    @property
    def publisher(self) -> Publisher:
        if self._publisher is None:
            self._publisher = self._factory(self.settings)
        return self._publisher

    def _send(self, topic: str, payload: Any, retain: bool = True) -> None:
        text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
        self.publisher.publish(topic, text, retain)

    def announce(self, box: str, device: Mapping[str, Any] | None = None) -> int:
        messages = discovery_messages(self.settings, box, device)
        for topic, payload in messages:
            self._send(topic, payload)
        self._announced.add(box)
        return len(messages)

    def publish(
        self,
        box: str,
        result: Mapping[str, Any],
        alarms: Sequence[Mapping[str, Any]] | None = None,
        device: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Publish one measurement (+ alarms). Never raises for broker problems – the collector must keep measuring."""
        try:
            announced = 0 if box in self._announced else self.announce(box, device)
            self._send(self.settings.topic(box, "availability"), "online" if result.get("ok") else "offline")
            self._send(self.settings.topic(box, "state"), state_message(result))
            if alarms is not None:
                self._send(self.settings.topic(box, "alarms"), alarms_message(alarms))
            return {"ok": True, "announced": announced}
        except ConfigError:
            raise
        except Exception as exc:  # broker down, TLS problem … – only the type, never the credentials
            log.warning("MQTT: Veröffentlichung für %s fehlgeschlagen (%s)", box, type(exc).__name__)
            self._publisher = None
            self._announced.discard(box)
            return {"ok": False, "error": type(exc).__name__}

    def close(self) -> None:
        if self._publisher is not None:
            try:
                self._publisher.close()
            except Exception as exc:  # pragma: no cover - best effort on shutdown
                log.debug("MQTT: Schließen fehlgeschlagen (%s)", type(exc).__name__)
            self._publisher = None
