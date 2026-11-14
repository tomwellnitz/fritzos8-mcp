# Home Assistant via MQTT

`fritzos8-collector` can publish the measurement series and the alarms to Home Assistant using **MQTT discovery** – no custom component needed, just a broker (e.g. the Mosquitto add-on) and HA's MQTT integration. Nothing is changed on the FRITZ!Box.

```bash
uv pip install 'fritzos8-mcp[mqtt]'
FRITZ_HOST=fritz.box FRITZ_USER=mcp FRITZ_PASSWORD_FILE=~/.config/fritzos8/pw \
FRITZ_MQTT_HOST=homeassistant.local FRITZ_MQTT_USER=fritzos8 FRITZ_MQTT_PASSWORD_FILE=~/.config/fritzos8/mqtt \
FRITZ_ALERTS_IN_COLLECTOR=1 fritzos8-collector
```

Each box becomes a device with sensors for Internet connectivity, connection uptime, DSL sync rate / noise margin / attenuation / error counters, throughput, active devices, alarms (count, list as attribute), a problem binary sensor and the time of the last measurement. Variables: `FRITZ_MQTT_HOST`, `_PORT`, `_USER`, `_PASSWORD`/`_PASSWORD_FILE` (secret, redacted), `_TLS`, `_DISCOVERY_PREFIX` (`homeassistant`), `_BASE_TOPIC` (`fritzos8`). The German page has all details.
