# Home Assistant über MQTT

> **Status: experimentell, wird nicht weiterentwickelt.** Für HA-Entitäten die offiziellen Integrationen (AVM FRITZ!Box Tools, FRITZ!SmartHome, Anrufmonitor) nutzen; Alarme besser per HA-Webhook aus `alarms_check`.

`fritzos8-collector` kann die Messreihe (Stufe 8.1) und die Alarme (Stufe 8.3) per **MQTT-Discovery** an Home Assistant übergeben. Es gibt bewusst **keine eigene Custom-Component**: ein MQTT-Broker (z. B. das Mosquitto-Add-on) und die MQTT-Integration von Home Assistant genügen. An der FRITZ!Box wird dabei nichts geändert – der Collector liest nur.

## Einrichtung

1. In Home Assistant den Broker einrichten (Einstellungen → Add-ons → Mosquitto broker) und für den Collector einen eigenen Benutzer anlegen (Einstellungen → Personen → Benutzer, „nur lokal anmelden“).
2. Die optionale Abhängigkeit installieren:
   ```bash
   uv pip install 'fritzos8-mcp[mqtt]'      # bzw. uvx --from 'fritzos8-mcp[mqtt]' fritzos8-collector
   ```
3. Den Collector mit den MQTT-Variablen starten (zusätzlich zu `FRITZ_HOST`/`FRITZ_USER`/`FRITZ_PASSWORD…`):

| Variable | Standard | Bedeutung |
|---|---|---|
| `FRITZ_MQTT_HOST` | – | Broker-Hostname; ohne diese Variable ist die Brücke aus |
| `FRITZ_MQTT_PORT` | 1883 (8883 mit TLS) | Broker-Port |
| `FRITZ_MQTT_USER` | – | Broker-Benutzer |
| `FRITZ_MQTT_PASSWORD` / `FRITZ_MQTT_PASSWORD_FILE` | – | Broker-Passwort (Geheimnis, wird in allen Logs/Ausgaben geschwärzt) |
| `FRITZ_MQTT_TLS` | aus | `1` = TLS (Zertifikat des Brokers wird geprüft) |
| `FRITZ_MQTT_DISCOVERY_PREFIX` | `homeassistant` | Discovery-Präfix der HA-MQTT-Integration |
| `FRITZ_MQTT_BASE_TOPIC` | `fritzos8` | Präfix der Zustands-Topics |
| `FRITZ_ALERTS_IN_COLLECTOR` | aus | `1` = nach jeder Messung Alarme prüfen (sonst wird der zuletzt bekannte Alarmzustand veröffentlicht) |

Beispiel (launchd/systemd/cron mit `--once` oder dauerhaft ohne `--once`):

```bash
FRITZ_HOST=192.0.2.1 FRITZ_USER=mcp FRITZ_PASSWORD_FILE=~/.config/fritzos8/pw \
FRITZ_MQTT_HOST=homeassistant.local FRITZ_MQTT_USER=fritzos8 FRITZ_MQTT_PASSWORD_FILE=~/.config/fritzos8/mqtt \
FRITZ_ALERTS_IN_COLLECTOR=1 fritzos8-collector
```

Mehrere Boxen (`FRITZ_BOXES`) erscheinen als je ein eigenes Gerät „FRITZ!Box <name>“.

## Entitäten

Je Box ein Gerät mit:

| Entität | Typ | Quelle |
|---|---|---|
| Internet verbunden | binary_sensor (connectivity) | `wan.connected` |
| Verbindungsdauer | sensor (s) | `wan.uptime_s` |
| DSL Sync Down/Up | sensor (kbit/s) | `dsl.down_kbps`, `dsl.up_kbps` |
| DSL Störabstand Down/Up | sensor (dB) | `dsl.snr_down_db`, `dsl.snr_up_db` |
| DSL Dämpfung | sensor (dB) | `dsl.attenuation_down_db` |
| DSL CRC-/FEC-Fehler | sensor (total_increasing) | `dsl.err.*` |
| Durchsatz Down/Up | sensor (Mbit/s) | `throughput.*_mbit_s` |
| Aktive Geräte | sensor | `hosts.active` |
| Alarme | sensor (Anzahl, Liste als Attribut `alarms`) | `alarms_check` bzw. letzter Alarmzustand |
| Problem | binary_sensor (problem) | mindestens ein Alarm mit Schweregrad warn/critical |
| Letzte Messung | sensor (timestamp, Diagnose) | Zeitpunkt der Messung |

Fehlt ein Wert (z. B. DSL an einem Kabelanschluss), bleibt die Entität „unbekannt“. Nicht erreichbare Box → Verfügbarkeit `offline`; Collector beendet → Last Will `offline`.

## Topics

- Discovery (retained): `homeassistant/<sensor|binary_sensor>/fritzos8_<box>/<id>/config`
- Zustand (retained, JSON): `fritzos8/<box>/state` – Messgrößen wie in `history_summary`, dazu `measured_at`
- Alarme (retained, JSON): `fritzos8/<box>/alarms` – `count`, `problem`, `alarms` (Typ, Schweregrad, Text)
- Verfügbarkeit: `fritzos8/<box>/availability`, `fritzos8/bridge/availability`

## Datenschutz

Es verlassen nur Zahlen der Messreihe und Alarmtexte den Rechner. Alarmtexte können Gerätenamen enthalten (z. B. „Neues Gerät: …“) – der Broker sollte also nicht öffentlich sein. MACs aus Alarmdetails werden nicht veröffentlicht. Zugangsdaten der Box oder des Brokers erscheinen nie in Topics oder Logs.

## Beispiel-Automation

```yaml
automation:
  - alias: "FRITZ!Box: Störabstand sinkt"
    triggers:
      - trigger: numeric_state
        entity_id: sensor.fritzos8_heim_dsl_snr_down
        below: 6
        for: "01:00:00"
    actions:
      - action: notify.notify
        data:
          message: "DSL-Störabstand seit einer Stunde unter 6 dB – history_anomalies / isp_report prüfen."
```

Alternativ ohne MQTT: Alarme per `FRITZ_ALERT_WEBHOOK` an einen HA-Webhook (Stufe 8.3).
