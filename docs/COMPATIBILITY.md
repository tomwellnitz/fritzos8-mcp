# Kompatibilität

Welche Modelle und FRITZ!OS-Versionen mit welchem Ergebnis geprüft wurden. „live“ = gegen eine echte Box (nur lesend, sofern nicht anders vermerkt), „Fixture“ = mit anonymisierten Antworten aus `tests/fixtures/community/`, „Mock“ = nur gegen erfundene Testdaten.

## Geprüfte Boxen

| Modell | FRITZ!OS | Anschluss | Stand | Ergebnis |
|---|---|---|---|---|
| FRITZ!Box 7583 | 8.26 | DSL/G.fast, PPP, DS-Lite | live 14.–16.11.2026 | Stufen 1–3 inkl. Schreiben (Umbenennen, feste IP aufheben/setzen, Eintrag löschen, Internetsperre, AB an/aus); Stufen 8–10 lesend (siehe unten); Korrekturen aus dem Lesetest eingearbeitet |
| FRITZ!Box 6660 Cable | 8.25 | Kabel (DOCSIS), öffentliche IPv4, kein IPv6 | live 14.11.2026 | lesend wie oben; Smart-Home-REST mit DECT-Thermostat, Thermostat-Schreibtest (Soll-Temperatur hin/zurück) |

## Bereiche je Box

✅ live korrekt · 🟡 live mit Einschränkung · ❌ fehlt auf der Box · – nicht geprüft

| Bereich / Tool | 7583 (8.26, DSL) | 6660 Cable (8.25) |
|---|---|---|
| `setup_check` | ✅ | ✅ |
| `set_static_ip` (unverändert, aufheben, festlegen), `delete_host` | ✅ schreibend, `verified` = Rücklesen (16.11.) | – |
| `wan_status` | ✅ (IPv4-Feld korrigiert, DS-Lite) | ✅ |
| `line_diagnostics` | ✅ DSL inkl. Kabeltest/Spektrum | 🟡 Kabel = `unknown` (per TR-064 nicht lesbar) |
| `get_dns_settings` (inkl. Upstream) | ✅ | ✅ |
| `guest_wifi_status` (Isolierung) | ✅ | ✅ |
| `firmware_status` (`build_type`) | ✅ | ✅ |
| `avm_device_updates` | ✅ inkl. Powerline | ✅ |
| `phone_numbers_status` | ✅ | – |
| `two_factor_status` | ✅ | ✅ |
| `ipv6_firewall_status` | ✅ (`WANIPv6Firewall1`, Felder ohne `New`) | – |
| `system_transparency` | ✅ nach Korrektur (Firewall, Zwangstrennung: Action fehlt → nicht verfügbar) | ✅ nach Korrektur (kein IPv6-Präfix) |
| `devices_change_counter` | 🟡 Box liefert dauerhaft 0 → „kein Zähler“ | – |
| `security_check`, `fritz_export`, `history_collect`, `network_optimizer_suggest`, `call_barring_list` | ✅ | ✅ |
| `smarthome_overview` (REST) | – (keine Smart-Home-Geräte) | ✅ Thermostat, Standort geschwärzt |
| `mesh_overview`, `device_connection_quality` (WLAN-Signal) | ✅ nachgetestet (16.11.): alle WLAN-Geräte mit gemessenem dBm aus der Mesh-Liste, keines ohne Signal. Gerät am als LAN genutzten WAN-Port (`WAN:1`) jetzt mit Port-Daten/EEE (Fix [#33](https://github.com/tomwellnitz/fritzos8-mcp/pull/33), live ✅ 16.11.) | 🟡 wie 7583 |
| `test_my_device` (`box_view.wlan_connection.service`) | ✅ nachgetestet (16.11.): Dienst = `quality.tr064.service` (5 GHz) | – |
| `isp_report` | 🟡 mit 1 Messpunkt jetzt `insufficient_data` (✅ 16.11.); Bericht nach ≥ 1 h Messreihe noch nachtesten | 🟡 wie 7583 |
| `devices_cleanup_report`/`_plan` | ✅ Report nachgetestet (16.11.): VPN-Peer und Powerline nicht mehr vorgeschlagen, „zuletzt online“ = `lastused`; `_plan` nicht live geprüft | ❌→🟡 98 Geräte: „gleiche IP“ als Duplikat-Löschgrund für echte Geräte mit Hersteller-MAC, „K--chen“-Umbenennung, Hersteller „China“ → Regeln verschärft, nachtesten |
| `myfritz_status` (`mcp_benutzer_internet`) | ✅ nachgetestet (16.11.): Text und Felder konsistent | – |
| `online_monitor` | ✅ `mode_note` (G.fast statt „VDSL“) und 64-bit-Volumen über IGD (16.11.). `rates.sync` = synchronisierte DSL-Rate, `rates.attainable` = erreichbare Rate (Fix [#34](https://github.com/tomwellnitz/fritzos8-mcp/pull/34), live ✅ 16.11.: = `line_diagnostics`) | – |
| `vpn_connections` | ✅ nachgetestet (16.11.): Fehler einer verbundenen Verbindung nur als `last_error` (historisch), keine Schlüssel in der Ausgabe | – |
| Sitzungsablauf (`/api/v0`, AHA) | – | 🟡 `/api/v0` antwortete HTTP 400 statt 401 → Re-Login (REST + AHA), nachtesten |
| Kindersicherung: `set_parental_profile` | ✅ schreibend (16.11., Web-UI gegengeprüft). Box meldet Standard-Geräte mit der Gast-ID `filtprof2`, Gast-Profil für Heimnetz-Geräte abgelehnt → Fix [#40](https://github.com/tomwellnitz/fritzos8-mcp/pull/40) | – |
| `parental_ticket_create`, `call_barring_add`/`_remove`, `set_alarm_clock`, `set_nas_protocol` (FTP) | ✅ schreibend hin/zurück (16.11.) | – |
| `devices_cleanup_plan`/`_execute` (Umbenennen) | ✅ schreibend hin/zurück (16.11.) | – |
| `smarthome_thermostat_mode` (Boost) | – | ✅ schreibend hin/zurück (16.11.), `endTime` in Unix-Sekunden |
| `guest_wifi_session_start`/`_stop`, `set_guest_wifi` | – | ✅ schreibend (16.11.); Sitzung auf schon eingeschaltetem Gast-WLAN hätte es am Ende abgeschaltet → Fix [#39](https://github.com/tomwellnitz/fritzos8-mcp/pull/39), live bestätigt: nach Ablauf bleibt es an, Sitzung beendet |
| `set_wlan_channel` | – | ✅ fester Kanal und Autokanal hin/zurück (Nachtest 16.11.). Beim ersten Versuch blieb der Kanal stehen und nur der Autokanal ging aus (nicht reproduzierbar) → Teiländerung wird erkannt und zurückgestellt (Fix [#38](https://github.com/tomwellnitz/fritzos8-mcp/pull/38)) |
| `set_lan_eee` | – (bewusst nicht: Pi am Port) | ✅ schreibend (16.11.), Body nur `eee_mode`; wirkt hier **pro Port** (7583: box-weit). Ein laufender Link bleibt mit EEE ausgehandelt (`eee_active`), auch nach einem Neustart von Home Assistant am Pi; Kabel-Neuverbindung noch nicht geprüft → Hinweis [#44](https://github.com/tomwellnitz/fritzos8-mcp/pull/44), live bestätigt (`still_negotiated`, angepasster Pi-Tipp) |
| `box_speedtest_info`, `box_speedtest_run` (`enable_temporarily`) | ✅ schreibend (17.11.): Server war aus, nur LAN-TCP eingeschaltet, 10 s gemessen (Rechner per WLAN: 184 Mbit/s gesendet, 169 Mbit/s von der Box gezählt), danach alle fünf Schalter wieder aus (Rücklesen + `box_speedtest_info`). Reines TCP-Senden auf Port 4711 wird gezählt | ✅ schreibend (17.11.), gleicher Ablauf und Rückstellung; über das Box-zu-Box-VPN gemessen (~1 Mbit/s) – zeigt den VPN-Weg, nicht das Heimnetz |
| Critical (16.11., `confirmed_via: elicitation`): Tickets verwerfen, statische Route, IPv4-Portfreigabe, FTP aus dem Internet, `fritz_apply` | ✅ je hin/zurück. Portfreigabe setzt am Ziel dauerhaft eine feste IP → Rückstellung [#42](https://github.com/tomwellnitz/fritzos8-mcp/pull/42), live bestätigt (feste IP nach dem Löschen wieder aufgehoben) | Tickets verwerfen ✅ |
| Elicitation-Ablehnung (critical `*_execute`) | – | ✅ „Nein“ im Dialog → `declined`, nichts geändert, Token danach ungültig (16.11.) |
| `ipv6_pinhole_add` | ❌ von der Box abgelehnt (nicht berechtigt) – keine UPnP-Pinholes per TR-064 in dieser Einstellung | – |
| Thermostat: `smarthome_holidays`, `smarthome_summer_period`, `smarthome_rename`, Fenster offen | – | ✅ je hin/zurück (16.11.). Urlaub ohne gespeicherte Temperatur → HTTP 400 → Vorabprüfung [#43](https://github.com/tomwellnitz/fritzos8-mcp/pull/43), live bestätigt |
| `wake_on_lan` | 🟡 Magic Packet gesendet, Zielgerät nicht aufgewacht (Geräteseite unklar) | – |
| nicht live getestet (bewusst) | Fernzugriff an/aus, WLAN-Band aus, WPS, Anrufe, Neustart/Reconnect/Firmware, Smart-Home anlernen/löschen, `delete_host_force` | – |

Offene Prüfpunkte je Stufe: `ROADMAP.md` im Repository („Live-Prüfpunkte“).

## Eigene Box beitragen

1. Read-only-Livetests laufen lassen (ändern nichts an der Box):
   ```bash
   FRITZ_LIVE_TEST=1 FRITZ_HOST=fritz.box FRITZ_USER=mcp FRITZ_PASSWORD_FILE=~/.config/fritzos8/pw \
     uv run pytest tests/live -o addopts="" -v
   ```
   Übersprungen = fehlendes Recht oder Firmware ohne die Schnittstelle (bitte so notieren).
2. Ergebnis als Issue („Kompatibilität“) melden: Modell, FRITZ!OS-Version, Anschlussart, welche Tests grün/übersprungen/rot waren – **ohne** Seriennummern, Adressen oder Gerätenamen.
3. Optional Antworten als anonymisierte Fixtures beitragen ([fixtures.md](fixtures.md)).
