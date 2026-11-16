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
| `mesh_overview`, `device_connection_quality` (WLAN-Signal) | 🟡 Signal fehlte → korrigiert (dBm laut Schema v8.7 + TR-064-Signal-%), nachtesten | 🟡 wie 7583 |
| `test_my_device` (`box_view.wlan_connection.service`) | 🟡 meldete `WLANConfiguration1` statt `…2` (5 GHz) → korrigiert, nachtesten | – |
| `isp_report` | 🟡 mit 1 Messpunkt „keine Ausfälle“ → jetzt `insufficient_data`, nachtesten | 🟡 wie 7583 |
| `devices_cleanup_report`/`_plan` | ✅ Report nachgetestet (16.11.): VPN-Peer und Powerline nicht mehr vorgeschlagen, „zuletzt online“ = `lastused`; `_plan` nicht live geprüft | ❌→🟡 98 Geräte: „gleiche IP“ als Duplikat-Löschgrund für echte Geräte mit Hersteller-MAC, „K--chen“-Umbenennung, Hersteller „China“ → Regeln verschärft, nachtesten |
| `myfritz_status` (`mcp_benutzer_internet`) | 🟡 Text widersprach den Feldern → Recht/Fernzugriff getrennt, nachtesten | – |
| `online_monitor` | 🟡 Sync-Gruppe „VDSL“ bei G.fast, `X_AVM-DE_GetAddonInfos` fehlt → Rohwert gekennzeichnet + Fallback `GetCommonLinkProperties`, nachtesten | – |
| `vpn_connections` | 🟡 Fehlercode bei verbundener Verbindung → jetzt `last_error` (historisch), nachtesten | – |
| Sitzungsablauf (`/api/v0`, AHA) | – | 🟡 `/api/v0` antwortete HTTP 400 statt 401 → Re-Login (REST + AHA), nachtesten |
| Schreib-/critical-Tools ab Stufe 4 | – | – |

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
