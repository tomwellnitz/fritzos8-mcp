# Roadmap

## Projektstand & Live-Prüfung (Stand 16.11.2026, abgeglichen mit docs/COMPATIBILITY.md)

Testboxen: **Box A** FRITZ!Box 7583 (FRITZ!OS 8.26, DSL) und **Box B** FRITZ!Box 6660 Cable (FRITZ!OS 8.25, DECT-Heizkörperthermostat). Ergebnis je Tool und Box: [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) – dort mit 🟡 „nachtesten“ markierte Punkte sind die offenen Live-Prüfungen.

### Stand je Stufe

| Stufe | Inhalt | Stand |
|---|---|---|
| 1 | Geräte & Netz | live lesend an beiden Boxen; Schreiben an Box A live: `rename_host` (hin/zurück), `set_static_ip` (unverändert, aufheben, festlegen), `delete_host` (16.11.); Portfreigabe an/aus (critical) live; Neustart/Reconnect bewusst nicht |
| 2 | WLAN/Gast, Smart Home (AHA), Diagnose/Security-Check | live lesend an beiden Boxen |
| 3 | Telefonie, Kindersicherung, Portfreigaben, DNS lesen | live an Box A inkl. Schreiben (Internetsperre, AB an/aus), lesend an Box B; DNS schreiben bewusst nicht gebaut |
| 4–7 | Aufräum-Assistent, Schnappschüsse, Mehrbox, Netz-Doktor; NAS & Fernzugang; LAN-Ports/VPN/Powerline/Qualität; Box-Schutz, WLAN-Einstellungen, Profile, Elicitation, `outputSchema` | live lesend an beiden Boxen („Live-Lesetest Stufen 4–7“), Korrekturen eingearbeitet und 🟡 nachzutesten; schreibend live (16.11.): Aufräum-Assistent (Umbenennen), `set_nas_protocol`, Kindersicherung (Profil, Ticket) an Box A, `set_lan_eee`, `set_wlan_channel` an Box B; critical live: Tickets verwerfen, FTP aus dem Internet; Fernzugriff und WLAN-Band bewusst nicht; 7.2/7.3 nicht gebaut |
| 8 | Überwachung & Komfort (8.0–8.12) | live lesend an beiden Boxen; schreibend live (16.11.): Rufsperre, Weckruf an Box A, Thermostat (Soll-Temperatur, Boost) und Gast-WLAN-Sitzung an Box B |
| 9 | Veröffentlichung, Rechte-Tabelle, Abdeckungspflege | Repo öffentlich seit 14.11.2026 (sauberer Initial-Commit), Releases über release-please |
| 10 | Ökosystem & Intelligenz | live lesend an beiden Boxen; critical live (16.11.): statische Route, `fritz_apply`, Thermostat-Urlaub/-Sommerzeit/-Umbenennen; IPv6-Pinhole von der Box abgelehnt; Firmware-Update/Anlernen bewusst nicht |

### Live verifizierte Schnittstellen (Auszug)

- PBKDF2-Login, Denylist (`GetSecurityKeys`/Reboot abgelehnt), Rücklesen nach jedem Schreiben.
- `set_static_ip` und `delete_host` an Box A (16.11.2026): `verified` stimmte bei jedem Aufruf mit unabhängigem Rücklesen überein; feste IP an einem schon festen Gerät → `changed: false` ohne Schreibzugriff.
- `/api/v0` an Box A: `GET /api/v0/generic/landevice`; `PUT /api/v0/generic/landevice/landevice/<UID>` mit `{"static_dhcp":"1"}` bzw. `{"friendly_name":"…"}`; `DELETE /api/v0/generic/landevice/landevice/<UID>`.
- TR-064: `Hosts:1 X_AVM-DE_SetHostNameByMACAddress`, `LANHostConfigManagement:1 GetDNSServer`, Upstream-DNS (`X_AVM_DE_GetDNSServer`), Gast-Isolierung (`NewX_AVM-DE_UserIsolation`), `X_AVM-DE_BuildType`, IGD `WANIPv6Firewall1`.
- Nachtest an Box A (16.11.2026, lesend): WLAN-Signal in Mesh-Liste (dBm), `test_my_device`-Dienstzuordnung, `myfritz_status`, `vpn_connections`, `online_monitor` (`mode_note`, 64-bit-Volumen über IGD `GetAddonInfos` – V-6 belegt), `isp_report` mit 1 Messpunkt → `insufficient_data`. Mesh-Interface-Namen live: `LAN:n`, `WAN:n` (WAN-Port als LAN), `AP:2G:0`, `AP:5G:0`. Nach den Fixes #33/#34 live bestätigt: Gerät am WAN-Port mit Port-Daten/EEE, `online_monitor.rates.sync` = synchronisierte DSL-Rate (DSL `GetInfo` CurrRate), `rates.attainable` = `Layer1*MaxBitRate`.
- Schreibtests 16.11.2026 (je hin und zurück, unabhängig zurückgelesen): Box A – Kindersicherungsprofil (mit Web-UI gegengeprüft), Ticket, Rufsperre, Weckruf, FTP, Umbenennen über den Aufräum-Assistenten; Box B – Thermostat-Boost, Gast-WLAN-Sitzung, Autokanal, EEE. Befunde mit Fixes [#38](https://github.com/tomwellnitz/fritzos8-mcp/pull/38), [#39](https://github.com/tomwellnitz/fritzos8-mcp/pull/39), [#40](https://github.com/tomwellnitz/fritzos8-mcp/pull/40).
- Critical-Tests 16.11.2026 (`confirmed_via: elicitation`, je hin und zurück): Box A – Tickets verwerfen, statische Route (`NewType` Network angenommen, Interface = Standardverbindung), IPv4-Portfreigabe, FTP aus dem Internet, `fritz_apply`; Box B – Tickets verwerfen, Thermostat-Urlaub/-Sommerzeit/-Umbenennen. IPv6-Pinhole abgelehnt (10.6a). Elicitation: Dialog erscheint im Client (auch im Modus ohne Rückfragen); „Nein“ → `declined`, nichts geändert, Token danach ungültig. Befunde mit Fixes [#42](https://github.com/tomwellnitz/fritzos8-mcp/pull/42), [#43](https://github.com/tomwellnitz/fritzos8-mcp/pull/43), [#44](https://github.com/tomwellnitz/fritzos8-mcp/pull/44); Fixes #38–#40 live bestätigt.
- Per Browser-Mitschnitt an Box A belegt (Stufe 6): `GET eth_ports`, `PUT eth_ports/eth/<UID>` (Body live an Box B belegt: nur `eee_mode` genügt), `eee_mode` 0 = Automatisch / 2 = Aus, `GET vpn` (Schlüssel im Klartext → zentrale Schwärzung), `GET plc`.

### Unbelegte Annahmen

- **Stufe 2:** Feldnamen von `X_AVM-DE_GetWPSInfo`, ob Web-UI-Portfreigaben im WAN-Portmapping erscheinen.
- **Stufe 3:** `<New>`-Semantik der AB-Liste (V-9), Felder von `/api/v0/generic/dnscfg` und `/ipv6` für einen Schreibweg, Fehlercode bei nicht erlaubten selbstständigen Portfreigaben.
- **Stufe 4:** Log-Muster des Netz-Doktors, `BeaconType`-Werte für WPA3, Feldwert Auto-Update, Einheit von `ds_current_bps` (V-22). Belegt (16.11., Box A): „zuletzt online“ kommt als Feld `lastused`; das Alter blieb bei den vorgeschlagenen Einträgen trotzdem leer (`last_seen_days: null`).
- **Stufe 6:** Green-Mode-Wert (daher kein `set_lan_power_mode`), LAN-Log-Muster, Einheit von PLC-PHY-Raten, Verhalten des Box-Speedtest-Servers.
- **Stufe 7:** `NightControl`-XML, Einheiten der Filterprofil-Budgets; ob ein Gerät im Gastnetz dieselbe Gast-ID meldet wie Standard-Geräte im Heimnetz.
- **AVM-Doku-Abgleich:** V-7 (`WANIPConn1` ist die IGD-ID, TR-064 = `WANIPConnection1`), V-8 (TR-064-Portfreigabe nur für den eigenen Rechner), V-11 (Einheit Gast-Timeout).

### Nächste Schritte (Reihenfolge)

1. **🟡-Punkte aus COMPATIBILITY nachtesten** (Korrekturen aus dem Lesetest sind eingebaut, Details unter „Live-Lesetest Stufen 4–7“/„8–10“):
   - `mesh_overview`/`device_connection_quality`: WLAN-Signal an Box B (an Box A erledigt 16.11., ebenso Gerät am WAN-Port mit Port-Daten/EEE nach Fix [#33](https://github.com/tomwellnitz/fritzos8-mcp/pull/33); Pi + EEE am WAN-Port nur per Regressionstest geprüft, live nicht – EEE dort bewusst aus)
   - `isp_report`: Bericht nach ≥ 1 h Collector (beide Boxen); `insufficient_data` bei 1 Messpunkt an Box A erledigt
   - `devices_cleanup_report`/`_plan`: an Box A erledigt für den Report (16.11.: VPN-Peer und Powerline nicht vorgeschlagen, `vpn_list_checked: true`); offen: `_plan` sowie Box B – keine Hersteller-MAC-Geräte ohne Alter unter `delete_candidates`, IP-Duplikate nur `info` (Box B)
   - Sitzungsablauf: `smarthome_list_devices`/`smarthome_overview` nach > 20 min Leerlauf ohne Fehler (Box B)
   - Box-Grenzen, kein Nachtest nötig: `line_diagnostics` an Kabel (`unknown`), `devices_change_counter` = 0 an Box A
2. **Restliche Live-Tests:** TR-064-Antwort bei 2FA, `wake_on_lan` an einem Gerät mit aktivem WoL, AB-Nachricht markieren (V-9, braucht eine Nachricht), Rufumleitung (braucht eine), Box-Speedtest (Server muss in der Web-UI an sein). Bewusst nur mit Tom: Fernzugriff an/aus, WLAN-Band aus, WPS, Anrufe, Neustart/Reconnect/Firmware, Smart-Home anlernen/löschen.
3. **Langzeit-Messreihe:** `fritzos8-collector` ≥ 24 h an beiden Boxen, danach `isp_report` (8.2) und `history_anomalies` (10.1).
4. **Browser-Mitschnitt** für 7.2/7.3 (DNS/DNSv6, Portfreigaben über die Web-UI) – Checkliste unter Stufe 7; erst danach bauen.

## Stufe 1 – Geräte & Netz (v0.1, erledigt)

- Auth: `login_sid.lua?version=2` mit PBKDF2 (MD5 nur auf Verlangen der Box), SID-Cache, Re-Login
- Sicherheitsstufen read / write / critical, Plan/Execute-Token, Denylist, Rücklesen, 2FA-Erkennung, Schwärzung
- TR-064 generisch (lesend): `tr064_list_services`, `tr064_describe_action`, `tr064_call`
- Kuratiert: `system_info`, `wan_status`, `list_hosts`, `list_landevices`, `rename_host`, `set_static_ip`, `delete_host`, `get_lan_dns`, `reboot_*`, `reconnect_wan_*`

## Stufe 2 – WLAN, Smart Home, Diagnose (erledigt, live lesend geprüft)

- **WLAN/Gast:** `wlan_status`, `guest_wifi_status` (read), `set_guest_wifi` (write, Rücklesen), `set_wlan_enabled_plan/_execute` (critical, Aussperr-Gefahr) – alles TR-064 `WLANConfiguration1..n`, keine Schlüssel
- **Smart Home** über das dokumentierte AHA-HTTP-Interface: `smarthome_list_devices`, `smarthome_device_stats` (read), `smarthome_set_switch`, `smarthome_set_thermostat` (write, Rücklesen)
- **Diagnose/Security-Check:** `system_log` (Textfilter), `dsl_info`, `firmware_status`, `security_check` (Fernzugriff, MyFRITZ!, Portfreigaben, UPnP, TR-064, WPS, Gast-WLAN, Firmware → ok/warn/unknown)
- Denylist/Schwärzung um WLAN-/WPS-Geheimnisse erweitert (`X_AVM-DE_GetWLANHybridMode`, `NewPreSharedKey`, `NewWEPKey*`, WPS-PIN)

Verschoben (nicht Teil von Stufe 2):
- Kanal/Band ändern, Mesh-Übersicht (Zugangspunkte, Uplinks, Clients je Knoten)
- Smart-Home-REST-API von FRITZ!OS 8.2 (`/api/v0/smarthome/...`), Vorlagen/Szenarien – erst mit echtem DECT-Gerät belegbar
- Benutzer ohne 2FA im Security-Check (per TR-064 nicht abfragbar)
- TR-064-Allowlist für ausgewählte schreibende Actions im generischen Caller
- `X_AVM-DE_Auth`-Ablauf (2FA anstoßen und Status abfragen) statt nur Erkennen

## Stufe 3 – Telefonie, Kindersicherung, Portfreigaben, DNS (gebaut, live geprüft inkl. Schreiben an Box A)

- **Telefonie** (TR-064 `X_AVM-DE_OnTel1`, `X_AVM-DE_TAM1`; Parser nach the78mole/fritzmoles-mcp, MIT): `call_list` (Tage/Anzahl/Typfilter), `tam_list` (aktiv, Nachrichten gesamt/neu), `phonebook_list` (Namen, optional Anzahl) – read; `set_tam_enabled` – write mit Rücklesen
- **Kindersicherung** (TR-064 `X_AVM-DE_HostFilter1`): `internet_access_status` – read; `set_internet_access` – write, MAC→IP über die Hostliste, Rücklesen, Schutz für Box und Server-Rechner
- **Portfreigaben** (TR-064 `WANIPConn1`/`WANPPPConnection1`): `list_port_forwards` – read; `add_port_forward_plan/_execute`, `delete_port_forward_plan/_execute` – critical, Rücklesen, UPnP-Fehlercodes übersetzt
- **DNS lesen:** `get_dns_settings` (TR-064 `GetDNSServer`, IGD `X_AVM_DE_GetDNSServer`/TR-064 `X_GetDNSServers`, IGD `X_AVM_DE_GetIPv6DNSServer` – Schreibweise am 14.11. nach AVM-Doku korrigiert; dazu `/api/v0/generic/dnscfg` und `/ipv6`)
- Denylist um SIP-Zugangsdaten (`X_AVM-DE_GetClients`) erweitert, Schwärzung von Passwort-Tags in XML-Feldern

Live zu prüfen (Reihenfolge: erst lesend):
1. `call_list`, `tam_list`, `phonebook_list` – liefert die Box die URLs mit dem MCP-Benutzer (Recht „Sprachnachrichten … Anrufliste“)? Ist `<New>` in der AB-Liste wirklich 1 = neu?
2. `internet_access_status` an einem bekannten Gerät; Feldwerte `NewDisallow`/`NewWANAccess`
3. `list_port_forwards` gegen eine in der Web-UI angelegte Freigabe (erscheint sie im TR-064-Portmapping?)
4. `get_dns_settings`: Upstream-Actions vorhanden? `/api/v0/generic/dnscfg` + `/ipv6` auf 7583/8.26 und 6660/8.25 – `fields_missing` muss leer sein
5. Schreibend nach Freigabe: `set_tam_enabled` hin/zurück, `set_internet_access` an einem unkritischen Gerät hin/zurück, `add_port_forward_*` → `delete_port_forward_*` (unbenutzter hoher Port; Fehlerbild bei nicht erlaubten selbstständigen Portfreigaben dokumentieren)

Bewusst nicht gebaut / offen:
- **DNS/DNSv6 schreiben:** per TR-064 nicht möglich. Für `/api/v0` gibt es keine belastbare Quelle: Meine-smarte-Welt/fritzbox_netzwerk beschreibt `PUT /api/v0/generic/dnscfg` bzw. `/ipv6` mit dem ganzen Objekt, sagt aber selbst „an keiner Box ausgeführt“ (und nennt im README MIT, hat aber keine Lizenzdatei → kein Code übernommen). **Endpunkt per Browser-Mitschnitt verifizieren** (Request-Body, HTTP-Status bei `TWO-FACTOR`, Abschluss der Bestätigung), dann als critical mit `confirmation_required` bauen – auf der 7583 verlangt die DNSv6-Änderung nachweislich eine Authenticator-Bestätigung. DNS-Rebind-Ausnahmen, DoT-Servernamen ebenso.
- Anrufbeantworter-Nachrichten markieren/löschen, Rufumleitungen, Rufsperren, Telefonbuch-Einträge
- Zugangsprofile/Zeitbudgets, Ticket-Funktionen (`X_AVM-DE_HostFilter` `MarkTicket`, `DiscardAllTickets`) und `/api/v0`-landevice-Felder zur Kindersicherung (nicht belegt)
- IPv6-Portfreigaben (Pinholes, `X_AVM-DE_WANIPv6FirewallControl`/Web-UI)

## Stufe 4 – Komfort, Überblick, Mehrbox (gebaut, live lesend geprüft – Schreiben ausstehend)

1. **Aufräum-Assistent:** `devices_cleanup_report` (read), `devices_cleanup_plan`/`_execute` (write, Token, Rücklesen je Aktion). Hersteller aus der IEEE-OUI-Registry (Laufzeit-Download, 30-Tage-Cache, keine eingebetteten Daten).

2. **Schnappschüsse:** `snapshot_create`, `snapshot_list`, `snapshot_diff` (read, schreibt nur lokal, Redaction vor dem Schreiben, Aufbewahrung `FRITZ_SNAPSHOT_KEEP`).
3. **Lückenschlüsse:** `wake_on_lan` (write), `mesh_overview`, `online_monitor`, `vpn_status` (read); Denylist per Namensmuster (VPN/WireGuard/DDNS/Password/Secret/PSK), Schwärzung von VPN-Schlüsselfeldern.
4. **Mehrere Boxen + Prompts/Ressourcen:** `FRITZ_BOXES` mit `FRITZ_<NAME>_*` (rückwärtskompatibel), Parameter `box` an allen Tools, `boxes_overview`, `compare_boxes`, Startskript `fritzos8-mcp-multi-start.sh`; Prompts `netz_doktor`, `geraete_aufraeumen`, `sicherheits_check`; Ressourcen `fritz://{box}/landevices`, `fritz://{box}/snapshot/latest`.
5. **Netz-Doktor & Sicherheits-Score:** `network_doctor(symptom?)` (read, dokumentierte Schwellen); `security_check` mit Score 0–100, `remediation` je Befund und neuen Checks (WPA-Modus, Gast-Isolierung, Fernzugriff-2FA, DNS over TLS, Auto-Update, feste IPs) – rückwärtskompatibel.

Live zu prüfen (Stufe 4, erst lesend):
1. `devices_cleanup_report` auf beiden Boxen: Liefert die landevice-Antwort ein „zuletzt online“-Feld (`last_seen_field`)? Sind die Vorschläge plausibel (keine aktiven Geräte, keine Box)? Lädt die OUI-Registry (`vendor_source: download`, danach `cache`)?
2. `snapshot_create` auf beiden Boxen → welche Bereiche fallen aus (`sections_failed`)? Dauer (Internetsperren = ein TR-064-Aufruf je Host)? Direkt danach `snapshot_diff` → `change_count: 0` (sonst flattert ein Feld, das als Messwert gelten muss).
3. `mesh_overview` (7583 mit Repeater?): stimmen Master/Knoten, Band und Raten? Signal: siehe „Live-Lesetest Stufen 4–7“ (Schema v8.7: `rx_rcpi`/`tx_rcpi` in dBm, live ohne Wert → TR-064-Signal-%). Sind die Raten kbit/s?
4. `online_monitor` während eines Downloads: Ist `ds_current_bps` Byte/s (Mbit/s-Wert plausibel zur Leitung)? Gibt es `X_AVM-DE_GetAddonInfos` mit 64-bit-Zählern?
5. `vpn_status`: Felder von `GetDDNSInfo` (Doku-Name, seit 14.11.; alter Name nur Fallback)/`MyFritz1:GetInfo` (`NewDynDNSName`, `NewStatusIPv4`) vorhanden? Tauchen VPN-Services in `tr064_services_found` auf?
6. `security_check` auf beiden Boxen: Werte von `NewBeaconType` (WPA2/WPA3-Mischmodus?), `NewX_AVM-DE_UserIsolation` (seit 14.11. laut Doku; vorher falscher Feldname → falsches warn), `NewX_AVM-DE_AutoUpdateMode`; Score plausibel? Menüpfade (`remediation`) in der Web-UI gegenprüfen.
7. `network_doctor` auf der 7583 (DSL) und 6660 (Kabel): Treffen die Log-Muster echte Meldungen (Sync-Verlust, DNS, Radar)? Gibt es Fehlalarme?
8. Mehrbox: beide Boxen über `fritzos8-mcp-multi-start.sh` in EINER Instanz → `server_status` (boxes), `boxes_overview`, `compare_boxes` (dns/firmware), ein read-Tool mit `box`, Prompts/Ressourcen im Client sichtbar.
9. Schreibend nach Freigabe: `wake_on_lan` an einem WoL-fähigen Gerät.
10. Schreibend nach Freigabe: `devices_cleanup_plan` mit einem Altgerät (delete) und einer Umbenennung hin/zurück, `devices_cleanup_execute` → `verified`.

## Veröffentlichung

- **Erledigt (14.11.2026):** öffentliches GitHub-Repo mit sauberem Initial-Commit (private Daten der früheren Entwicklungshistorie sind nicht enthalten; private Details liegen nur in der gitignorierten `CLAUDE.local.md`). Releases laufen über release-please, PyPI per Trusted Publishing (`PUBLISH_PYPI`).
- Weitere Kanäle (Docker-Image, HA-Add-on-Repository, Registry-Einträge) nur mit Toms Freigabe.

## Zielgruppen & Ideen (öffentliche Version)

Nur dokumentiert, nicht gebaut.

### Personas
- **Normalnutzer ohne Technikwissen:** will in Alltagssprache fragen („Warum ist das WLAN langsam?“, „Wer ist in meinem Netz?“) und verständliche Antworten ohne Fachbegriffe.
- **Eltern:** Kindersicherung, Online-Zeiten, Sperren/Freigeben per Satz statt Menü.
- **Smart-Home-/Home-Assistant-Nutzer:** DECT-Geräte, feste IPs, Portfreigaben und Geräte-Inventar im Zusammenspiel mit der Hausautomation.
- **Homelab/Power-User:** TR-064 generisch, Schnappschüsse, Diffs, Mehrbox, Skriptbarkeit.
- **„Familien-Admin“:** betreut die Box der Eltern/Verwandten aus der Ferne, mehrere Boxen, braucht Überblick und sichere, nachvollziehbare Änderungen.
- **Kleines Büro/Praxis:** Gastnetz, Portfreigaben, Firmware- und Sicherheitsstand, Nachweis gegenüber Dienstleistern.
- **Sicherheits-/Datenschutzbewusste:** Sicherheits-Score, DNS over TLS, keine Daten nach außen, lokale Speicherung.

### Ideen, die andere FRITZ!Box-MCPs nicht haben
- **Störungsprotokoll für den Provider:** DSL-Syncs, Fehlerzähler und Durchsatz über die Zeit sammeln und als Nachweis aufbereiten (mit Verweis auf die Breitbandmessung der Bundesnetzagentur).
- **Zeitlich begrenztes Gäste-WLAN inkl. QR-Code** – nur mit ausdrücklichem Opt-in, weil der WLAN-Schlüssel im QR-Code steckt.
- **Kindersicherung in natürlicher Sprache:** Zeitlimits, Tickets, Wochenbericht je Gerät.
- **Neue-Geräte-Alarm + „Wer ist das?“:** neues Gerät erkennen, Hersteller per OUI und Ort per Mesh-Zugangspunkt nennen.
- **„FRITZ as Code“:** deklarativer Sollzustand je Box mit Plan/Apply, Drift-Erkennung über Schnappschüsse.
- **Familien-Admin-Gesundheitsbericht** über mehrere Boxen: Firmware, Sicherheit, Erreichbarkeit.
- **Heiz-/Energiebericht** für DECT-Geräte: Fenster-offen-Ereignisse, Batteriestand, Verbrauch.
- **AVM-Firmware-/Sicherheitshinweise abgleichen** mit dem installierten FRITZ!OS.
- **Einrichtungs-Assistent:** prüft, ob TR-064 aktiv ist und welche Benutzerrechte fehlen, und erklärt, wo man sie setzt.

### Öffentlich-Readiness
- README auf Englisch (+ Deutsch).
- Plattformübergreifende Zugangsdaten über `keyring` (macOS/Windows/Linux) statt nur macOS-Startskript.
- Veröffentlichung als PyPI-Paket für `uvx fritzos8-mcp`.
- Optional Docker-Image und Home-Assistant-Add-on.
- Optional HTTP-Transport – nur mit Authentifizierung.
- Lizenz/NOTICE prüfen, `SECURITY.md`, `CONTRIBUTING.md`.
- Kompatibilitätsmatrix (Modelle × FRITZ!OS-Versionen, je Tool live geprüft ja/nein).

## Stufe 5 – NAS & Fernzugang (gebaut, live lesend geprüft – Schreiben ausstehend)

Grundlage: offizielle AVM/FRITZ!-TR-064-Dokumente (Storage, Filelinks, WebDAV, Media, MyFRITZ, Remote Access, USP Controller, App Setup; Stand 2025-08).

- **read:** `nas_status`, `backup_target_check`, `myfritz_status` (inkl. Bewertungen für `security_check`)
- **write:** `set_nas_protocol` (SMB/FTP im Heimnetz)
- **critical:** `set_nas_internet_access_plan/_execute` (FTP aus dem Internet), `set_remote_access_plan/_execute` (HTTPS-Fernzugriff, `SetEnable` ohne Passwort)
- **Geheimnis-Einstufung:** `WebDAVClient:GetInfo` (Konto-URL + Benutzer), Filelinks-Einträge/-Liste (ID/URL = Download-Token), `AppSetup:GetBoxSenderId`, `GetAppRemoteInfo`, `GetDDNSInfo` (Benutzer + Update-URL; laut Doku ohne Passwortfeld, bleibt gesperrt) → im generischen Caller gesperrt; Benutzernamen (Fernzugriff, USP) und MyFRITZ!-E-Mail → geschwärzt. Nicht geheim: `Storage:GetUserInfo` (fester Name „ftpuser“, kein Passwort), `AppSetup:GetConfig` (nur Rechte), `USPController:GetInfo` (nur Längenlimits).

Live zu prüfen (Stufe 5, erst lesend):
1. `nas_status` auf 6660 Cable (8.25) und 7583 (8.26): Felder von `Storage:GetInfo`, Filelinks (`NewExpire` = Resttage, 0 = unbegrenzt?; `NewAccessCountLimit` 0 = unbegrenzt?), DVB-C nur auf der Cable.
2. `myfritz_status`: `NewState`, MyFRITZ!-Dienste, `GetUSPMyFRITZEnable` vorhanden? `AppSetup:GetConfig` mit dem MCP-Benutzer erlaubt?
3. `backup_target_check` – ist `FTPStatus=Error` wirklich ein Indikator für fehlenden Datenträger?
4. Schreibend nach Freigabe: `set_nas_protocol` (FTP hin/zurück), `set_nas_internet_access_*` (an mit `ssl_only` → aus), `set_remote_access_*` nur, wenn der Fernzugriff ohnehin genutzt wird (verlangt die Box hier 2FA → `confirmation_required`?).
5. `security_check` (Stufe 4) um `NasRemoteService.security_check_items()` erweitern.

Bewusst nicht gebaut / offen:
- **Dateizugriff auf die NAS** (auflisten, herunterladen, hochladen) – später höchstens **opt-in** über eine eigene Umgebungsvariable, nur lesend, mit Pfad-Allowlist; TR-064 bietet dafür nichts (wäre WebDAV/FTP/SMB mit Benutzer-Zugangsdaten).
- **Speicherplatz** (belegt/frei/gesamt): per TR-064 nicht lesbar; ggf. `/api/v0` oder `nas/`-Web-UI per Browser-Mitschnitt belegen.
- **Liste angemeldeter Apps:** per TR-064 nicht abfragbar (`AppSetup` kennt nur Abfragen je AppId aus App-Kontext).
- **HTTPS-NAS-Zugriff aus dem Internet** (FRITZ!NAS über MyFRITZ!) ist kein eigener TR-064-Schalter – er hängt am Fernzugriff (`set_remote_access_*`).
- `RemoteAccess:SetConfig` (Internet-Benutzer anlegen), `SetDDNSConfig`, `Storage:SetUserConfig`, `WebDAVClient:SetConfig`, `MyFritz:SetMyFritz` (E-Mail) – verlangen Passwörter/Kontodaten, daher nicht gebaut. Freigabe-Links anlegen/löschen (`NewFilelinkEntry`/`DeleteFilelinkEntry`), `SetLetsEncryptEnable`, `SetUSPMyFRITZEnable`, MyFRITZ!-Dienste ändern – möglich, aber noch nicht gebaut.
- `SetDVBCEnable` – nicht gebaut (die Box startet dabei neu).

## Stufe 6 – LAN-Ports, VPN, Powerline, Verbindungsqualität (gebaut, live lesend geprüft – Schreiben ausstehend)

Anlass: Live-Vorfall – Raspberry Pi 5 (HAOS, Kernel 6.18) mit EEE an einem FRITZ!Box-Port → Link-Flapping alle ~10 s, 25–45 % Paketverlust, DNS (Pi ist DNS-Server) sporadisch weg (raspberrypi/linux#7511, home-assistant/operating-system#4861). Der Netz-Doktor hatte das nicht erkannt.

1. **Sicherheit zuerst:** zentrale Schwärzung jeder `/api/v0`-Antwort im `RestClient` (`redact_api`) – `generic/vpn` liefert Pre-Shared-Keys und WireGuard-Konfigurationen im Klartext.
2. **LAN-Ports:** `lan_ports` (read), `set_lan_eee` (write, Rücklesen aller Ports, box-weite Wirkung erkannt). Live belegt: `GET eth_ports`, `PUT eth_ports/eth/<UID>` (HTTP 200), `eee_mode` 0 = Automatisch / 2 = Aus.
3. **VPN & Powerline:** `vpn_connections`, `powerline_status` (read, Feld-Whitelist), `vpn_status` übernimmt die VPN-Verbindungen; `list_port_forwards(include_web_ui_lists)` mit `forwardrules`/`ipv6firewall` roh (unverifiziert).
4. **Speedtest & Qualität:** `box_speedtest_info` (read), `box_speedtest_run` (write), `device_connection_quality` (read), `test_my_device` (read, misst vom MCP-Rechner).
5. **Netz-Doktor:** Link-Flapping (Log-Muster + `flap_check_seconds`), Raspberry Pi + EEE, DNS als Single Point of Failure, `client_measurement` aus `test_my_device`.

Live zu prüfen (Stufe 6, Priorität absteigend):
1. `vpn_connections` und `vpn_status` auf der 7583: Ausgabe auf Schlüsselreste prüfen (kein `wg_*`-Schlüssel, keine Konfiguration, kein `***` an unerwarteten Stellen, die harmlose Felder verdecken). Danach `list_landevices`/`get_dns_settings` gegenprüfen, dass die zentrale Schwärzung dort nichts Nützliches verdeckt.
2. `set_lan_eee` – Body `{"eee_mode": "2"}` ist **nicht mitgeschnitten**, nur abgeleitet: hin (`off`) und zurück (`auto`) an einem unkritischen Port; `verified`, `other_ports_changed` (box-weit?) und 2FA-Verhalten notieren. Falls die Box nur das ganze Objekt akzeptiert: Body anpassen.
3. `network_doctor(flap_check_seconds=30)` an der 7583 mit dem Pi: findet er Pi+EEE (Mesh-Interface-Name `LAN:n` → Port) und – falls noch EEE an – das Flapping? Treffen die LAN-Log-Muster („LAN-Anschluss … getrennt/verbunden“) echte Meldungen?
4. `test_my_device` per WLAN und per LAN: plausible Latenz (LAN ~1 ms), DNS-Zeiten, Download; findet `box_view` den Rechner (IP → Host) und liefert `X_AVM-DE_GetWLANConnectionInfo` Werte? `NewX_AVM-DE_SignalStrength` = Prozent?
5. `device_connection_quality`: Mesh-Feld `name` der Box-Interfaces (`LAN:1`, `AP:5G:0`?), `phymodes`, `max_data_rate_*`; Bewertung plausibel?
6. `box_speedtest_info`: Service vorhanden, Felder laut AVM-Doku? `box_speedtest_run` nur, wenn der TCP-Speedtest in der Web-UI ohnehin an ist – akzeptiert der Box-Server reines TCP-Senden, zählt `NewByteCount` mit?
7. `powerline_status` (nur mit Powerline-Adapter): Einheit von `phyRateRX/TX`, Werte von `status`/`coupling`.
8. `list_port_forwards(include_web_ui_lists=true)`: Struktur von `forwardrules`/`ipv6firewall` → bei sinnvoller Struktur kuratiert auswerten (und in `security_check` einbeziehen).

Bewusst nicht gebaut / offen:
- **`set_lan_power_mode` (Power/Green Mode):** nur `mode "2"` = Power Mode belegt, der Green-Mode-Wert nicht → erst Browser-Mitschnitt beim Umschalten auf „100 Mbit/s Green Mode“.
- **Internet-Speedtest der Box:** TR-064 `X_AVM-DE_Speedtest` ist nur der Speedtest-Server der Box (laut AVM-Doku kein Start-Befehl). Den Server per `SetConfig` ein-/ausschalten ist möglich, aber nicht gebaut (Gefahr, die Internet-Variante versehentlich zu öffnen).
- `forwardrules`/`ipv6firewall` kuratiert und in `security_check`: erst nach Live-Befund der Struktur.
- Weitere vorhandene, ungeprüfte `/api/v0`-Endpunkte: `generic/trafficprio`, `generic/connections`, `generic/nexus`, `generic/wlan_light`, `generic/box`, `generic/user`, `generic/providerlist`, `dino/configflags`, `dino/misc/boxname`.

## Stufe 7 – Robustheit & fehlende Einstellungen (gebaut ohne 7.2/7.3, live lesend geprüft – Schreiben ausstehend)

1. **7.1 Box schützen** (`guard.py`): je Box Drosselung (2 parallel, 8/s, Burst 4), Kurzzeit-Cache 15 s (Hostliste, `landevice`, Mesh-JSON, `eth_ports`, `vpn`), Cache-Leerung nach jedem Schreibvorgang, Backoff nur für Lesezugriffe, Schutzschalter (3 Verbindungsfehler → 30 s sofort `connection_error`). Umgebungsvariablen `FRITZ_MAX_PARALLEL`, `FRITZ_RATE_LIMIT`, `FRITZ_BURST`, `FRITZ_CACHE_TTL`, `FRITZ_RETRIES`, `FRITZ_BREAKER_THRESHOLD`, `FRITZ_BREAKER_COOLDOWN`; Status in `server_status.box_protection`.
2. **7.4 WLAN-Einstellungen:** `wlan_settings` (read), `set_wlan_channel` (write) – AVM-Doku „WLANConfiguration“ 2026-03-10.
3. **7.5 Kindersicherung mit Profilen:** `parental_profiles`, `parental_device_status`, `parental_ticket_status` (read), `set_parental_profile`, `parental_ticket_create`, `parental_add_ticket_time` (write), `parental_tickets_discard_plan/_execute` (critical) – AVM-Doku „X_AVM-DE_HostFilter“ v8 2025-09-11.
4. **7.6 Elicitation** vor jedem critical-`*_execute` (Fallback Token), **7.7 `outputSchema`** für acht Kern-Tools.

Live zu prüfen (Stufe 7, Priorität absteigend):
1. **Box-Schutz:** `devices_cleanup_report` und `snapshot_create` an Box B (98 Geräte) – keine Timeouts, Web-UI bleibt bedienbar; danach `server_status.box_protection` (Zähler `throttle_wait_s`, `cache_hits`, `retries`, `breaker`). Laufzeit vorher/nachher notieren; ggf. `FRITZ_RATE_LIMIT`/`FRITZ_MAX_PARALLEL` nachjustieren. Prüfen, dass `rename_host`/`set_static_ip` direkt danach frisch zurücklesen (Cache geleert).
2. **Strukturierte Ausgaben:** die acht Tools live aufrufen und das MCP-Server-Log (stderr) auf „passt nicht zum Ausgabeschema“ prüfen; bei Treffer Feldtyp im Modell lockern. Zeigt der Client typisierte Ergebnisse?
3. **Elicitation:** mit Claude Code (Form-Elicitation?) einen harmlosen critical-Ablauf, z. B. `parental_tickets_discard_plan` → `_execute` ablehnen (muss `declined` liefern, nichts geändert) – erst danach einmal zustimmen, falls gewünscht. Ohne Elicitation-Support: `confirmed_via: "token"`.
4. **`wlan_settings`** an beiden Boxen: welche Schreibweise liefert `GetChannelInfo` – `NewX_AVM-DEAuto_ChannelEnabled` oder `NewX_AVM-DE_AutoChannelEnabled` (die Doku nutzt beide; der Code akzeptiert beide)? `PossibleChannels`-Format, Struktur des `NightControl`-XML, `X_AVM-DE_WLANGlobalEnable`. Mit `include_web_ui=true`: welche `wlan_light`-Felder kommen (Bandsteuerung? Kanalbreite?) – keine Schlüssel in der Ausgabe!
5. **`set_wlan_channel`** nach Freigabe an Box B im 2,4-GHz-Band: fester Kanal → `verified`, zurück auf 0 (auto) → `auto_channel: true`? Zusatzbestätigung nötig?
6. **Kindersicherung lesen:** `parental_profiles` (Hüllelement der Liste, Einheit der Wochentags-Budgets, `Action` 1 = erlauben?), `parental_device_status` an einem Kindergerät bzw. Offline-Gerät.
7. **Kindersicherung schreiben** nach Freigabe: `set_parental_profile` an einem Offline-Gerät hin und zurück (`verified`), `parental_ticket_create` → `parental_ticket_status` = marked; `parental_add_ticket_time` nur an einem Gerät mit Zeitbudget-Profil.

### Mitschnitt-Checkliste für 7.2/7.3 (vor dem Bauen, gemeinsam mit Tom, eingeloggt in der Web-UI)

Vorgehen je Punkt: Browser-Entwicklertools → Netzwerk → „Fetch/XHR“, Log beibehalten; **genau ein Feld** ändern, speichern, dann zurückstellen. Je Request notieren: Methode, Pfad, vollständiger Request-Body (anonymisiert), HTTP-Status, Antwort-Body; außerdem den GET davor/danach. Auf beiden Boxen (7583/8.26 und 6660/8.25), weil die Felder abweichen können.

**7.2 DNS/DNSv6** (`/api/v0/generic/dnscfg`, `/api/v0/generic/ipv6`):
- [ ] *Internet > Zugangsdaten > DNS-Server*: „Andere DNSv4-Server verwenden“ mit bevorzugtem/alternativem Server – Feldnamen für Modus (Anbieter/eigene) und beide Adressen; sendet die UI das ganze Objekt oder nur die Änderung?
- [ ] Dieselbe Seite für DNSv6 (bevorzugt/alternativ) – landet das in `dnscfg` oder `ipv6`?
- [ ] DNS over TLS: „Verschlüsselte Namensauflösung“, „Zertifikatsprüfung erzwingen“, „Fallback auf unverschlüsselt“, Liste der Auflösungsnamen – Feldnamen und Listenformat.
- [ ] *Heimnetz > Netzwerk > Netzwerkeinstellungen > IPv6-Einstellungen*: „DNSv6-Server im Heimnetz“ (lokaler DNSv6) – Felder.
- [ ] *Heimnetz > Netzwerk > Netzwerkeinstellungen > DNS-Rebind-Schutz*: Ausnahmen-Liste (Pfad, Format).
- [ ] **Zusatzbestätigung:** Antwort beim Speichern (Status, Body-Marker wie `TWO-FACTOR`, ggf. Token/ID), Folge-Requests während der Bestätigung (Polling-Pfad), Request nach Abschluss; Verhalten bei Abbruch/Zeitablauf (bleibt der alte Wert?).

**7.3 Portfreigaben über die Web-UI** (`/api/v0/generic/forwardrules`, `/api/v0/generic/ipv6firewall`):
- [ ] *Internet > Freigaben > Portfreigaben*: GET-Struktur mit einer bestehenden Freigabe (Gerät → Regeln? UID-Format).
- [ ] „Gerät für Freigaben hinzufügen“ → „Neue Freigabe“ → „Portfreigabe“, andere Anwendung: Bezeichnung, Protokoll, Port an Gerät (von/bis), Port extern gewünscht, IPv4/IPv6 – Body des Anlegens (POST oder PUT, Pfad), Antwort mit tatsächlich vergebenem externen Port.
- [ ] Freigabe deaktivieren/aktivieren (welches Feld), Freigabe löschen (Methode, Pfad).
- [ ] Gerätebezogene Schalter: „Selbstständige Portfreigaben für dieses Gerät erlauben“, „Exposed Host“, IPv6 „Firewall für delegierte Präfixe öffnen“, „PING6“, Interface-ID – Felder und Ort (`forwardrules` vs. `ipv6firewall`).
- [ ] Fehlerbilder: Port extern schon belegt, IPv4-Freigabe bei DS-Lite (7583), Zusatzbestätigung ja/nein.
- [ ] Danach Plan für den Bau: critical mit Plan/Execute, Testfreigabe auf hohem Port (z. B. TCP 61234) an einem unkritischen Gerät anlegen, rücklesen (auch im TR-064-Portmapping?), löschen.

Bewusst nicht gebaut / offen:
- **7.2 DNS/DNSv6 schreiben und 7.3 Portfreigaben/IPv6-Freigaben über `/api/v0`:** Endpunkte und Bodies nicht belegt → erst die Mitschnitt-Checkliste oben.
- **Nachtschaltung/WLAN-Zeitplan schreiben:** AVM-Doku kennt nur `X_AVM-DE_GetNightControl`. **Bandsteuerung, Kanalbandbreite des Zugangspunkts:** nicht in TR-064 (allenfalls `wlan_light`, unverifiziert, nur lesend).
- `X_AVM-DE_SetWLANGlobalEnable` (alle WLANs aus) – Aussperr-Gefahr, bewusst nicht gebaut; Band abschalten bleibt `set_wlan_enabled_*`.
- Profile anlegen/ändern (Budgets, Zeitpläne, Filterlisten): per TR-064 nicht vorgesehen.

## Stufe 8 – Überwachung & Komfort (gebaut 14.11.2026, live lesend geprüft – Schreiben ausstehend)

Reihenfolge und Abnahme: [docs/PLAN.md](docs/PLAN.md#stufe-8--überwachung--komfort). Alle 14 Pakete gebaut (8.0–8.12); Abdeckung danach: TR-064 lesend 49,8 % kuratiert + 41,8 % generisch, schreibend 17,8 %; AHA 39 % direkt; Smart-Home-REST 11 Endpunkte (nach Stufe 10: lesend 55,2 % + 36,3 %, schreibend 21,3 %, AHA 44 %, REST 8.5 23 Endpunkte) (siehe [COVERAGE](docs/COVERAGE.md)).

Bewusst offen / abgegrenzt:
- Urlaubs-/Sommerzeiten der Thermostate: nicht über `overview/globals` (enthält nur Presets/Standort/Geofence-Schalter), sondern in `configuration/units` → Stufe 10 (K-17).
- Gast-WLAN-Zeitlimit: die Box-eigene Zeitbegrenzung ist per TR-064 nur lesbar; `guest_wifi_session_start` schaltet über Server-Timer/Collector ab.
- Kabel (DOCSIS): keine Leitungswerte per TR-064 (`line_diagnostics` → `unknown`); ggf. `/api/v0`-Endpunkt per Mitschnitt finden.
- Störungsprotokoll nur als Markdown (PDF über externe Werkzeuge).
- DNS-Abweichungen und Portfreigaben in FRITZ as Code nur als Vergleich (Schreibwege 7.2/7.3 fehlen).

Live-Prüfpunkte (Stufe 8):
- **8.0** `wan_status` an beiden Boxen: welcher Dienst antwortet (`connection.service`/`source`) – 7583 (DSL, DS-Lite) und 6660 (Kabel)? Externe IPv6 weiterhin gefüllt? `online_monitor.volume.source` (IGD `WANCommonIFC1` vorhanden? Heißt der Dienst bei fritzconnection so?), `rates.sync` = Web-UI-Leitungsrate, `rates.tariff` gefüllt? `get_dns_settings.upstream` weiterhin verfügbar. V-11 (Einheit Gast-Timeout) und V-22 (`ds_current_bps` vs. `mc_current_bps` während eines Downloads) klären.
- **8.11** `avm_device_updates` an beiden Boxen: erscheinen Repeater/Powerline mit Modell und `update_available` (Hostliste: wird `X_AVM-DE_IsMeshable`/`X_AVM-DE_Model` geliefert?), DECT-Teil an Box B (Thermostat als `dect_ule`, ID ≥ 16?), Powerline über `X_AVM-DE_Homeplug` (Recht App)? `dect_handsets` an einer Box mit Mobilteil (Phone-Recht). `devices_change_counter` steigt, wenn ein Gerät online/offline geht?
- **8.1** `fritzos8-collector` 24 h an beiden Boxen (z. B. launchd mit `--once` alle 5 min): Last unauffällig (`server_status.box_protection`, Web-UI flüssig), `history_summary` plausibel (Intervall 300 s, keine Scheinlücken), Neuverbindung bei der Zwangstrennung als `wan_reconnect` erkannt, `device_online/offline` stimmt mit der Web-UI überein, Datei 0600.
- **8.9** `line_diagnostics` an der 7583 (DSL): `X_AVM-DE_GetDSLInfo` vorhanden? Format/Einheit von `SNRpsds` (dB? Gruppengröße `SNRGds`), `cable_test.state` = NONE bei synchroner Leitung, Profil = Web-UI. An der 6660 (Kabel): `access.kind` = cable (Wert von `WANAccessType`/`X_AVM-DE_WANAccessType` notieren), sonst Zuordnung in `classify_access` nachziehen. Glasfaser/Mobilfunk nur per Fixture geprüft.
- **8.2** nach ≥ 24 h Messreihe `isp_report` an der 7583: Zwangstrennung als Neuverbindung, Vertragsrate gefüllt (sonst „–“)? Bericht lesbar/vollständig für eine Störungsmeldung?
- **8.3** `alarms_check` an beiden Boxen zweimal hintereinander (zweiter Lauf: keine neuen Alarme); ein Testgerät ins Gast-WLAN → `new_device` mit „im Gastnetz“; Benachrichtigung testweise an einen eigenen ntfy-Topic bzw. HA-Webhook (`notify=true`), danach Wiederholung unterdrückt? Battery-Alarm am Thermostat (Box B) nur, wenn `batterylow` gesetzt ist.
- **8.12** `system_transparency` an beiden Boxen: 7583 → `ipv6.ds_lite` true und Präfix gefüllt; Service-ID der IPv6-Firewall (`WANIPv6Firewall1` oder `WANIPv6FirewallControl1`?); `time.offset_s` plausibel (Format von `CurrentLocalTime` mit Zeitzone?); TR-069 beim Kabelanbieter (6660) aktiv? `forced_disconnect` an der 7583 (PPP) vs. 6660 (kein PPP → available false).
- **8.10** an der 7583 (Phone-Recht nötig): `phone_numbers_status` = Web-UI (Telefonie > Eigene Rufnummern, „registriert“)? `alarm_clocks`, `call_deflections`, `call_barring_list` gegen die Web-UI; `phonebook_search` mit einem bekannten Kontakt (Name und Nummer); `call_list(resolve_names=true)` ergänzt Namen?
- **8.7** `family_admin_report` mit beiden Boxen (Mehrbox-Startskript): Ampeln plausibel, Box B per VPN erreichbar, Laufzeit akzeptabel (liest je Box Security-Check, Update-Übersicht, NAS)?
- **8.5a** `smarthome_overview` an Box B (6660/8.25, Thermostat): Struktur wie OpenAPI (`devices`/`units`/`interfaces`)? Soll/Ist = Web-UI, Batterie, `windowOpenMode`; `smarthome_unit` mit Heizplan (`timer`-Struktur notieren); `smarthome_energy_report` – Einheit `electricityRate` (Cent oder Euro?). Ausgabe auf Standort-/Mailreste prüfen. An der 7583 ohne Smart-Home-Geräte: leere Listen statt Fehler?
- **8.6** `fritz_export` an beiden Boxen → YAML plausibel; sofort `fritz_drift(name=…)` = keine Abweichung. Dann nach Freigabe eine harmlose Abweichung (z. B. `tam: {0: …}` oder EEE eines freien Ports) per `fritz_apply_plan/_execute` setzen, `verified` prüfen, zurückstellen.
- **8.5b** nach Freigabe an Box B: `smarthome_thermostat_mode` Boost 5 min am Thermostat → `verified`, danach `minutes=0`; Fenster-offen ebenso. Body-Format `endTime` (Unix-Sekunden) und Reaktionszeit des batteriebetriebenen Thermostats notieren. Routine/Vorlage nur, wenn eine harmlose existiert.
- **8.4** an Box B nach Freigabe: `guest_wifi_session_start(15)` → Gast-WLAN an (`verified`), Box-Zeitbegrenzung (Einheit von `X_AVM-DE_Timeout`, V-11) notieren; nach Ablauf schaltet der laufende Server/Collector ab? `wps_button(start)` nur, wenn WPS in der Box aktiv ist → Status `active`, nach ca. 2 min wieder `inactive`/`off`? `guest_wifi_qr` nur mit Toms Opt-in: QR mit dem Handy testen, Datei danach löschen.
- **8.8** nach Freigabe an der 7583: Weckruf an/aus, Rufsperre für eine Testnummer hinzufügen/entfernen (Format von `PhonebookEntryData` akzeptiert?), eine Test-AB-Nachricht als gehört markieren und wieder neu (klärt V-9: Bedeutung von `<New>`), `dial_number` nur mit Tom an einem eigenen Ziel (Wählhilfe muss eingerichtet sein). Rufumleitung nur kurz an/aus, wenn eine existiert.

## Live-Lesetest Stufen 8–10 (14.11.2026, 7583 DSL/PPP 8.26 und 6660 Cable 8.25)

Live verifiziert (lesend): `setup_check`, `line_diagnostics` (DSL inkl. Kabeltest/Spektrum, Kabel = `unknown`), `get_dns_settings` (Upstream-DNS-Fix V-2), `guest_wifi_status.user_isolation` (V-3), `firmware_status.build_type` (V-4), `avm_device_updates` inkl. Powerline, `phone_numbers_status`, `two_factor_status`, `ipv6_firewall_status` (IGD `WANIPv6Firewall1`, Felder ohne `New`-Präfix), `security_check`, `fritz_export`, `history_collect`, `network_optimizer_suggest`, `call_barring_list`, `smarthome_overview` (REST an der 6660 inkl. Thermostat, Standort geschwärzt).

Live gefunden und korrigiert:
- `wan_status` (7583, `WANPPPConnection1`): `GetExternalIPAddress` lieferte eine IPv6-Adresse → IPv4-Feld wird jetzt geprüft, sonst `external_ipv4: null` + `ipv4_note`; externe IPv6 bleibt IGD `X_AVM_DE_GetExternalIPv6Address` (laut IGD-Doku nur dort, auch bei PPP).
- `system_transparency.ipv6.firewall` meldete auf beiden Boxen false/false, obwohl `ipv6_firewall_status` an der 7583 true/true liefert: die Box sendet die Felder ohne `New`-Präfix. Beide Tools nutzen jetzt dieselbe Auswertung (`parse_firewall_status`), nicht lesbar = `unknown`/`null` statt false.
- `system_transparency.ipv6` an der 6660 (Kabel ohne IPv6): Präfix `::/0` mit Lebensdauer 0 wird jetzt als „kein IPv6-Präfix“ (`prefix: null`, `ipv6_active: false`) dargestellt. `connection_status` war auf beiden Boxen `unknown`: abgefragt wird laut AVM-Doku richtig `GetInfo` des aktiven WAN-Dienstes (`WANPPPConnection1` bzw. `WANIPConnection1`), das Feld `X_AVM-DE_IPv6ConnectionStatus` ist aber erst seit der Doku-Version 12/2025 beschrieben und wird von 8.25/8.26 nicht geliefert → Hinweis + `ipv6_active` aus dem Präfix abgeleitet.
- `system_transparency.forced_disconnect` fragte auf der Kabel-Box `WANPPPConnection1` ab: jetzt nur am aktiven PPP-Dienst, sonst `available: false` mit Hinweis. An der 7583 (PPP) meldet `X_AVM_DE_GetAutoDisconnectTimeSpan` (Doku-Name) not_found – die Bindestrich-Variante wird zusätzlich probiert (`call_first`); bleibt es not_found, lautet die Hauptaussage `available: false` + Verweis auf die Web-UI statt eines Fehlers.
- `devices_change_counter`/`history_collect`: `X_AVM-DE_GetChangeCounter` liefert an der 7583 dauerhaft 0 (25 aktive Hosts, Geräte wechseln). Feldname `NewX_AVM-DE_ChangeCounter` ist laut AVM-Doku richtig → 0 gilt jetzt als „Box liefert keinen Zähler“ (`available: false` + Hinweis); Messreihe und Alarme lesen dann jedes Mal die Hostliste statt sich auf den Zähler zu stützen. An der 6660 noch prüfen, ob der Zähler dort zählt.

## Live-Lesetest Stufen 4–7 (14.11.2026, 7583 DSL/G.fast PPP 8.26 und 6660 Cable 8.25)

Live gefunden und korrigiert (jeweils nach dem Fix an beiden Boxen nachtesten):
- **WLAN-Signal fehlte überall** (`mesh_overview`, `device_connection_quality`: `signal_dbm: null` bei allen WLAN-Clients, 18/22 „unbekannt“, `weak_signal_clients` leer). Ursache: Mesh-Schema v8.7 beschreibt `rx_rcpi`/`tx_rcpi` als **dBm** (255 = unbekannt); der Code las nur `rx_rcpi` als IEEE-RCPI (0–220) und verwarf negative Werte, außerdem die Messung von Knoten 1 statt der des Zugangspunkts. Jetzt: dBm und RCPI werden akzeptiert, AP-seitige Messung bevorzugt; zusätzlich Signal-% aller WLAN-Geräte aus **einer** Abfrage `X_AVM-DE_GetWLANDeviceListPath` (Fallback `GetGenericAssociatedDeviceInfo`, max. 64 je Dienst, Guard-Cache), Bewertung über `signal_dbm_estimated` ≈ % / 2 − 100 (Annahme, AVM nennt keine Skala). Nachtesten: Anteil „unbekannt“ ≈ 0, `signal_source`, liefert die Mesh-Liste nach dem Fix doch dBm? Prozent vs. dBm bei Geräten mit beiden Werten vergleichen (Skala plausibel?).
- **`test_my_device`: falscher WLAN-Dienst** (`box_view.wlan_connection.service` = `WLANConfiguration1`, Gerät aber auf 5 GHz/Kanal 36, `quality.tr064.service` = `WLANConfiguration2`). Ursache: `X_AVM-DE_GetWLANConnectionInfo` antwortet laut AVM-Doku für das anfragende Gerät auf jedem Dienst gleich; der Code nahm den ersten antwortenden. Jetzt: Dienst über `GetSpecificAssociatedDeviceInfo` mit der gemeldeten MAC, sonst über das Band (`service_match`, ggf. `answered_by`). Nachtesten: `service` = `quality.tr064.service`.
- **`isp_report` mit 1 Messpunkt** schrieb „Keine Ausfälle gemessen“, „Messlücken: Keine“ und „Intervall ca. ? s, Abdeckung ? %“. Ursache: keine Mindestdatenmenge; `find_gaps` kann ohne zwei Messungen kein Intervall bestimmen. Jetzt: unter 12 Messpunkten oder mit unbekannter Abdeckung `status: insufficient_data` (wie `history_anomalies`) und im Markdown deutlich „Zu wenig Messdaten – keine Aussage möglich“, keine „?“ mehr. Nachtesten: direkt nach dem ersten `history_collect` und nach ≥ 1 h Collector.
- **Sicherheit – `devices_cleanup_report` schlug zum Löschen vor:** (a) die WireGuard-Gegenstelle einer VPN-Verbindung (Eintrag ohne MAC, IP in `remote_networks`, heute gesehen), (b) einen FRITZ!Powerline-Adapter mit lokal administrierter, von einer AVM-OUI abgeleiteter MAC (`7A:42:7F:…` zu `74:42:7F`) als „Zufalls-MAC“, dazu Umbenennungen AVM-eigener Geräte. Ursache: keine Kenntnis von VPN-Verbindungen und Mesh/AVM; jede lokal administrierte MAC galt als zufällig. Jetzt: VPN-Gegenstellen (IP im entfernten Netz/Name der Verbindung) und AVM-Geräte (AVM-OUI-Liste aus dem IEEE-Register, davon abgeleitete LA-Adressen, Name „FRITZ!…“, Mesh-Knoten) werden nie vorgeschlagen, AVM-Geräte nie umbenannt; Einträge ohne MAC nur, wenn die VPN-Liste lesbar war, kein VPN-Bezug besteht und sie nicht heute gesehen wurden. Dieselben Regeln lehnen in `devices_cleanup_plan`/`_execute` mit Grund ab. Nachtesten: Report an beiden Boxen – WireGuard-Peer und Powerline unter `not_proposed`/nicht mehr gelistet, `protection.vpn_list_checked: true`.
- **Sicherheit – `devices_cleanup_report` an Box B (98 Geräte):** (a) „Duplikat (gleiche IP wie …)“ schlug echte, nur offline Geräte mit global eindeutiger Hersteller-MAC (ESP-Steuerungen, PC, Staubsauger, Zisternen-Sensor) zum Löschen vor – DHCP vergibt IPs neu; (b) Umbenennung „K--chen-Wand“ → „K-chen-Wand“ (Rest eines verlorenen Umlauts); (c) Hersteller „China“ aus dem OUI-Register; (d) Grund „verwaiste feste IP … an einem offline/zufälligen Gerät“ bei online Geräten. Jetzt: gleiche IP nur noch Hinweis (`duplicates` mit `by: ip`, `severity: info`); Namens-Duplikate nur bei zufälliger MAC, der online/zuletzt gesehene Eintrag bleibt; Hersteller-MACs nur bei bekanntem „zuletzt online“ ≥ `offline_days`, Grund nennt verlorene feste IP/Kindersicherungsprofil; „--“ im Wort → kein Vorschlag (`rename_not_proposed`); Orte/Rechtsformen/Platzhalter im OUI-Namen sind kein Hersteller; verwaiste-IP-Grund nur offline. `devices_cleanup_plan` (neuer Parameter `offline_days`) und `_execute` lehnen nach denselben Regeln ab. Nachtesten: Report an Box B – keine Hersteller-MAC-Geräte ohne Alter unter `delete_candidates`, IP-Duplikate nur `info`, Feld des Kindersicherungsprofils in der landevice-Antwort (angenommen: Schlüssel mit „profile“/„kisi“).
- **`myfritz_status`: widersprüchlich** („Benutzer darf auch aus dem Internet zugreifen“ bei `details.access_from_internet: false`). Ursache: laut AVM-Doku (AppSetup `GetConfig`) ist `InternetRights` das *Recht* des Benutzers, `AccessFromInternet` heißt „kommt die aktuelle Anfrage aus dem Internet?“ – ob der Internetzugang an ist, steht in `RemoteAccess:GetInfo`. Jetzt: Felder `mcp_user_internet_rights` (Recht) und `current_request_from_internet` (diese Anfrage); die Bewertung kombiniert Recht + Fernzugriff: Recht und Fernzugriff an → warn, Recht bei ausgeschaltetem Fernzugriff → ok mit Hinweis „derzeit nicht nutzbar“. Nachtesten: Text/Status an beiden Boxen konsistent mit `remote_access.enabled`.
- **`online_monitor`:** `sync_group.mode` = „VDSL“ an einer G.fast-Leitung – `SyncGroupMode` ist laut Doku nur die Bezeichnung der Sync-Gruppe; jetzt als Box-Rohwert gekennzeichnet (`mode_source`), bei DSL mit `line_modulation` aus `X_AVM-DE_GetDSLInfo` abgeglichen (`mode_note` bei Abweichung). `rates: X_AVM-DE_GetAddonInfos nicht verfügbar` (7583, PPP): die TR-064-Action steht erst in der Doku-Version v22 (02/2026) und fehlt auf 8.26; die IGD-Variante (V-6) enthält nur Zähler/Byte-Raten, keine Leitungsraten. Jetzt: beide Schreibweisen per `call_first`, sonst Sync-Rate aus `GetCommonLinkProperties` (`Layer1*MaxBitRate`, `rates.source`). Nachtesten: 7583 `rates.sync` ≈ `line_diagnostics`, `mode_note` erscheint; 6660: liefert sie `X_AVM-DE_GetAddonInfos`?
- **`vpn_connections`:** Verbindung mit `state: ready` zeigte zugleich `error: {code: 3400, reason: 3430}`. Die Box behält offenbar den letzten Fehler; jetzt steht er bei verbundenen Verbindungen unter `last_error` (`historical: true`), `error` nur bei nicht verbundenen. Codes sind undokumentiert → roh, keine geratene Übersetzung (`description: null`). Nachtesten: Fehlercodes beim gezielten Trennen/Neuverbinden notieren (ggf. Übersetzungstabelle `VPN_ERROR_TEXTS` mit Beleg füllen).
- **HTTP 400 bei abgelaufener Sitzung** (Box B, `/api/v0`, 56485ff): alle HTTP-Clients geprüft. Smart-Home-REST läuft über `RestClient` (abgedeckt). AHA (`homeautoswitch.lua`) meldete 400 sofort als „AIN unbekannt“ → jetzt wie `RestClient` einmal neu anmelden, erst ein zweites 400 ist der dokumentierte Parameterfehler. `login_sid.lua` mit HTTP ≠ 200 (z. B. 503, Box ausgelastet) gilt jetzt als Verbindungsfehler statt als „kein gültiges XML“. TR-064-Dokumente (`fetch`) nutzen die TR-064-Sitzung, nicht die Web-SID. Nachtesten: Box B nach Sitzungsablauf (> 20 min Leerlauf) `smarthome_list_devices` und `smarthome_overview` – beide ohne Fehler.

Neu danach: **`server_status` → `health`** je Box (ok/degraded/down + Begründung) aus dem Zustand, den Clients/Guard ohnehin kennen (je Schnittstelle letzte erfolgreiche Anfrage, letzter Fehler redigiert, Schutzschalter, Re-Logins, Sitzungsalter), optional `probe=true` (je Schnittstelle eine Leseanfrage über den Guard). Nachtesten: nach einem Lesetest an Box B `health` = ok; Sitzung in der Web-UI abmelden bzw. 20 min warten → nächster Aufruf zeigt `relogins_since_start` +1; `probe=true` an der 7583 (ohne Smart Home) → `smarthome_rest`/`aha` ok oder „nicht vorhanden“, kein Fehler.

## Stufe 10 – Ökosystem & Intelligenz (gebaut 14.11.2026, live lesend geprüft – Schreiben ausstehend)

Pakete und Status: [docs/PLAN.md](docs/PLAN.md#stufe-10--ökosystem--intelligenz).

Live-Prüfpunkte (Stufe 10):
- **10.1** nach ≥ 2 Tagen Messreihe (Collector) `history_anomalies` an beiden Boxen: Status `ok`/`anomalies` statt `insufficient_data`, keine Fehlalarme bei normaler Zwangstrennung (eine Neuverbindung pro Tag ist Basis), Schwellen plausibel (SNR-Steigung, Fehlerzähler-Faktor); `network_doctor(symptom="seit Tagen langsamer")` zeigt Trend-Befunde, `alarms_check` meldet `anomaly` nur bei warn.
- **10.2** `network_optimizer_suggest` an beiden Boxen: Vorschläge plausibel (Kanal, EEE nur bei Pi/Flapping, Bandsteuerung bei vielen 2,4-GHz-Geräten)? Nach Freigabe einen harmlosen Vorschlag ausführen (z. B. Autokanal 2,4 GHz an Box B), `verified` prüfen, nach 24 h `network_optimizer_effect` – Urteil nachvollziehbar? Danach ggf. zurückstellen. Bandsteuerung-Schreibweg: braucht Browser-Mitschnitt (`/api/v0`).
- **10.3** Collector mit `FRITZ_MQTT_HOST` gegen den Mosquitto-Broker in HA: Gerät „FRITZ!Box …“ erscheint mit allen Entitäten, Einheiten/Geräteklassen passen (Störabstand dB, Durchsatz Mbit/s), Kabel-Box zeigt DSL-Werte „unbekannt“, Collector stoppen → Entitäten `nicht verfügbar`, Broker-Passwort nicht im Log, Alarm-Attribut lesbar.
- **10.4** `fritzos8-mcp --http` lokal mit Token: Claude Code per `--transport http` + Header verbinden, Tools nutzbar, ohne/mit falschem Token 401; Elicitation über HTTP (Client-Unterstützung prüfen). Auf dem Pi hinter WireGuard der FRITZ!Box mit `FRITZ_HTTP_ALLOWED_HOSTS`.
- **10.5** `fritzos8-anonymize` auf echte Ausgaben beider Boxen anwenden (Hostliste, `list_landevices`, `system_log`, AHA-Liste von Box B) und das Ergebnis von Hand gegenlesen: bleiben Namen/Orte in Freitexten übrig? Fehlalarme von `find_leftovers`? Gute Kandidaten als erste echte Community-Fixtures (nach Toms Freigabe).
- **10.6a** lesend: `firmware_update_status` (Feld `X_AVM-DE_UpdateSuccessful`/`UpdateTime` gefüllt?), `ipv6_firewall_status` an der 7583 (Service-ID `WANIPv6Firewall1` oder `WANIPv6FirewallControl1`? Argumentnamen mit/ohne `New` – `tr064_describe_action` notieren), `two_factor_status` an beiden Boxen (2FA aktiv → Zustand `stopped`?). Schreiben nur nach Freigabe: statische Route zu einem ungenutzten Netz (z. B. 10.99.0.0/24 → Pi) anlegen und löschen (`NewType` akzeptiert? `Interface`-Wert?), IPv6-Pinhole für den eigenen Rechner (hoher Port, Lease 120 s) anlegen/löschen – klärt, ob die Box UPnP-Pinholes zulässt; `firmware_update_*` erst, wenn ein echtes Update ansteht (mit Tom).
- **10.6b** an Box B (Thermostat, 8.25): `smarthome_thermostat_config` – Struktur von `configuration/units` (Urlaub/Sommer, Zeiten in Minuten wie dokumentiert?) gegen die Web-UI; nach Freigabe einen Urlaubszeitraum in der Zukunft setzen und wieder löschen (leere Liste), Sommerzeit kurz an/aus; `smarthome_pairing_status` (Funkbasis, `isSmarthomeMaster`), Anlernen nur mit Tom und einem echten Gerät; `smarthome_tr064_devices` gegen `smarthome_list_devices` (Einheiten 1/100 W, 0,1 °C); Umbenennen eines Testobjekts hin/zurück. Löschen nur an eigens angelegter Testgruppe/-routine.
- **10.7** `avm_device_detail` an Box B: Thermostat per DECT-ID (≥ 16), Repeater/Mesh-Knoten per MAC – Feldnamen `device_model`/`device_firmware_version` im Mesh-JSON vorhanden? Uplink-Rate = Web-UI (Heimnetz > Mesh)?

## Abgleich mit den AVM-Dokumenten (14.11.2026)

Alle 37 TR-064-Services (375 Actions), das AHA-HTTP-Interface (36 Kommandos) und die Smart-Home-REST-API 8.2/8.5 (36/52 Endpunkte) gegen den Code geprüft. Matrix je Action: [docs/COVERAGE.md](docs/COVERAGE.md); Befunde V-1…V-24, D-1…D-10 und Feature-Kandidaten K-1…K-28: [docs/PLAN.md](docs/PLAN.md#verifikation-gegen-avm-doku).

- **Abdeckung:** TR-064 lesend 91,5 % erreichbar (34,5 % kuratiert, 57 % generisch, 8,5 % bewusst gesperrt), schreibend 13 % gebaut; AHA 19 % direkt + 25 % indirekt; Smart-Home-REST 0 %.
- **Korrigiert:** `GetDDNSInfo` (statt `X_AVM-DE_GetDDNSInfo`), Upstream-DNS `X_AVM_DE_GetDNSServer`/`X_AVM_DE_GetIPv6DNSServer` (erklärt „upstream.available: false“ live), Gast-Isolierung `NewX_AVM-DE_UserIsolation` (vorher falsches warn im Sicherheits-Check), `X_AVM-DE_BuildType` statt `LaborVersion`, Einheit Online-Monitor belegt.
- **Sicherheit:** Lücken geschlossen – SIP-Kontenliste, Mesh-Repeater-Login-Token, PPP-/TR-069-/Mobilfunk-Benutzernamen und IMSI, Online-Telefonbuch-Konto, Session-ID aus `X_AVM-DE_DoPrepareCGI`; gefährliche Schreib-Actions zusätzlich auf der Denylist.
- **Offen (Stufe 8.0):** 64-bit-Volumenzähler über IGD statt TR-064 (V-6), TR-064-WAN-Dienst vor IGD `WANIPConn1` (V-7), Portfreigaben per TR-064 laut Doku nur für den eigenen Rechner (V-8), `max_bit_rate`/WLAN-Paketzähler unzuverlässig (V-12); live klären: AB-`<New>`-Semantik (V-9, Doku widerspricht der Praxis), Einheiten Gast-Timeout (V-11) und Online-Monitor-Felder (V-22).
- **Neu im Plan:** Stufe 8 um Geräte-/Update-Übersicht (8.11), Leitungsdiagnose je Anschlussart (8.9), System-Transparenz TR-069/NTP/IPv6 (8.12), Telefonie lesen (8.10) erweitert, Smart Home REST in lesen (8.5a)/steuern (8.5b) geteilt; Stufe 9 um Rechte-Tabelle, Abdeckungspflege und Datenschutz-Feinschliff; Stufe 10 um Firmware-Update, 2FA-Ablauf, Smart-Home-Konfiguration, Zigbee-Anlernen, IPv6-Pinholes.

## Offene Punkte / Ideen

- Live-Verifikation der critical-Tools der Stufe 1 und der Schreib-Tools ab Stufe 2 gegen eine echte Box (Lese-Tools sind live geprüft, siehe „Projektstand & Live-Prüfung“)
- `list_hosts` und `list_landevices` zu einer zusammengeführten Ansicht verbinden
- Fixture-Recorder mit Anonymisierung für reale Antworten verschiedener Modelle
