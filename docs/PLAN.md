# Gesamtplan fritzos8-mcp

Stand: 2026-11-14 (überarbeitet nach dem Abgleich mit den AVM-Dokumenten). Ergänzt die [ROADMAP](../ROADMAP.md) um Reihenfolge, Abnahmekriterien und Risiken; die Abdeckung je Action/Endpunkt steht in [COVERAGE.md](COVERAGE.md).
Aufwand: S = bis ½ Tag Agentenarbeit, M = ~1 Tag, L = mehrere Tage. „Live“ = gegen echte Boxen geprüft
(FRITZ!Box 7583 / FRITZ!OS 8.26 und 6660 Cable / 8.25), immer erst lesend, Schreiben nur mit Freigabe.

## Übersicht

| Stufe | Thema | Status |
|---|---|---|
| 1 | Grundgerüst: Auth (PBKDF2), Sicherheitsstufen, TR-064 generisch, Geräte & Netz | ✅ live |
| 2 | WLAN/Gast, Smart Home (AHA), Diagnose, Sicherheits-Check | ✅ live |
| 3 | Telefonie, Kindersicherung, Portfreigaben (TR-064), DNS lesen | ✅ live (Portfreigabe: Box lehnt per TR-064 ab) |
| 4 | Aufräum-Assistent, Schnappschüsse/Diff, WoL, Mesh, Online-Monitor, VPN-Status, Mehrbox, Prompts/Ressourcen, Netz-Doktor, Score | ✅ gebaut, teils live |
| 5 | NAS & Fernzugang (Storage, Filelinks, WebDAV, MyFRITZ, Fernzugriff) | ✅ gebaut, teils live |
| 6 | Secret-Schutz `/api/v0`, LAN-Ports/EEE, VPN & Powerline lesen, Speedtest & Verbindungsqualität, `test_my_device`, Netz-Doktor+ | ✅ gebaut, Live-Test ausstehend |
| 7 | Box schützen, WLAN-Einstellungen, Kindersicherung-Profile, Elicitation, `outputSchema` (7.2/7.3 DNS & Portfreigaben über `/api/v0` warten auf Mitschnitt) | ✅ gebaut ohne 7.2/7.3 |
| – | Abgleich mit den offiziellen AVM-Dokumenten: [Abdeckungsmatrix](COVERAGE.md), Korrekturen, Denylist-Lücken | ✅ 14.11.2026 (siehe unten) |
| 8 | Überwachung & Komfort: Doku-Nacharbeiten, Geräte-/Update-Übersicht, Messreihe, Leitungsdiagnose je Anschlussart, Störungsprotokoll, Alarme, System-Transparenz, Telefonie lesen/schreiben, Smart Home REST, FRITZ as Code, Familien-Admin, Gast-WLAN+QR | ✅ gebaut (Mocks), Live-Test ausstehend |
| 9 | Veröffentlichung | ✅ lokal vorbereitet – Veröffentlichen wartet auf Toms Freigabe |
| 10 | Ökosystem & Intelligenz (vor Stufe 9 gebaut) | ✅ gebaut (Mocks), Live-Test ausstehend |

## Offene Live-Tests aus Stufe 4–6 (vor Stufe 7 abschließen)
- [ ] `devices_cleanup_report` an beiden Boxen (Box B: 98 Geräte) – OUI-Download/-Cache, `last_seen_field`; `devices_cleanup_plan/_execute` nur mit Freigabe.
- [ ] `snapshot_create` → sofort `snapshot_diff` muss `change_count: 0` liefern; Laufzeit bei 98 Geräten.
- [ ] `mesh_overview` Feldnamen/Einheiten, `wake_on_lan` (Freigabe), Mehrbox-Startskript mit beiden Boxen, Prompts/Ressourcen im Client sichtbar.
- [ ] Stufe 5: `nas_status`/`backup_target_check` an der NAS von Box B (HA-Backup-Ziel), Filelink-Felder, `GetUSPMyFRITZEnable`, 2FA bei `SetFTPServerWAN`/`SetEnable`.
- [ ] Stufe 6: `lan_ports`, `set_lan_eee` (zurück auf auto und wieder aus), `vpn_connections` (keine Schlüssel in der Ausgabe!), `powerline_status`, Speedtest, `device_connection_quality`, `test_my_device`, Netz-Doktor erkennt EEE/Link-Flapping.
- [ ] Nach dem Doku-Abgleich (V-1…V-4): `get_dns_settings` → `upstream.available` jetzt true (`X_AVM_DE_GetDNSServer`)? `myfritz_status`/`vpn_status` → DynDNS über `GetDDNSInfo`? `guest_wifi_status` → `user_isolation` true/false statt fehlend, `security_check.gast_isolierung` plausibel? `firmware_status.build_type` = „Release“?

---

## Stufe 7 – Robustheit & fehlende Einstellungen (gebaut ohne 7.2/7.3, Live-Test ausstehend)
Ziel: Die Box nie überlasten, und die wichtigsten Einstellungen, die nur die Web-Oberfläche kann, sicher setzbar machen.

| # | Paket | Aufwand | Abnahme |
|---|---|---|---|
| 7.1 | **Box schützen:** globale Drosselung (max. parallele/sekündliche Anfragen je Box), Kurzzeit-Cache (z. B. 10–30 s) für teure Lesezugriffe (Hostliste, landevice, Mesh), Backoff bei Timeouts, Abbruch statt Dauerschleife bei überlasteter Box | M | Lasttest gegen Mock; Aufräum-Assistent/Snapshot an 98-Geräte-Box ohne Timeouts; Box-Web-UI bleibt währenddessen bedienbar |
| 7.2 | **DNS/DNSv6 ändern** über `/api/v0` (`generic/dnscfg`, `generic/ipv6`): Endpunkt + Body per Browser-Mitschnitt verifizieren (mit Tom, eingeloggt), critical mit Plan/Execute, 2FA sauber als `confirmation_required` | M | Live: DNSv6 setzen → Box verlangt Authenticator → MCP meldet korrekt „nichts geändert“; nach Bestätigung `verified` |
| 7.3 | **Portfreigaben über `/api/v0/generic/forwardrules`** (umgeht die TR-064-Sperre „Selbstständige Portfreigaben“) + IPv6-Freigaben (`generic/ipv6firewall`), critical | M | Mitschnitt; Live: Testfreigabe hoher Port anlegen/löschen, Rücklesen |
| 7.4 | **WLAN-Einstellungen:** Kanal/Bandbreite, Bandsteuerung, Nachtschaltung (`X_AVM-DE_GetNightControl`), WLAN-Zeitplan; Band abschalten bleibt critical | M | Live an Box B: Nachtschaltung lesen, Kanal lesen; Schreiben mit Freigabe und Rücklesen |
| 7.5 | **Kindersicherung mit Profilen:** Zugangsprofile auflisten/zuweisen, Zeitkontingente, Tickets (`X_AVM-DE_HostFilter`, ggf. `/api/v0`) | M | Profil eines Offline-Geräts wechseln und zurück, `verified` |
| 7.6 | **Elicitation:** kritische Aktionen fragen per MCP-Elicitation direkt im Client nach („Neustart jetzt? Ja/Nein“); Plan/Execute-Token bleibt als Fallback für Clients ohne Elicitation | S–M | Test mit Client mit/ohne Elicitation-Support |
| 7.7 | **Strukturierte Ausgaben:** `outputSchema` je Tool (pydantic), stabile Feldnamen dokumentiert | M | Schema-Tests; Client zeigt typisierte Ergebnisse |

Reihenfolge: 7.1 → 7.2/7.3 (Mitschnitt-Session gemeinsam) → 7.4 → 7.5 → 7.6 → 7.7.

**Status (14.11.2026):** 7.1, 7.4, 7.5, 7.6, 7.7 gebaut und gegen Mocks getestet (Live-Test ausstehend, Prüfliste in ROADMAP „Live zu prüfen (Stufe 7)“). 7.2/7.3 **nicht gebaut** – Endpunkte/Bodies unbelegt; konkrete Mitschnitt-Checkliste (UI-Seiten, Felder, 2FA-Ablauf) in ROADMAP „Mitschnitt-Checkliste für 7.2/7.3“.
- 7.1 ✅ `guard.py`: Drosselung je Box, Cache 15 s + Leerung nach Schreiben, Backoff nur lesend, Schutzschalter; Lasttest gegen Mock (Schnappschuss an „überlasteter“ Box stoppt nach 3 Anfragen). Offen live: 98-Geräte-Box, Web-UI bedienbar.
- 7.2 ⏸ / 7.3 ⏸ – Mitschnitt nötig.
- 7.4 ✅ `wlan_settings`, `set_wlan_channel` (Kanal/Autokanal/Nachtschaltung lesen, Kanal setzen). Bandsteuerung, Kanalbreite, Zeitplan schreiben: nicht in TR-064.
- 7.5 ✅ Profile, Gerätestatus, Profil zuweisen, Tickets (AVM-Doku HostFilter v8).
- 7.6 ✅ Elicitation vor jedem critical-`*_execute`, Token bleibt Fallback.
- 7.7 ✅ `outputSchema` für system_info, wan_status, list_landevices, lan_ports, wlan_status, security_check, network_doctor, vpn_connections.
Risiken: `/api/v0` undokumentiert (kann sich mit FRITZ!OS-Updates ändern) → jede Funktion mit Firmware-Check und klarer Fehlermeldung; 2FA-pflichtige Einstellungen nie umgehen.

---

## Verifikation gegen AVM-Doku

Abgleich am 14.11.2026 mit den offiziellen Dokumenten (lokal unter `docs/vendor/avm/`, nicht im Repo). Matrix je Action/Endpunkt: [COVERAGE.md](COVERAGE.md). Zeilenangaben beziehen sich auf den Stand nach den Korrektur-Commits.

### Annahmen im Code (Action-/Feldnamen, Einheiten, Rechte)

| # | Stelle | Code bisher | Laut Doku | Ergebnis |
|---|---|---|---|---|
| V-1 | `myfritz.py:32,161`, `netinfo.py:289` | Action `X_AVM-DE_GetDDNSInfo` | heißt `GetDDNSInfo` (ohne Präfix) | ✅ korrigiert: dokumentierter Name zuerst, alter als Fallback (`Tr064Client.call_first`) |
| V-2 | `dns.py:72–73` | `X_AVM-DE_GetDNSServer`, `X_AVM-DE_GetIPv6DNSServer` | IGD-Doku: `X_AVM_DE_GetDNSServer` / `X_AVM_DE_GetIPv6DNSServer` (Unterstriche), Felder `NewIPv4DNSServer1/2`, `NewIPv6DNSServer1/2` | ✅ korrigiert – erklärt den Live-Befund „Upstream-DNS gibt es auf beiden Boxen nicht“ |
| V-3 | `wlan.py:127–128`, `diagnose.py:357` | `NewX_AVM-DE_UserIsolationEnabled`, `NewX_AVM-DE_NoForwardingEnabled` | `NewX_AVM-DE_UserIsolation`, `NewX_AVM-DE_NoForcedOff` (Gast-WLAN bleibt an, solange Geräte verbunden sind) | ✅ korrigiert – fehlendes Feld wurde als „nicht isoliert“ gewertet → falsches `warn` im Sicherheits-Check; jetzt `unknown`. `no_forwarding` → `no_forced_off` |
| V-4 | `diagnose.py:220` | `NewX_AVM-DE_LaborVersion` | seit Doku-Version 19 umbenannt in `NewX_AVM-DE_BuildType` (Release, Labor_Beta, …) | ✅ korrigiert: `build_type`, `labor_version` bleibt als Alias |
| V-5 | `netinfo.py:226` | Einheit der Online-Monitor-Felder „nicht live geprüft“ | `*_bps` = Byte pro Sekunde | ✅ Hinweis angepasst (Umrechnung war schon richtig) |
| V-6 | `netinfo.py:232–242` | sucht 64-bit-Zähler in TR-064 `X_AVM-DE_GetAddonInfos` | TR-064-Variante (2026-02) liefert nur Raten (Sync/Brutto/Tarif/L2/Manuell, bit/s); 64-bit-Zähler `NewX_AVM_DE_TotalBytesSent64/Received64` gibt es in der **IGD**-Action `GetAddonInfos`. 32-bit-Zähler sind laut Doku 0, wenn IGD nicht genutzt wird | ✅ 8.0: `WANCommonIFC1:GetAddonInfos` (IGD) zuerst, 32-bit-0 = `unknown` mit Hinweis auf UPnP-Statusinformationen, `online_monitor.rates` (Sync/Brutto/Tarif/L2/Manuell); Service-ID live prüfen |
| V-7 | `tr064.py:318–328` (`wan_connection_status`) und alles, was darauf aufsetzt (`wan_status`, Portfreigaben, Reconnect, DNS) | `WANIPConn1` zuerst | `WANIPConn1` ist die IGD-Service-ID (UPnP, ohne Anmeldung, nur mit „Statusinformationen über UPnP übertragen“); TR-064 heißt der Dienst `WANIPConnection1` | ✅ 8.0: Reihenfolge TR-064 `WANIPConnection1` → `WANPPPConnection1` → IGD `WANIPConn1`, verbundener Dienst gewinnt, `connection.source` = tr064/igd; IGD-eigene Actions (externe IPv6, Upstream-DNS) fallen auf `WANIPConn1` zurück (`Tr064Client.call_igd_first`); live an Kabel-/DS-Lite-Box prüfen |
| V-8 | `service.py:731` (`add_port_forward_plan`), `portforward.py:156` | Portfreigabe für beliebiges LAN-Gerät | `AddPortMapping`: Host darf nur Freigaben **für sich selbst** anlegen, nicht für andere Geräte, nicht im Gastnetz | ✅ 8.0: Plan und Execute lehnen Ziele ≠ eigene IP des MCP-Rechners mit Begründung + Verweis auf Web-UI/7.3 ab |
| V-9 | `telephony.py:143` | `<New>1</New>` = neue AB-Nachricht | Doku-Tabelle: 0 = neu, 1 = markiert (Widerspruch zur verbreiteten Praxis) | 🔲 live klären (eine Testnachricht), ggf. invertieren – ROADMAP Stufe 3 Punkt 1 |
| V-10 | `parental.py:164` | Einheit der Wochentags-Budgets unbekannt | Doku: TimeMax/TimeUsed in Sekunden, TicketValid/TicketTime in Minuten (Standard 45), Budget je Wochentag **ohne** Einheit; XML-Beispiel mit `</Action` ohne `>` (Code repariert das) | ✅ bestätigt bis auf Budget-Einheit → live |
| V-11 | `wlan.py:122–123` | `timeout_min`, `time_remaining_min` | Doku nennt für `X_AVM-DE_Timeout`/`TimeRemain` keine Einheit (String) | 🔲 live prüfen, sonst Feld ohne Einheit benennen |
| V-12 | `wlan.py:110` | `max_bit_rate` aus `GetInfo` | „nicht unterstützt, liefert Standardwert“; `GetStatistics`/`GetPacketStatistics` seit FRITZ!OS 8.10 immer 0 | ✅ 8.0: `max_bit_rate` aus `wlan_status` und Schema entfernt; Paketzähler werden nirgends genutzt |
| V-13 | `wlan.py` (`_loose`) | Autokanal-Argument locker gematcht | Doku schreibt `NewX_AVM-DEAuto_ChannelEnabled` (GetChannelInfo) und `NewX_AVM-DE_AutoChannelEnabled` (GetWLANConnectionInfo) | ✅ beide Schreibweisen abgedeckt |
| V-14 | `wlan.py:198`, `wlan.py:94` | Band-Werte, `APType` „unbelegt“ | `X_AVM-DE_FrequencyBand` 2400/5000/6000, `X_AVM-DE_APType` normal/guest; WPS-PIN-Felder obsolet | ✅ bestätigt |
| V-15 | `speedtest.py` | Felder/„kein Internet-Speedtest“ | alle 8 + 6 Felder exakt; kbit/s; nur bei der Box eingehende Pakete gezählt | ✅ bestätigt |
| V-16 | `nas.py:66–92` | Storage-/Filelink-Felder | `FTPEnable`, `FTPStatus`, `SMBEnable`, `FTPWANEnable`, `FTPWANSSLOnly`, `FTPWANPort`; Filelink `Expire`, `AccessCount(Limit)`, `ExpireDate`; `GetUserInfo` immer Benutzer „ftpuser“ | ✅ bestätigt |
| V-17 | `myfritz.py` | MyFRITZ!-/USP-/AppSetup-Feldnamen | MyFritz `GetInfo` (Enabled, DynDNSName, Port, DeviceRegistered, State, Email), USP `AccessRight{Smarthome,Mesh,Internet,System,Controller,WiFi,VoIP}`, AppSetup `GetConfig` Rechte + `InternetRights`/`AccessFromInternet` (Präfix `New`) | ✅ bestätigt |
| V-18 | `auth.py` | PBKDF2/MD5, SID-Ablauf | Challenge `2$iter1$salt1$iter2$salt2`, UTF-8, SHA-256 ✓; MD5 mit UTF-16LE und „.“ für Zeichen > U+00FF ✓; SID 20 min, verlängert sich bei Aktivität (an anderer Stelle nennt die Doku 10 min); Rechte 1 = lesen, 2 = schreiben ✓; BlockTime: Doku-Beispiel wartet, Code bricht mit Meldung ab (bewusst) | ✅ bestätigt |
| V-19 | `diagnose.py:391–395` | Auto-Update-Modi | `all`, `important`, `notify`, `off` (obsolet) | ✅ bestätigt |
| V-20 | `telephony.py` | Anruftypen 1/2/3/9/10/11, `days`/`max` | wie dokumentiert | ✅ bestätigt |
| V-21 | `smarthome.py` | AHA-Parameter | `sethkrtsoll` 16–56 (0,5 °C), 253/254; Leistung mW, Energie Wh, Temperatur 0,1 °C; `setname` braucht zusätzlich das App-Recht | ✅ bestätigt |
| V-22 | `netinfo.py:204–218` | `ds_current_bps` = Gesamt-Download | Doku beschreibt `ds_current_bps` als Multicast-Anteil und `mc_current_bps` als Heim+Gast+Multicast – vermutlich in der Doku vertauscht | 🔲 live während eines Downloads vergleichen |
| V-23 | `nas.py:35`, `diagnose.py` | UPnP-Service `X_AVM-DE_UPnP1` | Doku nennt `X_UPnP1` (und `SetConfig`-Argumente fälschlich „out“) | ✅ Code bleibt (live erfolgreich); Doku-Abweichung notiert |
| V-24 | README „Voraussetzungen“ | pauschal Recht „FRITZ!Box Einstellungen“ | je Action unterschiedlich: Kindersicherung, WLAN-Gast/WPS, Glasfaser, Mobilfunk, Storage-Info, Powerline → **App**; Telefonie → **Phone**; MyFRITZ!/Fernzugriff → App/Phone/NAS/Homeauto; viele Get-Actions ohne Recht | 🔲 Rechte-Tabelle je Tool (Spalte „Recht“ in COVERAGE) in README übernehmen → 9.2/9.3 |

### Denylist & Schwärzung

Geprüft: alle 375 TR-064-Actions auf Ausgaben mit Passwörtern, Schlüsseln, PINs, PSKs, Tokens, SIP-/PPP-Zugangsdaten, Session-IDs, Konfig-Exporten sowie auf gefährliche Wirkung. Ergebnis (Commit „Sicherheit: Denylist/Schwärzung gegen die AVM-Dokumente abgeglichen“, Tests in `tests/test_security.py`):

| # | Fund | Vorher | Jetzt |
|---|---|---|---|
| D-1 | `X_VoIP:X_AVM-DE_GetVoIPAccounts` liefert XML mit SIP-Benutzernamen und Registraren aller Konten | 🟡 generisch lesbar | ⛔ gesperrt (wie `X_AVM-DE_GetVoIPAccount`) |
| D-2 | `Hosts:X_AVM-DE_GetSpecificHostEntryByIP` liefert `X_AVM-DE_URLParameters` = Login-Token für Mesh-Repeater; dasselbe Feld steht in der Hostliste (XML) | ungeschwärzt | Feld global geschwärzt, `token=…` in Texten/URLs und `<…URLParameters>` in XML ebenso |
| D-3 | `WANPPPConnection:GetUserName` / `GetInfo.NewUserName` – PPP-Zugangsname (halbe Internet-Zugangsdaten) | lesbar | `GetUserName` gesperrt, Feld in `GetInfo` geschwärzt |
| D-4 | `ManagementServer:GetInfo` – Benutzernamen des TR-069-Servers des Providers | lesbar | `NewUsername`, `NewConnectionRequestUsername` geschwärzt |
| D-5 | `WANMobileConnection:GetInfoEx` – PPP-Benutzernamen, IMSI (SIM-Kennung) | lesbar | geschwärzt |
| D-6 | `OnTel:GetInfo`/`GetInfoByIndex` – Konto-Benutzername eines Online-Telefonbuchs | lesbar | geschwärzt |
| D-7 | Denylist-Einträge `X_AVM-DE_GetAppRemoteInfo`, `X_AVM-DE_GetDDNSInfo` in falscher Schreibweise (Doku: ohne Präfix) | `GetAppRemoteInfo` ungesperrt (DDNS griff über Namensmuster) | Doku-Schreibweisen ergänzt |
| D-8 | `UserInterface:X_AVM-DE_DoPrepareCGI` liefert eine Session-ID für Konfig-Import/Firmware-Upload | nur durch „kein Get“ blockiert | zusätzlich auf der Denylist |
| D-9 | Firmware-Updates angeschlossener Geräte (`DectDoUpdate`, `DeviceDoUpdate`, `X_AVM-DE_HostDoUpdate`), Support-Daten-Upload, SIM-PIN/PUK, WLAN global aus, Land/Annex, LAN-/DHCP-Umbau, `LANEthernetInterfaceConfig:SetEnable`, TR-069 an/aus/URL, `X_AVM-DE_DialNumber` | nur durch „kein Get“ blockiert | auf der Denylist – eine spätere Schreib-Allowlist kann sie nicht versehentlich öffnen |
| D-10 | Felder `New…Token` (z. B. `X_AVM-DE_Auth:SetConfig`) | – | geschwärzt (der MCP-Plan-Token `token` bleibt lesbar) |

Bereits vorher abgedeckt und bestätigt: `GetSecurityKeys`, `X_AVM-DE_GetWLANHybridMode` (WLAN-Schlüssel), `X_AVM-DE_GetConfigFile`/`SetConfigFile`, `X_AVM-DE_CreateUrlSID`, `X_AVM-DE_GetClient*` (SIP-Passwörter), `Reboot`/`FactoryReset`/`ForceTermination`/`RequestConnection`, Firmware-Update, WebDAV-Konto, Filelink-Token, `GetBoxSenderId`, alle Actions mit `VPN`/`DDNS`/`Password` im Namen, Passwort-/PSK-/WEP-/WPS-PIN-Felder global. Bewusst **nicht** geschwärzt: Seriennummern (`DeviceInfo`, SFP, GPON), lokale Benutzernamen (`X_AVM-DE_GetUserList`), `Storage:GetUserInfo` (fester Name „ftpuser“) – keine Zugangsdaten. Offene Abwägung für die Veröffentlichung: Seriennummern optional schwärzen (Stufe 9).

---

## Feature-Kandidaten aus der AVM-Doku

Noch nicht im Plan (oder nur als Stichwort). Aufwand S/M/L wie oben, Risiko = Gefahr für Box/Netz/Daten.

| # | Kandidat | Schnittstelle | Nutzen / Zielgruppe | Aufwand | Risiko | Einordnung |
|---|---|---|---|---|---|---|
| K-1 | DECT-Mobilteile: Namen, Modelle, Firmware-Update verfügbar, Telefonbuch je Mobilteil | TR-064 `X_AVM-DE_Dect`, `OnTel:GetDECTHandsetList/Info` | Familien-Admin, Normalnutzer („welches Telefon braucht ein Update?“) | S | gering | 8.11 |
| K-2 | Telefonbuch-Kontakte suchen, Rückwärtssuche in `call_list` | `OnTel:GetPhonebookEntry(UID)`, Telefonbuch-XML | Normalnutzer („wer hat angerufen?“) | S–M | gering (personenbezogen, nur auf Anfrage) | 8.10 |
| K-3 | Weckrufe lesen / an-aus | `X_VoIP:X_AVM-DE_GetAlarmClock`, `SetAlarmClockEnable` | Normalnutzer | S | gering | 8.10 / 8.8 |
| K-4 | Rufumleitungen lesen / an-aus | `OnTel:GetDeflections`, `SetDeflectionEnable` | Kleines Büro, Familien-Admin | S–M | mittel (Erreichbarkeit, Kosten) | 8.10 / 8.8 |
| K-5 | Rufsperren: Nummer sperren nach Spam-Anruf, Liste, entsperren | `OnTel:GetCallBarringList/Entry`, `SetCallBarringEntry`, `DeleteCallBarringEntryUID` | Normalnutzer, Eltern | M | gering | 8.10 / 8.8 |
| K-6 | AB-Nachrichten als gehört markieren / löschen | `TAM:MarkMessage`, `DeleteMessage` | Normalnutzer | S | gering / löschen critical | 8.8 |
| K-7 | Mobilfunk: Status, Technik (LTE/5G), Bänder, Signal (RSRP), Zelle; Fallback erkennen | `X_AVM-DE_WANMobileConnection` (Get*) | LTE/5G-Boxen, Ferienhaus, Ausfallsicherung | S–M | gering (IMSI geschwärzt) | 8.9 |
| K-8 | Glasfaser: optische Pegel mit Schwellen, GPON-Status, Fehlerzähler | `X_AVM-DE_WANFiber` | Glasfaserkunden, Störungsprotokoll | S | gering | 8.9 |
| K-9 | IPv6: Präfix + Lebensdauer, IPv6-Verbindungsstatus, DS-Lite erkennen; IPv6-Firewall-Status | IGD `X_AVM_DE_GetIPv6Prefix`, `X_AVM_DE_GetDsliteStatus`, `WANIPv6FirewallControl:GetFirewallStatus`; TR-064 `GetInfo.X_AVM-DE_IPv6ConnectionStatus` | Homelab, „warum ist mein Server nicht erreichbar?“ | S–M | gering (nur lesen) | 8.12 |
| K-10 | Provider-Fernwartung (TR-069) transparent machen | `ManagementServer:GetInfo`, `X_AVM_DE_GetTR069FirmwareDownloadEnabled` | Datenschutzbewusste, Kleines Büro | S | gering | 8.12 (security_check) |
| K-11 | Zeit/NTP: Server, Zeitzone, Uhrzeit-Abweichung | `Time:GetInfo` | Netz-Doktor (falsche Uhr → TLS-/Zertifikatsfehler) | S | gering | 8.12 |
| K-12 | Firmware: jetzt prüfen, Auto-Update-Modus setzen, Update ausführen | `UserInterface:X_AVM-DE_CheckUpdate`, `X_AVM-DE_SetConfig`, `X_AVM-DE_DoUpdate` | Familien-Admin | M | hoch (Neustart) → critical | 10 (Prüfen/Modus: 8.12) |
| K-13 | Rechte-/Einrichtungs-Check: Rechte des MCP-Benutzers, 2FA aktiv, anonymer Login, TR-064 aktiv | `LANConfigSecurity:X_AVM-DE_GetCurrentUser`, `X_AVM-DE_GetAnonymousLogin`, `X_AVM-DE_Auth:GetInfo`, `AppSetup:GetConfig` | alle Neueinsteiger – Voraussetzung für die Veröffentlichung | S | gering | 9.3 |
| K-14 | 2FA-Ablauf begleiten: Status abfragen, bis der Mensch an der Box bestätigt hat | `X_AVM-DE_Auth:GetState`/`SetConfig` | alle Schreib-Tools mit `confirmation_required` | M | mittel (nie umgehen, nur warten) | 10 |
| K-15 | Smart-Home-REST lesen: Geräte, Gruppen, Einheiten, Vorlagen, Routinen, globale Werte; Batterie, Fenster offen, Heizplan, Urlaubs-/Sommerzeit, Energie-Statistik | `GET /api/v0/smarthome/overview…`, `…/configuration/*/{UID}` | Smart-Home-/HA-Nutzer | M | gering | 8.5a |
| K-16 | Smart-Home-REST steuern: Vorlage anwenden, Routine an/aus, Einheit schalten/dimmen/Farbe/Rollo, Thermostat Boost/Fenster-offen, Urlaub (8.5: globals) | `POST …/overview/templates/{UID}`, `PUT …/triggers/{UID}`, `PUT …/units/{UID}`, `PUT …/globals` | Smart-Home-Nutzer | M | mittel | 8.5b |
| K-17 | Smart-Home-Konfiguration: Gruppen/Vorlagen/Routinen anlegen, ändern, löschen; Heizpläne bearbeiten | `POST/PUT/DELETE …/configuration/…` | Power-User | L | mittel–hoch (löschen critical) | 10 |
| K-18 | Geofencing (8.5) | `…/geofence/zones`, `…/registrations` | – | – | hoch (Standortdaten) | nicht geplant; höchstens Anzahl/Status ohne Koordinaten |
| K-19 | Zigbee-/DECT-ULE-Gerät anlernen (zeitlich begrenzt starten/stoppen) | REST `…/connect/startSubscription`, AHA `startulesubscription` | Smart-Home-Nutzer | M | mittel (Pairing-Codes nie ausgeben) | 10 |
| K-20 | AHA-Ergänzungen für Boxen < 8.2: Boost, Fenster-offen, Vorlagen, Routinen, Lampen, Rollos | AHA-Kommandos (COVERAGE) | Smart-Home-Nutzer mit älterem FRITZ!OS | S–M | gering–mittel | 8.5b (Fallback) |
| K-21 | Host-Extras: Änderungszähler (billige Erkennung neuer Geräte), Auto-WoL, Priorisierung, Gerätetyp setzen | `Hosts:X_AVM-DE_GetChangeCounter`, `…SetAutoWakeOnLANByMACAddress`, `…SetPrioritizationByIP`, `…SetDeviceClassUserByMAC` | Alarme (8.3), Homelab, Gamer/Homeoffice | S je | gering | 8.11 / 8.3 |
| K-22 | Update-Übersicht aller AVM-Geräte (Repeater, Powerline, DECT, Box) | `Hosts:X_AVM-DE_GetSpecificHostEntryByIP` (UpdateAvailable), `Dect`/`Homeplug` (UpdateAvailable) | Familien-Admin | S | gering | 8.11 |
| K-23 | WPS-Taste per Tool (2 min, Push-Button) | `WLANConfiguration:X_AVM-DE_SetWPSConfig` | Normalnutzer („Drucker verbinden“) | S | mittel (öffnet kurz das WLAN) | 8.4 |
| K-24 | Statische Routen lesen | `Layer3Forwarding:GetGenericForwardingEntry` | Homelab, Netz-Doktor | S | gering | 8.12 |
| K-25 | DSL-Diagnose: Kabeltest/Fehlerort, Spektrum (SNR je Träger) | `WANDSLInterfaceConfig:X_AVM-DE_GetDSLDiagnoseInfo`, `X_AVM-DE_GetDSLInfo` | DSL-Kunden, Störungsprotokoll | S | gering | 8.9 |
| K-26 | Zwangstrennung verschieben (Stunde der Wartungstrennung) | `WANPPPConnection:X_AVM_DE_Get/SetAutoDisconnectTimeSpan` | Homeoffice, Gamer | S | gering–mittel | 8.12 (lesen) / 8.8-Umfeld (schreiben) |
| K-27 | Telefonie-Gesundheit: alle Rufnummern registriert? | `X_VoIP:X_AVM-DE_GetVoIPStatus`, `X_AVM-DE_GetNumbers` | Normalnutzer, Netz-Doktor („Telefon geht nicht“) | S | gering | 8.10 |
| K-28 | Smart Home über TR-064 (ohne Web-Login) als Fallback | `X_AVM-DE_Homeauto:GetGenericDeviceInfos`, `SetSwitch` | Setups ohne `/api/v0`-Rechte | S | gering | 10 |

**Top 10 (Empfehlung, nach Nutzen/Aufwand):** K-13 Rechte-Check · K-21+K-22+K-1 Geräte-/Update-Übersicht mit Änderungszähler · K-15 Smart-Home-REST lesen · K-27+K-3+K-4 Telefonie-Überblick · K-25+K-8+K-7 Leitungsdiagnose je Anschlussart · K-10+K-11 TR-069/NTP-Transparenz · K-9 IPv6-Status · K-5 Rufsperren · K-16 Smart-Home steuern · K-12 Firmware prüfen/Modus.


## Stufe 8 – Überwachung & Komfort
Ziel: Probleme über die Zeit sichtbar machen und Alltagsaufgaben bequem erledigen. Neu nach dem Doku-Abgleich: 8.0 und 8.9–8.12, 8.5 aufgeteilt, 8.8 präzisiert.

| # | Paket | Aufwand | Abnahme |
|---|---|---|---|
| 8.0 ✅ | **Doku-Nacharbeiten:** V-6 (64-bit-Zähler über IGD, 0 = unbekannt, Tarif-/Sync-Raten), V-7 (TR-064-WAN-Dienst vor IGD), V-8 (Portfreigabe nur für den eigenen Rechner, sonst früh ablehnen), V-12 (`max_bit_rate`/Paketzähler), V-11/V-22 nach Live-Befund | S–M | Tests je Punkt; live: `wan_status.service` = TR-064-Dienst, `online_monitor.volume.source` plausibel, Portfreigabe-Plan für fremdes Gerät mit klarer Begründung abgelehnt |
| 8.11 ✅ | **Geräte- & Update-Übersicht:** `Hosts:X_AVM-DE_GetChangeCounter` als billiger Änderungsindikator (Cache/Alarme), Update-Status aller AVM-Geräte (Repeater, Powerline, DECT-Basis/-Mobilteile), DECT-Mobilteile (K-1, K-21, K-22) | S | Mock-Tests; live: Repeater/Mobilteil erscheinen mit Modell und `update_available` |
| 8.1 ✅ | **Messreihe:** optionaler Hintergrund-Collector (`fritzos8-collector`, systemd/launchd oder als HA-Add-on), sammelt alle N Minuten DSL-/Glasfaser-/Mobilfunk-Werte, Fehlerzähler, Resyncs, Durchsatz, Gerät online/offline (über den Änderungszähler), Link-Wechsel, Speedtest (selten) in lokale SQLite; Aufbewahrung konfigurierbar; MCP-Tools `history_query`, `history_summary` | L | 24 h Lauf an beiden Boxen, < 1 % Last, Lücken als Lücken erkennbar |
| 8.9 ✅ | **Leitungsdiagnose je Anschlussart** (`line_diagnostics`): DSL (Diagnose/Kabeltest, Fehlerort, Spektrum – K-25), Glasfaser (optische Pegel vs. Schwellen, GPON – K-8), Mobilfunk (Technik, Bänder, RSRP, Zelle – K-7), Kabel (soweit TR-064); Grenzwerte in Netz-Doktor und Messreihe | S–M | Mock-Fixtures je Anschlussart; live an 7583 (DSL) und 6660 (Kabel), Glasfaser/LTE nur Mock |
| 8.2 ✅ | **Störungsprotokoll** (`isp_report(from,to)`): Markdown (PDF über externe Werkzeuge) mit Abbrüchen, Fehlerverlauf, Durchsatz vs. Tarif (`X_AVM-DE_TariffDataRate*` aus V-6), Hinweis Breitbandmessung BNetzA | M | Bericht aus 8.1-Daten, inkl. eines simulierten Störfalls |
| 8.3 ✅ | **Alarme:** neue Geräte (Änderungszähler + Hostliste), Konfig-Drift (Snapshots), Link-Flapping, Leitungs-Grenzwerte (8.9), Batterie niedrig, Firmware-Update verfügbar (8.11), Rufnummer nicht registriert (8.10); Ausgabe als Tool + optionale Benachrichtigung (HA-Webhook, ntfy, Telegram) | M | Jeder Alarmtyp mit Test; keine Dauer-Alarme (Entprellung) |
| 8.12 ✅ | **System-Transparenz** (lesend, in `security_check`/`network_doctor`/`system_info`): Provider-Fernwartung TR-069 (K-10), Zeit/NTP inkl. Abweichung (K-11), IPv6-Präfix/Verbindungsstatus/DS-Lite/IPv6-Firewall (K-9), statische Routen (K-24), Zwangstrennungs-Stunde (K-26), Auto-Update-Modus | S–M | Mock-Tests; live beide Boxen: DS-Lite der 7583 erkannt, NTP-Abweichung plausibel |
| 8.10 ✅ | **Telefonie lesen:** Rufnummern registriert (K-27), DECT-Mobilteile, Weckrufe (K-3), Rufumleitungen (K-4), Rufsperren (K-5), Telefonbuch-Suche + Namen in der Anrufliste (K-2) | S–M | Mock-Tests; live: Rufnummernstatus = Web-UI |
| 8.7 ✅ | **Familien-Admin-Bericht:** alle Boxen auf einen Blick (Firmware, Update-Übersicht 8.11, Score, Erreichbarkeit, Alarme, Backup-Ziel) | S | Bericht über beide Boxen |
| 8.5a ✅ | **Smart Home REST lesen (FRITZ!OS ≥ 8.2):** `smarthome_overview` (Geräte, Gruppen, Einheiten, Vorlagen, Routinen, globale Werte), Batterie, Fenster offen, Heizplan/Urlaub/Sommer, Energie-Statistik; **Heiz-/Energiebericht**; AHA bleibt Fallback (K-15) | M | Live am Thermostat (Box B) gegen Web-UI; 8.2 und 8.5 per Fixture |
| 8.6 ✅ | **FRITZ as Code:** Sollzustand je Box als YAML (DNS, WLAN, Portfreigaben, Kindersicherung, feste IPs, EEE), `fritz_plan`/`fritz_apply` mit Vorschau, Drift-Erkennung via Snapshots | L | Plan zeigt Abweichungen korrekt; Apply nur mit Freigabe, idempotent |
| 8.5b ✅ | **Smart Home steuern:** Vorlage anwenden, Routine an/aus, Einheit schalten/dimmen/Farbe/Rollo, Thermostat Boost/Fenster-offen (Endzeit ≤ 24 h); Urlaub **nicht** über `globals` (enthält nur Presets/Standort/Geofence – Urlaub liegt in `configuration/units`, Stufe 10); AHA-Pendants für ältere Boxen (K-16, K-20); jede Änderung mit Rücklesen | M | Live am Thermostat mit Freigabe, zurückgestellt |
| 8.4 ✅ | **Gast-WLAN mit Zeitlimit + QR-Code**, Opt-in-Stufe `secrets` (Schlüssel landet im QR-Bild, nie im Text); dazu WPS-Taste per Tool (K-23, 2 min, write mit Warnung) | S–M | QR als Datei, Gastnetz nach Ablauf aus; WPS-Status nach 2 min wieder `off` |
| 8.8 ✅ | **Telefonie schreiben:** Weckruf an/aus, Rufumleitung an/aus (Warnung Kosten/Erreichbarkeit), Rufsperre hinzufügen/entfernen, AB-Nachricht gehört/löschen (löschen critical), Anrufen per Klick (`X_AVM-DE_DialNumber` – critical, steht auf der Denylist des generischen Callers) | M | Live nur mit Freigabe, alles zurückgestellt |

Reihenfolge: 8.0 → 8.11 → 8.1 → 8.9 → 8.2 → 8.3 → 8.12 → 8.10 → 8.7 → 8.5a → 8.6 → 8.5b → 8.4 → 8.8.

**Status (14.11.2026):** alle Pakete gebaut und gegen Mocks/Fixtures getestet (je Paket ein Commit, Live-Prüfpunkte in ROADMAP „Live-Prüfpunkte (Stufe 8)“). Abgrenzungen:
- 8.0 ✅ V-6/V-7/V-8/V-12 umgesetzt; V-11 (Einheit Gast-Timeout) und V-22 (`ds_current_bps`) bleiben Live-Befund.
- 8.2 ✅ nur Markdown; PDF bewusst ohne zusätzliche Abhängigkeit (pandoc/Viewer).
- 8.4 ✅ Box-Zeitbegrenzung per TR-064 nicht setzbar → Abschalten durch Server-Timer/Collector; QR in neuer Opt-in-Stufe `secrets` (`segno` optional).
- 8.5b ✅ ohne Urlaub: `overview/globals` trägt keine Urlaubszeiten (Plan-Annahme falsch) – Urlaub/Sommer liegt in `configuration/units` → Stufe 10.
- 8.6 ✅ DNS/Portfreigaben nur Vergleich (7.2/7.3 fehlen); Sollzustand nur aus `FRITZ_CODE_DIR` oder inline.
- 8.9 ✅ Kabel/DOCSIS per TR-064 nicht lesbar (`unknown`); Glasfaser/Mobilfunk nur per Fixture geprüft.
- 8.3 ✅ Rufnummer-nicht-registriert-Alarm kam mit 8.10 dazu (`AlarmService.extra_checks`).
Risiken: Smart-Home-REST kann Standortdaten (Geofencing) und URLs mit Zugangsdaten (`httpRequestInterface`) enthalten → vor dem ersten Tool Schwärzung erweitern und testen; Mobilfunk-/Glasfaser-Werte nur per Fixture prüfbar.

## Stufe 9 – Veröffentlichung
| # | Paket | Aufwand |
|---|---|---|
| 9.1 ✅ (lokal) | **Neues Repo mit sauberem Initial-Commit** (alte Historie enthält private Daten), Lizenz/NOTICE geprüft | S |
| 9.2 ✅ | **README Englisch** (+ Deutsch), Schnellstart, Sicherheitskonzept, Rechte-Einrichtung in der FRITZ!Box, Tool-Referenz aus Schemas generiert | M |
| 9.3 ✅ | **Zugangsdaten plattformübergreifend** über `keyring` (macOS/Windows/Linux), Einrichtungs-Assistent `setup_check` (K-13: TR-064 aktiv, Rechte des MCP-Benutzers über `X_AVM-DE_GetCurrentUser`/`AppSetup:GetConfig`, 2FA aktiv, anonymer Login; erklärt je fehlendem Recht, welche Tools betroffen sind) | M |
| 9.4 ✅ | **Pakete:** PyPI für `uvx fritzos8-mcp`, optional Docker, **Home-Assistant-Add-on** | M–L |
| 9.5 ✅ | **Kompatibilitätsmatrix** (Modelle/FRITZ!OS), opt-in **Live-Testsuite** (nur lesend) für Beitragende | M |
| 9.6 ✅ | SECURITY.md, CONTRIBUTING.md, Issue-Vorlagen, Release-Workflow (Changelog, SemVer), Dependabot bleibt | S |
| 9.7 ✅ | **Rechte-Tabelle je Tool** in der README (aus der Spalte „Recht (Doku)“ in COVERAGE, V-24): welches FRITZ!Box-Recht (App/Phone/NAS/Smart Home/Einstellungen) jedes Tool braucht; Hinweis, dass für Kindersicherung/WLAN das App-Recht genügt | S |
| 9.8 ✅ | **Abdeckung aktuell halten:** `docs/COVERAGE.md` bei jedem neuen Tool nachziehen; optional Generator-Skript, das lokal aus den (nicht versionierten) AVM-Dokumenten die Action-Listen zieht und mit Denylist/Tool-Zuordnung abgleicht; CI-Test, dass jede kuratierte Action auch in COVERAGE steht | S–M |
| 9.9 ✅ | **Datenschutz-Feinschliff vor Veröffentlichung:** Seriennummern (Box, SFP, GPON) optional schwärzen, Geofencing-/Standortfelder in der `/api/v0`-Schwärzung, `httpRequestInterface`-URLs | S |

**Status Stufe 9 (14.11.2026):**
- 9.1 ✅ lokal: `scripts/make_public_snapshot.sh [ZIEL] [--force]` erzeugt aus HEAD (nur versionierte Dateien, `git archive`) außerhalb des Repos einen frischen Ein-Commit-Stand ohne Historie und ohne Remote – nur, wenn die Prüfung nichts findet: private Muster werden zur Laufzeit aus `CLAUDE.local.md` (IPs, AINs, Schlüsselbund-Namen, zitierte Geräte-/Raumnamen, Straßen/Orte, Home-Pfade) und optional `.private-patterns` (gitignored) gelesen und nie ausgegeben; dazu verbotene Dateien (CLAUDE.local.md, AVM-Doku, `.env`, Schlüssel), Token-Muster und nicht erfundene MAC-Adressen. Einmal ausgeführt: erster Lauf fand 2 echte Treffer (Beispielnamen in den Skript-Kommentaren, ein zitierter PR-Titel in CLAUDE.md) und eine Fehlmeldung (erfundene MAC) → bereinigt; zweiter Lauf ✓, Ziel `../fritzos8-mcp-public` mit 1 Commit/183 Dateien, Testsuite dort grün. Beispiel-IPs der Doku vorher auf `fritz.box`/192.0.2.x umgestellt. LICENSE/NOTICE unverändert geprüft (MIT, Fremdcode vermerkt).
- 9.3 ✅ `keyring` als Extra (`fritzos8-mcp[keyring]`): fehlt `FRITZ_PASSWORD`/`_FILE`, liest `config.load` den Schlüsselbund (Dienst `FRITZ_KEYRING_SERVICE`, Standard `fritzos8-mcp`; Konto `<user>@<host>`, dann `<user>`; je Box `FRITZ_<NAME>_KEYRING_SERVICE`). `setup_check` (read, `setupcheck.py`): TR-064, Rechte über `X_AVM-DE_GetCurrentUser` (Fallback `AppSetup:GetConfig`), anonyme Anmeldung, Standardkennwort, 2FA, `/api/v0`, AHA, Smart-Home-REST, Stufen; je fehlendem Recht die betroffenen Tools. Tests lesen nie den echten Schlüsselbund (autouse-Fixture).
- 9.2 ✅ `README.md` jetzt Englisch (Schnellstart, Funktionsüberblick, Sicherheitsmodell, Rechte, Konfiguration, Installation), `README.de.md` Deutsch (bisheriger Inhalt + Schnellstart, Rechte-Einrichtung, Installationswege). Tool-Referenz `docs/TOOLS.md` aus den registrierten Tools generiert (`toolref.py`, `scripts/gen_tool_reference.py`: Stufe, Recht, Parameter aus dem Eingabeschema, Beschreibung, Hinweis auf strukturierte Ausgabe); Test schlägt fehl, wenn sie veraltet ist. Website bindet sie ein.
- 9.4 ✅ `pyproject.toml` PyPI-fertig (Klassifikatoren, Projekt-URLs, `py.typed`, `mcp>=2.3,<3` statt der zu weiten Untergrenze 1.10, Extras `keyring`/`mqtt`/`qr`, Skripte `fritzos8-mcp`/`fritzos8-collector`/`fritzos8-anonymize`); `uv build` lokal geprüft – sdist/wheel enthalten nur `src/`, LICENSE, NOTICE, README (kein CLAUDE.local.md, keine AVM-Doku). `Dockerfile` (mehrstufig, Nicht-root-Benutzer, `/data` als Zustand, stdio/HTTP/Collector) lokal gebaut und gestartet, `.dockerignore`. Home-Assistant-Add-on-Vorlage `ha-addon/` (Collector + MQTT über den Supervisor-MQTT-Dienst, optional HTTP-MCP mit Token; installiert die PyPI-Version – erst nach Veröffentlichung nutzbar). **Nicht** hochgeladen (PyPI/Docker Hub/Add-on-Repo brauchen Toms Freigabe).
- 9.5 ✅ `docs/COMPATIBILITY.md` (7583/8.26 DSL und 6660/8.25 Kabel mit den Ergebnissen des Live-Lesetests, Bereiche je Box, Anleitung zum Beitragen; auch auf der Website). Opt-in-Livesuite `tests/live/` (Marker `live`, nur mit `FRITZ_LIVE_TEST=1`, Service mit Gate(False, False), 19 lesende Prüfungen, prüft zusätzlich, dass das Passwort nie in einer Ausgabe steht); standardmäßig übersprungen.
- 9.6 ✅ `SECURITY.md` (private Meldung über GitHub Security Advisories, Scope), `CONTRIBUTING.md` (Regeln: Stufen, Rücklesen, Guard, Schwärzung, COVERAGE, Rechte, keine privaten Daten, Release-Ablauf), Issue-Vorlagen (Fehler, Kompatibilität, Idee; leere Issues aus), PR-Vorlage, Release-Workflow `.github/workflows/release.yml` (nur bei Tag `vX.Y.Z`: Version = pyproject + CHANGELOG-Abschnitt, Checks, Build, GitHub-Release mit Notizen aus `scripts/changelog_section.py`; PyPI per Trusted Publishing nur mit Repository-Variable `PUBLISH_PYPI=true`). Kein Tag gepusht. Dependabot bleibt.
- 9.8 ✅ `tests/test_coverage_doc.py`: AST-Scan aller `call`/`try_call`/`call_first`/`call_igd_first`-Aufrufe mit konstantem Action-Namen – jede kuratierte Action muss in `docs/COVERAGE.md` stehen (fand 3 Lücken: IGD-Firewall/Pinholes, Bindestrich-Variante der Zwangstrennung → neue IGD-Tabelle). `scripts/coverage_stats.py` zählt die TR-064-Statistik aus den Zeilen neu (Service-Kopfzeilen, Service-Tabelle, Zusammenfassung; `--check` in CI und als Test); AHA/REST-Zahlen von Hand nachgezogen. Neuer Stand: TR-064 lesend 55,2 % kuratiert + 36,3 % generisch, schreibend 21,3 %; AHA 44 %; Smart-Home-REST 8.2 58 %, 8.5 44 %. Der lokale Abgleich gegen die (nicht versionierten) AVM-Dokumente bleibt manuell.
- 9.9 ✅ `FRITZ_REDACT_SERIALS=1` maskiert Seriennummern, IMEI/ICCID, UDN/UUID in allen Tool-Ausgaben und Ressourcen (`redact.redact_serials`, `build_server(redact_serial_numbers=…)`); Standard bleibt sichtbar (keine Zugangsdaten). Geofencing-Koordinaten und `httpRequest`/`httpRequestInterface`-Objekte waren seit 8.5a in `redact_api` – jetzt zusätzlich mit Test für `httpRequestInterface` und Koordinaten in Geofence-Registrierungen abgesichert.
- 9.7 ✅ `rights.py` (`TOOL_RIGHTS` für alle Tools, `PARTIAL` für Tools, die ohne Recht teilweise laufen); Test erzwingt einen Eintrag je registriertem Tool; Rechte-Spalte in der generierten Tool-Referenz.

## Stufe 10 – Ökosystem & Intelligenz
Ursprünglich „nach der Veröffentlichung“ geplant; am 14.11.2026 vorgezogen und vor Stufe 9 gebaut (nur gegen Mocks/Fixtures getestet, Live-Prüfpunkte in ROADMAP „Live-Prüfpunkte (Stufe 10)“).

| # | Paket | Status |
|---|---|---|
| 10.1 | **Anomalie-Erkennung** auf der Messreihe (8.1): sinkende DSL-Marge (Trend + Prognose), niedrigere Sync-Rate, schneller wachsende Fehlerzähler, gehäufte Neuverbindungen, häufigere Geräteabbrüche; in `alarms_check` und `network_doctor` | ✅ `history_anomalies` |
| 10.2 | **Netz-Optimierer:** Vorschläge (WLAN-Kanal, Bandsteuerung, EEE, Repeater) → Plan → Ausführung über bestehende Schreib-Tools → Wirkung messen (vorher/nachher) | ✅ `network_optimizer_*` |
| 10.3 | **Home-Assistant-Anbindung:** MQTT-Brücke mit HA-MQTT-Discovery für Messreihe/Alarme (Extra `mqtt`), Doku; kein Custom-Component | ✅ `mqttbridge.py`, [Doku](home-assistant.md) |
| 10.4 | **Sichere Fernverwaltung:** Streamable-HTTP-Transport mit Pflicht-Bearer-Token, Bind 127.0.0.1, Warnung bei 0.0.0.0; Doku Pi/VPN | ✅ `httpserve.py`, [Doku](remote.md) |
| 10.5 | **Community-Fixtures:** Anonymisierer für Box-Antworten + Doku zum Einreichen | ✅ `fritzos8-anonymize`, [Doku](fixtures.md) |
| 10.6 | **Aus dem Doku-Abgleich (critical):** Firmware-Update (K-12), IPv6-Pinholes (IGD), statische Routen schreiben, Smart-Home-Urlaub (`configuration/units`), Smart-Home-Konfiguration (K-17), Zigbee/DECT-ULE anlernen (K-19), Smart Home über TR-064 (K-28), 2FA erkennen/begleiten (K-14) | ✅ 10.6a (Firmware, Routen, Pinholes, 2FA) + 10.6b (Smart Home); offen: Smart-Home-Objekte anlegen, Heizpläne |
| 10.7 | **Weitere AVM-Geräte** (Repeater/Powerline/DECT), soweit über die Box dokumentiert | ✅ `avm_device_detail`; direkte Geräte-Schnittstellen offen |
| 10.8 | **Doku-Website** (mkdocs, DE/EN) im Repo, nicht deployt | ✅ `mkdocs.yml`, `website/` |

Bewusst nicht: Geofencing-Koordinaten, Pairing-/Install-/Reset-Codes, Zugangsdaten setzen (SIP, PPP, WLAN-Schlüssel, Fernzugriff-Benutzer), 2FA umgehen. Neue undokumentierte `/api/v0`-Endpunkte werden nicht geraten (→ „braucht Browser-Mitschnitt“).

**10.8 ✅** `mkdocs.yml` + `website/` (Material-Theme, `mkdocs-static-i18n` mit Suffix-Struktur `seite.md`/`seite.en.md`): Start, Schnellstart, Sicherheit, Tool-Referenz, Home Assistant, Fernverwaltung, Community-Fixtures je DE/EN; deutsche Detailseiten binden `docs/*.md` per Snippet ein (eine Quelle). Bauen nur lokal (`uvx --with mkdocs-material --with mkdocs-static-i18n mkdocs build --strict`, geprüft), kein Deploy, kein Workflow. `site/` ist gitignored.

**10.7 ✅ (teilweise, bewusst)** Über die Box dokumentiert und genutzt: DECT (`X_AVM-DE_Dect` – Liste und jetzt auch `GetSpecificDectEntry`), Powerline (`X_AVM-DE_Homeplug` – Liste und `GetSpecificDeviceEntry`), Hostliste (Modell, Mesh-fähig, Update) und die Mesh-Topologie (AVM-Dokument „Mesh Topology“, JSON-Schema je FRITZ!OS). Neu `avm_device_detail` (read): ein Gerät per MAC/DECT-ID/Name mit DECT-/Powerline-/Hostlisten-Eintrag und Mesh-Knoten (Rolle, Uplink zur Box mit Rate, Anzahl Clients; Mesh-Feldnamen `device_model`/`device_firmware_version` unverifiziert). Zusammen mit `avm_device_updates`, `dect_handsets`, `powerline_status`, `mesh_overview` ist damit alles abgedeckt, was die Box-Schnittstellen über andere AVM-Geräte hergeben. **Offen:** direkte Abfrage von FRITZ!Repeater/Powerline-Adaptern über deren eigenes TR-064/Web-UI (eigene Zugangsdaten je Gerät, nicht über die Box dokumentiert), Updates angeschlossener Geräte starten (`DectDoUpdate`/`DeviceDoUpdate`/`X_AVM-DE_HostDoUpdate` – bleiben gesperrt; wäre ein eigener critical-Kandidat), DECT-Telefon-Einstellungen (keine Box-Schnittstelle).

**10.6b ✅** `smarthome_config.py` (nach Smart-Home-REST 8.5, AHA, TR-064 Homeauto): `smarthome_thermostat_config` (read), `smarthome_holidays_plan/_execute` und `smarthome_summer_period_plan/_execute` (critical, `PUT configuration/units/{UID}`, Minuten seit Jahresbeginn mit Schalttag, max. 4 Zeiträume ohne Überschneidung, Rücklesen) – erledigt die Abgrenzung aus 8.5b; `smarthome_delete_plan/_execute` (critical, Gruppe/Vorlage/Routine, Rücklesen = 404); `smarthome_rename_plan/_execute` (critical, REST `name`, Fallback TR-064 `SetDeviceName`); `smarthome_pairing_plan/_execute` (critical, K-19, `connect/startSubscription` auf der Master-Funkbasis bzw. AHA `startulesubscription`, Rücklesen über den Anmeldestatus), `smarthome_pairing_status` (read), `smarthome_pairing_stop` (write); `smarthome_tr064_devices` (read) und `smarthome_tr064_set_switch` (write, K-28 – wie die anderen Schalt-Tools write statt critical, da harmlos und rücklesbar). Install-/Reset-/Pairing-Codes werden nie angefragt; die zentrale Schwärzung fängt sie zusätzlich ab (Test). **Offen (K-17, bewusst):** Gruppen/Vorlagen/Routinen anlegen oder inhaltlich ändern und Heizpläne (`timer`) bearbeiten – große Bodies, Vorlagen können `httpRequest` mit Zugangsdaten tragen; erst nach Live-Prüfung der Lese-Strukturen.

**10.6a ✅** `syswrite.py`: `firmware_update_plan/_execute` (critical, `X_AVM-DE_CheckUpdate` optional im Plan, Token an installierte + angebotene Version gebunden, `X_AVM-DE_DoUpdate` → `accepted`, `verified: false` bis nach dem Neustart, `firmware_update_status` liest `X_AVM-DE_UpdateSuccessful`; `X_AVM-DE_DoUpdate` bleibt im generischen Caller gesperrt). `static_route_add/_delete_plan/_execute` (critical, Netzadresse/Gateway geprüft, keine Default-Route, Gateway privat und außerhalb des Zielnetzes, Rücklesen über `GetSpecificForwardingEntry`; `NewType` Host/Network unbelegt). `ipv6_pinhole_add/_delete_plan/_execute` + `ipv6_firewall_status` (IGD `WANIPv6FirewallControl`; nur globale IPv6-Ziele, Lease 60–86400 s, Argumentnamen aus der SCPD, Rücklesen über `UpdatePinhole`, lokale Liste `pinholes.json`, da die Box keine Liste anbietet; Ablehnung 606 mit Erklärung). `two_factor_status` (K-14, nur `GetInfo`/`GetState` + Anleitung; `SetConfig` bewusst nicht gebaut – der Abschluss bräuchte das Token im SOAP-Header, fritzconnection kann das nicht, und der Server soll die Bestätigung nie selbst auslösen). `confirmation_required`-Hinweis verweist auf `two_factor_status`.

**10.5 ✅** `anonymize.py` + Konsolenbefehl `fritzos8-anonymize`: konsistente Ersetzung (MAC, IPv4/IPv6, Namen, SSIDs, Benutzer, Seriennummern/UUID/AIN, Rufnummern, E-Mail, DynDNS, Standort) plus zentrale Schwärzung; `find_leftovers` verweigert das Schreiben bei Resten. CI-Test prüft jede Datei unter `tests/fixtures/community/` (ein Beispiel mit erfundenen Werten liegt bei). Doku: [docs/fixtures.md](fixtures.md).

**10.4 ✅** `httpserve.py`: `fritzos8-mcp --http` bzw. `FRITZ_TRANSPORT=http` → `MCPServer.streamable_http_app()` hinter einer eigenen ASGI-Bearer-Middleware (zeitkonstanter Vergleich, 401 ohne Details), Token Pflicht (≥ 32 Zeichen, aus env/Datei/keyring), `--generate-token`, Bind 127.0.0.1, Warnungen bei nicht-lokalem Bind/ohne TLS/ohne `FRITZ_HTTP_ALLOWED_HOSTS` (DNS-Rebinding-Schutz des SDK), optional TLS direkt (uvicorn). Token wird wie das Box-Passwort geschwärzt. Kein OAuth (ein Token je Installation). Doku: [docs/remote.md](remote.md).

**10.3 ✅ (eingefroren 14.11.2026)** – bleibt drin, wird aber nicht weiterverfolgt: Die offiziellen HA-Integrationen (FRITZ!Box Tools/SmartHome/Anrufmonitor) decken die Entitäten ab, Alarme kommen per HA-Webhook an; die Zusatzwerte (SNR, Score, Updates) rechtfertigen keinen weiteren Ausbau. Gleiches gilt für die Add-on-Vorlage aus 9.4 (kein Add-on-Repo). `mqttbridge.py`: läuft im `fritzos8-collector`, sobald `FRITZ_MQTT_HOST` gesetzt ist; Discovery einmal je Prozess (retained), Zustand/Alarme/Verfügbarkeit retained, Last Will; Broker-Fehler brechen die Messung nie ab (nur Typ im Log). Broker-Passwort gehört zu den Geheimnissen (`alert_secrets`). paho-mqtt als Extra `mqtt`. Kein MCP-Tool nötig. Doku: [docs/home-assistant.md](home-assistant.md).

**10.2 ✅** `optimizer.py`: `network_optimizer_suggest` (read) → `network_optimizer_apply_plan/_execute` (critical, Aktionen serverseitig ans Token gebunden, Ausführung nur über `set_wlan_channel`/`set_lan_eee` mit deren Rücklesen) → `network_optimizer_effect` (read, Vorher/nachher-Fenster aus der Messreihe: Abbrüche/Tag gesamt bzw. der betroffenen Geräte, Neuverbindungen; Urteil ±30 %). Bandsteuerung und Repeater-Standort nur als manuelle Empfehlung (per TR-064 nicht schreibbar; Bandsteuerung über `/api/v0` bräuchte einen Browser-Mitschnitt). Änderungsprotokoll `optimizer.json` (0600).

**10.1 ✅ (14.11.2026)** `anomaly.py`: vergleicht die letzten `recent_hours` (Standard 24) mit den Tagen davor (Standard 14), Schwellen in `ANOMALY_THRESHOLDS` (mit jedem Bericht ausgegeben). Zu wenig Daten → `insufficient_data`, nie „ok“. Befunde mit `area: trend` im Netz-Doktor (Symptome wie „seit Tagen langsamer“ markieren sie als relevant) und als Alarmtyp `anomaly` (nur warn/critical). Liest nur die lokale SQLite-Datei.

## Querschnitt (gilt für alle Stufen)
- Sicherheit: Lesen frei, Schreiben `FRITZ_ALLOW_WRITE`, kritisch zusätzlich `FRITZ_ALLOW_CRITICAL` + Bestätigung; jeder Schreibvorgang mit Rücklesen; Geheimnisse nie in Ausgaben/Logs/Snapshots; 2FA wird gemeldet, nie umgangen.
- Neue `/api/v0`-Endpunkte nur nach Browser-Mitschnitt an echter Box; Feldnamen in Tests als Fixtures (erfundene Werte).
- Keine privaten Daten in versionierten Dateien (Privates in `CLAUDE.local.md`).
- Commits ohne KI-Hinweise; CI (ruff, mypy strict, pytest 3.12/3.13) grün; Dependabot wöchentlich.
