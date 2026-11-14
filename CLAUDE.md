# CLAUDE.md – fritzos8-mcp

Kontext für Agenten, die an diesem Repo arbeiten. **Lokale, private Details (Boxen, IPs, Schlüsselbund-Einträge, Testgeräte, Registrierungsbefehle) stehen in `CLAUDE.local.md` (gitignored) – nie in versionierte Dateien übernehmen.** Sprache mit Tom: Deutsch. **Projekt-Kommunikation auf Englisch:** Commits, PR-Titel/-Texte, Issues, CHANGELOG, Vorlagen, CONTRIBUTING/SECURITY/SUPPORT. **Code-Kommentare und Tool-Beschreibungen bleiben deutsch** (nicht übersetzen). `README.md` ist Englisch, `README.de.md` Deutsch; `docs/TOOLS.md` ist generiert (`uv run python scripts/gen_tool_reference.py` nach jeder Tool-Änderung, Test prüft das); neue Tools brauchen einen Eintrag in `rights.TOOL_RIGHTS`.

## Was das ist
Plattform-MCP-Server für AVM FRITZ!Box mit **FRITZ!OS 8**, Python ≥3.12, `uv`, offizielles MCP-SDK (`mcp` 2.x, `MCPServer`), `fritzconnection` für TR-064, `httpx` für Web/REST. Privates Repo `tomwellnitz/fritzos8-mcp`, MIT-Lizenz.

Drei Schichten:
1. **TR-064** (offiziell): generisch über SCPD (`tr064_list_services`, `tr064_describe_action`, `tr064_call` – nur lesend + Denylist) und kuratierte Tools.
2. **Smart Home** über das dokumentierte AHA-HTTP-Interface (`/webservices/homeautoswitch.lua`, SID als Query-Parameter) – `smarthome.py`. Die neuere Smart-Home-REST-API (FRITZ!OS 8.2) ist noch nicht umgesetzt.
3. **`/api/v0`** (inoffizielle REST der Web-UI): Geräte/landevice. Header `AUTHORIZATION: AVM-SID <sid>`.

## Stand (14.11.2026)
- **Stufe 1 fertig** (Geräte & Netz). Siehe README, ROADMAP.md, CHANGELOG.md.
- **Stufe 2 gebaut** (WLAN/Gast, Smart Home via AHA, Diagnose/Security-Check), nur gegen Mocks getestet – **Live-Test ausstehend**. Unbelegte Annahmen: `X_AVM-DE_GetWLANExtInfo`/`APType` für die Gast-Erkennung, Band-Feld `FrequencyBand`, `X_AVM-DE_GetWPSInfo`-Feldnamen, `UserInterface:X_AVM-DE_GetInfo`, Portfreigaben aus der Web-UI im WAN-Portmapping, AHA-Antworten (kein DECT-Gerät an der Box).
- **Stufe 3 gebaut (14.11.)**, nur gegen Mocks getestet – **Live-Test ausstehend** (Reihenfolge in ROADMAP.md „Live zu prüfen“): Telefonie (`call_list`, `tam_list`, `phonebook_list`, `set_tam_enabled`), Kindersicherung (`internet_access_status`, `set_internet_access`), Portfreigaben (`list_port_forwards`, `add/delete_port_forward_plan/_execute` – critical), `get_dns_settings` (read). Unbelegte Annahmen: `<New>`-Semantik der AB-Liste, Feldwerte `NewDisallow`/`NewWANAccess`, Upstream-DNS-Actions `X_AVM-DE_GetDNSServer`/`X_AVM-DE_GetIPv6DNSServer`, `/api/v0/generic/dnscfg`+`/ipv6`-Felder, Fehlercode bei nicht erlaubten selbstständigen Portfreigaben. **DNS schreiben bewusst nicht gebaut** (kein belegter Endpunkt → erst Browser-Mitschnitt).
- **Live geprüft am 14.11.** (siehe docs/COMPATIBILITY.md): PBKDF2-Login, alle read-Tools, Denylist (GetSecurityKeys/Reboot abgelehnt), `rename_host` mit Rücklesen. Noch nicht live: `set_static_ip`, `delete_host`, critical-Tools, TR-064-2FA-Antwort. Live verifizierte `/api/v0`-Aufrufe (FRITZ!Box 7583, FRITZ!OS 8.26):
  - `GET /api/v0/generic/landevice`
  - `PUT /api/v0/generic/landevice/landevice/<UID>` mit `{"static_dhcp":"1"}` bzw. `{"friendly_name":"…"}`
  - `DELETE /api/v0/generic/landevice/landevice/<UID>`
  - TR-064 `Hosts:1 X_AVM-DE_SetHostNameByMACAddress`, `LANHostConfigManagement:1 GetDNSServer`
- **Zwei Gerätenamen:** TR-064-Hostname und `friendly_name` (zeigt die Web-UI). `rename_host` muss beide setzen.
- Ein eigener TypeScript-Vorgänger läuft lokal parallel, bis dieser Server live geprüft ist (Details in `CLAUDE.local.md`).
- **Stufe 4 in Arbeit (14.11.)**, nur gegen Mocks getestet – Live-Test ausstehend (ROADMAP „Live zu prüfen (Stufe 4)“): Aufräum-Assistent (`devices_cleanup_*`, OUI-Cache unter `~/.cache/fritzos8-mcp`), Schnappschüsse (`snapshot_*`, lokal unter `~/.local/state/fritzos8-mcp/<host>/snapshots`), `wake_on_lan`, `mesh_overview`, `online_monitor`, `vpn_status`. Mehrbox (`FRITZ_BOXES`, Parameter `box`, `boxes_overview`, `compare_boxes`, `scripts/fritzos8-mcp-multi-start.sh`), MCP-Prompts/-Ressourcen, `network_doctor`, Sicherheits-Score. Unbelegt: Log-Muster des Netz-Doktors, `BeaconType`-Werte für WPA3, Gast-Isolierungs-/Auto-Update-Feldwerte, Mesh-JSON-Felder/Einheiten, Einheit von `ds_current_bps`, DDNS-Feldnamen, „zuletzt online“-Feld der landevice-Antwort.
- **Stufe 5 gemergt** (NAS & Fernzugang), Stufe 4/5 teils live geprüft.
- **Stufe 6 gebaut (14.11.)**, nur gegen Mocks getestet – **Live-Test ausstehend** (ROADMAP „Live zu prüfen (Stufe 6)“): `lan_ports`, `set_lan_eee`, `vpn_connections`, `powerline_status`, `box_speedtest_info`/`_run`, `device_connection_quality`, `test_my_device`, Netz-Doktor-Checks (Flapping, Pi+EEE, DNS-SPOF). Code in `connectivity.py` (+ `lanports.py`, `vpnplc.py`, `speedtest.py`, `quality.py`, `clienttest.py`). Live belegt per Browser-Mitschnitt (7583/8.26): `GET eth_ports`, `PUT eth_ports/eth/<UID>` (Body NICHT mitgeschnitten), `eee_mode` 0/2, `GET vpn`, `GET plc`. **`/api/v0/generic/vpn` liefert Schlüssel im Klartext → `RestClient` schwärzt jede `/api/v0`-Antwort (`redact_api`); nie umgehen.** Unbelegt: Green-Mode-Wert (daher kein `set_lan_power_mode`), LAN-Log-Muster, Mesh-Interface-Namen `LAN:n`, Einheit `SignalStrength`/PLC-PHY-Raten, Verhalten des Box-Speedtest-Servers.
- **Stufe 7 gebaut (14.11.) ohne 7.2/7.3**, nur gegen Mocks getestet – **Live-Test ausstehend** (ROADMAP „Live zu prüfen (Stufe 7)“): `guard.py` (BoxGuard je Box unter Tr064Client/RestClient/AhaClient: Drosselung, Cache 15 s, Leerung nach jedem Schreiben, Backoff nur für Lesen, Schutzschalter; Status in `server_status.box_protection`), `wlan_settings`/`set_wlan_channel` (wlan.py `WlanSettings`), Kindersicherung `parental_*`/`set_parental_profile` (parental.py), Elicitation vor jedem critical-`*_execute` (confirm.py, SDK-Resolver; Token bleibt Fallback), `outputSchema` (schemas.py, `OUTPUT_MODELS`). Neue Tools in `server.py` mit dem `tool`-Decorator registrieren: critical-`*_plan`/`*_execute` bekommen Plan-Zusammenfassung bzw. Rückfrage automatisch; Tools in `OUTPUT_MODELS` bekommen ihr Schema automatisch. **Schreibzugriffe nie am Guard vorbei** (sonst wird der Cache nicht geleert). Unbelegt: Autokanal-Argumentname, NightControl-XML, Hüllelement/Einheiten der Filterprofile. 7.2/7.3: erst Browser-Mitschnitt (Checkliste in ROADMAP).
- **Stufe 8 gebaut (14.11.)**, nur gegen Mocks getestet – **Live-Test ausstehend** (ROADMAP „Live-Prüfpunkte (Stufe 8)“): neue Module `devices.py` (8.11), `history.py` (8.1, Collector `fritzos8-collector`), `line.py` (8.9), `ispreport.py` (8.2), `alerts.py` (8.3), `transparency.py` (8.12), `phone.py`/`phonewrite.py` (8.10/8.8), `family.py` (8.7), `smarthome_rest.py` (8.5a/b), `fritzcode.py` (8.6, PyYAML), `guestwifi.py` (8.4, Opt-in-Stufe `secrets` = `FRITZ_ALLOW_SECRETS`, optional `segno`). Gemeinsame Arg-Typen in `toolargs.py`. Lokale Dateien unter `~/.local/state/fritzos8-mcp/<box>/` (history.sqlite, alarms.json, guest_session.json, reports/, qr/; Sollzustände in `desired/`). WAN-Dienst jetzt TR-064 vor IGD (`connection.source`), IGD-eigene Actions über `Tr064Client.call_igd_first`. **`redact_api` maskiert jetzt auch Smart-Home-Standort/Geofencing, `recipient`, Pairing-Codes, `httpRequest`-Objekte; Alarm-Kanäle (`FRITZ_ALERT_*`) zählen zu den Secrets.**
- **AVM-Doku-Abgleich (14.11.):** `docs/COVERAGE.md` (Matrix je Action/Endpunkt) + PLAN „Verifikation gegen AVM-Doku“. Korrigiert: `GetDDNSInfo`, `X_AVM_DE_GetDNSServer`/`…IPv6DNSServer` (IGD, Unterstriche), `NewX_AVM-DE_UserIsolation`/`NoForcedOff`, `X_AVM-DE_BuildType`; Denylist/Schwärzung ergänzt (SIP-Kontenliste, Repeater-Token, PPP-/TR-069-/Mobilfunk-Benutzer, IMSI). Offen: V-6 (64-bit-Zähler nur in IGD), V-7 (`WANIPConn1` ist IGD-ID, TR-064 = `WANIPConnection1`), V-8 (TR-064-Portfreigabe nur für den eigenen Rechner). **Neue Tools: COVERAGE-Zeile nachziehen; Actions mit mehreren Schreibweisen über `Tr064Client.call_first` (Doku-Name zuerst).**
- **Stufe 10 gebaut (14.11.)** und **Stufe 9 lokal vorbereitet** (nur Mocks; Live-Prüfpunkte in ROADMAP „Stufe 10“, Live-Lesetest-Befunde dort eingearbeitet): neue Module `anomaly.py`, `optimizer.py`, `mqttbridge.py` (Extra `mqtt`), `httpserve.py` (HTTP mit Pflicht-Token), `anonymize.py`, `syswrite.py` (Firmware/Routen/Pinholes/2FA), `smarthome_config.py`, `rights.py`, `setupcheck.py`, `toolref.py`. Veröffentlichung (Repo, PyPI, Docker, HA-Add-on, Tags) nur mit Toms Freigabe – `scripts/make_public_snapshot.sh` erzeugt den sauberen Stand lokal.
- **Öffentlich-Vorbereitung (14.11.):** private Daten aus versionierten Dateien entfernt (Beispiel-IPs 192.0.2.x/198.51.100.x/2001:db8::, MACs AA:BB:CC…). Alte Commits enthalten sie noch → vor Veröffentlichung Historie bereinigen bzw. neues Repo mit sauberem Initial-Commit (ROADMAP).

## Nächste Schritte
1. ✅ Eingebunden (14.11.) als MCP in der User-Konfig, **nur lesend** (Befehl in `CLAUDE.local.md`). Für Schreibrechte neu registrieren mit `-e FRITZ_ALLOW_WRITE=1` vor `--` (nur nach Toms Freigabe).
2. ✅ Live-Lesetest und ✅ Umbenennung hin/zurück (14.11.).
3. Offen live: `set_static_ip` (z. B. an einem Gerät, das schon fest ist → muss „unchanged“ melden), `delete_host` an einem echten Altgerät nach Toms Freigabe.
4. Offene, ungeprüfte Annahmen verifizieren: Denylist für Credential-liefernde TR-064-Actions, TR-064-Antwort bei 2FA (Codes 866/867/868), Reconnect-Nachweis.
5. Stufe 2 live prüfen (erst read-Tools, dann `set_guest_wifi` hin/zurück nach Toms Freigabe), danach den alten Vorgänger-MCP entfernen.
6. Stufe 3 live prüfen (erst read-Tools, dann Schreiben nach Freigabe, siehe ROADMAP); DNS/DNSv6-Schreibweg per Browser-Mitschnitt belegen, erst dann bauen.
7. Den automatisch geöffneten Renovate-PR mit Tom klären (Details lokal).
8. Stufe 4 live prüfen (Reihenfolge in ROADMAP „Live zu prüfen (Stufe 4)“).
9. Stufe 6 live prüfen (ROADMAP „Live zu prüfen (Stufe 6)“) – zuerst `vpn_connections` auf Schlüsselreste, dann `set_lan_eee` hin/zurück nach Freigabe.
10. Stufe 7 live prüfen (ROADMAP „Live zu prüfen (Stufe 7)“) – zuerst Box-Schutz an Box B, dann Schema-Warnungen im Log, Elicitation-Ablehnung; Mitschnitt-Session für 7.2/7.3 mit Tom.
11. Stufe 8 live prüfen (ROADMAP „Live-Prüfpunkte (Stufe 8)“) – erst alle read-Tools an beiden Boxen, dann Schreiben einzeln nach Freigabe.

## Netz / Box
- Zwei Testboxen: **Box A** FRITZ!Box 7583 (FRITZ!OS 8.26, DSL) und **Box B** FRITZ!Box 6660 Cable (FRITZ!OS 8.25, an Box B ein DECT-Heizkörperthermostat). Adressen, Schlüsselbund-Einträge und Gerätedetails: `CLAUDE.local.md`.
- Schreibtests an Smart-Home-Geräten nur nach Toms Freigabe, immer zurückstellen.
- Einstellungen wie DNS/DNSv6 verlangen eine **Zusatzbestätigung** (Authenticator-App/FRITZ!-Taste) – die macht nur Tom.
- **Keine privaten Daten in versionierte Dateien** (IPs, MACs, AINs, Geräte-/Raum-/Standortnamen, Schlüsselbund-Namen): in Tests/Doku nur Beispielwerte (192.0.2.x, 198.51.100.x, 2001:db8::, AA:BB:CC…, „Wohnzimmer“, „Box A/B“).

## Harte Regeln
- **Kein Passwort sehen, eingeben oder loggen.** Zugangsdaten nur über Schlüsselbund → Startskript → Umgebung (`FRITZ_HOST`, `FRITZ_USER`, `FRITZ_PASSWORD`/`FRITZ_PASSWORD_FILE`). Nie als CLI-Argument.
- **Schreib-/kritische Aktionen gegen die echte Box nur nach Toms ausdrücklicher Freigabe.** Neustart/Reconnect/Werksreset/Löschen nie eigenmächtig.
- Geräte nie per Browser-Schleife umbenennen (am 14.11. ging das schief: SPA lud asynchron, Namen landeten beim falschen Gerät). Immer per MAC über den MCP, danach gegenprüfen.
- **Commits: Englisch, Conventional Commits** (`feat:`, `fix:`, `docs:`, `refactor:`, `perf:`, `test:`, `build:`, `ci:`, `chore:`, `revert:`, `style:`; `!`/`BREAKING CHANGE:` für Breaking Changes) – geprüft vom commit-msg-Hook und (PR-Titel, Squash-Merge) in CI.
- **Commits, PRs, Issues: KEINE Co-Authored-By-Zeilen, KEINE Hinweise auf Claude/AI** (Toms ausdrücklicher Wunsch).
- **Versionen/CHANGELOG nie von Hand ändern, keine Tags pushen:** release-please pflegt Version (pyproject, `__init__`, uv.lock, HA-Add-on) und `CHANGELOG.md` über den Release-PR; Release → PyPI (Trusted Publishing, nur mit `PUBLISH_PYPI=true`) + GHCR.
- Fremdcode nur aus MIT-Quellen übernehmen und in NOTICE vermerken (Schimmilab, gr9driver, the78mole, fritzconnection). Kein Code aus dimitree2k, maxmeis, ghbalf (keine Lizenzdatei), kambriso (proprietär) oder Meine-smarte-Welt/fritzbox_netzwerk (MIT nur im README, keine Lizenzdatei – nur als Endpunkt-Hinweis genutzt).
- Rufnummern (Anrufliste/AB) dürfen in Tool-Ausgaben stehen, aber nie in Logs.
- `/api/v0` ist undokumentiert: bei 404/403 klar „Firmware/Recht nicht unterstützt“ melden, nie still scheitern; jeder Schreibvorgang wird zurückgelesen (`verified`).

## Entwicklung
```bash
make setup    # einmalig: uv sync (alle Extras/Gruppen), pre-commit-Hooks (pre-commit, commit-msg, pre-push), .private-patterns
make check    # alles wie CI: ruff, mypy, pytest, TOOLS.md/COVERAGE-Checks, mkdocs --strict, uv build + twine check
make help     # weitere Targets (format, docs-serve, docker, audit, snapshot …)
```
- Hooks: `.pre-commit-config.yaml` (ruff, mypy, gitleaks, Privatdaten-Hook `scripts/check_private_data.py` mit Mustern aus `.private-patterns`/`CLAUDE.local.md`, pre-push: pytest + Doku-Checks). Hooks nie mit `--no-verify` umgehen.
- CI: `.github/workflows/` – `ci.yml` (Jobs lint, typecheck, test (py3.12/3.13, 3.14 informativ), docs, package, docker), `pr-title.yml`, `security.yml` (pip-audit, gitleaks), `codeql.yml`/`dependency-review.yml`/`scorecard.yml` (nur öffentliches Repo), `release-please.yml`, `release.yml`. Alle Actions auf Commit-SHA gepinnt (Versionskommentar), Dependabot hält sie aktuell.
- Repo-Einstellungen als Code: `scripts/github_setup.sh OWNER/REPO` (Standard Dry-Run; `--apply` nur mit Toms Freigabe).
- Öffentlicher Stand: `make snapshot` (= `scripts/make_public_snapshot.sh`) → Ein-Commit-Repo `../fritzos8-mcp-public` mit Privatdaten-Prüfung.

## Referenzdokumente (lokal, nicht im Repo)
Offizielle AVM-Schnittstellendokumente (TR-064-Services, AHA-HTTP-Interface, Session-ID/Login, Smart-Home-REST-API FRITZ!OS 8.2 und 8.5, Mesh-Topologie, IGD) liegen unter `docs/vendor/avm/` (55 Dateien, Stand 2026-11-14, gitignored wegen AVM-Urheberrecht). Neu laden: Links von https://fritz.com/pages/schnittstellen. Bei neuen Tools zuerst dort Action-/Argumentnamen belegen.
