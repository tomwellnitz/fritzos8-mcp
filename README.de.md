# fritzos8-mcp

[![CI](https://github.com/tomwellnitz/fritzos8-mcp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tomwellnitz/fritzos8-mcp/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/fritzos8-mcp)](https://pypi.org/project/fritzos8-mcp/)
[![License: MIT](https://img.shields.io/github/license/tomwellnitz/fritzos8-mcp)](LICENSE)

[English](README.md) · **Deutsch**

**Lass deinen KI-Assistenten die FRITZ!Box verwalten – sicher.** Ein [MCP](https://modelcontextprotocol.io)-Server für AVM FRITZ!Boxen mit FRITZ!OS 8: langsames Internet diagnostizieren, Sicherheit prüfen, die Geräteliste aufräumen, Gast-WLAN, Telefonie und Smart Home steuern – standardmäßig nur lesend, und jede Änderung wird nachgeprüft.

![Demo: Netz-Doktor, Sicherheits-Check und das Sicherheitsmodell Plan → Token → Ausführen](docs/demo.gif)

## Was du fragen kannst

> **„Warum ist mein Internet heute Abend so langsam?"**
> Der Netz-Doktor prüft Leitungswerte (SNR-Marge, Fehler, Resyncs), Ereignisprotokoll, WLAN und Mesh, LAN-Link-Flapping und DNS als Single Point of Failure – und liefert Befunde mit Schweregrad, wahrscheinlicher Ursache und Empfehlung.

> **„Wie sicher ist meine FRITZ!Box?"**
> Sicherheits-Check mit Score 0–100: Fernzugriff, MyFRITZ!, Portfreigaben, WPS, WLAN-Verschlüsselung, Gast-Isolierung, Firmware, DNS over TLS – je Befund mit dem genauen Menüpfad zur Behebung.

> **„Räum Geräte auf, die seit drei Monaten nicht mehr online waren."**
> Findet Kandidaten (lange offline, Zufalls-MACs, Duplikate, verwaiste feste IPs), schlägt bessere Namen per Hersteller-Erkennung vor, zeigt dir den Plan und ändert nichts, bevor du zustimmst.

> **„Schalte das Gast-WLAN für zwei Stunden ein."** · **„Boost im Wohnzimmer für 30 Minuten."** · **„Sperr diese Spam-Nummer."**
> Schreibaktionen – jede wird an der Box zurückgelesen und als `verified: true` oder `false` gemeldet.

## Funktionen

- **Diagnose** – Netz-Doktor, Leitungsdiagnose für DSL, Kabel, Glasfaser und LTE, Verbindungsqualität je Gerät, Link-Flapping-Erkennung, System-Transparenz (TR-069, NTP, IPv6/DS-Lite)
- **Sicherheit** – Sicherheits-Check mit Score, 2FA-Status, Firmware- und Update-Übersicht aller AVM-Geräte
- **Geräte** – beide Gerätenamen (TR-064 und Web-UI), Umbenennen, feste IP, Aufräum-Assistent, Schnappschüsse mit Vergleich, Wake-on-LAN, Mesh und LAN-Ports
- **WLAN & Familie** – WLAN-Kanäle und -Einstellungen, Gast-WLAN mit Zeitlimit, Zugangsprofile, Tickets, Internetsperre je Gerät
- **Telefonie** – Anrufliste mit Rückwärtssuche, Anrufbeantworter, Telefonbücher, Rufumleitung und -sperre, Weckrufe
- **Smart Home** – Thermostate, Schalter, Rollos, Energiebericht, Routinen, Urlaubsschaltung (REST-API, AHA als Rückfall)
- **Überwachung** – optionaler Collector für eine lokale Messreihe, Störungsprotokoll für den Provider, Anomalie-Erkennung, Alarme per Webhook, ntfy oder Telegram
- **Mehrere Boxen** – mehrere Boxen aus einem Server, mit Familien-Admin-Bericht über alle

Rund 160 Tools – siehe die generierte **[Tool-Referenz](docs/TOOLS.md)**.

## Schnellstart

**1. Box vorbereiten.** *Heimnetz › Netzwerk › Netzwerkeinstellungen › Zugriff für Anwendungen zulassen* aktivieren und unter *System › FRITZ!Box-Benutzer* einen eigenen Benutzer anlegen.

**2. Passwort im Schlüsselbund ablegen** (oder `FRITZ_PASSWORD_FILE` mit Rechten `600`):

```bash
uvx --from 'fritzos8-mcp[keyring]' keyring set fritzos8-mcp <benutzer>
```

**3. Server im Client eintragen** – hier Claude Code; JSON-Konfiguration für Claude Desktop, Cursor und andere unter [Konfiguration](docs/configuration.md#client-setup):

```bash
claude mcp add fritzos8 -s user -e FRITZ_HOST=fritz.box -e FRITZ_USER=<benutzer> -- \
  uvx --from 'fritzos8-mcp[keyring]' fritzos8-mcp
```

**4. Den Assistenten `setup_check` ausführen lassen.** Er prüft TR-064, die Rechte des Benutzers und die 2FA-Einstellung und nennt die Tools, die ein fehlendes Recht abschaltet.

Der Server startet **nur lesend**. Änderungen schaltet `FRITZ_ALLOW_WRITE=1` frei, kritische Aktionen zusätzlich `FRITZ_ALLOW_CRITICAL=1`.

## Sicherheitsmodell

| Stufe | Freischaltung | Was sie erlaubt |
|---|---|---|
| `read` | immer | nur lesende Tools |
| `write` | `FRITZ_ALLOW_WRITE=1` | Änderungen – jede wird zurückgelesen und meldet `verified` |
| `critical` | `+ FRITZ_ALLOW_CRITICAL=1` | Neustart, Portfreigaben, Firmware-Update … nur über **Plan → Einmal-Token → Ausführen**, dazu eine Ja/Nein-Rückfrage in Clients, die das können |

- **Behauptet nie einen Erfolg, den es nicht gesehen hat.** Lässt sich das Ergebnis nicht zurücklesen, kommt `verified: false`.
- **Umgeht nie die Zusatzbestätigung (2FA).** Verlangt die Box sie, meldet das Tool `confirmation_required` und erklärt, wie man bestätigt.
- **Zeigt nie Geheimnisse.** Passwörter, WLAN-Schlüssel, PINs, Session-IDs und VPN-Schlüssel werden in jeder Ausgabe, Fehlermeldung und Logzeile geschwärzt.
- **Schont die Box.** Drosselung, Cache und Schutzschalter je Box; `server_status` zeigt die Gesundheit jeder Schnittstelle (letzter Erfolg/Fehler, Neuanmeldungen), auch wenn der Client den Server noch als verbunden anzeigt.

Details: [SECURITY.md](SECURITY.md).

## Läuft mit

- **Boxen:** FRITZ!OS 8 – getestet mit FRITZ!Box 7583 (DSL) und 6660 Cable. Berichte zu weiteren Modellen sind willkommen: [Kompatibilität](docs/COMPATIBILITY.md).
- **Clients:** jeder MCP-Client – Claude Code, Claude Desktop, Cursor, VS Code, …
- **Schnittstellen:** TR-064 (über [fritzconnection](https://github.com/kbr/fritzconnection)), AHA- und Smart-Home-REST-API sowie `/api/v0` der Web-Oberfläche – Letzteres nur, wo TR-064 nicht reicht.

**Kein Ersatz für Home Assistant.** Für HA-Entitäten die offiziellen Integrationen *AVM FRITZ!Box Tools*, *FRITZ!SmartHome* und *Anrufmonitor* nutzen. Dieser Server ist für KI-Assistenten – Diagnose, Prüfungen und abgesicherte Änderungen. Alarme lassen sich an einen Home-Assistant-Webhook schicken.

## Dokumentation

| | |
|---|---|
| [Konfiguration](docs/configuration.md) | Rechte, alle Umgebungsvariablen, mehrere Boxen, Client-Einrichtung (Englisch) |
| [Tool-Referenz](docs/TOOLS.md) | jedes Tool mit Stufe, benötigtem Recht und Parametern |
| [Fernzugriff](docs/remote.md) | Streamable HTTP mit Bearer-Token, z. B. auf einem Raspberry Pi |
| [Abdeckung](docs/COVERAGE.md) | Abdeckung gegenüber der offiziellen AVM-Dokumentation |
| [Kompatibilität](docs/COMPATIBILITY.md) · [Fixtures](docs/fixtures.md) | getestete Modelle, anonymisierte Box-Antworten beitragen |

## Mitmachen

Fehlerberichte, Kompatibilitätsberichte und Pull Requests sind willkommen – siehe [CONTRIBUTING.md](CONTRIBUTING.md) (Issues gern auch auf Deutsch). `make setup` richtet alles inklusive Git-Hooks ein; die Tests laufen nur gegen Mocks, eine Box ist nicht nötig.

## Lizenz

[MIT](LICENSE). Teile stammen aus MIT-lizenzierten Projekten, siehe [NOTICE](NOTICE).

Unabhängiges Projekt, nicht mit AVM / FRITZ! GmbH verbunden. FRITZ!Box und FRITZ!OS sind Marken der FRITZ! GmbH. Die `/api/v0`-Endpunkte sind undokumentiert und können sich mit Firmware-Updates ändern; betroffene Tools melden dann `unsupported_firmware`.
