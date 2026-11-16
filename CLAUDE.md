# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## fritzos8-mcp

Kontext für Agenten, die an diesem Repo arbeiten. **Lokale, private Details (Boxen, IPs, Schlüsselbund-Einträge, Testgeräte, Registrierungsbefehle) stehen in `CLAUDE.local.md` (gitignored) – nie in versionierte Dateien übernehmen.** Sprache mit Tom: Deutsch. **Projekt-Kommunikation auf Englisch:** Commits, PR-Titel/-Texte, Issues, CHANGELOG, Vorlagen, CONTRIBUTING/SECURITY/SUPPORT. **Code-Kommentare und Tool-Beschreibungen bleiben deutsch** (nicht übersetzen). `README.md` ist Englisch, `README.de.md` Deutsch; `docs/TOOLS.md` ist generiert (`uv run python scripts/gen_tool_reference.py` nach jeder Tool-Änderung, Test prüft das); neue Tools brauchen einen Eintrag in `rights.TOOL_RIGHTS`.

**Projektstand, unbelegte Annahmen und offene Live-Prüfpunkte stehen in `ROADMAP.md`** (Abschnitt „Projektstand & Live-Prüfung“ und je Stufe), live geprüfte Modelle/Firmware in `docs/COMPATIBILITY.md`, die Abdeckung je Action/Endpunkt in `docs/COVERAGE.md`, Paketplanung in `docs/PLAN.md`.

## Was das ist
Plattform-MCP-Server für AVM FRITZ!Box mit **FRITZ!OS 8**, Python ≥3.12, `uv`, offizielles MCP-SDK (`mcp` 2.x, `MCPServer`), `fritzconnection` für TR-064, `httpx` für Web/REST. Öffentliches Repo `tomwellnitz/fritzos8-mcp` (öffentlich seit 14.11.2026), MIT-Lizenz.

Drei Schichten:
1. **TR-064** (offiziell): generisch über SCPD (`tr064_list_services`, `tr064_describe_action`, `tr064_call` – nur lesend + Denylist) und kuratierte Tools.
2. **Smart Home** über das dokumentierte AHA-HTTP-Interface (`/webservices/homeautoswitch.lua`, SID als Query-Parameter) – `smarthome.py`; dazu die Smart-Home-REST-API (FRITZ!OS 8.2+) in `smarthome_rest.py`/`smarthome_config.py`.
3. **`/api/v0`** (inoffizielle REST der Web-UI): Geräte/landevice, LAN-Ports, VPN, Powerline u. a. Header `AUTHORIZATION: AVM-SID <sid>`.

## Architektur (Überblick über mehrere Dateien)
- **Einstieg:** `fritzos8_mcp:main` (`__init__.py`) → `config.load_all()` (eine oder mehrere Boxen aus `FRITZ_*`/`FRITZ_BOXES`) → je Box ein `FritzService` → `server.build_server(services, gate, secrets)`. stdio standardmäßig, HTTP (`httpserve.py`) nur mit Pflicht-Token. Logging geht auf stderr durch `RedactingFilter` (stdout gehört dem MCP-Protokoll). Weitere Einstiegspunkte: `fritzos8-collector` (`history.py`, Messreihe/Alarme/MQTT), `fritzos8-anonymize`.
- **Clients je Box:** `auth.SessionManager` (SID, PBKDF2-Login) → `tr064.Tr064Client` (fritzconnection), `rest.RestClient` (`/api/v0`), `smarthome.AhaClient`. Alle drei laufen über denselben `guard.BoxGuard` (Drosselung, 15-s-Cache, Leerung nach jedem Schreiben, Backoff nur für Lesen, Schutzschalter; Status in `server_status.box_protection`).
- **Fachlogik ohne MCP:** `service.FritzService` und die Fachmodule (`landevice.py`, `wlan.py`, `portforward.py`, `connectivity.py`, …) sind MCP-unabhängig und werden direkt unit-getestet. Gemeinsame Arg-Typen in `toolargs.py`.
- **Tool-Registrierung:** `build_server` definiert einen lokalen `tool(tier, annotations)`-Decorator. Die Kern-Tools stehen in `server.py`; neuere Module exportieren `register_<x>_tools(tool, svc)` und werden von `build_server` aufgerufen. Der Decorator registriert nur, wenn `security.Gate` die Stufe freigibt (`read` immer, `write` = `FRITZ_ALLOW_WRITE`, `critical` = zusätzlich `FRITZ_ALLOW_CRITICAL`, `secrets` = `FRITZ_ALLOW_SECRETS`). Außerdem: `_wrap` (FritzError → strukturierter, geschwärzter `ToolError`; jedes Ergebnis via `redact_obj`), bei critical `*_plan` → `with_plan_summary` und `*_execute` → `with_confirmation` (Elicitation, Token aus `PlanStore` als Fallback), bei Namen in `schemas.OUTPUT_MODELS` → `outputSchema`. Der optionale Parameter `box` wählt bei Mehrbox den Service.
- **Fehler:** `errors.py` (`FritzError`-Hierarchie mit `to_dict()`; u. a. `ConfirmationRequiredError` für 2FA, `UnsupportedFirmwareError` für 404/403 an `/api/v0`).
- **Lokale Dateien:** Zustand unter `~/.local/state/fritzos8-mcp/<box>/` (Schnappschüsse, `history.sqlite`, `alarms.json`, `guest_session.json`, `reports/`, `qr/`, Sollzustände in `desired/`), OUI-Cache unter `~/.cache/fritzos8-mcp`.
- **Checkliste neues Tool:** Action-/Argumentnamen zuerst in den AVM-Dokumenten belegen (siehe unten). Decorator mit passender Stufe/Annotation (`READ`/`WRITE`/`DESTRUCTIVE`), Eintrag in `rights.TOOL_RIGHTS`, Zeile in `docs/COVERAGE.md`, ggf. `OUTPUT_MODELS`, danach `uv run python scripts/gen_tool_reference.py` (erzeugt `docs/TOOLS.md`). Test dazu in `tests/test_<modul>.py` mit den Fakes aus `tests/conftest.py`.

## Feste Code-Regeln
- **Schreibzugriffe nie am Guard vorbei** – sonst wird der Cache nicht geleert und das Rücklesen sieht alte Werte.
- **`/api/v0`-Antworten werden im `RestClient` zentral geschwärzt (`redact_api`) – nie umgehen.** `/api/v0/generic/vpn` liefert Pre-Shared-Keys/WireGuard-Konfigurationen im Klartext. `redact_api` maskiert außerdem Smart-Home-Standort/Geofencing, `recipient`, Pairing-Codes und `httpRequest`-Objekte; Alarm-Kanäle (`FRITZ_ALERT_*`) und das HTTP-Token zählen zu den Secrets.
- **Zwei Gerätenamen:** TR-064-Hostname und `friendly_name` (zeigt die Web-UI). `rename_host` muss beide setzen.
- **Actions mit mehreren Schreibweisen** über `Tr064Client.call_first` (Doku-Name zuerst); IGD-eigene Actions über `Tr064Client.call_igd_first`. Beim WAN-Dienst gilt TR-064 vor IGD (`connection.source`). Schreibweisen unterscheiden sich oft nur in Bindestrich/Unterstrich (`X_AVM-DE_…` vs. IGD `X_AVM_DE_…`).
- **Credential-liefernde TR-064-Actions** stehen auf der Denylist in `security.py`; neue Actions mit Zugangsdaten, Tokens oder Schlüsseln dort ergänzen und in der Schwärzung abdecken.
- **Undokumentierte Schreibwege** (z. B. DNS/DNSv6, Portfreigaben über `/api/v0`, Green Mode) erst per Browser-Mitschnitt belegen, dann bauen. Unbelegte Annahmen im Code und in `ROADMAP.md` als solche kennzeichnen.

## Netz / Box
- Zwei Testboxen: **Box A** FRITZ!Box 7583 (FRITZ!OS 8.26, DSL) und **Box B** FRITZ!Box 6660 Cable (FRITZ!OS 8.25, an Box B ein DECT-Heizkörperthermostat). Adressen, Schlüsselbund-Einträge und Gerätedetails: `CLAUDE.local.md`.
- Schreibtests an Smart-Home-Geräten nur nach Toms Freigabe, immer zurückstellen.
- Einstellungen wie DNS/DNSv6 verlangen eine **Zusatzbestätigung** (Authenticator-App/FRITZ!-Taste) – die macht nur Tom.
- **Keine privaten Daten in versionierte Dateien** (IPs, MACs, AINs, Geräte-/Raum-/Standortnamen, Schlüsselbund-Namen): in Tests/Doku nur Beispielwerte (192.0.2.x, 198.51.100.x, 2001:db8::, AA:BB:CC…, „Wohnzimmer“, „Box A/B“).

## Harte Regeln
- **Kein Passwort sehen, eingeben oder loggen.** Zugangsdaten nur über Schlüsselbund → Startskript → Umgebung (`FRITZ_HOST`, `FRITZ_USER`, `FRITZ_PASSWORD`/`FRITZ_PASSWORD_FILE`). Nie als CLI-Argument.
- **Schreib-/kritische Aktionen gegen die echte Box nur nach Toms ausdrücklicher Freigabe.** Neustart/Reconnect/Werksreset/Löschen nie eigenmächtig. Der MCP ist in Claude Code nur lesend eingebunden; Schreibrechte (`FRITZ_ALLOW_WRITE=1`) nur nach Toms Freigabe.
- Geräte nie per Browser-Schleife umbenennen (am 14.11. ging das schief: SPA lud asynchron, Namen landeten beim falschen Gerät). Immer per MAC über den MCP, danach gegenprüfen.
- **Commits: Englisch, Conventional Commits** (`feat:`, `fix:`, `docs:`, `refactor:`, `perf:`, `test:`, `build:`, `ci:`, `chore:`, `revert:`, `style:`; `!`/`BREAKING CHANGE:` für Breaking Changes) – geprüft vom commit-msg-Hook und (PR-Titel, Squash-Merge) in CI.
- **Commits, PRs, Issues: KEINE Co-Authored-By-Zeilen, KEINE Hinweise auf Claude/AI** (Toms ausdrücklicher Wunsch).
- **Versionen/CHANGELOG nie von Hand ändern, keine Tags pushen:** release-please pflegt Version (pyproject, `__init__`, uv.lock, HA-Add-on) und `CHANGELOG.md` über den Release-PR; Release → PyPI (Trusted Publishing, nur mit `PUBLISH_PYPI=true`) + GHCR. Weitere Veröffentlichungsschritte (Docker, HA-Add-on, Registry-Einträge) nur mit Toms Freigabe.
- Fremdcode nur aus MIT-Quellen übernehmen und in NOTICE vermerken (Schimmilab, gr9driver, the78mole, fritzconnection). Kein Code aus dimitree2k, maxmeis, ghbalf (keine Lizenzdatei), kambriso (proprietär) oder Meine-smarte-Welt/fritzbox_netzwerk (MIT nur im README, keine Lizenzdatei – nur als Endpunkt-Hinweis genutzt).
- Rufnummern (Anrufliste/AB) dürfen in Tool-Ausgaben stehen, aber nie in Logs.
- `/api/v0` ist undokumentiert: bei 404/403 klar „Firmware/Recht nicht unterstützt“ melden, nie still scheitern; jeder Schreibvorgang wird zurückgelesen (`verified`).

## Entwicklung
```bash
make setup    # einmalig: uv sync (alle Extras/Gruppen), pre-commit-Hooks (pre-commit, commit-msg, pre-push), .private-patterns
make check    # alles wie CI: ruff, mypy, pytest, TOOLS.md/COVERAGE-Checks, mkdocs --strict, uv build + twine check
make help     # weitere Targets (format, docs-serve, docker, audit, snapshot …)
make lint / make typecheck / make test / make docs-check   # Einzelschritte von make check

uv run --frozen pytest tests/test_guard.py                 # eine Testdatei
uv run --frozen pytest tests/test_guard.py -k breaker      # einzelne Tests per Namensfilter
make test-live   # opt-in, nur lesend gegen eine echte Box (FRITZ_LIVE_TEST=1 + FRITZ_HOST/USER/PASSWORD_FILE) – nur nach Absprache mit Tom
```
- `make test` läuft ausschließlich gegen Fakes (`tests/conftest.py`, `tests/fixtures_api.py`); kein Test spricht mit einer echten Box. mypy läuft strict, ruff mit Zeilenlänge 120.
- Hooks: `.pre-commit-config.yaml` (ruff, mypy, gitleaks, Privatdaten-Hook `scripts/check_private_data.py` mit Mustern aus `.private-patterns`/`CLAUDE.local.md`, pre-push: pytest + Doku-Checks). Hooks nie mit `--no-verify` umgehen.
- CI: `.github/workflows/` – `ci.yml` (Jobs lint, typecheck, test (py3.12/3.13, 3.14 informativ), docs, package, docker), `pr-title.yml`, `security.yml` (pip-audit, gitleaks), `codeql.yml`/`dependency-review.yml`/`scorecard.yml`, `release-please.yml`, `release.yml`, `cflite-pr.yml`/`cflite-batch.yml` (ClusterFuzzLite: atheris-Targets in `fuzz/`, Build in `.clusterfuzzlite/`; Funde → eigener `fix:`-PR mit Regressionstest). Alle Actions auf Commit-SHA gepinnt (Versionskommentar), Dependabot hält sie aktuell.
- Repo-Einstellungen als Code: `scripts/github_setup.sh OWNER/REPO` (Standard Dry-Run; `--apply` nur mit Toms Freigabe).
- `make snapshot` (= `scripts/make_public_snapshot.sh`) erzeugt ein Ein-Commit-Repo `../fritzos8-mcp-public` mit Privatdaten-Prüfung.

## Referenzdokumente (lokal, nicht im Repo)
Offizielle AVM-Schnittstellendokumente (TR-064-Services, AHA-HTTP-Interface, Session-ID/Login, Smart-Home-REST-API FRITZ!OS 8.2 und 8.5, Mesh-Topologie, IGD) liegen unter `docs/vendor/avm/` (gitignored wegen AVM-Urheberrecht). Neu laden: Links von https://fritz.com/pages/schnittstellen. Bei neuen Tools zuerst dort Action-/Argumentnamen belegen.
