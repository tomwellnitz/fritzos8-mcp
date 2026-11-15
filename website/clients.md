# MCP-Clients

Kurzfassung der englischen Anleitung [docs/clients.md](https://github.com/tomwellnitz/fritzos8-mcp/blob/main/docs/clients.md) – dort stehen alle Blöcke je Client, Docker und HTTP. Formate geprüft gegen die offiziellen Dokus der Clients, Stand November 2026.

Platzhalter: `<user>` = FRITZ!Box-Benutzer, `<you>` = eigenes Betriebssystem-Konto, `~` = Home-Verzeichnis (Windows `%USERPROFILE%`).

## Claude Desktop – Ein-Klick-Bundle (.mcpb)

Jedes Release enthält ein [MCP Bundle](https://github.com/modelcontextprotocol/mcpb) für Claude Desktop (macOS, Windows, Linux-Beta) – ohne Terminal, ohne uv-Installation, ohne Konfigurationsdatei.

1. Box vorbereiten: TR-064 erlauben, eigenen Benutzer anlegen (siehe [Schnellstart](quickstart.md)).
2. `fritzos8-mcp-<version>.mcpb` aus dem [neuesten Release](https://github.com/tomwellnitz/fritzos8-mcp/releases/latest) laden.
3. Datei öffnen (Doppelklick) – Claude Desktop zeigt den Installationsdialog. Alternativ in den Erweiterungs-Einstellungen von Claude Desktop über *Advanced settings › Install Extension…* (englische Oberfläche).
4. Felder ausfüllen: Adresse (Standard `fritz.box`), Benutzer, Passwort, optional *Allow changes* (`FRITZ_ALLOW_WRITE`) und *Allow critical actions* (`FRITZ_ALLOW_CRITICAL`, nur zusammen mit Schreiben).
5. Claude `setup_check` ausführen lassen.

Das Passwortfeld ist im Manifest als `sensitive` markiert. Laut [Claude-Hilfe](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop) verschlüsselt Claude Desktop solche Werte mit dem Schlüsselspeicher des Betriebssystems (macOS: Schlüsselbund, Windows: Anmeldeinformationsverwaltung, Linux: Schlüsselbund der Distribution) und übergibt sie beim Start als Umgebungsvariable `FRITZ_PASSWORD`.

Das Bundle enthält den Quellcode samt `uv.lock` (Server-Typ `uv`); Claude Desktop startet es mit `uv run --frozen --no-dev` und lädt dabei uv, Python ≥ 3.12 und genau die gesperrten Abhängigkeiten selbst. Der erste Start braucht deshalb Internet und etwas länger. Aktualisieren: das `.mcpb` des neueren Releases installieren. Windows auf ARM: Scheitert der uv-Download mit einem Prüfsummenfehler ([mcpb#203](https://github.com/modelcontextprotocol/mcpb/issues/203)), uv systemweit installieren (`winget install --id=astral-sh.uv -e`).

Alles Weitere auf dieser Seite gilt für die manuelle Einrichtung und andere Clients.

## Voraussetzungen

**uv installieren** (bringt `uvx` mit und lädt Python bei Bedarf selbst):

| System | Befehl |
|---|---|
| macOS | `brew install uv` oder Installer: `curl -LsSf https://astral.sh/uv/install.sh` an `sh` übergeben |
| Linux | Installer wie oben |
| Windows | `winget install --id=astral-sh.uv -e` oder PowerShell-Installer `install.ps1` von astral.sh |

Prüfen: `uvx fritzos8-mcp --version`. GUI-Clients sehen den PATH der Shell oft nicht (macOS nie) – dann den vollen Pfad als `command` eintragen (`which uvx` bzw. `where.exe uvx`; in JSON Backslashes verdoppeln: `C:\\Users\\<you>\\.local\\bin\\uvx.exe`).

## Passwort ablegen

Nie in die Client-Konfiguration und nie als Argument.

```bash
uvx --from 'fritzos8-mcp[keyring]' keyring set fritzos8-mcp <user>
```

(Windows: doppelte Anführungszeichen.) Der Server liest Dienst `fritzos8-mcp` (änderbar mit `FRITZ_KEYRING_SERVICE`), Konto zuerst `<user>@<host>`, dann `<user>` – nur mit dem Extra `fritzos8-mcp[keyring]`. macOS: Schlüsselbund, Windows: Anmeldeinformationsverwaltung, Linux: Secret Service über D-Bus (laufender, entsperrter Anbieter wie GNOME Keyring nötig; auf Servern ohne Desktop meist nicht vorhanden).

Alternative `FRITZ_PASSWORD_FILE`: Datei nur mit dem Passwort, `chmod 600` (macOS/Linux) bzw. unter Windows `icacls <datei> /inheritance:r /grant:r "%USERNAME%:F"`. Die Schlüsselbund-Startskripte unter `scripts/` funktionieren nur unter macOS.

## Eintrag je Client

Alle Clients starten denselben Befehl: `uvx --from fritzos8-mcp[keyring] fritzos8-mcp` mit `FRITZ_HOST=fritz.box` und `FRITZ_USER=<user>`.

| Client | Datei / Befehl | Schlüssel |
|---|---|---|
| Claude Code | `claude mcp add fritzos8 -s user -e FRITZ_HOST=fritz.box -e FRITZ_USER=<user> -- uvx --from 'fritzos8-mcp[keyring]' fritzos8-mcp` | – |
| Claude Desktop | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows `%APPDATA%\Claude\claude_desktop_config.json`, Linux (Beta) `~/.config/Claude/claude_desktop_config.json` | `mcpServers` |
| Cursor | `~/.cursor/mcp.json` oder `.cursor/mcp.json` | `mcpServers` |
| VS Code (Copilot) | `~/.copilot/mcp-config.json` oder `.mcp.json` im Workspace (`.vscode/mcp.json` ist abgekündigt) | `mcpServers` |
| Windsurf | macOS/Linux `~/.config/devin/mcp_config.json`, Windows `%APPDATA%\devin\mcp_config.json` | `mcpServers` |
| Zed | macOS/Linux `~/.config/zed/settings.json`, Windows `%APPDATA%\Zed\settings.json` | `context_servers` |
| Cline | `~/.cline/data/settings/cline_mcp_settings.json` | `mcpServers` |
| Continue | `~/.continue/config.yaml` (nur Agent-Modus) | `mcpServers` (Liste) |
| Codex CLI | `~/.codex/config.toml` oder `codex mcp add` | `[mcp_servers.fritzos8]` |
| Gemini CLI | `~/.gemini/settings.json` | `mcpServers` |
| LM Studio (ab 0.3.17) | in der App: *Program › Install › Edit mcp.json* | `mcpServers` |

Typischer JSON-Eintrag:

```json
{
  "mcpServers": {
    "fritzos8": {
      "command": "uvx",
      "args": ["--from", "fritzos8-mcp[keyring]", "fritzos8-mcp"],
      "env": { "FRITZ_HOST": "fritz.box", "FRITZ_USER": "<user>" }
    }
  }
}
```

Docker (Passwort als eingebundene Datei, das Image hat keinen Schlüsselbund) und HTTP mit Token je Client: siehe englische Fassung und [Fernverwaltung](remote.md). Claude Desktop kann einen Server im Heimnetz nicht per HTTP erreichen – dort stdio verwenden.

## Fehlersuche

- **`uvx` nicht gefunden:** vollen Pfad als `command`, Client komplett neu starten.
- **„Kein Passwort“:** Eintrag für Dienst `fritzos8-mcp` / Konto `<user>` fehlt, Extra `[keyring]` fehlt oder `FRITZ_USER` weicht ab. Server zum Test im Terminal starten (`FRITZ_HOST=fritz.box FRITZ_USER=<user> uvx --from 'fritzos8-mcp[keyring]' fritzos8-mcp`) – Fehler stehen auf stderr.
- **Linux-Schlüsselbund:** `keyring --list-backends` zeigt nur `fail.Keyring` → kein Secret Service erreichbar; `FRITZ_PASSWORD_FILE` verwenden.
- **Server erscheint nicht:** JSON prüfen (kein Komma am Ende), richtigen Schlüssel verwenden, Client neu starten, MCP-Log lesen.
- **Verbunden:** den Assistenten `server_status` und `setup_check` ausführen lassen.
