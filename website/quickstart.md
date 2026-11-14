# Schnellstart

## 1. Benutzer in der FRITZ!Box

1. **Heimnetz > Netzwerk > Netzwerkeinstellungen:** „Zugriff für Anwendungen zulassen“ (TR-064) aktivieren.
2. **System > FRITZ!Box-Benutzer:** eigenen Benutzer für den MCP-Server anlegen. Welche Rechte welches Tool braucht, steht in der [Tool-Referenz](tools.md) (Spalte „Recht“); zum Lesen genügt meist „FRITZ!Box Einstellungen“ oder das App-Recht.

## 2. Passwort ablegen

```bash
uvx --from 'fritzos8-mcp[keyring]' keyring set fritzos8-mcp <benutzer>
```

(oder `FRITZ_PASSWORD_FILE` auf eine Datei mit Rechten `600`).

## 3. Einbinden (Claude Code)

```bash
claude mcp add fritzos8 -s user \
  -e FRITZ_HOST=fritz.box -e FRITZ_USER=<benutzer> -- uvx fritzos8-mcp
```

Danach `setup_check` aufrufen: prüft TR-064, Rechte, Zusatzbestätigung und Erreichbarkeit der Schnittstellen und sagt, welche Tools wegen fehlender Rechte nicht funktionieren.

## 4. Schreiben freischalten (optional)

`-e FRITZ_ALLOW_WRITE=1` (Schreib-Tools mit Rücklesen) und zusätzlich `-e FRITZ_ALLOW_CRITICAL=1` (Neustart, Portfreigaben, Firmware-Update … nur über Plan/Token).
