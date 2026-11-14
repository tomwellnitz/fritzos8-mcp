# Sichere Fernverwaltung (HTTP-Transport)

Standardmäßig spricht `fritzos8-mcp` MCP über **stdio** – der Client startet den Server lokal. Für Familien-Admins, die mehrere Haushalte betreuen, kann der Server auch dauerhaft im Heimnetz laufen (z. B. auf einem Raspberry Pi) und über **Streamable HTTP** erreichbar sein.

## Grundsätze

- **Authentifizierung ist Pflicht.** Ohne Bearer-Token startet der HTTP-Transport nicht. Jede Anfrage braucht `Authorization: Bearer <token>`; falsche oder fehlende Tokens bekommen `401` ohne Details. Der Vergleich ist zeitkonstant.
- **Standardmäßig nur lokal:** Bind an `127.0.0.1`. Eine andere Adresse (z. B. `0.0.0.0`) erzeugt beim Start Warnungen.
- **Nie per Portfreigabe ins Internet.** Erreichbarkeit von außen nur über **VPN** (FRITZ!Box-WireGuard) oder einen **TLS-Reverse-Proxy** im Heimnetz. Ohne TLS geht das Token im Klartext über das Netz.
- Die Sicherheitsstufen gelten unverändert: Ohne `FRITZ_ALLOW_WRITE` bleibt der Server auch über HTTP rein lesend; kritische Aktionen laufen weiter nur über Plan → Token → Execute (und Elicitation, wenn der Client sie kann).

## Einrichten

```bash
# 1. Token erzeugen (einmalig) und sicher ablegen
fritzos8-mcp --generate-token > ~/.config/fritzos8/http-token && chmod 600 ~/.config/fritzos8/http-token
#    oder im Schlüsselbund (plattformübergreifend über keyring):
keyring set fritzos8-mcp http-token

# 2. Server starten
FRITZ_HOST=192.0.2.1 FRITZ_USER=mcp FRITZ_PASSWORD_FILE=~/.config/fritzos8/pw \
FRITZ_HTTP_TOKEN_FILE=~/.config/fritzos8/http-token \
fritzos8-mcp --http
```

| Variable | Standard | Bedeutung |
|---|---|---|
| `FRITZ_TRANSPORT` | `stdio` | `http` = Streamable HTTP (gleichbedeutend mit `--http`) |
| `FRITZ_HTTP_HOST` | `127.0.0.1` | Bind-Adresse; nicht-lokal nur hinter VPN/TLS-Proxy |
| `FRITZ_HTTP_PORT` | `8765` | Port; Endpunkt ist `/mcp` |
| `FRITZ_HTTP_TOKEN` / `FRITZ_HTTP_TOKEN_FILE` | – | Bearer-Token (≥ 32 Zeichen, Geheimnis – wird überall geschwärzt) |
| `FRITZ_HTTP_KEYRING_SERVICE` | `fritzos8-mcp` | Schlüsselbund-Dienst für das Token (Benutzer `http-token`), braucht `keyring` |
| `FRITZ_HTTP_ALLOWED_HOSTS` | – | DNS-Rebinding-Schutz bei nicht-lokalem Bind, z. B. `pi.fritz.box:8765,192.0.2.10:*` |
| `FRITZ_HTTP_TLS_CERT` / `FRITZ_HTTP_TLS_KEY` | – | TLS direkt im Server (sonst Reverse-Proxy) |

## Client anbinden

Claude Code (Beispiel):

```bash
claude mcp add --transport http fritzos8-remote http://127.0.0.1:8765/mcp \
  --header "Authorization: Bearer $(cat ~/.config/fritzos8/http-token)"
```

Andere Clients: Server-URL `…/mcp`, Header `Authorization: Bearer <token>`.

## Raspberry Pi im Heimnetz (Beispiel)

1. Pi mit fester IP in der FRITZ!Box (z. B. über `set_static_ip`).
2. Dienst als eigener Benutzer (systemd), Zugangsdaten in Dateien mit Rechten `600`:
   ```ini
   # /etc/systemd/system/fritzos8-mcp.service
   [Unit]
   Description=fritzos8-mcp (HTTP)
   After=network-online.target

   [Service]
   User=fritzos8
   Environment=FRITZ_HOST=192.0.2.1 FRITZ_USER=mcp
   Environment=FRITZ_PASSWORD_FILE=/home/fritzos8/.config/fritzos8/pw
   Environment=FRITZ_HTTP_TOKEN_FILE=/home/fritzos8/.config/fritzos8/http-token
   Environment=FRITZ_HTTP_HOST=0.0.0.0 FRITZ_HTTP_ALLOWED_HOSTS=pi.fritz.box:8765
   ExecStart=/home/fritzos8/.local/bin/uvx fritzos8-mcp --http
   Restart=on-failure

   [Install]
   WantedBy=multi-user.target
   ```
3. Von unterwegs: WireGuard-VPN der FRITZ!Box verbinden, dann `http://pi.fritz.box:8765/mcp` nutzen. Keine Portfreigabe für 8765 anlegen.
4. Optional TLS über einen Reverse-Proxy (Caddy/nginx) mit eigenem Zertifikat; dann `FRITZ_HTTP_HOST=127.0.0.1` und nur den Proxy nach außen (ins LAN) lauschen lassen.

## Was der HTTP-Transport bewusst nicht kann

- Keine Benutzerverwaltung/OAuth: ein Token pro Installation. Für mehrere Personen je Person einen eigenen Server bzw. Token verwenden und regelmäßig wechseln.
- Kein Schutz gegen jemanden, der das Token hat – es berechtigt zu allem, was die freigeschalteten Stufen erlauben.
