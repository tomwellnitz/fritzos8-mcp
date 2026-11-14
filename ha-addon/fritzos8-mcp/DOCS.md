# FRITZ!OS 8 MCP – Home-Assistant-Add-on

Läuft den `fritzos8-collector` (Messreihe alle `interval_s` Sekunden, nur lesend) und veröffentlicht Werte und Alarme per **MQTT-Discovery** – mit dem Mosquitto-Add-on erscheinen die Entitäten automatisch (Gerät „FRITZ!Box default“). Optional startet es zusätzlich den MCP-Server über **Streamable HTTP** (Port 8765, Endpunkt `/mcp`, Bearer-Token Pflicht) – nur im Heimnetz oder über VPN nutzen, nie per Portfreigabe.

1. In der FRITZ!Box einen eigenen Benutzer anlegen (Rechte siehe `docs/TOOLS.md`), TR-064 „Zugriff für Anwendungen“ aktivieren.
2. Adresse, Benutzer, Passwort eintragen, starten. Passwörter liegen nur in `/data` des Add-ons (Rechte 600).
3. Für HTTP-MCP: `mcp_http` an, Token mit `fritzos8-mcp --generate-token` erzeugen und eintragen, Port 8765 freigeben.

Details: `docs/home-assistant.md`, `docs/remote.md` im Repository.
