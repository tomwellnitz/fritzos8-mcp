#!/bin/zsh
# Startet fritzos8-mcp für EINE FRITZ!Box. Die Zugangsdaten kommen aus dem macOS-Schlüsselbund,
# nicht aus der Claude-Konfiguration und nie als Kommandozeilenargument an den Server.
#
#   Aufruf:  fritzos8-mcp-start.sh <host> <schluesselbund-dienst>
#   Beispiel: fritzos8-mcp-start.sh 192.0.2.1 fritzos8-mcp-heim
#
# Eintrag einmalig im eigenen Terminal anlegen (fragt das Passwort interaktiv ab):
#   security add-generic-password -s <schluesselbund-dienst> -a <fritzbox-benutzer> -w
#
# Stufen werden über die Umgebung durchgereicht, z. B. in Claude Code:
#   claude mcp add ... -e FRITZ_ALLOW_WRITE=1 -- /pfad/zu/fritzos8-mcp-start.sh <host> <dienst>
set -eu

if [ $# -ne 2 ]; then
  echo "Aufruf: $0 <host> <schluesselbund-dienst>" >&2
  exit 64
fi
HOST="$1"; DIENST="$2"
REPO="${0:A:h:h}"
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH"

BENUTZER=$(security find-generic-password -s "$DIENST" 2>/dev/null | sed -n 's/^ *"acct"<blob>="\(.*\)"$/\1/p')
PASSWORT=$(security find-generic-password -s "$DIENST" -w 2>/dev/null) || true
if [ -z "${BENUTZER:-}" ] || [ -z "${PASSWORT:-}" ]; then
  echo "Kein Schlüsselbund-Eintrag '$DIENST'. Anlegen mit: security add-generic-password -s $DIENST -a <benutzer> -w" >&2
  exit 1
fi

export FRITZ_HOST="$HOST" FRITZ_USER="$BENUTZER" FRITZ_PASSWORD="$PASSWORT"
unset PASSWORT
exec uv run --directory "$REPO" --frozen --quiet fritzos8-mcp
