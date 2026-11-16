#!/bin/zsh
# Startet fritzos8-mcp für MEHRERE FRITZ!Boxen in einer Instanz. Zugangsdaten kommen je Box aus dem
# macOS-Schlüsselbund und gehen nur per Umgebung an den Server – nie als Kommandozeilenargument.
#
#   Aufruf:   fritzos8-mcp-multi-start.sh [--collector] <name>=<host>:<schluesselbund-dienst> [...]
#   Beispiel: fritzos8-mcp-multi-start.sh heim=192.0.2.1:fritzos8-mcp-heim zweit=198.51.100.1:fritzos8-mcp-zweit
#
# --collector startet statt des Servers die Messreihe fritzos8-collector (immer nur lesend, Intervall
# FRITZ_HISTORY_INTERVAL, Standard 300 s) – z. B. als launchd-Dienst, siehe docs/configuration.md.
#
# Die erste Box ist Standard für alle Tools (Parameter box=<name> wählt eine andere).
# Schlüsselbund-Einträge einmalig im eigenen Terminal anlegen (fragt das Passwort interaktiv ab):
#   security add-generic-password -s <schluesselbund-dienst> -a <fritzbox-benutzer> -w
#
# Stufen gelten für alle Boxen und werden über die Umgebung durchgereicht, z. B.:
#   claude mcp add ... -e FRITZ_ALLOW_WRITE=1 -- /pfad/zu/fritzos8-mcp-multi-start.sh heim=...
set -eu

PROGRAMM=fritzos8-mcp
if [ "${1:-}" = "--collector" ]; then
  PROGRAMM=fritzos8-collector
  shift
fi
if [ $# -lt 1 ]; then
  echo "Aufruf: $0 [--collector] <name>=<host>:<schluesselbund-dienst> [...]" >&2
  exit 64
fi
REPO="${0:A:h:h}"
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH"

NAMEN=()
for SPEC in "$@"; do
  NAME="${SPEC%%=*}"; REST="${SPEC#*=}"
  HOST="${REST%%:*}"; DIENST="${REST#*:}"
  if [ "$NAME" = "$SPEC" ] || [ "$HOST" = "$REST" ] || [ -z "$NAME" ] || [ -z "$HOST" ] || [ -z "$DIENST" ]; then
    echo "Ungültige Angabe '$SPEC' – Format <name>=<host>:<schluesselbund-dienst>" >&2
    exit 64
  fi
  if ! [[ "$NAME" =~ '^[a-z0-9][a-z0-9_-]{0,31}$' ]]; then
    echo "Ungültiger Boxname '$NAME' (erlaubt: a–z 0–9 _ -)" >&2
    exit 64
  fi
  BENUTZER=$(security find-generic-password -s "$DIENST" 2>/dev/null | sed -n 's/^ *"acct"<blob>="\(.*\)"$/\1/p')
  PASSWORT=$(security find-generic-password -s "$DIENST" -w 2>/dev/null) || true
  if [ -z "${BENUTZER:-}" ] || [ -z "${PASSWORT:-}" ]; then
    echo "Kein Schlüsselbund-Eintrag '$DIENST' (Box '$NAME'). Anlegen mit: security add-generic-password -s $DIENST -a <benutzer> -w" >&2
    exit 1
  fi
  PREFIX="FRITZ_${${NAME:u}//[^A-Z0-9]/_}_"
  export "${PREFIX}HOST=$HOST" "${PREFIX}USER=$BENUTZER" "${PREFIX}PASSWORD=$PASSWORT"
  unset PASSWORT
  NAMEN+=("$NAME")
done

export FRITZ_BOXES="${(j:,:)NAMEN}"
unset FRITZ_HOST FRITZ_USER FRITZ_PASSWORD FRITZ_PASSWORD_FILE
exec uv run --directory "$REPO" --frozen --quiet "$PROGRAMM"
