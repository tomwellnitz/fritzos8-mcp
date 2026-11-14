#!/usr/bin/with-contenv bashio
# Startet den Collector (Messreihe + MQTT-Discovery) und optional den MCP-Server über HTTP mit Token.
set -e
export FRITZ_HOST="$(bashio::config 'fritz_host')"
export FRITZ_USER="$(bashio::config 'fritz_user')"
umask 077
bashio::config 'fritz_password' > /data/fritz_password
export FRITZ_PASSWORD_FILE=/data/fritz_password
export FRITZ_STATE_DIR=/data/state FRITZ_CACHE_DIR=/data/cache
export FRITZ_HISTORY_INTERVAL="$(bashio::config 'interval_s')"
export FRITZ_HISTORY_DAYS="$(bashio::config 'history_days')"
if bashio::config.true 'alerts'; then export FRITZ_ALERTS_IN_COLLECTOR=1; fi

if bashio::services.available "mqtt"; then
  export FRITZ_MQTT_HOST="$(bashio::services mqtt 'host')"
  export FRITZ_MQTT_PORT="$(bashio::services mqtt 'port')"
  export FRITZ_MQTT_USER="$(bashio::services mqtt 'username')"
  bashio::services mqtt 'password' > /data/mqtt_password
  export FRITZ_MQTT_PASSWORD_FILE=/data/mqtt_password
else
  bashio::log.warning "Kein MQTT-Broker gefunden – Messreihe läuft nur lokal."
fi

if bashio::config.true 'mcp_http'; then
  if ! bashio::config.has_value 'mcp_http_token'; then
    bashio::exit.nok "mcp_http ist an, aber mcp_http_token fehlt (mind. 32 Zeichen)."
  fi
  bashio::config 'mcp_http_token' > /data/http_token
  if bashio::config.true 'allow_write'; then export FRITZ_ALLOW_WRITE=1; fi
  FRITZ_TRANSPORT=http FRITZ_HTTP_HOST=0.0.0.0 FRITZ_HTTP_TOKEN_FILE=/data/http_token fritzos8-mcp &
fi

exec fritzos8-collector
