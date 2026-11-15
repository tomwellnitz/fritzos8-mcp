# Configuration

Everything the [README](../README.md) leaves out: requirements on the box, permissions, all environment variables, multi-box mode and client setup.

## Requirements on the FRITZ!Box

- **FRITZ!OS 8.x.** Tested on a FRITZ!Box 7583 (8.26) and a 6660 Cable (8.25); more models in [COMPATIBILITY.md](COMPATIBILITY.md). TR-064 tools also work on older firmware, the REST-based tools do not.
- **Home Network › Network › Network Settings:** enable *Allow access for applications* (TR-064).
- If **two-factor confirmation** is active for the user, the box rejects or silently discards some changes. The server then reports `confirmation_required` instead of pretending success; `two_factor_status` explains the state.
- Port forwarding needs *Allow independent port sharing for this device* on the target device; IPv6 pinholes need *Allow changes to security settings via UPnP*.

## Permissions

Create a dedicated user under *System › FRITZ!Box Users* with only the rights you need. The *Right* column in [TOOLS.md](TOOLS.md) names the right per tool (`rights.py`, checked against the AVM documentation).

| Right on the box | Code | Needed for |
|---|---|---|
| FRITZ!Box settings | `settings` | everything via `/api/v0` (device list, static IP, LAN ports, VPN …), diagnostics, most write tools; includes `app` |
| Restricted FRITZ!Box settings for apps | `app` | parental control, Wi-Fi / guest Wi-Fi / WPS, NAS info, line values, device and update overview |
| Voice messages, fax messages, FRITZ!App Fon and call list | `phone` | call list, answering machines, phone books, deflections, call barring, alarm clocks |
| Dialing aid | `dial` | `dial_number_*`, `dial_hangup` |
| Smart Home | `smarthome` | all `smarthome_*` tools (pairing and renaming also need `app`) |
| Access to NAS contents | `nas` | currently not required by any tool |

`setup_check` reads the user's actual rights and lists the affected tools for every missing one. For read-only use without `/api/v0` the `app` right is often enough; REST tools then report `permission_denied`.

## Environment variables

Secrets are read from the environment, a file or the OS keychain – never from command-line arguments.

| Variable | Default | Meaning |
|---|---|---|
| `FRITZ_HOST` | `fritz.box` | host name or IP of the box |
| `FRITZ_USER` | – | FRITZ!Box user (required) |
| `FRITZ_PASSWORD` / `FRITZ_PASSWORD_FILE` | – | password, or path to a file (mode `600`) containing only the password |
| `FRITZ_KEYRING_SERVICE` | `fritzos8-mcp` | keychain service used when no password is given; account `<user>@<host>` or `<user>` (extra `keyring`) |
| `FRITZ_ALLOW_WRITE` | off | `1` enables the `write` tier |
| `FRITZ_ALLOW_CRITICAL` | off | `1` additionally enables the `critical` tier (requires `FRITZ_ALLOW_WRITE`) |
| `FRITZ_ALLOW_SECRETS` | off | `1` enables the `secrets` tier (only `guest_wifi_qr`: the key exists only inside the local QR image) |
| `FRITZ_BOXES` | – | multi-box mode, see below |
| `FRITZ_USE_TLS` | off | `1` = HTTPS / TR-064 over TLS (self-signed box certificate, not verified) |
| `FRITZ_TIMEOUT` | `15` | request timeout in seconds (greater than 0, at most 300) |
| `FRITZ_REDACT_SERIALS` | off | `1` also masks serial numbers, IMEI/ICCID, UDN/UUID |
| `FRITZ_STATE_DIR` | `~/.local/state/fritzos8-mcp` | snapshots, measurement series, alarms, reports (0700/0600) |
| `FRITZ_SNAPSHOT_KEEP` | `30` | snapshots kept per box |
| `FRITZ_CACHE_DIR` | `~/.cache/fritzos8-mcp` | cache (OUI registry) |
| `FRITZ_OUI_DOWNLOAD` | on | `0` = never download the IEEE OUI registry |
| `FRITZ_CODE_DIR` | `<state>/desired` | "FRITZ as code" desired-state files |
| `FRITZ_TEST_DOWNLOAD_URL` | Cloudflare speed test | download URL for `test_my_device` (`{bytes}` placeholder) |

**Box protection** (also per box as `FRITZ_<NAME>_…`):

| Variable | Default | Meaning |
|---|---|---|
| `FRITZ_MAX_PARALLEL` | `2` | concurrent requests per box |
| `FRITZ_RATE_LIMIT` / `FRITZ_BURST` | `8` / `4` | requests per second (0 = off) and burst |
| `FRITZ_CACHE_TTL` | `15` | seconds expensive reads are cached (0 = off) |
| `FRITZ_RETRIES` | `1` | retries of read requests after a timeout |
| `FRITZ_BREAKER_THRESHOLD` / `FRITZ_BREAKER_COOLDOWN` | `3` / `30` | pause for *cooldown* seconds after *threshold* consecutive connection errors |

**Measurement series and alerts** (`fritzos8-collector`):

| Variable | Default | Meaning |
|---|---|---|
| `FRITZ_HISTORY_INTERVAL` | `300` | seconds between measurements (min. 30) |
| `FRITZ_HISTORY_DAYS` | `30` | retention in days |
| `FRITZ_ALERTS_IN_COLLECTOR` | off | `1` = check alerts after every measurement |
| `FRITZ_ALERT_WEBHOOK` / `FRITZ_ALERT_NTFY` | – | webhook URL (e.g. Home Assistant) / ntfy topic URL – treated as secrets |
| `FRITZ_ALERT_TELEGRAM_TOKEN` / `FRITZ_ALERT_TELEGRAM_CHAT` | – | alerts via Telegram bot |
| `FRITZ_ALERT_REPEAT_H` | `24` | repeat an active alert at most every N hours |

**Transport and experimental integrations:**

| Variable | Default | Meaning |
|---|---|---|
| `FRITZ_TRANSPORT` / `--http` | stdio | `http` = Streamable HTTP, only with a bearer token (`FRITZ_HTTP_TOKEN` / `_TOKEN_FILE` / keychain), bind `FRITZ_HTTP_HOST` (`127.0.0.1`), port `FRITZ_HTTP_PORT` (`8765`) – see [remote.md](remote.md) |
| `FRITZ_MQTT_HOST` (+ `_PORT`, `_USER`, `_PASSWORD[_FILE]`, `_TLS`, `_DISCOVERY_PREFIX`, `_BASE_TOPIC`) | – | experimental MQTT discovery from the collector, see [home-assistant.md](home-assistant.md) |

## Multiple boxes

Without `FRITZ_BOXES` the single-box settings above apply (box name `default`). With `FRITZ_BOXES=home,cabin` the server reads `FRITZ_<NAME>_HOST`, `_USER`, `_PASSWORD` / `_PASSWORD_FILE` (optionally `_USE_TLS`, `_TIMEOUT`) per box – `<NAME>` upper-case, `-` becomes `_`. The tier switches apply to all boxes, the first box is the default, and plan tokens are only valid on the box they were planned on. Every tool takes an optional `box` parameter.

## Client setup

Installation (uv), password storage per OS and copy-ready entries for Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Zed, Cline, Continue, Codex CLI, Gemini CLI, LM Studio, Docker and the HTTP transport on macOS, Windows and Linux: [clients.md](clients.md).

**macOS keychain helper scripts (macOS only).** `scripts/fritzos8-mcp-start.sh` and `scripts/fritzos8-mcp-multi-start.sh` read user and password from the macOS keychain (`security add-generic-password -s <service> -a <user> -w`) and pass them to the server through the environment only:

```bash
claude mcp add fritzos8 -s user -- scripts/fritzos8-mcp-start.sh 192.0.2.1 fritzos8-mcp-home
claude mcp add fritzos8 -s user -- scripts/fritzos8-mcp-multi-start.sh \
  home=192.0.2.1:fritzos8-mcp-home cabin=198.51.100.1:fritzos8-mcp-cabin
```

Check the connection with `server_status` (active tiers) and `setup_check`.

## Two names per device

The box keeps two names per device: the **TR-064 host name** (`name`) and the **display name** shown in the web UI (`friendly_name`, writable only via `/api/v0`). `rename_host` sets both, reads both back and reports each step. If a MAC matches several entries, it refuses before writing – pass the `uid` from `list_landevices` instead.

## Error types

Every failure is returned as `{"ok": false, "error": {"type", "message", "hint"}}` with one of: `auth_error`, `permission_denied`, `confirmation_required`, `connection_error` (also: circuit breaker open), `declined` (rejected in the client), `not_found`, `unsupported_firmware` (404 on `/api/v0`), `invalid_parameter`, `tier_disabled`, `action_denied`, `plan_error`.
