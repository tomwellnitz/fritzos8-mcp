# fritzos8-mcp

[![CI](https://github.com/tomwellnitz/fritzos8-mcp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tomwellnitz/fritzos8-mcp/actions/workflows/ci.yml)
[![CodeQL](https://github.com/tomwellnitz/fritzos8-mcp/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/tomwellnitz/fritzos8-mcp/actions/workflows/codeql.yml)
[![PyPI](https://img.shields.io/pypi/v/fritzos8-mcp)](https://pypi.org/project/fritzos8-mcp/)
[![Python versions](https://img.shields.io/pypi/pyversions/fritzos8-mcp)](https://pypi.org/project/fritzos8-mcp/)
[![License: MIT](https://img.shields.io/github/license/tomwellnitz/fritzos8-mcp)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/tomwellnitz/fritzos8-mcp/badge)](https://scorecard.dev/viewer/?uri=github.com/tomwellnitz/fritzos8-mcp)

**English** · [Deutsch](README.de.md)

<!-- mcp-name: io.github.tomwellnitz/fritzos8-mcp -->

**Let your AI assistant run your FRITZ!Box – safely.** An [MCP](https://modelcontextprotocol.io) server for AVM FRITZ!Box routers on FRITZ!OS 8: diagnose slow internet, audit security, clean up the device list, manage guest Wi-Fi, telephony and smart home – read-only by default, and every change is verified.

![Demo: network doctor, security check and the plan → token → execute safety model](https://raw.githubusercontent.com/tomwellnitz/fritzos8-mcp/main/docs/demo.gif)

## What you can ask

> **"Why is my internet slow tonight?"**
> Runs the network doctor: line values (SNR margin, errors, resyncs), event log, Wi-Fi and mesh, LAN link flapping, DNS as a single point of failure – and returns findings with severity, likely cause and what to do.

> **"How secure is my FRITZ!Box?"**
> Security check with a 0–100 score: remote access, MyFRITZ!, port forwards, WPS, Wi-Fi encryption, guest isolation, firmware, DNS over TLS – each finding with the exact menu path to fix it.

> **"Clean up devices that haven't been online for three months."**
> Finds candidates (long offline, random MACs, duplicates, orphaned static IPs), suggests better names via vendor lookup, shows you the plan and changes nothing until you confirm.

> **"Turn on guest Wi-Fi for two hours."** · **"Boost the living room heating for 30 minutes."** · **"Block this spam number."**
> Write actions – each one is read back from the box and reported as `verified: true` or `false`.

## Features

- **Diagnostics** – network doctor, line diagnostics for DSL, cable, fibre and LTE, per-device connection quality, link-flapping detection, system transparency (TR-069, NTP, IPv6/DS-Lite)
- **Security** – scored security check, two-factor status, firmware and update overview for all AVM devices
- **Devices** – both device names (TR-064 and web UI), rename, static IP, clean-up assistant, snapshots with diff, Wake-on-LAN, mesh and LAN ports
- **Wi-Fi & family** – Wi-Fi channels and settings, guest Wi-Fi with time limit, access profiles, tickets, internet block per device
- **Telephony** – call list with reverse lookup, answering machines, phone books, call deflection and barring, alarm clocks
- **Smart home** – thermostats, switches, blinds, energy report, routines, holiday periods (REST API, AHA fallback)
- **Monitoring** – optional collector for a local measurement series, ISP fault reports, anomaly detection, alerts via webhook, ntfy or Telegram
- **Multi-box** – manage several boxes from one server, with a family-admin report across all of them

About 160 tools in total – see the generated **[tool reference](docs/TOOLS.md)**.

## Quick start

**1. Prepare the box.** Enable *Home Network › Network › Network Settings › Allow access for applications* and create a dedicated user under *System › FRITZ!Box Users*.

**2. Store the password** in your OS keychain (or use `FRITZ_PASSWORD_FILE` with mode `600`):

```bash
uvx --from 'fritzos8-mcp[keyring]' keyring set fritzos8-mcp <user>
```

**3. Add the server to your client** – Claude Code shown, JSON config for Claude Desktop, Cursor and others in [configuration](docs/configuration.md#client-setup):

```bash
claude mcp add fritzos8 -s user -e FRITZ_HOST=fritz.box -e FRITZ_USER=<user> -- \
  uvx --from 'fritzos8-mcp[keyring]' fritzos8-mcp
```

**4. Ask your assistant to run `setup_check`.** It verifies TR-064, the user's rights and two-factor settings, and tells you which tools a missing right would disable.

The server starts **read-only**. Enable changes with `FRITZ_ALLOW_WRITE=1`, critical actions additionally with `FRITZ_ALLOW_CRITICAL=1`.

## Safety model

| Tier | Enabled by | What it allows |
|---|---|---|
| `read` | always | read-only tools |
| `write` | `FRITZ_ALLOW_WRITE=1` | changes – each one is read back and reports `verified` |
| `critical` | `+ FRITZ_ALLOW_CRITICAL=1` | reboot, port forwards, firmware update, … only via **plan → one-time token → execute**, plus a yes/no prompt in clients that support it |

- **Never claims success it didn't see.** If the result can't be read back, you get `verified: false`.
- **Never bypasses two-factor confirmation.** If the box asks for it, the tool reports `confirmation_required` and explains how to confirm.
- **Never shows secrets.** Passwords, Wi-Fi keys, PINs, session IDs and VPN keys are redacted from every output, error and log line.
- **Protects the box.** Throttling, caching and a circuit breaker per box; `server_status` shows the health of each interface (last success/error, re-logins) even when the client still shows the server as connected.

Details: [SECURITY.md](SECURITY.md).

## Works with

- **Boxes:** FRITZ!OS 8 – tested on FRITZ!Box 7583 (DSL) and 6660 Cable. Reports for other models are welcome: [compatibility](docs/COMPATIBILITY.md).
- **Clients:** any MCP client – Claude Code, Claude Desktop, Cursor, VS Code, …
- **Interfaces:** TR-064 (via [fritzconnection](https://github.com/kbr/fritzconnection)), the AHA and Smart Home REST APIs, and the web UI's `/api/v0` – the latter only where TR-064 can't help.
- **Language:** tool descriptions and messages are in German; assistants handle them fine in any conversation language.

**Not a Home Assistant replacement.** For HA entities use the official *AVM FRITZ!Box Tools*, *FRITZ!SmartHome* and *Call Monitor* integrations. This server is for AI assistants – diagnostics, audits and guarded changes. Alerts can be sent to a Home Assistant webhook.

## Documentation

| | |
|---|---|
| [Configuration](docs/configuration.md) | permissions, all environment variables, multiple boxes, client setup |
| [Tool reference](docs/TOOLS.md) | every tool with tier, required right and parameters |
| [Remote access](docs/remote.md) | Streamable HTTP with bearer token, e.g. on a Raspberry Pi |
| [Interface coverage](docs/COVERAGE.md) | what is covered against the official AVM documentation |
| [Compatibility](docs/COMPATIBILITY.md) · [Fixtures](docs/fixtures.md) | tested models, contributing anonymized box answers |

## Contributing

Bug reports, compatibility reports and pull requests are welcome – see [CONTRIBUTING.md](CONTRIBUTING.md). `make setup` installs everything including the git hooks; tests run against mocks only, no box required.

## License

[MIT](LICENSE). Parts are adapted from MIT-licensed projects, see [NOTICE](NOTICE).

Independent project, not affiliated with AVM / FRITZ! GmbH. FRITZ!Box and FRITZ!OS are trademarks of FRITZ! GmbH. The `/api/v0` endpoints are undocumented and may change with firmware updates; affected tools then report `unsupported_firmware`.
