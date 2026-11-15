# Client setup

How to install `fritzos8-mcp` and add it to an MCP client on macOS, Windows and Linux. Formats were checked against each client's official documentation in November 2026 (source linked per client). Clients change their formats; if a block no longer works, the linked page is authoritative.

Placeholders: `<user>` is the FRITZ!Box user, `<you>` your operating system account. `~` is your home directory (`%USERPROFILE%` on Windows). `FRITZ_HOST` is `fritz.box` throughout; use the box's IP if that name does not resolve.

## Claude Desktop – one-click bundle (.mcpb)

Every release ships an [MCP Bundle](https://github.com/modelcontextprotocol/mcpb) for Claude Desktop (macOS, Windows, Linux beta). No terminal, no uv installation, no config file.

1. Prepare the box as described under [Prerequisites](#prerequisites) (step 1 only).
2. Download `fritzos8-mcp-<version>.mcpb` from the [latest release](https://github.com/tomwellnitz/fritzos8-mcp/releases/latest).
3. Open the file (double-click). Claude Desktop shows an install dialog. Alternatively: *Settings*, *Manage* next to *Extensions*, then *Advanced settings › Install Extension…* and pick the file.
4. Fill in the fields and enable the extension:

| Field | Default | Becomes |
|---|---|---|
| FRITZ!Box address | `fritz.box` | `FRITZ_HOST` |
| FRITZ!Box user (required) | – | `FRITZ_USER` |
| Password (required) | – | `FRITZ_PASSWORD` |
| Allow changes | off | `FRITZ_ALLOW_WRITE` |
| Allow critical actions | off | `FRITZ_ALLOW_CRITICAL` (only together with *Allow changes*) |

5. Ask Claude to run `setup_check`.

**Where the password goes.** The field is marked `sensitive` in the bundle manifest. According to the [Claude Help Center](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop), Claude Desktop encrypts such values with the operating system's secure storage – Keychain on macOS, Credential Manager on Windows, the distribution's keyring on Linux – and hands the value to the server as `FRITZ_PASSWORD` in its environment when it starts.

**How it runs.** The bundle contains this project's source and its `uv.lock` (server type `uv`, manifest version 0.4). Claude Desktop starts it with `uv run --frozen --no-dev fritzos8-mcp`, using an installed uv or one it downloads itself; uv fetches Python ≥ 3.12 and exactly the locked dependencies. The first start therefore needs internet access and takes a little longer; nothing is installed system-wide.

**Updates.** A bundle is pinned to its release. To update, install the `.mcpb` of the newer release.

**Known issue.** On Windows on ARM, older Claude Desktop versions failed to download uv with a checksum error ([mcpb#203](https://github.com/modelcontextprotocol/mcpb/issues/203)). Installing uv system-wide (`winget install --id=astral-sh.uv -e`) avoids the download.

Logs are in the same place as for the manual setup (see [Claude Desktop](#claude-desktop) below). Everything else on this page is for the manual setup and for other clients.

## Prerequisites

**1. The box.** Enable *Home Network › Network › Network Settings › Allow access for applications* and create a dedicated user under *System › FRITZ!Box Users*. Required rights: [configuration](https://github.com/tomwellnitz/fritzos8-mcp/blob/main/docs/configuration.md#permissions).

**2. uv.** The server is started with `uvx` (part of [uv](https://docs.astral.sh/uv/getting-started/installation/)). uv downloads a suitable Python by itself; no separate Python installation is needed.

macOS (Homebrew or the standalone installer):

```bash
brew install uv
# or
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Linux:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Windows (WinGet or the standalone installer in PowerShell):

```powershell
winget install --id=astral-sh.uv -e
# or
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

The standalone installer puts `uvx` into `~/.local/bin` (Windows: `C:\Users\<you>\.local\bin\uvx.exe`), Homebrew on Apple silicon into `/opt/homebrew/bin`. Open a new terminal afterwards and check:

```bash
uvx fritzos8-mcp --version
```

**3. The full path to `uvx`.** GUI clients often do not see the PATH of your shell (on macOS they never read `~/.zshrc`). If a client reports that `uvx` cannot be found, put the full path into `command`: `which uvx` on macOS/Linux, `where.exe uvx` on Windows.

## Store the password

The password never goes into a client configuration or onto a command line. The server reads it, in this order, from `FRITZ_PASSWORD`, from the file named in `FRITZ_PASSWORD_FILE`, or from the OS keychain.

### OS keychain (recommended)

```bash
uvx --from 'fritzos8-mcp[keyring]' keyring set fritzos8-mcp <user>
```

On Windows use double quotes: `uvx --from "fritzos8-mcp[keyring]" keyring set fritzos8-mcp <user>`. The command prompts for the password; uv may print a warning that `keyring` comes from a dependency, which is harmless.

What the server looks up (`config.py`): service `fritzos8-mcp` (override with `FRITZ_KEYRING_SERVICE`), account `<user>@<host>` first, then `<user>` – so `keyring set fritzos8-mcp <user>@192.0.2.1` stores a box-specific password if several boxes share the user name. The keychain is only used when the server is started with the `keyring` extra (`--from 'fritzos8-mcp[keyring]'`), as in all examples below.

| OS | Backend | Notes |
|---|---|---|
| macOS | Keychain | works out of the box |
| Windows | Credential Manager (Windows Credential Locker) | works out of the box |
| Linux | Secret Service via D-Bus | needs a running, unlocked Secret Service provider in your desktop session, e.g. GNOME Keyring. The KWallet backend needs `dbus-python`, which `uvx` does not install. On headless systems (servers, SSH sessions, containers) there is usually no Secret Service – use a password file instead. |

`uvx --from 'fritzos8-mcp[keyring]' keyring --list-backends` shows which backend is active (`fail.Keyring` means none is usable).

### Password file

A file that contains only the password (a trailing line break is ignored), readable only by you. Point `FRITZ_PASSWORD_FILE` at it.

macOS / Linux – the password is read without echo and does not land in the shell history:

```bash
mkdir -p ~/.config/fritzos8
( umask 077; printf 'FRITZ!Box password: '; IFS= read -rs pw; printf '%s\n' "$pw" > ~/.config/fritzos8/pw ); echo
chmod 600 ~/.config/fritzos8/pw
```

Windows (PowerShell) – create the file with an editor, save it as UTF-8 without BOM, then restrict it to your account:

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.config\fritzos8" | Out-Null
notepad "$env:USERPROFILE\.config\fritzos8\pw"
icacls "$env:USERPROFILE\.config\fritzos8\pw" /inheritance:r /grant:r "${env:USERNAME}:F"
```

Then add `"FRITZ_PASSWORD_FILE": "/Users/<you>/.config/fritzos8/pw"` (Linux `/home/<you>/…`, Windows `"C:\\Users\\<you>\\.config\\fritzos8\\pw"`) to the `env` block of the client entry. The `keyring` extra is then not needed.

### macOS only: keychain start scripts

`scripts/fritzos8-mcp-start.sh` and `scripts/fritzos8-mcp-multi-start.sh` in a clone of the repository read user and password from the macOS keychain with `security` and run the server from that checkout. Usage is described in the scripts and in [configuration](https://github.com/tomwellnitz/fritzos8-mcp/blob/main/docs/configuration.md). They are zsh scripts using the macOS `security` tool and do not work on Windows or Linux.

## The server entry

Every client below starts the same command:

| Field | Value |
|---|---|
| command | `uvx` (or its full path, see above) |
| args | `--from`, `fritzos8-mcp[keyring]`, `fritzos8-mcp` |
| env | `FRITZ_HOST=fritz.box`, `FRITZ_USER=<user>` |

The server starts read-only. Add `FRITZ_ALLOW_WRITE=1` (and optionally `FRITZ_ALLOW_CRITICAL=1`) to `env` to enable changes – see the [safety model](https://github.com/tomwellnitz/fritzos8-mcp#safety-model).

Full path examples for `command`:

| OS | `command` |
|---|---|
| macOS (Homebrew) | `/opt/homebrew/bin/uvx` |
| macOS / Linux (installer) | `/Users/<you>/.local/bin/uvx` / `/home/<you>/.local/bin/uvx` |
| Windows (installer) | `C:\\Users\\<you>\\.local\\bin\\uvx.exe` – in JSON every backslash is doubled |

TOML (Codex) accepts single-quoted literal strings without escaping: `command = 'C:\Users\<you>\.local\bin\uvx.exe'`.

## Clients

| Client | Where | Top-level key | stdio | HTTP + header |
|---|---|---|---|---|
| [Claude Code](#claude-code) | `claude mcp add` | `mcpServers` | yes | yes |
| [Claude Desktop](#claude-desktop) | `claude_desktop_config.json` | `mcpServers` | yes | no (connectors connect from Anthropic's cloud) |
| [Cursor](#cursor) | `mcp.json` | `mcpServers` | yes | yes |
| [VS Code (Copilot)](#vs-code-github-copilot) | `mcp-config.json` | `mcpServers` | yes | yes |
| [Windsurf](#windsurf) | `mcp_config.json` | `mcpServers` | yes | yes |
| [Zed](#zed) | `settings.json` | `context_servers` | yes | yes |
| [Cline](#cline) | `cline_mcp_settings.json` | `mcpServers` | yes | yes |
| [Continue](#continue) | `config.yaml` | `mcpServers` (list) | yes | yes |
| [OpenAI Codex CLI](#openai-codex-cli) | `config.toml` | `[mcp_servers.<name>]` | yes | yes |
| [Gemini CLI](#gemini-cli) | `settings.json` | `mcpServers` | yes | yes |
| [LM Studio](#lm-studio) | `mcp.json` | `mcpServers` | yes | yes |

HTTP variants for each client are collected under [Remote (HTTP with token)](#remote-http-with-token).

### Claude Code

Source: [code.claude.com/docs/en/mcp](https://code.claude.com/docs/en/mcp). Same command on all three OSes; `-s user` makes the server available in all projects (stored in `~/.claude.json`).

```bash
claude mcp add fritzos8 -s user -e FRITZ_HOST=fritz.box -e FRITZ_USER=<user> -- \
  uvx --from 'fritzos8-mcp[keyring]' fritzos8-mcp
```

Windows (PowerShell, one line):

```powershell
claude mcp add fritzos8 -s user -e FRITZ_HOST=fritz.box -e FRITZ_USER=<user> -- uvx --from "fritzos8-mcp[keyring]" fritzos8-mcp
```

Everything before `--` belongs to Claude Code, everything after it is the server command. `-s project` writes a shared `.mcp.json` into the project instead. Check with `claude mcp list`.

### Claude Desktop

Source: [modelcontextprotocol.io – Connect to local MCP servers](https://modelcontextprotocol.io/docs/develop/connect-local-servers), [Claude Help Center](https://support.claude.com/en/articles/10065433-install-claude-desktop) (Linux is a beta for Ubuntu 22.04+ / Debian 12+). The one-click bundle at the top of this page is the easier way; this is the manual setup. Open the file via *Settings › Developer › Edit Config*, then quit and restart the app completely.

| OS | Config file |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux (beta) | `~/.config/Claude/claude_desktop_config.json` |

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

Claude Desktop is a GUI app: on macOS use the full path (`/opt/homebrew/bin/uvx` or `/Users/<you>/.local/bin/uvx`), on Windows for example:

```json
{
  "mcpServers": {
    "fritzos8": {
      "command": "C:\\Users\\<you>\\.local\\bin\\uvx.exe",
      "args": ["--from", "fritzos8-mcp[keyring]", "fritzos8-mcp"],
      "env": { "FRITZ_HOST": "fritz.box", "FRITZ_USER": "<user>" }
    }
  }
}
```

Logs: `~/Library/Logs/Claude` (macOS), `%APPDATA%\Claude\logs` (Windows), `~/.config/Claude/logs` (Linux) – `mcp-server-fritzos8.log` contains the server's error output. Remote servers in Claude Desktop are added as connectors, which Anthropic connects to from its cloud – a server in your home network is not reachable that way, so use stdio.

### Cursor

Source: [cursor.com/docs/context/mcp](https://cursor.com/docs/context/mcp).

| Scope | File (all OSes) |
|---|---|
| global | `~/.cursor/mcp.json` |
| project | `.cursor/mcp.json` |

```json
{
  "mcpServers": {
    "fritzos8": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "fritzos8-mcp[keyring]", "fritzos8-mcp"],
      "env": { "FRITZ_HOST": "fritz.box", "FRITZ_USER": "<user>" }
    }
  }
}
```

Cursor resolves `${env:NAME}` in `command`, `args`, `env`, `url` and `headers`.

### VS Code (GitHub Copilot)

Source: [code.visualstudio.com – MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration). VS Code now reads the Copilot configuration files; the editor-managed `.vscode/mcp.json` / profile `mcp.json` with `servers` and `inputs` is deprecated (removal announced for February 2027).

| Scope | File |
|---|---|
| user | `~/.copilot/mcp-config.json` (or `$COPILOT_HOME/mcp-config.json`) |
| workspace | `.mcp.json` in the workspace root |

```json
{
  "mcpServers": {
    "fritzos8": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "fritzos8-mcp[keyring]", "fritzos8-mcp"],
      "env": { "FRITZ_HOST": "fritz.box", "FRITZ_USER": "<user>" },
      "tools": ["*"]
    }
  }
}
```

`${NAME}` and `${NAME:-default}` are expanded from the environment. Only the deprecated editor-managed format supports secret prompts (`inputs` with `"password": true`, see [HTTP](#remote-http-with-token)).

### Windsurf

Source: [Windsurf Cascade MCP configuration](https://docs.devin.ai/windsurf/plugins/cascade/mcp) (docs.windsurf.com redirects there). Open the file via *Open MCP config file* in Cascade's MCP menu, or add the server under *Settings › Tools › Windsurf Settings › Add Server*; refresh afterwards.

| OS | Config file |
|---|---|
| macOS / Linux | `~/.config/devin/mcp_config.json` (`$XDG_CONFIG_HOME/devin/mcp_config.json` if set) |
| Windows | `%APPDATA%\devin\mcp_config.json` |

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

`${env:NAME}` is interpolated in `command`, `args`, `env`, `serverUrl`, `url` and `headers`.

### Zed

Source: [zed.dev/docs/ai/mcp](https://zed.dev/docs/ai/mcp). Add the entry to the settings file (or use *Settings › AI › MCP Servers › Add Server*).

| OS | Settings file |
|---|---|
| macOS / Linux | `~/.config/zed/settings.json` |
| Windows | `%APPDATA%\Zed\settings.json` |

```jsonc
{
  // merge into your existing settings
  "context_servers": {
    "fritzos8": {
      "command": "uvx",
      "args": ["--from", "fritzos8-mcp[keyring]", "fritzos8-mcp"],
      "env": { "FRITZ_HOST": "fritz.box", "FRITZ_USER": "<user>" }
    }
  }
}
```

### Cline

Source: [docs.cline.bot – Configuring MCP servers](https://docs.cline.bot/mcp/configuring-mcp-servers). Open the file via the MCP servers icon › *Configure* › *Configure MCP Servers*. It lives at `~/.cline/data/settings/cline_mcp_settings.json` (override with `CLINE_MCP_SETTINGS_PATH`).

```json
{
  "mcpServers": {
    "fritzos8": {
      "command": "uvx",
      "args": ["--from", "fritzos8-mcp[keyring]", "fritzos8-mcp"],
      "env": { "FRITZ_HOST": "fritz.box", "FRITZ_USER": "<user>" },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

### Continue

Source: [docs.continue.dev – MCP](https://docs.continue.dev/customize/deep-dives/mcp), [config reference](https://docs.continue.dev/reference). MCP tools are only available in agent mode.

| OS | Config file |
|---|---|
| macOS / Linux | `~/.continue/config.yaml` |
| Windows | `%USERPROFILE%\.continue\config.yaml` |

```yaml
mcpServers:
  - name: fritzos8
    type: stdio
    command: uvx
    args: ["--from", "fritzos8-mcp[keyring]", "fritzos8-mcp"]
    env:
      FRITZ_HOST: fritz.box
      FRITZ_USER: <user>
```

Per workspace, the same entry can go into `.continue/mcpServers/fritzos8.yaml`; such block files additionally need `name`, `version` and `schema: v1` at the top. The VS Code and JetBrains extensions do not see shell environment variables; secrets come from `.env` files via `${{ secrets.NAME }}`.

### OpenAI Codex CLI

Source: [Codex MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli), [config reference](https://learn.chatgpt.com/docs/config-file/config-reference) (developers.openai.com/codex redirects there). User config: `~/.codex/config.toml` (directory overridable with `CODEX_HOME`); project config `.codex/config.toml` is only read in trusted projects.

```bash
codex mcp add fritzos8 --env FRITZ_HOST=fritz.box --env FRITZ_USER=<user> -- \
  uvx --from 'fritzos8-mcp[keyring]' fritzos8-mcp
```

or directly in `config.toml`:

```toml
[mcp_servers.fritzos8]
command = "uvx"
args = ["--from", "fritzos8-mcp[keyring]", "fritzos8-mcp"]

[mcp_servers.fritzos8.env]
FRITZ_HOST = "fritz.box"
FRITZ_USER = "<user>"
```

`env_vars = ["NAME"]` forwards variables from Codex's own environment to the server.

### Gemini CLI

Source: [Gemini CLI – MCP servers](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md). User config `~/.gemini/settings.json`, project config `.gemini/settings.json`.

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

Leave `trust` unset (default `false`) so Gemini CLI keeps asking before tool calls. Gemini CLI removes variables matching `*TOKEN*`, `*PASSWORD*`, `*KEY*` and similar from the environment it passes on; values listed in `env` (`"$NAME"` expands a variable) are passed through.

### LM Studio

Source: [lmstudio.ai/docs/app/mcp](https://lmstudio.ai/docs/app/mcp), [LM Studio 0.3.17 release notes](https://lmstudio.ai/blog/lmstudio-v0.3.17). Requires LM Studio 0.3.17 or later. Edit the file in the app: *Program* tab in the right sidebar › *Install* › *Edit mcp.json*. LM Studio follows Cursor's `mcp.json` notation; per the release notes the file is `~/.lmstudio/mcp.json` (Windows `%USERPROFILE%\.lmstudio\mcp.json`).

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

## Docker

The image `ghcr.io/tomwellnitz/fritzos8-mcp` contains no keyring backend; pass the password as a mounted file. Any client with a `command`/`args` entry can start it over stdio (`-i` keeps stdin open, `--rm` removes the container afterwards). Example for the `mcpServers` format (Linux path shown):

```json
{
  "mcpServers": {
    "fritzos8": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "FRITZ_HOST=fritz.box",
        "-e", "FRITZ_USER=<user>",
        "-e", "FRITZ_PASSWORD_FILE=/run/secrets/fritz_password",
        "-v", "/home/<you>/.config/fritzos8/pw:/run/secrets/fritz_password:ro",
        "ghcr.io/tomwellnitz/fritzos8-mcp:latest"
      ]
    }
  }
}
```

- Host path on macOS `/Users/<you>/.config/fritzos8/pw`, on Windows `C:\\Users\\<you>\\.config\\fritzos8\\pw`.
- **Linux:** a bind mount keeps the host file's owner and mode, and the container runs as UID 10001. With mode `600` that user cannot read your file – use a separate copy owned by that UID: `sudo install -o 10001 -m 400 ~/.config/fritzos8/pw /etc/fritzos8-pw` and mount `/etc/fritzos8-pw`. Docker Desktop on macOS and Windows does not need this.
- State (snapshots, measurement series) lives in `/data` inside the container; add `-v fritzos8-data:/data` to keep it.
- GUI clients may need the full path to `docker` (`which docker` / `where.exe docker`).

## Remote (HTTP with token)

`fritzos8-mcp --http` serves Streamable HTTP at `/mcp` and requires a bearer token; setup, bind address and security rules are in [remote access](remote.md). Below, the server runs at `http://127.0.0.1:8765/mcp`; replace the URL with your host (reach it only via VPN or a TLS reverse proxy, never via port forwarding). Where a client can read the token from an environment variable, the examples use `FRITZ_HTTP_TOKEN` – it must be set in the environment the client is started from. Otherwise `<token>` stands for the literal token; that file then contains a secret.

Starting the server in Docker (inside the container it has to listen on `0.0.0.0`, the port is only published on the host's loopback; the warning about the non-local bind is expected):

```bash
docker run -d --name fritzos8-mcp -p 127.0.0.1:8765:8765 \
  -e FRITZ_HOST=fritz.box -e FRITZ_USER=<user> \
  -e FRITZ_PASSWORD_FILE=/run/secrets/fritz_password -v ~/.config/fritzos8/pw:/run/secrets/fritz_password:ro \
  -e FRITZ_HTTP_TOKEN_FILE=/run/secrets/http_token -v ~/.config/fritzos8/http-token:/run/secrets/http_token:ro \
  -e FRITZ_HTTP_HOST=0.0.0.0 -e FRITZ_HTTP_ALLOWED_HOSTS=127.0.0.1:8765,localhost:8765 \
  ghcr.io/tomwellnitz/fritzos8-mcp:latest fritzos8-mcp --http
```

**Claude Code**

```bash
claude mcp add --transport http -s user fritzos8-remote http://127.0.0.1:8765/mcp \
  --header "Authorization: Bearer $(cat ~/.config/fritzos8/http-token)"
```

**Cursor** (`mcp.json`)

```json
{
  "mcpServers": {
    "fritzos8-remote": {
      "url": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer ${env:FRITZ_HTTP_TOKEN}" }
    }
  }
}
```

**VS Code** (`~/.copilot/mcp-config.json`)

```json
{
  "mcpServers": {
    "fritzos8-remote": {
      "type": "http",
      "url": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer ${FRITZ_HTTP_TOKEN}" },
      "tools": ["*"]
    }
  }
}
```

VS Code, deprecated editor-managed format (`.vscode/mcp.json`), which prompts for the token once and stores it securely:

```json
{
  "inputs": [
    { "type": "promptString", "id": "fritzos8-token", "description": "fritzos8-mcp HTTP token", "password": true }
  ],
  "servers": {
    "fritzos8-remote": {
      "type": "http",
      "url": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer ${input:fritzos8-token}" }
    }
  }
}
```

**Windsurf** (`mcp_config.json`)

```json
{
  "mcpServers": {
    "fritzos8-remote": {
      "serverUrl": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer ${env:FRITZ_HTTP_TOKEN}" }
    }
  }
}
```

**Zed** (`settings.json`)

```jsonc
{
  "context_servers": {
    "fritzos8-remote": {
      "url": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

**Cline** (`cline_mcp_settings.json`) – `type` is required, without it Cline falls back to the legacy SSE transport:

```json
{
  "mcpServers": {
    "fritzos8-remote": {
      "type": "streamableHttp",
      "url": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer <token>" },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

**Continue** (`config.yaml`; the token comes from a `.env` file, e.g. `~/.continue/.env` with `FRITZ_HTTP_TOKEN=…`)

```yaml
mcpServers:
  - name: fritzos8-remote
    type: streamable-http
    url: http://127.0.0.1:8765/mcp
    requestOptions:
      headers:
        Authorization: "Bearer ${{ secrets.FRITZ_HTTP_TOKEN }}"
```

**OpenAI Codex CLI** (`config.toml`; the token is read from the variable at runtime)

```toml
[mcp_servers.fritzos8-remote]
url = "http://127.0.0.1:8765/mcp"
bearer_token_env_var = "FRITZ_HTTP_TOKEN"
```

**Gemini CLI** (`settings.json`; `httpUrl` selects Streamable HTTP, `url` would mean SSE)

```json
{
  "mcpServers": {
    "fritzos8-remote": {
      "httpUrl": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

**LM Studio** (`mcp.json`)

```json
{
  "mcpServers": {
    "fritzos8-remote": {
      "url": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

**Claude Desktop:** not possible for a server in your home network (see above) – use stdio.

## Troubleshooting

**`uvx` not found / server fails to start immediately.** The client does not see your PATH. Use the full path from `which uvx` (macOS/Linux) or `where.exe uvx` (Windows) as `command`, double the backslashes in JSON, and restart the client completely.

**Run the server by hand.** This shows the error the client hides. Without a valid configuration the server prints the reason and exits; with one it waits silently for MCP input (stop with Ctrl+C).

```bash
FRITZ_HOST=fritz.box FRITZ_USER=<user> uvx --from 'fritzos8-mcp[keyring]' fritzos8-mcp
```

```powershell
$env:FRITZ_HOST = "fritz.box"; $env:FRITZ_USER = "<user>"; uvx --from "fritzos8-mcp[keyring]" fritzos8-mcp
```

**"Kein Passwort: …"** No password was found. Check that the entry exists for service `fritzos8-mcp` and account `<user>` (or `<user>@<host>`), that the `keyring` extra is in `args`, and that `FRITZ_USER` matches the stored account exactly.

**Keyring errors on Linux.** `keyring --list-backends` showing only `fail.Keyring` / `chainer` means no Secret Service is reachable: no desktop session, keyring locked, or `DBUS_SESSION_BUS_ADDRESS` missing in the client's environment (clients that filter the environment, e.g. Codex, need it in `env_vars`). On servers and over SSH use `FRITZ_PASSWORD_FILE`.

**The client does not show the server or its tools.** Validate the file (a trailing comma breaks JSON), check the top-level key for your client (`mcpServers`, `context_servers`, `[mcp_servers.…]`), restart the client completely, and read its MCP log (Claude Desktop: see above). Continue only offers MCP tools in agent mode.

**Connected – now check the box.** Ask the assistant to run `server_status` (active tiers) and `setup_check`: it checks TR-064 access, the user's rights and two-factor confirmation, and names the tools a missing right disables.
