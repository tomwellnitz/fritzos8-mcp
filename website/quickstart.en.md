# Quick start

## 1. User on the FRITZ!Box

1. **Home Network > Network > Network Settings:** enable "Allow access for applications" (TR-064).
2. **System > FRITZ!Box Users:** create a dedicated user for the MCP server. The rights each tool needs are listed in the [tool reference](tools.md) (column "Recht"); for reading, "FRITZ!Box settings" or the app right is usually enough.

## 2. Store the password

```bash
uvx --from 'fritzos8-mcp[keyring]' keyring set fritzos8-mcp <user>
```

(or point `FRITZ_PASSWORD_FILE` to a file with mode `600`).

## 3. Add it to your client (Claude Code)

```bash
claude mcp add fritzos8 -s user \
  -e FRITZ_HOST=fritz.box -e FRITZ_USER=<user> -- uvx --from 'fritzos8-mcp[keyring]' fritzos8-mcp
```

Other clients and Windows/Linux: [MCP clients](clients.md). **Claude Desktop:** easier with the one-click bundle `fritzos8-mcp-<version>.mcpb` from the [latest release](https://github.com/tomwellnitz/fritzos8-mcp/releases/latest) – double-click, fill in the fields ([guide](clients.md#claude-desktop-one-click-bundle-mcpb)).

Then run `setup_check`: it checks TR-064, the user's rights, two-factor confirmation and the reachability of all interfaces, and tells you which tools will not work because a right is missing.

## 4. Enable writing (optional)

`-e FRITZ_ALLOW_WRITE=1` (write tools with read-back) plus `-e FRITZ_ALLOW_CRITICAL=1` (reboot, port forwarding, firmware update … plan/token only).
