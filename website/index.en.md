# fritzos8-mcp

MCP server for AVM FRITZ!Box routers running **FRITZ!OS 8**: more than 150 tools for devices, Wi-Fi, telephony, smart home, diagnostics, a measurement series and alerts – for Claude and other MCP clients.

- **Read-only by default.** Writing (`FRITZ_ALLOW_WRITE=1`) and critical actions (`FRITZ_ALLOW_CRITICAL=1`) must be enabled explicitly; critical actions only run via *plan → token → execute* and – if the client supports it – a yes/no confirmation by the human.
- **Never claims success it did not see:** every write is read back (`verified`).
- **No secrets:** passwords, Wi-Fi keys, PINs, tokens and session IDs are redacted in every output and log.
- **Three interfaces:** TR-064 (official), AHA-HTTP and Smart Home REST (official), the web UI's `/api/v0` (unofficial, only where needed).

Tool descriptions and messages are in German; the tools work the same for every language.

!!! note "Independent project"
    Not a product of AVM/FRITZ! GmbH. FRITZ!Box and FRITZ!OS are trademarks of FRITZ! GmbH.

Continue with the [quick start](quickstart.md).
