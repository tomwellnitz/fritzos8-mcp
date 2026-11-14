# Remote access (HTTP transport)

`fritzos8-mcp --http` serves MCP over **Streamable HTTP** at `/mcp`.

- **A bearer token is mandatory** (`FRITZ_HTTP_TOKEN`, `FRITZ_HTTP_TOKEN_FILE` or keyring service `fritzos8-mcp` / user `http-token`; at least 32 characters, `fritzos8-mcp --generate-token`). Wrong or missing token → `401`.
- **Binds to `127.0.0.1` by default** (`FRITZ_HTTP_HOST`, `FRITZ_HTTP_PORT` = 8765). Any other bind address logs warnings.
- **Never expose it via port forwarding.** Reach it from outside only through a VPN (e.g. the FRITZ!Box WireGuard VPN) or a TLS reverse proxy. Optional direct TLS: `FRITZ_HTTP_TLS_CERT` + `FRITZ_HTTP_TLS_KEY`. DNS rebinding protection for non-local binds: `FRITZ_HTTP_ALLOWED_HOSTS`.
- The tiers stay as configured – without `FRITZ_ALLOW_WRITE` the server is read-only over HTTP as well.

```bash
claude mcp add --transport http fritzos8-remote http://127.0.0.1:8765/mcp \
  --header "Authorization: Bearer $(cat ~/.config/fritzos8/http-token)"
```
