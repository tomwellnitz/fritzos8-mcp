"""fritzos8-mcp – platform MCP server for AVM FRITZ!Box with FRITZ!OS 8."""

from __future__ import annotations

__version__ = "0.3.0"


def main() -> None:
    import logging
    import os
    import sys

    from . import config as config_mod
    from . import httpserve
    from .errors import ConfigError
    from .redact import RedactingFilter

    argv = sys.argv[1:]
    if "--generate-token" in argv:  # stage 10.4: print a fresh bearer token for the HTTP transport
        print(httpserve.generate_token())
        return
    if "--version" in argv:
        print(__version__)
        return
    try:
        configs = config_mod.load_all()
        http = httpserve.load_http_settings() if httpserve.wants_http(argv=argv) else None
    except ConfigError as exc:
        print(f"fritzos8-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2) from None

    handler = logging.StreamHandler(sys.stderr)  # stdout belongs to the MCP protocol
    from .alerts import alert_secrets

    secrets = tuple(s for cfg in configs for s in cfg.secrets) + alert_secrets()  # stage 8.3: notification URLs
    if http is not None:
        secrets += http.secrets  # stage 10.4: the bearer token is redacted like the box password
    handler.addFilter(RedactingFilter(secrets))
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
    logging.getLogger("httpx").setLevel(logging.WARNING)

    from .security import Gate
    from .server import build_server, create_services

    services = create_services(configs)
    serials = (os.environ.get("FRITZ_REDACT_SERIALS") or "").strip().lower() in {"1", "true", "yes", "on"}
    server = build_server(services, Gate.from_config(configs[0]), secrets, redact_serial_numbers=serials)
    if http is not None:
        httpserve.serve_http(server, http)
    else:
        server.run("stdio")
