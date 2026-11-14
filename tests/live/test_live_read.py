"""Opt-in live suite (stage 9.5): ONLY read-only calls against a real FRITZ!Box – for contributors who want to check
compatibility of their model. Skipped unless FRITZ_LIVE_TEST=1.

    FRITZ_LIVE_TEST=1 FRITZ_HOST=fritz.box FRITZ_USER=mcp FRITZ_PASSWORD_FILE=~/.config/fritzos8/pw \
      uv run pytest tests/live -o addopts="" -v

The service is built with write/critical DISABLED (Gate(False, False)); every check calls a read method only.
Results feed docs/COMPATIBILITY.md (please report model, FRITZ!OS version and access type, no personal data).
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from typing import Any

import pytest

from fritzos8_mcp import config
from fritzos8_mcp.errors import FritzError, PermissionDeniedError, UnsupportedFirmwareError
from fritzos8_mcp.security import Gate
from fritzos8_mcp.server import create_service
from fritzos8_mcp.setupcheck import SetupChecker

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("FRITZ_LIVE_TEST") != "1", reason="Live-Tests nur mit FRITZ_LIVE_TEST=1"),
]


@pytest.fixture(scope="module")
def live() -> Any:
    from dataclasses import replace

    cfg = replace(config.load(), allow_write=False, allow_critical=False, allow_secrets=False)
    service = create_service(cfg)
    service.gate = Gate(False, False)
    return service, cfg.password


READ_CHECKS: dict[str, Callable[[Any], Any]] = {
    "system_info": lambda s: s.system_info(),
    "wan_status": lambda s: s.wan_status(),
    "list_hosts": lambda s: s.list_hosts(),
    "list_landevices": lambda s: s.list_landevices(),
    "wlan_status": lambda s: s.wlan_status(),
    "guest_wifi_status": lambda s: s.guest_wifi_status(),
    "firmware_status": lambda s: s.firmware_status(),
    "get_dns_settings": lambda s: s.get_dns_settings(),
    "security_check": lambda s: s.security_check(),
    "mesh_overview": lambda s: s.mesh_overview(),
    "online_monitor": lambda s: s.online_monitor(),
    "line_diagnostics": lambda s: s.line.diagnose(),
    "system_transparency": lambda s: s.transparency.overview(),
    "avm_device_updates": lambda s: s.devices.updates_overview(),
    "devices_change_counter": lambda s: s.devices.change_counter(),
    "lan_ports": lambda s: s.connectivity.lan.status(),
    "two_factor_status": lambda s: s.system_write.two_factor_status(),
    "smarthome_tr064_devices": lambda s: s.smarthome_config.tr064_devices(),
    "setup_check": lambda s: SetupChecker(s).check(),
}


@pytest.mark.parametrize("name", sorted(READ_CHECKS))
def test_read_tool_live(live: Any, name: str) -> None:
    service, password = live
    try:
        result = READ_CHECKS[name](service)
    except (PermissionDeniedError, UnsupportedFirmwareError) as exc:
        pytest.skip(f"{name}: {exc.code} – Recht/Firmware fehlt (für die Matrix notieren)")
    except FritzError as exc:
        pytest.fail(f"{name}: {exc.code}: {exc}")
    text = json.dumps(result, ensure_ascii=False, default=str)
    assert password not in text, "Passwort in der Ausgabe – Schwärzung prüfen!"
    assert isinstance(result, dict)
