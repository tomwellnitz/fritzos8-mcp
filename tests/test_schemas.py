"""Stage 7.7 – outputSchema for the main tools: schemas published, real outputs fit, no field lost."""

from __future__ import annotations

import copy
import json
import logging
from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel

from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.schemas import OUTPUT_MODELS
from fritzos8_mcp.security import Gate
from fritzos8_mcp.server import build_server

from .conftest import FakeBox, FakeFC, make_service
from .fixtures_api import ETH_PORTS, VPN
from .test_diagnose import secure_box
from .test_doctor import doctor_fc
from .test_wlan import Radios, wlan_fc

TOOLS = {
    "system_info",
    "wan_status",
    "list_landevices",
    "lan_ports",
    "wlan_status",
    "security_check",
    "network_doctor",
    "vpn_connections",
}


def _jsonable(obj: Any) -> Any:
    return json.loads(json.dumps(obj, default=str))


def assert_fits_without_loss(model: type[BaseModel], result: dict[str, Any]) -> None:
    """Validates strictly (no fallback) and the dump keeps every original field with its value."""
    dumped = model.model_validate(result).model_dump(mode="json")
    original = _jsonable(result)

    def contains(sup: Any, sub: Any, path: str) -> None:
        if isinstance(sub, dict):
            assert isinstance(sup, dict), path
            for k, v in sub.items():
                assert k in sup, f"{path}.{k} fehlt"
                contains(sup[k], v, f"{path}.{k}")
        elif isinstance(sub, list):
            assert isinstance(sup, list) and len(sup) == len(sub), path
            for i, (a, b) in enumerate(zip(sup, sub, strict=True)):
                contains(a, b, f"{path}[{i}]")
        else:
            assert sup == sub, f"{path}: {sup!r} != {sub!r}"

    contains(dumped, original, model.__name__)


def test_output_models_cover_the_required_tools() -> None:
    assert set(OUTPUT_MODELS) == TOOLS


async def test_tools_publish_output_schema() -> None:
    tools = {t.name: t for t in await build_server(MagicMock(), Gate(True, True)).list_tools()}
    for name in TOOLS:
        schema = tools[name].output_schema
        assert schema and schema["type"] == "object", name
        assert schema.get("additionalProperties", True) is not False, name  # extra fields stay allowed
    props = tools["system_info"].output_schema["properties"]
    assert {"model", "software_version", "uptime_s"} <= set(props)
    assert "landevices" in tools["list_landevices"].output_schema["properties"]
    assert "findings" in tools["network_doctor"].output_schema["properties"]
    assert "checks" in tools["security_check"].output_schema["required"]


# ------------------------------------------------------------------ real outputs from the fakes


def test_system_info_and_wan_status_fit(landevices: LanDeviceClient) -> None:
    fc = FakeFC(
        {
            ("DeviceInfo1", "GetInfo"): {
                "NewModelName": "FRITZ!Box 7583",
                "NewSoftwareVersion": "185.08.26",
                "NewHardwareVersion": "FRITZ!Box 7583",
                "NewUpTime": 12345,
                "NewDescription": "FRITZ!Box 7583 185.08.26",
                "NewManufacturerName": "AVM",
            },
            ("WANIPConn1", "GetStatusInfo"): {"NewConnectionStatus": "Connected", "NewUptime": 100},
            ("WANIPConn1", "X_AVM_DE_GetExternalIPv6Address"): {"NewExternalIPv6Address": "2001:db8::1"},
            ("WANCommonInterfaceConfig1", "GetCommonLinkProperties"): {
                "NewWANAccessType": "DSL",
                "NewPhysicalLinkStatus": "Up",
                "NewLayer1DownstreamMaxBitRate": 100000000,
                "NewLayer1UpstreamMaxBitRate": 40000000,
            },
        }
    )
    svc = make_service(landevices, fc)
    assert_fits_without_loss(OUTPUT_MODELS["system_info"], svc.system_info())
    wan = svc.wan_status()
    assert wan["ipv4_note"]  # DS-Lite path: conditional field included
    assert_fits_without_loss(OUTPUT_MODELS["wan_status"], wan)


def test_landevices_lan_ports_vpn_fit(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    fake_box.generic["eth_ports"] = copy.deepcopy(ETH_PORTS)
    fake_box.generic["vpn"] = copy.deepcopy(VPN)
    svc = make_service(landevices, FakeFC())
    assert_fits_without_loss(OUTPUT_MODELS["list_landevices"], svc.list_landevices())
    assert_fits_without_loss(OUTPUT_MODELS["lan_ports"], svc.connectivity.lan_ports())
    assert_fits_without_loss(OUTPUT_MODELS["vpn_connections"], svc.connectivity.vpn_connections())


def test_wlan_security_doctor_fit(landevices: LanDeviceClient) -> None:
    assert_fits_without_loss(OUTPUT_MODELS["wlan_status"], make_service(landevices, wlan_fc(Radios())).wlan_status())
    assert_fits_without_loss(OUTPUT_MODELS["security_check"], make_service(landevices, secure_box()).security_check())
    doctor = make_service(landevices, doctor_fc()).network_doctor("WLAN langsam")
    assert_fits_without_loss(OUTPUT_MODELS["network_doctor"], doctor)


def test_wlan_status_with_broken_service_fits(landevices: LanDeviceClient) -> None:
    from fritzconnection.core.exceptions import FritzActionError

    fc = wlan_fc(Radios())
    fc.responses[("WLANConfiguration2", "GetInfo")] = FritzActionError("kaputt")
    result = make_service(landevices, fc).wlan_status()
    assert any("error" in n for n in result["networks"])
    assert_fits_without_loss(OUTPUT_MODELS["wlan_status"], result)


# ------------------------------------------------------------------ through the MCP layer


async def test_structured_content_keeps_all_fields() -> None:
    service = MagicMock()
    service.system_info.return_value = {
        "model": "7583",
        "description": None,
        "software_version": "8.26",
        "hardware_version": None,
        "uptime_s": 5,
        "manufacturer": "AVM",
        "zusatz": {"neu": 1},
    }
    result = await build_server(service, Gate(False, False)).call_tool("system_info", {})
    assert result.structured_content["zusatz"] == {"neu": 1}
    assert result.structured_content["uptime_s"] == 5


@pytest.mark.filterwarnings("ignore:Pydantic serializer warnings")
async def test_non_fitting_result_is_passed_on_and_logged(caplog: pytest.LogCaptureFixture) -> None:
    service = MagicMock()
    service.wan_status.return_value = {"connection": {"service": "WANIPConn1", "status": 7}, "external_ipv4": 42}
    with caplog.at_level(logging.WARNING):
        result = await build_server(service, Gate(False, False)).call_tool("wan_status", {})
    assert result.structured_content["external_ipv4"] == 42
    assert result.structured_content["connection"]["status"] == 7
    assert "Ausgabeschema" in caplog.text
