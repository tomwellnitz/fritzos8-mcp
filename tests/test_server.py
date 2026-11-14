from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from fritzos8_mcp.errors import ConfirmationRequiredError
from fritzos8_mcp.security import Gate
from fritzos8_mcp.server import build_server

from .conftest import PASSWORD

READ_TOOLS = {
    "server_status",
    "system_info",
    "wan_status",
    "list_hosts",
    "list_landevices",
    "get_lan_dns",
    "tr064_list_services",
    "tr064_describe_action",
    "tr064_call",
    "wlan_status",
    "guest_wifi_status",
    "smarthome_list_devices",
    "smarthome_device_stats",
    "system_log",
    "dsl_info",
    "firmware_status",
    "security_check",
    "call_list",
    "tam_list",
    "phonebook_list",
    "internet_access_status",
    "list_port_forwards",
    "get_dns_settings",
    "devices_cleanup_report",
    "snapshot_create",
    "snapshot_list",
    "snapshot_diff",
    "mesh_overview",
    "online_monitor",
    "vpn_status",
    "boxes_overview",
    "compare_boxes",
    "network_doctor",
}
WRITE_TOOLS = {
    "rename_host",
    "set_static_ip",
    "delete_host",
    "set_guest_wifi",
    "smarthome_set_switch",
    "smarthome_set_thermostat",
    "set_tam_enabled",
    "set_internet_access",
    "devices_cleanup_plan",
    "devices_cleanup_execute",
    "wake_on_lan",
}
CRITICAL_TOOLS = {
    "delete_host_force_plan",
    "delete_host_force_execute",
    "reboot_plan",
    "reboot_execute",
    "reconnect_wan_plan",
    "reconnect_wan_execute",
    "set_wlan_enabled_plan",
    "set_wlan_enabled_execute",
    "add_port_forward_plan",
    "add_port_forward_execute",
    "delete_port_forward_plan",
    "delete_port_forward_execute",
}

# Stage 5 – NAS & remote access
READ_TOOLS |= {"nas_status", "backup_target_check", "myfritz_status"}
WRITE_TOOLS |= {"set_nas_protocol"}
CRITICAL_TOOLS |= {
    "set_nas_internet_access_plan",
    "set_nas_internet_access_execute",
    "set_remote_access_plan",
    "set_remote_access_execute",
}

# Stage 6 – LAN ports, VPN/Powerline, speed test, connection quality
READ_TOOLS |= {
    "lan_ports",
    "vpn_connections",
    "powerline_status",
    "box_speedtest_info",
    "device_connection_quality",
    "test_my_device",
}
WRITE_TOOLS |= {"set_lan_eee", "box_speedtest_run"}

# Stage 7.4 – WLAN settings
READ_TOOLS |= {"wlan_settings"}
WRITE_TOOLS |= {"set_wlan_channel"}

# Stage 7.5 – parental control profiles and tickets
READ_TOOLS |= {"parental_profiles", "parental_device_status", "parental_ticket_status"}
WRITE_TOOLS |= {"set_parental_profile", "parental_ticket_create", "parental_add_ticket_time"}
CRITICAL_TOOLS |= {"parental_tickets_discard_plan", "parental_tickets_discard_execute"}

# Stage 8.11 – device & update overview
READ_TOOLS |= {"avm_device_updates", "dect_handsets", "devices_change_counter"}

# Stage 8.1 – measurement series
READ_TOOLS |= {"history_collect", "history_query", "history_summary"}

# Stage 8.9 – line diagnostics
READ_TOOLS |= {"line_diagnostics"}

# Stage 8.2 – Störungsprotokoll
READ_TOOLS |= {"isp_report"}

# Stage 8.3 – alarms
READ_TOOLS |= {"alarms_check"}

# Stage 8.12 – system transparency
READ_TOOLS |= {"system_transparency"}

# Stage 8.10 – telephony read
READ_TOOLS |= {"phone_numbers_status", "alarm_clocks", "call_deflections", "call_barring_list", "phonebook_search"}

# Stage 8.7 – family admin report
READ_TOOLS |= {"family_admin_report"}

# Stage 8.5a – Smart-Home-REST read
READ_TOOLS |= {"smarthome_overview", "smarthome_unit", "smarthome_energy_report"}
# Stage 8.5b – Smart-Home control
WRITE_TOOLS |= {"smarthome_set_unit", "smarthome_thermostat_mode", "smarthome_set_routine", "smarthome_apply_template"}

# Stage 8.6 – FRITZ as Code
READ_TOOLS |= {"fritz_drift", "fritz_export"}
CRITICAL_TOOLS |= {"fritz_apply_plan", "fritz_apply_execute"}

# Stage 8.4 – guest WLAN session, WPS (guest_wifi_qr only with FRITZ_ALLOW_SECRETS)
READ_TOOLS |= {"guest_wifi_session"}
WRITE_TOOLS |= {"guest_wifi_session_start", "guest_wifi_session_stop", "wps_button"}

# Stage 8.8 – telephony write
WRITE_TOOLS |= {
    "set_alarm_clock",
    "set_call_deflection",
    "call_barring_add",
    "call_barring_remove",
    "tam_mark_message",
    "dial_hangup",
}
CRITICAL_TOOLS |= {"tam_delete_message_plan", "tam_delete_message_execute", "dial_number_plan", "dial_number_execute"}

# Stage 9.3 – setup check
READ_TOOLS |= {"setup_check"}

# Stage 10.1 – anomaly detection
READ_TOOLS |= {"history_anomalies"}

# Stage 10.2 – network optimizer
READ_TOOLS |= {"network_optimizer_suggest", "network_optimizer_effect"}
CRITICAL_TOOLS |= {"network_optimizer_apply_plan", "network_optimizer_apply_execute"}

# Stage 10.6a – firmware update, static routes, IPv6 pinholes, 2FA status
READ_TOOLS |= {"firmware_update_status", "ipv6_firewall_status", "two_factor_status"}
CRITICAL_TOOLS |= {
    "firmware_update_plan",
    "firmware_update_execute",
    "static_route_add_plan",
    "static_route_add_execute",
    "static_route_delete_plan",
    "static_route_delete_execute",
    "ipv6_pinhole_add_plan",
    "ipv6_pinhole_add_execute",
    "ipv6_pinhole_delete_plan",
    "ipv6_pinhole_delete_execute",
}

# Stage 10.7 – one AVM device in detail
READ_TOOLS |= {"avm_device_detail"}

# Stage 10.6b – Smart-Home configuration, pairing, TR-064 fallback
READ_TOOLS |= {"smarthome_thermostat_config", "smarthome_pairing_status", "smarthome_tr064_devices"}
WRITE_TOOLS |= {"smarthome_pairing_stop", "smarthome_tr064_set_switch"}
CRITICAL_TOOLS |= {
    "smarthome_holidays_plan",
    "smarthome_holidays_execute",
    "smarthome_summer_period_plan",
    "smarthome_summer_period_execute",
    "smarthome_delete_plan",
    "smarthome_delete_execute",
    "smarthome_rename_plan",
    "smarthome_rename_execute",
    "smarthome_pairing_plan",
    "smarthome_pairing_execute",
}


async def _names(gate: Gate) -> set[str]:
    return {t.name for t in await build_server(MagicMock(), gate).list_tools()}


@pytest.mark.parametrize(
    "write,critical,expected",
    [
        (False, False, READ_TOOLS),
        (True, False, READ_TOOLS | WRITE_TOOLS),
        (False, True, READ_TOOLS),
        (True, True, READ_TOOLS | WRITE_TOOLS | CRITICAL_TOOLS),
    ],
)
async def test_tools_registered_per_tier(write: bool, critical: bool, expected: set[str]) -> None:
    assert await _names(Gate(write, critical)) == expected


async def test_descriptions_carry_tier() -> None:
    tools = {t.name: t for t in await build_server(MagicMock(), Gate(True, True)).list_tools()}
    assert tools["reboot_execute"].description.startswith("[Stufe: critical]")
    assert tools["rename_host"].description.startswith("[Stufe: write]")
    assert tools["list_landevices"].annotations.read_only_hint is True
    assert tools["reboot_execute"].annotations.destructive_hint is True


async def test_structured_result_is_redacted() -> None:
    service = MagicMock()
    service.system_info.return_value = {"model": "7583", "debug": f"pw={PASSWORD}"}
    server = build_server(service, Gate(False, False), (PASSWORD,))
    result = await server.call_tool("system_info", {})
    assert result.structured_content["model"] == "7583"
    assert PASSWORD not in json.dumps(result.structured_content)


async def test_fritz_error_becomes_structured_tool_error() -> None:
    service = MagicMock()
    service.rename_host.side_effect = ConfirmationRequiredError(f"x {PASSWORD}")
    server = build_server(service, Gate(True, False), (PASSWORD,))
    with pytest.raises(ToolError) as ei:
        await server.call_tool("rename_host", {"mac": "AA:BB:CC:DD:EE:01", "name": "x"})
    text = str(ei.value)
    assert PASSWORD not in text
    payload = json.loads(text[text.index("{") :])
    assert payload["ok"] is False
    assert payload["error"]["type"] == "confirmation_required"
    assert "NICHTS geändert" in payload["error"]["hint"]


async def test_unexpected_error_is_redacted() -> None:
    service = MagicMock()
    service.wan_status.side_effect = RuntimeError(f"boom sid=0123456789abcdef {PASSWORD}")
    server = build_server(service, Gate(False, False), (PASSWORD,))
    with pytest.raises(ToolError) as ei:
        await server.call_tool("wan_status", {})
    assert PASSWORD not in str(ei.value) and "0123456789abcdef" not in str(ei.value)


async def test_server_status_lists_tiers() -> None:
    result = await build_server(MagicMock(), Gate(True, False)).call_tool("server_status", {})
    data = result.structured_content
    assert data["tiers"] == {"read": True, "write": True, "critical": False, "secrets": False}
    assert data["tools"]["rename_host"] == "write"


async def test_stage2_tools_carry_tier_and_annotations() -> None:
    tools = {t.name: t for t in await build_server(MagicMock(), Gate(True, True)).list_tools()}
    assert tools["set_guest_wifi"].description.startswith("[Stufe: write]")
    assert tools["set_wlan_enabled_execute"].description.startswith("[Stufe: critical]")
    assert tools["set_wlan_enabled_execute"].annotations.destructive_hint is True
    assert tools["security_check"].annotations.read_only_hint is True


async def test_wlan_keys_redacted_even_if_service_leaks_them() -> None:
    service = MagicMock()
    service.guest_wifi_status.return_value = {"ssid": "Gast", "NewKeyPassphrase": "x-geheim-x", "NewWEPKey0": "abc"}
    result = await build_server(service, Gate(False, False)).call_tool("guest_wifi_status", {})
    assert result.structured_content["NewKeyPassphrase"] == "***"
    assert "x-geheim-x" not in json.dumps(result.structured_content)


async def test_thermostat_schema_rejects_unknown_mode() -> None:
    service = MagicMock()
    server = build_server(service, Gate(True, False))
    with pytest.raises(ToolError):
        await server.call_tool("smarthome_set_thermostat", {"ain": "1", "mode": "eco"})
    service.smarthome_set_thermostat.assert_not_called()


async def test_stage3_tools_carry_tier_and_annotations() -> None:
    tools = {t.name: t for t in await build_server(MagicMock(), Gate(True, True)).list_tools()}
    assert tools["add_port_forward_execute"].description.startswith("[Stufe: critical]")
    assert tools["add_port_forward_execute"].annotations.destructive_hint is True
    assert tools["delete_port_forward_execute"].annotations.destructive_hint is True
    assert tools["set_internet_access"].description.startswith("[Stufe: write]")
    assert tools["call_list"].annotations.read_only_hint is True


async def test_port_forward_schema_rejects_bad_protocol_and_port() -> None:
    service = MagicMock()
    server = build_server(service, Gate(True, True))
    base = {"external_port": 8443, "internal_port": 443, "description": "x", "ip": "192.0.2.20"}
    with pytest.raises(ToolError):
        await server.call_tool("add_port_forward_plan", {**base, "protocol": "ICMP"})
    with pytest.raises(ToolError):
        await server.call_tool("add_port_forward_plan", {**base, "protocol": "TCP", "external_port": 70000})
    service.add_port_forward_plan.assert_not_called()


async def test_call_list_schema_rejects_unknown_type() -> None:
    service = MagicMock()
    with pytest.raises(ToolError):
        await build_server(service, Gate(False, False)).call_tool("call_list", {"call_type": "spam"})
    service.call_list.assert_not_called()


async def test_cleanup_tools_tier_and_schema() -> None:
    service = MagicMock()
    service.devices_cleanup_plan.return_value = {"accepted": []}
    server = build_server(service, Gate(True, False))
    tools = {t.name: t for t in await server.list_tools()}
    assert tools["devices_cleanup_plan"].description.startswith("[Stufe: write]")
    assert tools["devices_cleanup_execute"].annotations.destructive_hint is True
    assert tools["devices_cleanup_report"].annotations.read_only_hint is True
    with pytest.raises(ToolError):
        await server.call_tool("devices_cleanup_plan", {"actions": [{"action": "wipe", "mac": "x"}]})
    service.devices_cleanup_plan.assert_not_called()
    await server.call_tool(
        "devices_cleanup_plan", {"actions": [{"action": "rename", "mac": "AA:BB:CC:DD:EE:01", "name": "x"}]}
    )
    service.devices_cleanup_plan.assert_called_once_with(
        [{"action": "rename", "mac": "AA:BB:CC:DD:EE:01", "name": "x", "uid": None}], 90
    )


async def test_serial_numbers_masked_only_on_request() -> None:
    """Stage 9.9: FRITZ_REDACT_SERIALS=1 → serial numbers/UDN masked in every tool result."""
    service = MagicMock()
    service.system_info.return_value = {"model": "7583", "NewSerialNumber": "SERIAL0001", "nested": [{"udn": "u"}]}
    plain = await build_server(service, Gate(False, False)).call_tool("system_info", {})
    assert plain.structured_content["NewSerialNumber"] == "SERIAL0001"
    masked = await build_server(service, Gate(False, False), redact_serial_numbers=True).call_tool("system_info", {})
    assert masked.structured_content["NewSerialNumber"] == "***"
    assert masked.structured_content["nested"] == [{"udn": "***"}]
    assert masked.structured_content["model"] == "7583"
