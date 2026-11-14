"""Stage 8.12 – system transparency (TR-069, NTP, IPv6/DS-Lite, routes, forced disconnect)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fritzconnection.core.exceptions import FritzActionError, FritzServiceError

from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.transparency import SystemTransparency

from .conftest import FakeFC, make_service

NOW = datetime(2026, 11, 14, 12, 0, 0, tzinfo=UTC).timestamp()

RESPONSES: dict[tuple[str, str], Any] = {
    ("ManagementServer1", "GetInfo"): {
        "NewURL": "https://acs.provider.example:7547/cwmp?id=1",
        "NewUsername": "acs-user-geheim",
        "NewConnectionRequestUsername": "cr-user",
        "NewConnectionRequestURL": "http://198.51.100.9:8089/geheimer-pfad",
        "NewPeriodicInformEnable": "1",
        "NewPeriodicInformInterval": "86400",
        "NewUpgradesManaged": "0",
        "NewParameterKey": "pk",
    },
    ("ManagementServer1", "X_AVM_DE_GetTR069FirmwareDownloadEnabled"): {"NewTR069FirmwareDownloadEnabled": "1"},
    ("Time1", "GetInfo"): {
        "NewNTPServer1": "ntp1.example",
        "NewNTPServer2": "",
        "NewCurrentLocalTime": "2026-11-14T13:05:00+01:00",  # 5 min ahead
    },
    ("WANIPConnection1", "GetStatusInfo"): {"NewConnectionStatus": "Connected"},
    ("WANIPConnection1", "GetInfo"): {"NewX_AVM-DE_IPv6ConnectionStatus": "Connected", "NewX_AVM-DE_IPv6Uptime": 99},
    ("WANIPConnection1", "X_AVM_DE_GetIPv6Prefix"): FritzActionError("x"),
    ("WANIPConn1", "X_AVM_DE_GetIPv6Prefix"): {
        "NewIPv6Prefix": "2001:db8:1234:5600::",
        "NewPrefixLength": 56,
        "NewValidLifetime": 7200,
        "NewPreferedLifetime": 3600,
    },
    ("WANIPConnection1", "X_AVM_DE_GetDsliteStatus"): FritzActionError("x"),
    ("WANIPConn1", "X_AVM_DE_GetDsliteStatus"): {"NewX_AVM_DE_DsliteStatus": "1"},
    ("WANIPv6Firewall1", "GetFirewallStatus"): FritzServiceError("x"),
    ("WANIPv6FirewallControl1", "GetFirewallStatus"): {"NewFirewallEnabled": "1", "NewInboundPinholeAllowed": "0"},
    ("Layer3Forwarding1", "GetForwardNumberOfEntries"): {"NewForwardNumberOfEntries": 1},
    ("Layer3Forwarding1", "GetGenericForwardingEntry"): lambda NewForwardingIndex: {
        "NewEnable": "1",
        "NewStatus": "Enabled",
        "NewDestIPAddress": "192.0.2.128",
        "NewDestSubnetMask": "255.255.255.128",
        "NewGatewayIPAddress": "192.0.2.254",
        "NewForwardingMetric": 1,
    },
    ("WANPPPConnection1", "X_AVM_DE_GetAutoDisconnectTimeSpan"): {
        "NewX_AVM-DE_DisconnectPreventionEnable": "1",
        "NewX_AVM-DE_DisconnectPreventionHour": "4",
    },
    ("UserInterface1", "GetInfo"): {"NewUpgradeAvailable": "0"},
    ("UserInterface1", "X_AVM-DE_GetInfo"): {"NewX_AVM-DE_AutoUpdateMode": "important"},
}


def transparency(
    landevices: LanDeviceClient, responses: dict[tuple[str, str], Any] | None = None
) -> SystemTransparency:
    svc = make_service(landevices, FakeFC(dict(RESPONSES if responses is None else responses)))
    svc.transparency.now = lambda: NOW
    return svc.transparency


def test_overview_all_sections(landevices: LanDeviceClient) -> None:
    r = transparency(landevices).overview()
    t = r["tr069"]
    assert (
        t["active"] is True and t["acs"] == "https://acs.provider.example" and t["provider_firmware_download"] is True
    )
    assert (
        r["time"]["offset_s"] == 300.0
        and r["time"]["offset_ok"] is False
        and r["time"]["ntp_servers"] == ["ntp1.example"]
    )
    v6 = r["ipv6"]
    assert (
        v6["prefix"] == "2001:db8:1234:5600::/56" and v6["ds_lite"] is True and v6["connection_status"] == "Connected"
    )
    assert v6["firewall"] == {"service": "WANIPv6FirewallControl1", "enabled": True, "inbound_pinholes_allowed": False}
    assert r["static_routes"]["routes"][0]["gateway"] == "192.0.2.254"
    assert r["forced_disconnect"]["available"] is False  # active service is not PPP
    assert r["auto_update"]["mode"] == "important"


PPP = {
    ("WANIPConnection1", "GetStatusInfo"): FritzServiceError("x"),
    ("WANPPPConnection1", "GetStatusInfo"): {"NewConnectionStatus": "Connected"},
}


def test_forced_disconnect_on_active_ppp_service(landevices: LanDeviceClient) -> None:
    fd = transparency(landevices, {**RESPONSES, **PPP}).forced_disconnect()
    assert fd["hour"] == 4 and "4–5" in fd["meaning"]


def test_forced_disconnect_dash_spelling_and_not_found(landevices: LanDeviceClient) -> None:
    """Live korrigiert: 7583 (PPP, 8.26) meldet not_found; Kabel-Box hat keinen PPP-Dienst."""
    responses = {**RESPONSES, **PPP}
    responses[("WANPPPConnection1", "X_AVM_DE_GetAutoDisconnectTimeSpan")] = FritzActionError("x")
    responses[("WANPPPConnection1", "X_AVM-DE_GetAutoDisconnectTimeSpan")] = {
        "NewX_AVM-DE_DisconnectPreventionEnable": "0",
    }
    assert transparency(landevices, responses).forced_disconnect()["shift_enabled"] is False
    responses[("WANPPPConnection1", "X_AVM-DE_GetAutoDisconnectTimeSpan")] = FritzActionError("x")
    fd = transparency(landevices, responses).forced_disconnect()
    assert fd["available"] is False and "Web-UI" in fd["note"] and "error" not in fd
    cable = transparency(landevices).forced_disconnect()
    assert cable["available"] is False and "PPP" in cable["note"]
    fc = FakeFC(dict(RESPONSES))
    make_service(landevices, fc).transparency.forced_disconnect()
    assert not any(a.endswith("AutoDisconnectTimeSpan") for _, a, _ in fc.calls)


def test_no_tr069_credentials_or_connection_request_url(landevices: LanDeviceClient) -> None:
    text = str(transparency(landevices).overview())
    for secret in ("acs-user-geheim", "cr-user", "geheimer-pfad", "id=1"):
        assert secret not in text


def test_sections_degrade_independently(landevices: LanDeviceClient) -> None:
    responses = dict(RESPONSES)
    responses[("ManagementServer1", "GetInfo")] = FritzServiceError("x")
    responses[("WANPPPConnection1", "X_AVM_DE_GetAutoDisconnectTimeSpan")] = FritzActionError("x")
    responses[("WANIPv6FirewallControl1", "GetFirewallStatus")] = FritzServiceError("x")
    r = transparency(landevices, responses).overview()
    assert r["tr069"]["status"] == "unknown" and r["forced_disconnect"]["available"] is False
    assert r["ipv6"]["firewall"]["status"] == "unknown" and r["time"]["available"] is True


def test_ipv6_without_prefix_and_without_status_field(landevices: LanDeviceClient) -> None:
    """Live korrigiert (6660 Cable ohne IPv6, 8.25): Präfix "::"/0, Lebensdauer 0; Statusfeld fehlt (beide Boxen)."""
    responses = dict(RESPONSES)
    responses[("WANIPConnection1", "GetInfo")] = {"NewConnectionStatus": "Connected"}
    responses[("WANIPConn1", "X_AVM_DE_GetIPv6Prefix")] = {
        "NewIPv6Prefix": "::",
        "NewPrefixLength": 0,
        "NewValidLifetime": 0,
        "NewPreferedLifetime": 0,
    }
    v6 = transparency(landevices, responses).ipv6()
    assert v6["prefix"] is None and v6["ipv6_active"] is False
    assert "kein IPv6-Präfix" in v6["prefix_note"]
    assert v6["connection_status"] == "unknown" and "12/2025" in v6["connection_status_note"]


def test_ipv6_active_derived_from_prefix(landevices: LanDeviceClient) -> None:
    responses = dict(RESPONSES)
    responses[("WANIPConnection1", "GetInfo")] = {}
    v6 = transparency(landevices, responses).ipv6()
    assert v6["prefix"] == "2001:db8:1234:5600::/56" and v6["ipv6_active"] is True


def test_ipv6_firewall_fields_without_new_prefix(landevices: LanDeviceClient) -> None:
    """Live korrigiert (7583/8.26): WANIPv6Firewall1 liefert FirewallEnabled/InboundPinholeAllowed ohne 'New' –
    vorher wurde daraus fälschlich false/false."""
    responses = dict(RESPONSES)
    responses[("WANIPv6Firewall1", "GetFirewallStatus")] = {"FirewallEnabled": "1", "InboundPinholeAllowed": "1"}
    fw = transparency(landevices, responses).ipv6()["firewall"]
    assert fw == {"service": "WANIPv6Firewall1", "enabled": True, "inbound_pinholes_allowed": True}


def test_ipv6_firewall_unreadable_fields_are_unknown(landevices: LanDeviceClient) -> None:
    responses = dict(RESPONSES)
    responses[("WANIPv6FirewallControl1", "GetFirewallStatus")] = {"Other": "x"}
    fw = transparency(landevices, responses).ipv6()["firewall"]
    assert fw["enabled"] is None and fw["status"] == "unknown"


def test_doctor_findings_and_security_item(landevices: LanDeviceClient) -> None:
    t = transparency(landevices)
    findings = t.doctor_findings()
    areas = {(f["area"], f["severity"]) for f in findings}
    assert ("system", "warn") in areas and ("wan", "info") in areas
    status, summary, details = t.security_item()
    assert status == "ok" and "TR-069" in summary and "Firmware" in summary and details["active"] is True


def test_security_check_and_doctor_include_transparency(landevices: LanDeviceClient) -> None:
    svc = make_service(landevices, FakeFC(dict(RESPONSES)))
    svc.transparency.now = lambda: NOW
    sec = svc.security_check()
    item = next(c for c in sec["checks"] if c["check"] == "provider_fernwartung")
    assert item["weight"] == 0 and item["status"] == "ok"
    doc = svc.network_doctor()
    assert doc["sources"]["system"] == "ok" and any("Uhrzeit" in f["finding"] for f in doc["findings"])
