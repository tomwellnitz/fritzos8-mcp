from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest

from fritzos8_mcp.errors import UnsupportedFirmwareError
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.vpnplc import RAW_LIMIT, VpnPlcClient, epoch_to_iso, parse_vpn

from .conftest import FakeBox, FakeFC, make_service
from .fixtures_api import FAKE_SECRETS, PLC, VPN


def _no_secret(data: object) -> None:
    text = json.dumps(data, ensure_ascii=False)
    for secret in FAKE_SECRETS:
        assert secret not in text, secret
    for marker in ("PrivateKey", "PresharedKey", "[Interface]", "wg_preshared_key", "xauth", "access_psk"):
        assert marker not in text, marker


@pytest.fixture
def client(fake_box: FakeBox, landevices: LanDeviceClient) -> VpnPlcClient:
    fake_box.generic["vpn"] = copy.deepcopy(VPN)
    fake_box.generic["plc"] = copy.deepcopy(PLC)
    return VpnPlcClient(landevices.rest)


def test_vpn_connections_whitelisted(client: VpnPlcClient) -> None:
    r = client.vpn_connections()
    _no_secret(r)
    assert r["count"] == 2 and r["active"] == 1
    wg, ipsec = r["connections"]
    assert wg["type"] == "WireGuard" and ipsec["type"] == "IPSec"
    assert wg["state_label"] == "verbunden/bereit"
    assert wg["connected_since"] == "2025-11-14T11:33:20+00:00"
    assert wg["remote"] == "box-b.example:51820"
    assert wg["local_networks"] == ["192.0.2.0/24"] and wg["remote_networks"] == ["198.51.100.0/24"]
    assert wg["error"] is None
    assert ipsec["activated"] is False and ipsec["connected_since"] is None
    assert r["wireguard_listen_port"] == 51820


def test_parse_vpn_is_safe_even_without_rest_redaction() -> None:
    # whitelist alone must already keep every secret out
    _no_secret(parse_vpn(copy.deepcopy(VPN)))


def test_vpn_error_code_reported() -> None:
    doc = {"connection": [{"name": "x", "wg_endpoint": "a", "wg_error": "3", "wg_error_reason": "handshake"}]}
    c = parse_vpn(doc)["connections"][0]
    assert c["error"]["code"] == "3" and c["error"]["reason"] == "handshake" and c["error"]["active"] is True
    assert c["last_error"] is None


def test_vpn_error_on_connected_link_is_historical() -> None:
    """Live (7583, 8.26): state ready together with wg_error 3400 / reason 3430."""
    doc = {
        "connection": [
            {"name": "x", "wg_endpoint": "a", "state": "ready", "wg_error": "3400", "wg_error_reason": "3430"}
        ]
    }
    c = parse_vpn(doc)["connections"][0]
    assert c["error"] is None
    assert c["last_error"]["code"] == "3400" and c["last_error"]["reason"] == "3430"
    assert c["last_error"]["historical"] is True and c["last_error"]["description"] is None
    assert "kein aktiver" in c["last_error"]["note"]


@pytest.mark.parametrize("value", ["0", "", None, "abc", "-5"])
def test_epoch_to_iso_invalid(value: object) -> None:
    assert epoch_to_iso(value) is None


def test_powerline_status(client: VpnPlcClient) -> None:
    r = client.powerline()
    text = json.dumps(r)
    assert "FAKE-DPW" not in text and "FAKE-plc-pass" not in text
    dev = r["devices"][0]
    assert dev["model"] == "FRITZ!Powerline 1260"
    assert dev["mac"] == "AA:BB:CC:DD:EE:50"
    assert dev["phy_rate_rx"] == 512 and dev["green_mode"] is True and dev["local"] is False
    assert dev["remote_adapters"][0]["phy_rate_tx"] == 470
    assert r["power_save"] is True and r["hints"] == []


def test_powerline_hints_low_rate_and_update(client: VpnPlcClient, fake_box: FakeBox) -> None:
    fake_box.generic["plc"]["device"][0].update({"phyRateRX": "40", "hasFirmwareupdate": "1"})
    hints = client.powerline()["hints"]
    assert any("niedrige PHY-Rate" in h for h in hints) and any("Firmware" in h for h in hints)


def test_missing_endpoints(landevices: LanDeviceClient) -> None:
    c = VpnPlcClient(landevices.rest)
    with pytest.raises(UnsupportedFirmwareError):
        c.vpn_connections()
    lists = c.web_firewall_lists()
    assert lists["forwardrules"]["available"] is False


def test_raw_documents_redacted_and_marked(client: VpnPlcClient, fake_box: FakeBox) -> None:
    fake_box.generic["forwardrules"] = {"rule": [{"name": "nas", "port": "443", "secret": "FAKE-user"}]}
    fake_box.generic["ipv6firewall"] = {"x": "y" * (RAW_LIMIT + 10)}
    r = client.web_firewall_lists()
    assert r["forwardrules"]["verified_structure"] is False
    assert r["forwardrules"]["raw"]["rule"][0]["secret"] == "***"
    assert "unverifiziert" in r["forwardrules"]["note"]
    assert r["ipv6firewall"]["raw_truncated"] is True and len(r["ipv6firewall"]["raw_json"]) == RAW_LIMIT


def test_vpn_status_uses_api_v0_when_available(fake_box: FakeBox, landevices: LanDeviceClient) -> None:
    fake_box.generic["vpn"] = copy.deepcopy(VPN)
    fc = FakeFC()
    fc.services["X_AVM-DE_WireGuardVPN1"] = SimpleNamespace(actions={}, state_variables={})
    r = make_service(landevices, fc).vpn_status()
    _no_secret(r)
    section = r["vpn_connections"]
    assert section["status"] == "known" and section["count"] == 2
    assert section["tr064_services_found"] == ["X_AVM-DE_WireGuardVPN1"]


def test_vpn_status_keeps_unknown_without_api_v0(landevices: LanDeviceClient) -> None:
    r = make_service(landevices, FakeFC()).vpn_status()
    assert r["vpn_connections"]["status"] == "unknown"
    assert r["vpn_connections"]["api_v0_error"]["type"] == "unsupported_firmware"


def test_list_port_forwards_web_lists_opt_in(fake_box: FakeBox, landevices: LanDeviceClient) -> None:
    fake_box.generic["forwardrules"] = {"rule": []}
    fc = FakeFC({("WANIPConn1", "GetStatusInfo"): {"NewConnectionStatus": "Connected"}})
    svc = make_service(landevices, fc)
    plain = svc.list_port_forwards()
    assert "web_ui_lists" not in plain
    assert "web_ui_lists" in svc.list_port_forwards(include_web_ui_lists=True)
