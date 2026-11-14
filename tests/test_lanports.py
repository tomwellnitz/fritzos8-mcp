from __future__ import annotations

import copy
import json

import httpx
import pytest

from fritzos8_mcp.errors import (
    ConfirmationRequiredError,
    InvalidParameterError,
    NotFoundError,
    TierDisabledError,
    UnsupportedFirmwareError,
)
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.lanports import LanPortClient, parse_port

from .conftest import FakeBox, FakeFC, make_service
from .fixtures_api import ETH_PORTS


@pytest.fixture
def ports(fake_box: FakeBox, landevices: LanDeviceClient) -> LanPortClient:
    fake_box.generic["eth_ports"] = copy.deepcopy(ETH_PORTS)
    return LanPortClient(landevices.rest)


def _puts(fake_box: FakeBox) -> list[tuple[str, dict]]:
    return [(r.url.path, json.loads(r.content)) for r in fake_box.requests if r.method == "PUT"]


def test_parse_port_maps_values() -> None:
    p = parse_port(ETH_PORTS["eth"][1])
    assert p["label"] == "LAN:2"
    assert p["connected"] is True
    assert p["speed_mbit"] == 100
    assert p["below_max_speed"] is True
    assert p["eee_mode"] == "auto"
    assert p["eee_active"] is False
    assert p["power_mode"] == "power"
    disconnected = parse_port(ETH_PORTS["eth"][2])
    assert disconnected["speed_mbit"] is None and disconnected["function"] == "guest"
    assert parse_port({**ETH_PORTS["eth"][0], "mode": "1", "eee_mode": "7"})["power_mode"] == "unbekannt (1)"


def test_status_lists_ports_and_notes(ports: LanPortClient) -> None:
    r = ports.status()
    assert r["count"] == 4
    assert [p["label"] for p in r["ports"]] == ["LAN:1", "LAN:2", "LAN:3", "WAN:1"]
    assert r["ports"][0]["eee_active"] is True
    assert "LAN:1" in r["eee_enabled_ports"]
    assert any("box-weit" in n for n in r["notes"])
    assert any("LAN:2" in n for n in r["notes"])  # 100 of 1000 Mbit/s


@pytest.mark.parametrize("name", ["LAN:2", "lan 2", "LAN2", "2", "eth1", "ethport8055"])
def test_resolve_port_spellings(ports: LanPortClient, name: str) -> None:
    assert ports.resolve(name)["UID"] == "ethport8055"


def test_resolve_unknown_port(ports: LanPortClient) -> None:
    with pytest.raises(NotFoundError, match="LAN:1"):
        ports.resolve("LAN:9")


def test_set_eee_single_port_sends_only_field(ports: LanPortClient, fake_box: FakeBox) -> None:
    r = ports.set_eee("LAN:1", "off")
    assert _puts(fake_box) == [("/api/v0/generic/eth_ports/eth/ethport8054", {"eee_mode": "2"})]
    assert r["verified"] is True
    assert r["ports"][0] == {
        "port": "LAN:1",
        "uid": "ethport8054",
        "before": "auto",
        "after": "off",
        "written": True,
        "verified": True,
    }
    assert r["other_ports_changed"] == []
    assert r["box_wide_effect"] is False


def test_set_eee_reports_box_wide_change(ports: LanPortClient, fake_box: FakeBox) -> None:
    fake_box.eee_box_wide = True
    r = ports.set_eee("LAN:1", "off")
    assert r["verified"] is True
    assert r["box_wide_effect"] is True
    assert {c["port"] for c in r["other_ports_changed"]} == {"LAN:2", "LAN:3", "WAN:1"}
    assert any("box-weit" in n for n in r["notes"])


def test_set_eee_all_writes_once_when_box_wide(ports: LanPortClient, fake_box: FakeBox) -> None:
    fake_box.eee_box_wide = True
    r = ports.set_eee("all", "off")
    assert len(_puts(fake_box)) == 1
    assert r["verified"] is True and all(p["verified"] for p in r["ports"])
    assert r["box_wide_effect"] is True


def test_set_eee_all_writes_each_port_otherwise(ports: LanPortClient, fake_box: FakeBox) -> None:
    r = ports.set_eee("alle", "off")
    assert len(_puts(fake_box)) == 4
    assert r["verified"] is True and r["box_wide_effect"] is False


def test_set_eee_unchanged_writes_nothing(ports: LanPortClient, fake_box: FakeBox) -> None:
    r = ports.set_eee("LAN:1", "auto")
    assert _puts(fake_box) == []
    assert r["changed"] is False and r["verified"] is True


def test_set_eee_silent_discard_is_confirmation_required(ports: LanPortClient, fake_box: FakeBox) -> None:
    fake_box.discard_writes = True
    with pytest.raises(ConfirmationRequiredError, match="Nichts geändert"):
        ports.set_eee("LAN:1", "off")


def test_set_eee_two_factor_answer(ports: LanPortClient, fake_box: FakeBox) -> None:
    fake_box.put_response = httpx.Response(403, text='{"errors":["TWO-FACTOR"]}')
    with pytest.raises(ConfirmationRequiredError):
        ports.set_eee("LAN:1", "off")


def test_set_eee_rejects_bad_mode_and_unsupported(ports: LanPortClient, fake_box: FakeBox) -> None:
    with pytest.raises(InvalidParameterError):
        ports.set_eee("LAN:1", "green")
    fake_box.generic["eth_ports"]["eth"][0]["eee_supported"] = "0"
    with pytest.raises(InvalidParameterError, match="kein EEE"):
        ports.set_eee("LAN:1", "off")


def test_missing_endpoint_is_unsupported_firmware(landevices: LanDeviceClient) -> None:
    with pytest.raises(UnsupportedFirmwareError):
        LanPortClient(landevices.rest).ports()


def test_service_write_needs_tier(fake_box: FakeBox, landevices: LanDeviceClient, fc: FakeFC) -> None:
    fake_box.generic["eth_ports"] = copy.deepcopy(ETH_PORTS)
    svc = make_service(landevices, fc, write=False, critical=False)
    assert svc.connectivity.lan_ports()["count"] == 4
    with pytest.raises(TierDisabledError):
        svc.connectivity.set_lan_eee("LAN:1", "off")
