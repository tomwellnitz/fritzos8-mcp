"""Stage 10.7 – one AVM device in detail over the box interfaces (invented values)."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from fritzconnection.core.exceptions import FritzActionError

from fritzos8_mcp.devices import DeviceUpdateClient
from fritzos8_mcp.errors import InvalidParameterError, NotFoundError
from fritzos8_mcp.tr064 import Tr064Client

from .conftest import FakeFC

REPEATER_MAC = "AA:BB:CC:00:00:50"
PLC_MAC = "AA:BB:CC:00:00:60"

MESH = {
    "nodes": [
        {
            "uid": "n-box",
            "device_name": "fritz.box",
            "mesh_role": "master",
            "is_meshed": True,
            "node_interfaces": [{"uid": "i-box", "name": "AP:5G:0", "type": "WLAN", "node_links": []}],
        },
        {
            "uid": "n-rep",
            "device_name": "Repeater Flur",
            "device_mac_address": REPEATER_MAC,
            "device_model": "FRITZ!Repeater 3000",
            "mesh_role": "slave",
            "is_meshed": True,
            "node_interfaces": [
                {
                    "uid": "i-rep-up",
                    "name": "UPLINK:5G:0",
                    "type": "WLAN",
                    "node_links": [
                        {
                            "uid": "l1",
                            "state": "CONNECTED",
                            "type": "WLAN",
                            "node_1_uid": "n-box",
                            "node_2_uid": "n-rep",
                            "cur_data_rate_rx": 866000,
                            "cur_data_rate_tx": 650000,
                        }
                    ],
                },
                {
                    "uid": "i-rep-ap",
                    "name": "AP:2G:0",
                    "type": "WLAN",
                    "node_links": [
                        {
                            "uid": "l2",
                            "state": "CONNECTED",
                            "type": "WLAN",
                            "node_1_uid": "n-rep",
                            "node_2_uid": "n-tv",
                        },
                        {
                            "uid": "l3",
                            "state": "DISCONNECTED",
                            "type": "WLAN",
                            "node_1_uid": "n-rep",
                            "node_2_uid": "n-x",
                        },
                    ],
                },
            ],
        },
        {"uid": "n-tv", "device_name": "TV", "device_mac_address": "AA:BB:CC:00:00:70", "node_interfaces": []},
    ]
}


def _client(responses: dict[tuple[str, str], Any], mesh: dict[str, Any] | None = MESH) -> DeviceUpdateClient:
    fc = FakeFC(responses)
    tr = Tr064Client(lambda: fc, ())  # type: ignore[arg-type,return-value]
    return DeviceUpdateClient(tr, None, mesh=(lambda: copy.deepcopy(mesh)) if mesh else None)  # type: ignore[arg-type]


def test_dect_ule_by_id() -> None:
    c = _client(
        {
            ("X_AVM-DE_Dect1", "GetSpecificDectEntry"): lambda NewID: {
                "NewName": "Heizung",
                "NewModel": "FRITZ!Smart Thermo 301",
                "NewActive": "1",
                "NewUpdateAvailable": "0",
                "NewUpdateSuccessful": "succeeded",
            }
        }
    )
    r = c.device_detail("16")
    assert r["found_in"] == ["dect"]
    assert r["dect"]["kind"] == "dect_ule" and r["dect"]["last_update"] == "succeeded"


def test_repeater_by_mac_merges_mesh_node() -> None:
    c = _client({("X_AVM-DE_Homeplug1", "GetSpecificDeviceEntry"): FritzActionError("errorCode: 714")})
    r = c.device_detail(REPEATER_MAC.lower())
    assert r["found_in"] == ["mesh"]
    node = r["mesh"]
    assert node["model"] == "FRITZ!Repeater 3000" and node["mesh_role"] == "slave"
    assert node["uplinks"] == [
        {
            "interface": "UPLINK:5G:0",
            "type": "WLAN",
            "peer": "fritz.box",
            "peer_is_mesh_node": True,
            "rate_rx_mbit": 866.0,
            "rate_tx_mbit": 650.0,
        }
    ]
    assert node["clients"] == 1  # disconnected link does not count


def test_powerline_by_mac() -> None:
    c = _client(
        {
            ("X_AVM-DE_Homeplug1", "GetSpecificDeviceEntry"): lambda NewMACAddress: {
                "NewName": "PLC Keller",
                "NewModel": "FRITZ!Powerline 1260",
                "NewActive": "1",
                "NewUpdateAvailable": "1",
            }
        },
        mesh=None,
    )
    r = c.device_detail(PLC_MAC)
    assert r["powerline"]["update_available"] is True and "powerline" in r["found_in"]


def test_by_name_and_not_found() -> None:
    c = _client({})
    assert c.device_detail("Repeater Flur")["mesh"]["name"] == "Repeater Flur"
    with pytest.raises(NotFoundError):
        c.device_detail("Unbekannt")
    with pytest.raises(InvalidParameterError):
        c.device_detail(" ")


def test_non_decimal_digits_and_oversized_rates() -> None:
    """'²'.isdigit() is True but int('²') raises – the query and mesh rates must not crash (found by fuzzing)."""
    mesh = copy.deepcopy(MESH)
    link = mesh["nodes"][1]["node_interfaces"][0]["node_links"][0]
    link.update(cur_data_rate_rx="²", cur_data_rate_tx="9" * 400)
    c = _client({}, mesh=mesh)
    with pytest.raises(NotFoundError):
        c.device_detail("²")
    uplink = c.device_detail(REPEATER_MAC)["mesh"]["uplinks"][0]
    assert uplink["rate_rx_mbit"] is None and uplink["rate_tx_mbit"] is None
