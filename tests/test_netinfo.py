from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from fritzconnection.core.exceptions import FritzActionError, FritzServiceError

from fritzos8_mcp.errors import ActionDeniedError, FritzError, NotFoundError, TierDisabledError
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.netinfo import band_of_channel, parse_mesh, rcpi_to_dbm
from fritzos8_mcp.redact import is_secret_field, redact_obj
from fritzos8_mcp.security import check_generic_action, is_denied

from .conftest import FakeFC, make_service

MESH = {
    "schema_version": "5.6.1",
    "nodes": [
        {
            "uid": "n-box",
            "device_name": "fritz.box",
            "device_model": "FRITZ!Box 7583",
            "device_mac_address": "AA:BB:CC:00:00:01",
            "device_firmware_version": "164.08.26",
            "is_meshed": True,
            "mesh_role": "master",
            "node_interfaces": [
                {
                    "uid": "i-box-5",
                    "type": "WLAN",
                    "current_channel": 36,
                    "node_links": [
                        {
                            "uid": "l-rep",
                            "type": "WLAN",
                            "state": "CONNECTED",
                            "node_1_uid": "n-box",
                            "node_2_uid": "n-rep",
                            "node_interface_1_uid": "i-box-5",
                            "node_interface_2_uid": "i-rep-5",
                            "cur_data_rate_rx": 866000,
                            "cur_data_rate_tx": 780000,
                            "rx_rcpi": 120,
                        },
                        {
                            "uid": "l-phone",
                            "type": "WLAN",
                            "state": "CONNECTED",
                            "node_1_uid": "n-box",
                            "node_2_uid": "n-phone",
                            "node_interface_1_uid": "i-box-5",
                            "node_interface_2_uid": "i-phone",
                            "cur_data_rate_rx": 144000,
                            "cur_data_rate_tx": 72000,
                            "rx_rcpi": 60,
                        },
                    ],
                },
                {
                    "uid": "i-box-lan",
                    "type": "LAN",
                    "node_links": [
                        {
                            "uid": "l-nas",
                            "type": "LAN",
                            "state": "CONNECTED",
                            "node_1_uid": "n-box",
                            "node_2_uid": "n-nas",
                            "node_interface_1_uid": "i-box-lan",
                            "node_interface_2_uid": "i-nas",
                            "cur_data_rate_rx": 1000000,
                            "cur_data_rate_tx": 1000000,
                        },
                        {
                            "uid": "l-old",
                            "type": "LAN",
                            "state": "DISCONNECTED",
                            "node_1_uid": "n-box",
                            "node_2_uid": "n-nas",
                        },
                    ],
                },
            ],
        },
        {
            "uid": "n-rep",
            "device_name": "Repeater-Flur",
            "device_model": "FRITZ!Repeater 1200 AX",
            "is_meshed": True,
            "mesh_role": "slave",
            "node_interfaces": [{"uid": "i-rep-5", "type": "WLAN", "current_channel": 36, "node_links": []}],
        },
        {
            "uid": "n-phone",
            "device_name": "Handy",
            "device_mac_address": "AA:BB:CC:00:00:10",
            "mesh_role": "unknown",
            "node_interfaces": [{"uid": "i-phone", "type": "WLAN"}],
        },
        {
            "uid": "n-nas",
            "device_name": "NAS",
            "device_mac_address": "AA:BB:CC:00:00:20",
            "node_interfaces": [{"uid": "i-nas", "type": "LAN"}],
        },
    ],
}


def test_helpers() -> None:
    assert rcpi_to_dbm(120) == -50 and rcpi_to_dbm(255) is None and rcpi_to_dbm("x") is None
    # schema v8.7: value already in dBm
    assert rcpi_to_dbm(-67) == -67.0 and rcpi_to_dbm("-80") == -80.0 and rcpi_to_dbm(0) is None
    assert band_of_channel(6) == "2.4" and band_of_channel(100) == "5" and band_of_channel(0) is None


def test_parse_mesh() -> None:
    m = parse_mesh(MESH)
    assert m["mesh_master"] == "fritz.box"
    assert [n["name"] for n in m["nodes"]] == ["fritz.box", "Repeater-Flur"]
    assert m["backbone"] == [
        {
            "from": "fritz.box",
            "to": "Repeater-Flur",
            "type": "WLAN",
            "band_ghz": "5",
            "rate_down_mbit": 866.0,
            "rate_up_mbit": 780.0,
            "max_rate_down_mbit": None,
            "max_rate_up_mbit": None,
            "signal_dbm": -50.0,
        }
    ]
    clients = {c["name"]: c for c in m["clients"]}
    assert set(clients) == {"Handy", "NAS"}  # disconnected link ignored
    assert clients["Handy"]["band_ghz"] == "5" and clients["Handy"]["signal_dbm"] == -80.0
    assert clients["NAS"]["type"] == "LAN" and clients["NAS"]["rate_down_mbit"] == 1000.0
    assert m["summary"]["weak_signal_clients"] == ["Handy"]
    assert m["summary"]["clients_per_node"] == {"fritz.box": 2}


def test_parse_mesh_merges_station_signal_percent() -> None:
    import copy

    doc = copy.deepcopy(MESH)
    for link in doc["nodes"][0]["node_interfaces"][0]["node_links"]:
        link["rx_rcpi"] = 255  # live: no signal in the mesh list
    stations = {
        "AA:BB:CC:00:00:10": {"signal_percent": 40, "signal_dbm_estimated": -80.0, "speed_mbit": 144},
    }
    m = parse_mesh(doc, stations)
    handy = next(c for c in m["clients"] if c["name"] == "Handy")
    assert handy["signal_dbm"] is None and handy["signal_percent"] == 40 and handy["signal_dbm_estimated"] == -80.0
    assert m["summary"]["weak_signal_clients"] == ["Handy"]
    assert m["summary"]["wlan_clients_without_signal"] == []
    assert parse_mesh(doc)["summary"]["wlan_clients_without_signal"] == ["Handy"]


def mesh_fc(doc: Any = MESH) -> FakeFC:
    fc = FakeFC(
        {("Hosts1", "X_AVM-DE_GetMeshListPath"): {"NewX_AVM-DE_MeshListPath": "/meshlist.lua?sid=0123456789abcdef"}}
    )
    body = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
    fc.session = SimpleNamespace(get=lambda url: SimpleNamespace(ok=True, content=body))
    return fc


def test_mesh_overview_service(landevices: LanDeviceClient) -> None:
    r = make_service(landevices, mesh_fc()).mesh_overview()
    assert r["summary"]["nodes"] == 2 and r["summary"]["clients"] == 2
    assert r["signal_source"] == "keine TR-064-Signaldaten"


def test_mesh_overview_errors(landevices: LanDeviceClient) -> None:
    fc = FakeFC({("Hosts1", "X_AVM-DE_GetMeshListPath"): FritzActionError("x")})
    with pytest.raises(NotFoundError):
        make_service(landevices, fc).mesh_overview()
    with pytest.raises(FritzError) as ei:
        make_service(landevices, mesh_fc(b"<html>")).mesh_overview()
    assert "0123456789abcdef" not in str(ei.value)


# ------------------------------------------------------------------ online monitor


def test_online_monitor(landevices: LanDeviceClient) -> None:
    fc = FakeFC(
        {
            ("WANCommonInterfaceConfig1", "X_AVM-DE_GetOnlineMonitor"): {
                "NewSyncGroupName": "sg0",
                "NewSyncGroupMode": "VDSL",
                "Newmax_ds": 12_500_000,
                "Newmax_us": 5_000_000,
                "Newds_current_bps": "1250000,250000,0",
                "Newus_current_bps": "125000,125000,125000",
            },
            ("WANCommonInterfaceConfig1", "X_AVM-DE_GetAddonInfos"): {
                "NewX_AVM_DE_TotalBytesSent64": "2000000000",
                "NewX_AVM_DE_TotalBytesReceived64": "30000000000",
            },
        }
    )
    r = make_service(landevices, fc).online_monitor()
    t = r["throughput"]
    assert t["down"]["current_mbit_s"] == 10.0 and t["down"]["avg_mbit_s"] == 4.0 and t["down"]["samples"] == 3
    assert t["up"]["current_mbit_s"] == 1.0 and t["max_down_mbit_s"] == 100.0
    assert r["volume"]["received_gb"] == 30.0 and "64 bit" in r["volume"]["source"]
    assert r["day_month_volume"]["available"] is False


def test_online_monitor_fallbacks(landevices: LanDeviceClient) -> None:
    fc = FakeFC(
        {
            ("WANCommonInterfaceConfig1", "X_AVM-DE_GetOnlineMonitor"): FritzActionError("x"),
            ("WANCommonInterfaceConfig1", "X_AVM-DE_GetAddonInfos"): FritzActionError("x"),
            ("WANCommonInterfaceConfig1", "GetTotalBytesSent"): {"NewTotalBytesSent": 1000},
            ("WANCommonInterfaceConfig1", "GetTotalBytesReceived"): {"NewTotalBytesReceived": 2000},
        }
    )
    r = make_service(landevices, fc).online_monitor()
    assert r["throughput"]["available"] is False
    assert r["volume"]["sent_bytes"] == 1000 and "32 bit" in r["volume"]["source"]


def test_online_monitor_igd_64bit_and_rates(landevices: LanDeviceClient) -> None:
    """V-6: 64-bit counters from IGD WANCommonIFC1:GetAddonInfos, rates from the TR-064 action."""
    fc = FakeFC(
        {
            ("WANCommonIFC1", "GetAddonInfos"): {
                "NewX_AVM_DE_TotalBytesSent64": "5000000000",
                "NEWX_AVM_DE_TotalBytesReceived64": "60000000000",  # spelling as in the AVM IGD table
            },
            ("WANCommonInterfaceConfig1", "X_AVM-DE_GetAddonInfos"): {
                "NewX-AVM-DE_unused": "x",
                "NewX_AVM-DE_SyncDownstream": "116790000",
                "NewX_AVM-DE_SyncUpstream": "46720000",
                "NewX_AVM-DE_TariffDataRateDownstream": "0",
                "NewX_AVM-DE_WANAccessType": "DSL",
            },
        }
    )
    r = make_service(landevices, fc).online_monitor()
    assert r["volume"]["received_gb"] == 60.0 and r["volume"]["source"].startswith("IGD")
    assert r["rates"]["sync"] == {"down_mbit_s": 116.79, "up_mbit_s": 46.72}
    assert r["rates"]["tariff"]["down_mbit_s"] is None  # 0 = unknown
    assert r["rates"]["wan_access_type"] == "DSL"


def test_online_monitor_zero_counters_are_unknown(landevices: LanDeviceClient) -> None:
    """V-6: without IGD the 32-bit counters are 0 – that is 'unknown', not 0 bytes."""
    fc = FakeFC(
        {
            ("WANCommonIFC1", "GetAddonInfos"): FritzServiceError("x"),
            ("WANCommonInterfaceConfig1", "X_AVM-DE_GetAddonInfos"): FritzActionError("x"),
            ("WANCommonInterfaceConfig1", "GetTotalBytesSent"): {"NewTotalBytesSent": 0},
            ("WANCommonInterfaceConfig1", "GetTotalBytesReceived"): {"NewTotalBytesReceived": 0},
        }
    )
    r = make_service(landevices, fc).online_monitor()
    assert r["volume"]["available"] is False and r["volume"]["status"] == "unknown"
    assert "UPnP" in r["volume"]["hint"]
    assert r["rates"]["available"] is False


# ------------------------------------------------------------------ VPN / DynDNS


def test_vpn_status_never_leaks_credentials(landevices: LanDeviceClient) -> None:
    fc = FakeFC(
        {
            ("X_AVM-DE_MyFritz1", "GetInfo"): {
                "NewEnabled": "1",
                "NewDeviceRegistered": "1",
                "NewDynDNSName": "abc123.myfritz.example",
                "NewPort": 443,
            },
            ("X_AVM-DE_MyFritz1", "GetNumberOfServices"): {"NewNumberOfServices": 2},
            ("X_AVM-DE_RemoteAccess1", "GetInfo"): {"NewEnabled": "0", "NewPort": 0, "NewUsername": "admin-user"},
            ("X_AVM-DE_RemoteAccess1", "GetDDNSInfo"): {
                "NewEnabled": "1",
                "NewProviderName": "Example DNS",
                "NewDomain": "home.example.org",
                "NewStatusIPv4": "registered",
                "NewUsername": "ddns-user",
                "NewPassword": "ddns-geheim-123",
            },
        }
    )
    fc.services["X_AVM-DE_AppSetup1"] = SimpleNamespace(actions={}, state_variables={})
    fc.services["X_AVM-DE_WireGuardVPN1"] = SimpleNamespace(actions={}, state_variables={})
    r = make_service(landevices, fc).vpn_status()
    text = json.dumps(r)
    assert "ddns-geheim-123" not in text and "ddns-user" not in text and "admin-user" not in text
    assert r["myfritz"]["enabled"] is True and r["myfritz"]["services"] == 2
    assert r["dyndns"]["domain"] == "home.example.org" and r["dyndns"]["status_ipv4"] == "registered"
    assert r["remote_access"]["enabled"] is False
    assert r["vpn_connections"]["status"] == "unknown"
    assert r["vpn_connections"]["tr064_services_found"] == ["X_AVM-DE_WireGuardVPN1"]


def test_vpn_status_dyndns_legacy_action_name(landevices: LanDeviceClient) -> None:
    """AVM doc: GetDDNSInfo. Older spelling X_AVM-DE_GetDDNSInfo is only tried when the box lacks it."""
    fc = FakeFC(
        {
            ("X_AVM-DE_RemoteAccess1", "GetDDNSInfo"): FritzActionError("x"),
            ("X_AVM-DE_RemoteAccess1", "X_AVM-DE_GetDDNSInfo"): {"NewEnabled": "1", "NewDomain": "home.example.org"},
        }
    )
    r = make_service(landevices, fc).vpn_status()
    assert r["dyndns"]["domain"] == "home.example.org"
    tried = [a for s, a, _ in fc.calls if s == "X_AVM-DE_RemoteAccess1" and "DDNS" in a]
    assert tried == ["GetDDNSInfo", "X_AVM-DE_GetDDNSInfo"]


def test_call_first_stops_on_other_errors(landevices: LanDeviceClient) -> None:
    fc = FakeFC({("Svc1", "A"): FritzServiceError("x"), ("Svc1", "B"): {"NewX": 1}})
    tr = make_service(landevices, fc).tr064
    assert tr.call_first("Svc1", ("A", "B")) == ("B", {"NewX": 1})
    with pytest.raises(NotFoundError):
        tr.call_first("Svc1", ("A",))


def test_vpn_status_missing_services(landevices: LanDeviceClient) -> None:
    fc = FakeFC(
        {
            ("X_AVM-DE_MyFritz1", "GetInfo"): FritzServiceError("x"),
            ("X_AVM-DE_RemoteAccess1", "GetInfo"): FritzServiceError("x"),
            ("X_AVM-DE_RemoteAccess1", "GetDDNSInfo"): FritzActionError("x"),
            ("X_AVM-DE_RemoteAccess1", "X_AVM-DE_GetDDNSInfo"): FritzActionError("x"),
        }
    )
    r = make_service(landevices, fc).vpn_status()
    assert r["myfritz"]["available"] is False and r["dyndns"]["available"] is False


@pytest.mark.parametrize(
    "action",
    [
        "X_AVM-DE_GetAppVPN",
        "X_AVM-DE_GetAppVPNwithPFS",
        "X_AVM-DE_GetWireGuardSettings",
        "X_AVM-DE_GetDDNSInfo",
        "X_AVM-DE_GetVPNPeerList",
        "GetUserPassword",
    ],
)
def test_vpn_and_secret_actions_denied(action: str) -> None:
    assert is_denied(action)
    with pytest.raises(ActionDeniedError):
        check_generic_action("X_AVM-DE_AppSetup1", action)


def test_harmless_get_still_allowed() -> None:
    check_generic_action("DeviceInfo1", "GetInfo")
    check_generic_action("WANCommonInterfaceConfig1", "X_AVM-DE_GetOnlineMonitor")


@pytest.mark.parametrize(
    "field", ["NewWireGuardPrivateKey", "wg_key", "NewIPSecPreSharedKey", "private_key", "vpn_shared_key", "IKESecret"]
)
def test_vpn_fields_redacted(field: str) -> None:
    assert is_secret_field(field)
    assert redact_obj({field: "x-geheim"}) == {field: "***"}


def test_public_key_not_masked() -> None:
    assert not is_secret_field("NewPublicKeyFingerprint")


# ------------------------------------------------------------------ Wake on LAN


def wol_fc(hosts_active: bool = False) -> FakeFC:
    hosts = {"NewHostNumberOfEntries": 1}
    entry = {
        "NewHostName": "nas",
        "NewIPAddress": "192.0.2.20",
        "NewMACAddress": "AA:BB:CC:00:00:20",
        "NewActive": hosts_active,
    }
    return FakeFC(
        {
            ("Hosts1", "X_AVM-DE_GetHostListPath"): FritzActionError("x"),
            ("Hosts1", "GetHostNumberOfEntries"): hosts,
            ("Hosts1", "GetGenericHostEntry"): lambda NewIndex: entry,
            ("Hosts1", "X_AVM-DE_WakeOnLANByMACAddress"): {},
        }
    )


def test_wake_on_lan(landevices: LanDeviceClient) -> None:
    fc = wol_fc()
    r = make_service(landevices, fc).wake_on_lan("aa-bb-cc-00-00-20")
    assert ("Hosts1", "X_AVM-DE_WakeOnLANByMACAddress", {"NewMACAddress": "AA:BB:CC:00:00:20"}) in fc.calls
    assert r["sent"] is True and r["verified"] is False and r["name"] == "nas" and "warning" not in r


def test_wake_on_lan_unknown_or_active(landevices: LanDeviceClient) -> None:
    assert "nicht bekannt" in make_service(landevices, wol_fc()).wake_on_lan("AA:BB:CC:00:00:99")["warning"]
    assert "bereits aktiv" in make_service(landevices, wol_fc(True)).wake_on_lan("AA:BB:CC:00:00:20")["warning"]


def test_wake_on_lan_needs_write(landevices: LanDeviceClient) -> None:
    fc = wol_fc()
    with pytest.raises(TierDisabledError):
        make_service(landevices, fc, write=False, critical=False).wake_on_lan("AA:BB:CC:00:00:20")
    assert fc.calls == []


def test_online_monitor_marks_sync_group_mode_as_raw(landevices: LanDeviceClient) -> None:
    """Live (7583, G.fast): SyncGroupMode said "VDSL" while the line runs G.FAST."""
    fc = FakeFC(
        {
            ("WANCommonInterfaceConfig1", "X_AVM-DE_GetOnlineMonitor"): {
                "NewSyncGroupName": "sg0",
                "NewSyncGroupMode": "VDSL",
                "Newds_current_bps": "0",
                "Newus_current_bps": "0",
            },
            ("WANDSLInterfaceConfig1", "X_AVM-DE_GetDSLInfo"): {"NewModulationType": "G.FAST"},
        }
    )
    t = make_service(landevices, fc).online_monitor()["throughput"]
    assert t["mode"] == "VDSL" and "Rohwert" in t["mode_source"]
    assert t["line_modulation"] == "G.FAST" and "G.FAST" in t["mode_note"]
    fc.responses[("WANDSLInterfaceConfig1", "X_AVM-DE_GetDSLInfo")] = {"NewModulationType": "VDSL"}
    fc2 = FakeFC(dict(fc.responses))
    assert "mode_note" not in make_service(landevices, fc2).online_monitor()["throughput"]


def test_online_monitor_rates_fallback_without_addon_infos(landevices: LanDeviceClient) -> None:
    """Live (7583, PPP, 8.26): X_AVM-DE_GetAddonInfos missing (new in AVM doc v22) → sync rate from
    GetCommonLinkProperties."""
    fc = FakeFC(
        {
            ("WANCommonInterfaceConfig1", "X_AVM-DE_GetAddonInfos"): FritzActionError("x"),
            ("WANCommonInterfaceConfig1", "X_AVM_DE_GetAddonInfos"): FritzActionError("x"),
            ("WANCommonInterfaceConfig1", "GetCommonLinkProperties"): {
                "NewWANAccessType": "DSL",
                "NewLayer1DownstreamMaxBitRate": "250000000",
                "NewLayer1UpstreamMaxBitRate": "40000000",
            },
        }
    )
    rates = make_service(landevices, fc).online_monitor()["rates"]
    assert rates["available"] is True and rates["source"].startswith("GetCommonLinkProperties")
    assert rates["sync"] == {"down_mbit_s": 250.0, "up_mbit_s": 40.0}
    assert rates["tariff"] == {"down_mbit_s": None, "up_mbit_s": None}
    assert ("WANCommonInterfaceConfig1", "X_AVM_DE_GetAddonInfos", {}) in fc.calls  # second spelling tried
