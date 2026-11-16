"""Stage 6.4: box speed test, connection quality, test_my_device – all against fakes, no network."""

from __future__ import annotations

import copy
import json
import struct
from types import SimpleNamespace
from typing import Any

import pytest
from fritzconnection.core.exceptions import FritzActionError

from fritzos8_mcp import clienttest
from fritzos8_mcp.connectivity import Probes
from fritzos8_mcp.errors import FritzError, InvalidParameterError, NotFoundError, TierDisabledError
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.quality import is_raspberry_pi, lan_port_label, mesh_clients, rate_device
from fritzos8_mcp.speedtest import parse_info, parse_statistics

from .conftest import FakeBox, FakeFC, make_service
from .fixtures_api import ETH_PORTS

PI_MAC = "2C:CF:67:00:00:01"

MESH_Q = {
    "nodes": [
        {
            "uid": "n-box",
            "device_name": "fritz.box",
            "mesh_role": "master",
            "is_meshed": True,
            "node_interfaces": [
                {
                    "uid": "i-24",
                    "name": "AP:2G:0",
                    "type": "WLAN",
                    "current_channel": 6,
                    "node_links": [
                        {
                            "uid": "l-tv",
                            "type": "WLAN",
                            "state": "CONNECTED",
                            "node_1_uid": "n-box",
                            "node_2_uid": "n-tv",
                            "node_interface_1_uid": "i-24",
                            "node_interface_2_uid": "i-tv",
                            "cur_data_rate_rx": 26000,
                            "max_data_rate_rx": 144000,
                            "rx_rcpi": 62,  # -79 dBm
                        }
                    ],
                },
                {
                    "uid": "i-5",
                    "name": "AP:5G:0",
                    "type": "WLAN",
                    "current_channel": 36,
                    "node_links": [
                        {
                            "uid": "l-nb",
                            "type": "WLAN",
                            "state": "CONNECTED",
                            "node_1_uid": "n-box",
                            "node_2_uid": "n-nb",
                            "node_interface_1_uid": "i-5",
                            "node_interface_2_uid": "i-nb",
                            "cur_data_rate_rx": 1200000,
                            "max_data_rate_rx": 1200000,
                            "rx_rcpi": 130,  # -45 dBm
                        }
                    ],
                },
                {
                    "uid": "i-lan1",
                    "name": "LAN:1",
                    "type": "LAN",
                    "node_links": [
                        {
                            "uid": "l-pi",
                            "type": "LAN",
                            "state": "CONNECTED",
                            "node_1_uid": "n-box",
                            "node_2_uid": "n-pi",
                            "node_interface_1_uid": "i-lan1",
                            "node_interface_2_uid": "i-pi",
                            "cur_data_rate_rx": 1000000,
                        }
                    ],
                },
                {
                    "uid": "i-lan2",
                    "name": "LAN:2",
                    "type": "LAN",
                    "node_links": [
                        {
                            "uid": "l-pc",
                            "type": "LAN",
                            "state": "CONNECTED",
                            "node_1_uid": "n-box",
                            "node_2_uid": "n-pc",
                            "node_interface_1_uid": "i-lan2",
                            "node_interface_2_uid": "i-pc",
                        }
                    ],
                },
            ],
        },
        {
            "uid": "n-tv",
            "device_name": "TV",
            "device_mac_address": "AA:BB:CC:00:00:30",
            "node_interfaces": [{"uid": "i-tv"}],
        },
        {
            "uid": "n-nb",
            "device_name": "Notebook",
            "device_mac_address": "AA:BB:CC:00:00:31",
            "node_interfaces": [{"uid": "i-nb", "phymodes": ["ax"]}],
        },
        {
            "uid": "n-pi",
            "device_name": "raspi",
            "device_mac_address": PI_MAC,
            "node_interfaces": [{"uid": "i-pi"}],
        },
        {
            "uid": "n-pc",
            "device_name": "PC",
            "device_mac_address": "AA:BB:CC:00:00:33",
            "node_interfaces": [{"uid": "i-pc"}],
        },
    ]
}


def quality_fc(extra: dict[tuple[str, str], Any] | None = None) -> FakeFC:
    fc = FakeFC(
        {
            ("Hosts1", "X_AVM-DE_GetMeshListPath"): {"NewX_AVM-DE_MeshListPath": "/meshlist.lua"},
            ("WLANConfiguration1", "X_AVM-DE_GetWLANExtInfo"): {"NewX_AVM-DE_FrequencyBand": "2400"},
            ("WLANConfiguration1", "GetSpecificAssociatedDeviceInfo"): FritzActionError("714 NoSuchEntryInArray"),
            ("WLANConfiguration1", "X_AVM-DE_GetWLANConnectionInfo"): FritzActionError("714"),
            **(extra or {}),
        }
    )
    body = json.dumps(MESH_Q).encode()
    fc.session = SimpleNamespace(get=lambda url: SimpleNamespace(ok=True, content=body))
    return fc


@pytest.fixture
def eth(fake_box: FakeBox) -> None:
    fake_box.generic["eth_ports"] = copy.deepcopy(ETH_PORTS)


# ------------------------------------------------------------------ helpers / rating


def test_raspberry_pi_ouis() -> None:
    for prefix in ("B8:27:EB", "DC:A6:32", "E4:5F:01", "D8:3A:DD", "28:CD:C1", "2C:CF:67", "88:A2:9E", "98:FE:54"):
        assert is_raspberry_pi(prefix + ":12:34:56")
    assert not is_raspberry_pi("AA:BB:CC:00:00:01") and not is_raspberry_pi("")


def test_lan_port_label() -> None:
    assert (
        lan_port_label("LAN:1") == "LAN:1" and lan_port_label("lan 3") == "LAN:3" and lan_port_label("AP:2G:0") is None
    )


def test_lan_port_label_accepts_wan_port_used_as_lan() -> None:
    # Regression (live 7583/8.26): device on the WAN port used as LAN was "unbekannt" without port data
    assert lan_port_label("WAN:1") == "WAN:1" and lan_port_label("wan 1") == "WAN:1"
    assert lan_port_label("AP:5G:0") is None and lan_port_label("") is None


def test_mesh_clients_extracts_port_band_and_signal() -> None:
    clients = {c["name"]: c for c in mesh_clients(MESH_Q)}
    assert clients["TV"]["band_ghz"] == "2.4" and clients["TV"]["signal_dbm"] == -79.0
    assert clients["Notebook"]["band_ghz"] == "5" and clients["Notebook"]["standards"] == ["ax"]
    assert clients["raspi"]["connection"] == "lan" and clients["raspi"]["lan_port"] == "LAN:1"


def test_rate_weak_24ghz_gets_tip() -> None:
    r = rate_device({"connection": "wlan", "band_ghz": "2.4", "signal_dbm": -78.0, "rate_down_mbit": 26.0})
    assert r["rating"] == "schwach"
    assert any("2,4 GHz mit -78 dBm" in t and "5 GHz" in t for t in r["tips"])


def test_rate_low_link_rate_downgrades() -> None:
    r = rate_device(
        {
            "connection": "wlan",
            "band_ghz": "5",
            "signal_dbm": -50.0,
            "rate_down_mbit": 100.0,
            "max_rate_down_mbit": 1200.0,
        }
    )
    assert r["rating"] == "ok" and any("Linkrate" in t for t in r["tips"])


def test_rate_percent_fallback_and_unknown() -> None:
    # percent → dBm estimate (% / 2 − 100): 50 % ≈ −75 dBm → schwach, 30 % ≈ −85 dBm → sehr schwach
    assert rate_device({"connection": "wlan", "signal_percent": 50})["rating"] == "schwach"
    assert rate_device({"connection": "wlan", "signal_percent": 30})["rating"] == "sehr schwach"
    assert rate_device({"connection": "wlan", "signal_percent": 85})["rating"] == "gut"
    assert rate_device({"connection": "wlan"})["rating"] == "unbekannt"


def test_rate_lan_slow_port_and_pi_eee() -> None:
    slow = rate_device({"connection": "lan", "port_speed_mbit": 100, "port_max_speed_mbit": 1000})
    assert slow["rating"] == "ok" and "100 Mbit/s" in slow["tips"][0]
    pi = rate_device(
        {
            "connection": "lan",
            "mac": PI_MAC,
            "port_speed_mbit": 1000,
            "port_max_speed_mbit": 1000,
            "port_eee_active": True,
        }
    )
    assert pi["rating"] == "schwach" and "raspberrypi/linux/issues/7511" in pi["tips"][0]


# ------------------------------------------------------------------ device_connection_quality


def test_quality_all_devices_worst_first(eth: None, landevices: LanDeviceClient) -> None:
    r = make_service(landevices, quality_fc()).connectivity.device_connection_quality()
    assert r["count"] == 4
    assert r["devices"][0]["rating"] in {"schwach", "sehr schwach"}
    pi = next(d for d in r["devices"] if d["name"] == "raspi")
    assert pi["port_eee_active"] is True and pi["port_speed_mbit"] == 1000
    pc = next(d for d in r["devices"] if d["name"] == "PC")
    assert pc["port_speed_mbit"] == 100 and pc["rating"] == "ok"
    assert r["sources"] == {"mesh": "ok", "lan_ports": "ok", "tr064_wlan_stations": "keine TR-064-Signaldaten"}


# Live finding (7583/6660): the mesh list carried no usable signal for any WLAN client → signal_dbm null for all.
# Schema v8.7 documents rx_rcpi/tx_rcpi as dBm (255 = unknown); the box may also list the client as node 1.
WLAN_LIST_XML = b"""<?xml version="1.0" encoding="UTF-8"?><List><TotalAssociations>2</TotalAssociations>
<Item><AssociatedDeviceIndex>1</AssociatedDeviceIndex><AssociatedDeviceMACAddress>aa:bb:cc:00:00:30</AssociatedDeviceMACAddress>
<AssociatedDeviceIPAddress>192.0.2.40</AssociatedDeviceIPAddress><X_AVM-DE_Speed>26</X_AVM-DE_Speed>
<X_AVM-DE_SignalStrength>40</X_AVM-DE_SignalStrength><AssociatedDeviceChannel>6</AssociatedDeviceChannel>
<X_AVM-DE_ChannelWidth>20</X_AVM-DE_ChannelWidth><AssociatedDeviceGuest>0</AssociatedDeviceGuest></Item>
<Item><AssociatedDeviceIndex>2</AssociatedDeviceIndex><AssociatedDeviceMACAddress>aa:bb:cc:00:00:31</AssociatedDeviceMACAddress>
<X_AVM-DE_SignalStrength>90</X_AVM-DE_SignalStrength><AssociatedDeviceChannel>36</AssociatedDeviceChannel></Item>
</List>"""


def _mesh_without_signal() -> dict[str, Any]:
    doc = copy.deepcopy(MESH_Q)
    for iface in doc["nodes"][0]["node_interfaces"]:
        for link in iface["node_links"]:
            if link["type"] == "WLAN":
                link["rx_rcpi"] = 255
                link["tx_rcpi"] = 255
    return doc


def test_mesh_signal_schema_87_dbm_and_ap_side() -> None:
    doc = copy.deepcopy(MESH_Q)
    tv = doc["nodes"][0]["node_interfaces"][0]["node_links"][0]
    tv.update({"rx_rcpi": -71, "tx_rcpi": 255})
    nb = doc["nodes"][0]["node_interfaces"][1]["node_links"][0]
    # client listed as node 1 → the AP measurement is tx_rcpi (measured at node 2)
    nb.update(
        {
            "node_1_uid": "n-nb",
            "node_2_uid": "n-box",
            "node_interface_1_uid": "i-nb",
            "node_interface_2_uid": "i-5",
            "rx_rcpi": -40,
            "tx_rcpi": -55,
        }
    )
    clients = {c["name"]: c for c in mesh_clients(doc)}
    assert clients["TV"]["signal_dbm"] == -71.0 and clients["Notebook"]["signal_dbm"] == -55.0
    assert clients["raspi"]["signal_dbm"] is None


def test_quality_all_devices_uses_wlan_device_list(eth: None, landevices: LanDeviceClient) -> None:
    fc = quality_fc(
        {("WLANConfiguration1", "X_AVM-DE_GetWLANDeviceListPath"): {"NewX_AVM-DE_WLANDeviceListPath": "/wlan.lua"}}
    )
    mesh_body = json.dumps(_mesh_without_signal()).encode()
    fc.session = SimpleNamespace(
        get=lambda url: SimpleNamespace(ok=True, content=WLAN_LIST_XML if "wlan.lua" in url else mesh_body)
    )
    r = make_service(landevices, fc).connectivity.device_connection_quality()
    by = {d["name"]: d for d in r["devices"]}
    assert by["TV"]["signal_dbm"] is None and by["TV"]["signal_percent"] == 40
    assert by["TV"]["signal_dbm_estimated"] == -80.0 and by["TV"]["rating"] == "sehr schwach"
    assert by["Notebook"]["signal_percent"] == 90 and by["Notebook"]["rating"] == "gut"
    assert r["sources"]["tr064_wlan_stations"] == "TR-064 X_AVM-DE_GetWLANDeviceListPath"
    assert "signal_percent" in r["thresholds"]
    # one list request – no per-station calls
    assert not any(c[1] in {"GetSpecificAssociatedDeviceInfo", "GetGenericAssociatedDeviceInfo"} for c in fc.calls)


def test_wlan_stations_fallback_generic_loop_is_bounded(landevices: LanDeviceClient) -> None:
    from fritzos8_mcp import netinfo

    def generic(NewAssociatedDeviceIndex: int) -> dict[str, Any]:
        return {
            "NewAssociatedDeviceMACAddress": f"AA:BB:CC:00:01:{NewAssociatedDeviceIndex:02X}",
            "NewX_AVM-DE_SignalStrength": "70",
            "NewX_AVM-DE_Speed": "400",
        }

    fc = quality_fc(
        {
            ("WLANConfiguration1", "X_AVM-DE_GetWLANDeviceListPath"): FritzActionError("x"),
            ("WLANConfiguration1", "GetTotalAssociations"): {"NewTotalAssociations": "500"},
            ("WLANConfiguration1", "GetGenericAssociatedDeviceInfo"): generic,
        }
    )
    stations, source = make_service(landevices, fc).netinfo.wlan_stations_with_source()
    assert source == "TR-064 GetGenericAssociatedDeviceInfo"
    assert len(stations) == netinfo.MAX_GENERIC_STATIONS
    first = stations["AA:BB:CC:00:01:00"]
    assert first["signal_percent"] == 70 and first["signal_dbm_estimated"] == -65.0
    assert first["service"] == "WLANConfiguration1"


def test_quality_single_mac_merges_tr064(eth: None, landevices: LanDeviceClient) -> None:
    fc = quality_fc(
        {
            ("WLANConfiguration1", "GetSpecificAssociatedDeviceInfo"): {
                "NewAssociatedDeviceIPAddress": "192.0.2.40",
                "NewAssociatedDeviceAuthState": "1",
                "NewX_AVM-DE_Speed": "26",
                "NewX_AVM-DE_SignalStrength": "20",
                "NewX_AVM-DE_ChannelWidth": "20",
            }
        }
    )
    r = make_service(landevices, fc).connectivity.device_connection_quality("aa:bb:cc:00:00:30")
    d = r["devices"][0]
    assert d["name"] == "TV" and d["ip"] == "192.0.2.40" and d["signal_percent"] == 20
    assert d["tr064"]["band_ghz"] == "2.4" and d["channel_width_mhz"] == 20


def test_quality_unknown_mac(eth: None, landevices: LanDeviceClient) -> None:
    with pytest.raises(NotFoundError):
        make_service(landevices, quality_fc()).connectivity.device_connection_quality("AA:BB:CC:99:99:99")


def test_quality_without_mesh_and_ports(landevices: LanDeviceClient) -> None:
    fc = FakeFC({("Hosts1", "X_AVM-DE_GetMeshListPath"): FritzActionError("x")})
    r = make_service(landevices, fc).connectivity.device_connection_quality()
    assert r["count"] == 0 and r["sources"]["mesh"]["type"] == "not_found"
    assert r["sources"]["lan_ports"]["type"] == "unsupported_firmware"


# ------------------------------------------------------------------ box speed test


ST_INFO = {
    "NewEnableTcp": "1",
    "NewEnableUdp": "0",
    "NewEnableUdpBidirect": "0",
    "NewWANEnableTcp": "0",
    "NewWANEnableUdp": "0",
    "NewPortTcp": "4711",
    "NewPortUdp": "4712",
    "NewPortUdpBidirect": "4713",
}
ST_STATS = {
    "NewByteCount": "125000000",
    "NewKbitsCurrent": "95000",
    "NewKbitsAvg": "100000",
    "NewPacketCount": "90000",
    "NewPPSCurrent": "8000",
    "NewPPSAvg": "9000",
}


def test_parse_speedtest() -> None:
    assert parse_info(ST_INFO)["port_tcp"] == 4711 and parse_info(ST_INFO)["lan_tcp_enabled"] is True
    assert parse_statistics(ST_STATS)["avg_mbit_s"] == 100.0


def test_speedtest_info_warns_on_internet(landevices: LanDeviceClient) -> None:
    fc = FakeFC(
        {
            ("X_AVM-DE_Speedtest1", "GetInfo"): {**ST_INFO, "NewWANEnableTcp": "1"},
            ("X_AVM-DE_Speedtest1", "GetStatistics"): ST_STATS,
        }
    )
    r = make_service(landevices, fc).connectivity.box_speedtest_info()
    assert r["internet_tcp_enabled"] is True and r["warnings"]
    assert "Kein Internet-Speedtest" in r["what_this_is"]


def test_speedtest_info_missing_service(landevices: LanDeviceClient) -> None:
    fc = FakeFC({("X_AVM-DE_Speedtest1", "GetInfo"): FritzActionError("x")})
    with pytest.raises(NotFoundError):
        make_service(landevices, fc).connectivity.box_speedtest_info()


def test_speedtest_run_resets_sends_and_reads(landevices: LanDeviceClient) -> None:
    fc = FakeFC({("X_AVM-DE_Speedtest1", "GetInfo"): ST_INFO, ("X_AVM-DE_Speedtest1", "GetStatistics"): ST_STATS})
    svc = make_service(landevices, fc)
    sent: list[tuple[str, int, float]] = []

    def sender(host: str, port: int, seconds: float) -> dict[str, Any]:
        sent.append((host, port, seconds))
        return {"bytes_sent": 125_000_000, "duration_s": 10.0, "error": None}

    svc.connectivity.probes = Probes(sender=sender)
    r = svc.connectivity.box_speedtest_run(10)
    assert sent == [("fritz.test", 4711, 10.0)]
    assert ("X_AVM-DE_Speedtest1", "ResetStatistics", {}) in fc.calls
    assert not any(c[1] == "SetConfig" for c in fc.calls)  # never switches the server on
    assert r["client"]["mbit_s"] == 100.0 and r["box_counted_mbit_s"] == 100.0 and r["verified"] is True


def test_speedtest_run_refuses_when_server_off(landevices: LanDeviceClient) -> None:
    fc = FakeFC({("X_AVM-DE_Speedtest1", "GetInfo"): {**ST_INFO, "NewEnableTcp": "0"}})
    svc = make_service(landevices, fc)
    with pytest.raises(FritzError, match="nichts umgestellt"):
        svc.connectivity.box_speedtest_run(5)
    assert not any(c[1] in {"ResetStatistics", "SetConfig"} for c in fc.calls)


def test_speedtest_run_needs_write_and_valid_seconds(landevices: LanDeviceClient) -> None:
    with pytest.raises(TierDisabledError):
        make_service(landevices, FakeFC(), write=False).connectivity.box_speedtest_run(5)
    with pytest.raises(InvalidParameterError):
        make_service(landevices, FakeFC()).connectivity.box_speedtest_run(60)


# ------------------------------------------------------------------ test_my_device primitives


def test_summarize_loss_and_jitter() -> None:
    s = clienttest.summarize([1.0, 3.0, None, 2.0])
    assert s["loss_pct"] == 25.0 and s["avg_ms"] == 2.0 and s["jitter_ms"] == 1.5
    assert clienttest.summarize([None, None])["received"] == 0


def test_tcp_ping_counts_failures() -> None:
    calls = iter([None, OSError("x"), None])
    ticks = iter([0.0, 0.002, 1.0, 1.0, 2.0, 2.004])

    def connect(host: str, port: int, timeout: float) -> None:
        r = next(calls)
        if isinstance(r, Exception):
            raise r

    r = clienttest.tcp_ping("192.0.2.1", 80, 3, connect=connect, clock=lambda: next(ticks), sleep=lambda s: None)
    assert r["sent"] == 3 and r["received"] == 2 and r["loss_pct"] == 33.3
    assert r["errors"] == {"OSError": 1} and r["min_ms"] == 2.0


def test_dns_query_roundtrip() -> None:
    q = clienttest.build_query("example.com", 0x1234)
    assert q[:2] == b"\x12\x34" and b"\x07example\x03com\x00" in q
    ok = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    assert clienttest.parse_response(ok, 0x1234) == {"ok": True, "rcode": "NOERROR", "answers": 1}
    assert clienttest.parse_response(ok, 0x9999)["ok"] is False
    nx = struct.pack(">HHHHHH", 1, 0x8183, 1, 0, 0, 0)
    assert clienttest.parse_response(nx, 1)["rcode"] == "NXDOMAIN"


def _dns_answer(server: str, packet: bytes, timeout: float) -> bytes:
    return packet[:2] + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0)


def test_dns_time_with_fake_exchange() -> None:
    r = clienttest.dns_time("192.0.2.53", exchange=_dns_answer)
    assert r["answered"] == 3 and r["last_result"]["ok"] is True

    def dead(server: str, packet: bytes, timeout: float) -> bytes:
        raise TimeoutError

    assert clienttest.dns_time("192.0.2.53", exchange=dead)["answered"] == 0


def test_http_download_with_mock(respx_mock) -> None:
    import httpx

    respx_mock.get("https://dl.example/file").mock(return_value=httpx.Response(200, content=b"x" * 300_000))
    ticks = iter([0.0, 0.1, 0.2, 0.3, 0.4, 1.0])
    r = clienttest.http_download("https://dl.example/file", 200_000, client=httpx.Client(), clock=lambda: next(ticks))
    assert r["bytes"] >= 200_000 and r["error"] is None and r["url_host"] == "dl.example" and r["mbit_s"]


def test_download_url_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FRITZ_TEST_DOWNLOAD_URL", "https://mirror.example/{bytes}.bin")
    assert clienttest.download_url_default(1000) == "https://mirror.example/1000.bin"


def test_assess_findings() -> None:
    f = clienttest.assess(
        {"loss_pct": 30.0, "avg_ms": 60.0, "jitter_ms": 20.0},
        {"box_dns": [{"server": "192.0.2.53", "answered": 0}], "public": {"avg_ms": 20}},
    )
    sev = sorted(x["severity"] for x in f)
    assert sev.count("critical") == 2 and "warn" in sev and "info" in sev
    assert clienttest.assess({"loss_pct": 0, "avg_ms": 1.0, "jitter_ms": 0.1}, None) == []


# ------------------------------------------------------------------ test_my_device end-to-end (fakes)


def test_test_my_device_combines_measurement_and_box_view(eth: None, landevices: LanDeviceClient) -> None:
    fc = quality_fc(
        {
            ("LANHostConfigManagement1", "GetDNSServer"): {"NewDNSServers": "192.0.2.53"},
            ("Hosts1", "X_AVM-DE_GetHostListPath"): FritzActionError("x"),
            ("Hosts1", "GetHostNumberOfEntries"): {"NewHostNumberOfEntries": 1},
            ("Hosts1", "GetGenericHostEntry"): {
                "NewHostName": "PC",
                "NewIPAddress": "192.0.2.33",
                "NewMACAddress": "AA:BB:CC:00:00:33",
                "NewActive": True,
            },
        }
    )
    svc = make_service(landevices, fc)
    svc.connectivity.local_ips = lambda: {"192.0.2.33"}
    targets: list[tuple[str, int]] = []
    downloads: list[str] = []

    def connect(host: str, port: int, timeout: float) -> None:
        targets.append((host, port))

    def download(url: str, max_bytes: int) -> dict[str, Any]:
        downloads.append(url)
        return {"bytes": max_bytes, "mbit_s": 50.0, "error": None}

    svc.connectivity.probes = Probes(connect=connect, exchange=_dns_answer, download=download, sleep=lambda s: None)
    r = svc.connectivity.test_my_device(count=3, download_url="https://dl.example/x")
    assert set(targets) == {("fritz.test", 80), ("fritz.test", 49000)}
    assert r["latency_summary"]["loss_pct"] == 0.0
    assert r["dns"]["box_dns"][0]["server"] == "192.0.2.53" and r["dns"]["public"]["server"] == "9.9.9.9"
    assert downloads == ["https://dl.example/x"]
    assert r["box_view"]["host"]["mac"] == "AA:BB:CC:00:00:33"
    assert r["box_view"]["connection"] == "lan" and r["box_view"]["quality"]["lan_port"] == "LAN:2"
    assert r["findings"] == []
    assert set(r["for_network_doctor"]) == {"latency", "dns"}


def test_test_my_device_validates_and_skips_download(landevices: LanDeviceClient) -> None:
    svc = make_service(landevices, FakeFC())
    svc.connectivity.probes = Probes(connect=lambda h, p, t: None, exchange=_dns_answer, sleep=lambda s: None)
    with pytest.raises(InvalidParameterError):
        svc.connectivity.test_my_device(count=0)
    with pytest.raises(InvalidParameterError):
        svc.connectivity.test_my_device(count=1, download_url="file:///etc/passwd")
    r = svc.connectivity.test_my_device(count=1, download=False, public_dns="")
    assert r["download"] == {"skipped": True} and r["dns"]["public"] is None
    assert r["box_view"]["connection"] == "unbekannt"


def test_box_view_wlan_service_matches_band_not_first_answer(
    landevices: LanDeviceClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Live finding: GetWLANConnectionInfo answers on every service → WLANConfiguration1 was reported although
    the device is on 5 GHz (WLANConfiguration2)."""
    conn = {
        "NewAssociatedDeviceMACAddress": "aa:bb:cc:00:00:31",
        "NewChannel": "36",
        "NewX_AVM-DE_FrequencyBand": "5000",
        "NewX_AVM-DE_SignalStrength": "61",
    }
    fc = FakeFC(
        {
            ("WLANConfiguration1", "X_AVM-DE_GetWLANConnectionInfo"): conn,
            ("WLANConfiguration2", "X_AVM-DE_GetWLANConnectionInfo"): conn,
            ("WLANConfiguration1", "GetSpecificAssociatedDeviceInfo"): FritzActionError("714"),
            ("WLANConfiguration2", "GetSpecificAssociatedDeviceInfo"): {"NewX_AVM-DE_SignalStrength": "61"},
        }
    )
    svc = make_service(landevices, fc).connectivity
    monkeypatch.setattr(svc, "_wlan_services", lambda: [("WLANConfiguration1", "2.4"), ("WLANConfiguration2", "5")])
    view = svc._box_view()
    assert view["wlan_connection"]["service"] == "WLANConfiguration2"
    assert view["wlan_connection"]["service_match"] == "GetSpecificAssociatedDeviceInfo"
    assert view["wlan_connection"]["answered_by"] == "WLANConfiguration1"
    # without the MAC route: band match
    fc.responses[("WLANConfiguration2", "GetSpecificAssociatedDeviceInfo")] = FritzActionError("714")
    view = svc._box_view()
    assert view["wlan_connection"]["service"] == "WLANConfiguration2"
    assert view["wlan_connection"]["service_match"] == "band"
