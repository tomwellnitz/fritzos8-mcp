from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from fritzconnection.core.exceptions import FritzActionError, FritzServiceError

from fritzos8_mcp.doctor import THRESHOLDS, NetworkDoctor
from fritzos8_mcp.landevice import LanDeviceClient

from .conftest import FakeFC, make_service
from .test_diagnose import DSL
from .test_netinfo import MESH
from .test_wlan import Radios, wlan_fc

LOG_BAD = "\n".join(
    [f"14.11.26 10:0{i}:00 DSL antwortet nicht (Keine DSL-Synchronisation)." for i in range(4)]
    + [
        "14.11.26 09:00:00 Internetverbindung wurde getrennt.",
        "14.11.26 08:00:00 DNS-Störung: DNS-Server nicht erreichbar.",
        "14.11.26 07:00:00 Radarsignal erkannt, WLAN-Kanal 52 gewechselt.",
    ]
)


def doctor_fc(
    *,
    connected: bool = True,
    dsl: dict[str, Any] | None = None,
    stats: dict[str, Any] | None = None,
    log: str = "14.11.26 10:00:00 Internetverbindung wurde erfolgreich hergestellt.",
    mesh: Any = None,
    monitor: dict[str, Any] | None = None,
) -> FakeFC:
    radios = Radios()
    fc = wlan_fc(radios)
    fc.responses.update(
        {
            ("WANIPConn1", "GetStatusInfo"): {
                "NewConnectionStatus": "Connected" if connected else "Disconnected",
                "NewUptime": 100,
                "NewLastConnectionError": "ERROR_NONE",
            },
            ("WANDSLInterfaceConfig1", "GetInfo"): dsl if dsl is not None else DSL,
            ("WANDSLInterfaceConfig1", "GetStatisticsTotal"): stats or {"NewCRCErrors": 3},
            ("DeviceInfo1", "GetDeviceLog"): {"NewDeviceLog": log},
            ("WANCommonInterfaceConfig1", "X_AVM-DE_GetOnlineMonitor"): monitor or FritzActionError("x"),
        }
    )
    if mesh is None:
        fc.responses[("Hosts1", "X_AVM-DE_GetMeshListPath")] = FritzActionError("x")
    else:
        import json

        fc.responses[("Hosts1", "X_AVM-DE_GetMeshListPath")] = {"NewX_AVM-DE_MeshListPath": "/mesh.lua"}
        fc.session = SimpleNamespace(get=lambda url: SimpleNamespace(ok=True, content=json.dumps(mesh).encode()))
    return fc


def areas(r: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for f in r["findings"]:
        out.setdefault(f["area"], []).append(f["severity"])
    return out


def test_healthy_box_has_no_findings(landevices: LanDeviceClient) -> None:
    r = make_service(landevices, doctor_fc()).network_doctor()
    assert r["findings"] == [] and "keine Auffälligkeiten" in r["verdict"]
    assert r["sources"]["mesh"]["type"] == "not_found"  # missing source reported, not fatal
    assert r["thresholds"] == THRESHOLDS


def test_bad_line_findings(landevices: LanDeviceClient) -> None:
    fc = doctor_fc(
        dsl={**DSL, "NewDownstreamNoiseMargin": 25, "NewUpstreamNoiseMargin": 50, "NewDownstreamAttenuation": 520},
        stats={"NewCRCErrors": 9000, "NewSeverelyErroredSecs": 5},
        log=LOG_BAD,
    )
    r = make_service(landevices, fc).network_doctor()
    a = areas(r)
    assert "critical" in a["dsl"] and "warn" in a["dsl"] and "info" in a["dsl"]  # SNR 2.5 / 5.0, attenuation
    assert sorted(a["log"]) == ["info", "warn"]  # 4 resyncs → warn; 1 disconnect (< 3) → none; 1 DNS → info
    resync = next(f for f in r["findings"] if "Synchronisationsverluste" in f["finding"])
    assert resync["evidence"]["count"] == 4 and len(resync["evidence"]["examples"]) == 3
    assert "deutet auf" in resync["likely_cause"]
    assert any("Radar" in f["finding"] for f in r["findings"])
    assert r["findings"][0]["severity"] == "critical"


def test_wan_down_is_critical(landevices: LanDeviceClient) -> None:
    r = make_service(landevices, doctor_fc(connected=False)).network_doctor()
    assert areas(r)["wan"] == ["critical"]


def test_mesh_and_throughput_findings(landevices: LanDeviceClient) -> None:
    import copy

    mesh = copy.deepcopy(MESH)
    link = mesh["nodes"][0]["node_interfaces"][0]["node_links"][0]
    link["cur_data_rate_rx"] = 50000
    monitor = {"Newmax_ds": 12_500_000, "Newds_current_bps": "12000000", "Newus_current_bps": "0"}
    r = make_service(landevices, doctor_fc(mesh=mesh, monitor=monitor)).network_doctor()
    a = areas(r)
    assert "warn" in a["mesh"] and "info" in a["mesh"]  # weak backbone + weak client
    assert a["throughput"] == ["info"]


def test_wlan_findings(landevices: LanDeviceClient) -> None:
    fc = doctor_fc()
    fc.responses[("WLANConfiguration1", "GetInfo")] = lambda: {"NewEnable": True, "NewSSID": "H", "NewChannel": 3}
    fc.responses[("WLANConfiguration2", "GetInfo")] = lambda: {"NewEnable": False, "NewSSID": "H", "NewChannel": 36}
    fc.responses[("WLANConfiguration1", "GetTotalAssociations")] = {"NewTotalAssociations": 40}
    r = make_service(landevices, fc).network_doctor()
    texts = " ".join(f["finding"] for f in r["findings"])
    assert "Kanal 3" in texts and "ausgeschaltet" in texts and "40 Geräte" in texts


def test_symptom_prioritises_relevant_areas(landevices: LanDeviceClient) -> None:
    import copy

    mesh = copy.deepcopy(MESH)
    mesh["nodes"][0]["node_interfaces"][0]["node_links"][0]["cur_data_rate_rx"] = 50000
    fc = doctor_fc(dsl={**DSL, "NewDownstreamNoiseMargin": 25}, mesh=mesh)
    r = make_service(landevices, fc).network_doctor("WLAN im Schlafzimmer schlecht")
    assert r["findings"][0]["area"] == "mesh" and r["findings"][0]["relevant_to_symptom"] is True
    assert any(f["area"] == "dsl" and not f["relevant_to_symptom"] for f in r["findings"])
    assert r["symptom"] == "WLAN im Schlafzimmer schlecht"


def test_cable_box_without_dsl(landevices: LanDeviceClient) -> None:
    fc = doctor_fc()
    fc.responses[("WANDSLInterfaceConfig1", "GetInfo")] = FritzServiceError("no dsl")
    r = NetworkDoctor(make_service(landevices, fc)).run()
    assert r["sources"]["dsl"] == "ok" and "dsl" not in areas(r)


# ------------------------------------------------------------------ stage 6 checks


def _stage6_service(fake_box: Any, landevices: LanDeviceClient, *, mesh: Any = None, log: str | None = None) -> Any:
    import copy

    from .fixtures_api import ETH_PORTS
    from .test_quality import MESH_Q

    fake_box.generic["eth_ports"] = copy.deepcopy(ETH_PORTS)
    kwargs: dict[str, Any] = {"mesh": MESH_Q if mesh is None else mesh}
    if log is not None:
        kwargs["log"] = log
    return make_service(landevices, doctor_fc(**kwargs))


def test_eee_with_raspberry_pi_is_warned(fake_box: Any, landevices: LanDeviceClient) -> None:
    r = _stage6_service(fake_box, landevices).network_doctor()
    pi = [f for f in r["findings"] if "Raspberry Pi" in f["finding"]]
    assert len(pi) == 1 and pi[0]["severity"] == "warn" and pi[0]["area"] == "lan"
    assert pi[0]["evidence"]["port"] == "LAN:1"
    assert any("raspberrypi/linux/issues/7511" in u for u in pi[0]["evidence"]["links"])
    assert r["sources"]["lan_ports"] == "ok"


def test_no_eee_warning_when_eee_off(fake_box: Any, landevices: LanDeviceClient) -> None:
    svc = _stage6_service(fake_box, landevices)
    for p in fake_box.generic["eth_ports"]["eth"]:
        p.update({"eee_mode": "2", "eee_active": "0"})
    assert not any("Raspberry Pi" in f["finding"] for f in svc.network_doctor()["findings"])


def test_lan_link_events_in_log(fake_box: Any, landevices: LanDeviceClient) -> None:
    lines = [f"14.11.26 10:{i:02d}:00 LAN-Anschluss 1 getrennt." for i in range(4)] + [
        f"14.11.26 10:{i:02d}:05 LAN 1: Verbindung hergestellt (1000 Mbit/s)." for i in range(4)
    ]
    r = _stage6_service(fake_box, landevices, log="\n".join(lines)).network_doctor()
    f = next(f for f in r["findings"] if "Link-Wechsel" in f["finding"])
    assert f["evidence"]["port"] == "LAN:1" and f["evidence"]["count"] == 8 and f["severity"] == "warn"


def test_flap_check_detects_carrier_changes(fake_box: Any, landevices: LanDeviceClient) -> None:
    svc = _stage6_service(fake_box, landevices)
    state = {"n": 0}

    def toggle(_: float) -> None:
        state["n"] += 1
        fake_box.generic["eth_ports"]["eth"][0]["carrier"] = "0" if state["n"] % 2 else "1"
        fake_box.devices[0]["active"] = fake_box.devices[0]["online"] = "0" if state["n"] % 2 else "1"

    svc._sleep = toggle
    r = svc.network_doctor(flap_check_seconds=10)
    texts = [f["finding"] for f in r["findings"]]
    assert any("Link-Flapping an LAN:1" in t for t in texts)
    assert any("PC Büro" in t and "online/offline" in t for t in texts)
    assert r["sources"]["flap_check"]["rounds"] == 6


def test_flap_check_quiet_network(fake_box: Any, landevices: LanDeviceClient) -> None:
    r = _stage6_service(fake_box, landevices).network_doctor(flap_check_seconds=4)
    assert not any("Flapping" in f["finding"] or "online/offline" in f["finding"] for f in r["findings"])


def test_dns_single_point_of_failure(fake_box: Any, landevices: LanDeviceClient) -> None:
    svc = _stage6_service(fake_box, landevices)
    svc.tr064.fc.responses[("LANHostConfigManagement1", "GetDNSServer")] = {"NewDNSServers": "192.0.2.53"}
    f = next(f for f in svc.network_doctor()["findings"] if f["area"] == "dns")
    assert "Single Point of Failure" in f["likely_cause"] and f["severity"] == "warn"


@pytest.mark.parametrize("servers", ["192.0.2.1", "192.0.2.53, 192.0.2.54", "9.9.9.9"])
def test_dns_no_spof(fake_box: Any, landevices: LanDeviceClient, servers: str) -> None:
    svc = _stage6_service(fake_box, landevices)
    svc.tr064.fc.responses[("LANHostConfigManagement1", "GetDNSServer")] = {"NewDNSServers": servers}
    assert not any(f["area"] == "dns" for f in svc.network_doctor()["findings"])


def test_client_measurement_included(fake_box: Any, landevices: LanDeviceClient) -> None:
    svc = _stage6_service(fake_box, landevices)
    m = {"for_network_doctor": {"latency": {"loss_pct": 35.0, "avg_ms": 3.0, "jitter_ms": 1.0}, "dns": None}}
    r = svc.network_doctor("Internet bricht ab", client_measurement=m)
    client = [f for f in r["findings"] if f["area"] == "client"]
    assert client and client[0]["severity"] == "critical" and client[0]["relevant_to_symptom"] is True
    assert r["sources"]["client_measurement"] == "übergeben"
