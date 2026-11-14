from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from fritzconnection.core.exceptions import FritzActionError, FritzConnectionException, FritzServiceError

from fritzos8_mcp.diagnose import parse_log_text, parse_log_xml
from fritzos8_mcp.errors import InvalidParameterError, NotFoundError
from fritzos8_mcp.landevice import LanDeviceClient

from .conftest import FakeBox, FakeFC, make_service
from .test_wlan import KEY, Radios, wlan_fc

LOG = (
    "14.11.26 10:22:01 WLAN-Gerät angemeldet (5 GHz), 866 Mbit/s, Pixel, IP 192.0.2.40\n"
    "14.11.26 09:00:00 Internetverbindung wurde erfolgreich hergestellt.\n"
    "13.11.26 23:59:59 DSL antwortet nicht (Keine DSL-Synchronisation).\n"
    "ohne Zeitstempel\n"
)


def test_parse_log_text() -> None:
    entries = parse_log_text(LOG)
    assert entries[0] == {
        "date": "14.11.26",
        "time": "10:22:01",
        "message": "WLAN-Gerät angemeldet (5 GHz), 866 Mbit/s, Pixel, IP 192.0.2.40",
    }
    assert entries[-1] == {"date": None, "time": None, "message": "ohne Zeitstempel"}


def test_parse_log_xml() -> None:
    xml = (
        b"<DeviceLog><Event><id>1</id><group>sys</group><date>14.11.26</date>"
        b"<time>10:00:00</time><msg>Start</msg></Event></DeviceLog>"
    )
    assert parse_log_xml(xml) == [
        {"date": "14.11.26", "time": "10:00:00", "group": "sys", "id": "1", "message": "Start"}
    ]


# ------------------------------------------------------------------ system_log


def test_system_log_count_and_filter(landevices: LanDeviceClient) -> None:
    svc = make_service(landevices, FakeFC({("DeviceInfo1", "GetDeviceLog"): {"NewDeviceLog": LOG}}))
    r = svc.system_log(2)
    assert r["total"] == 4 and r["returned"] == 2 and r["source"] == "GetDeviceLog"
    r = svc.system_log(50, "dsl")
    assert r["matched"] == 1 and "DSL antwortet" in r["entries"][0]["message"]


def test_system_log_path_fallback(landevices: LanDeviceClient) -> None:
    fc = FakeFC(
        {
            ("DeviceInfo1", "GetDeviceLog"): FritzActionError("unknown"),
            ("DeviceInfo1", "X_AVM-DE_GetDeviceLogPath"): {"NewDeviceLogPath": "/devicelog.lua?sid=0123456789abcdef"},
        }
    )
    xml = b"<DeviceLog><Event><date>14.11.26</date><time>10:00:00</time><msg>Start</msg></Event></DeviceLog>"
    fc.session = SimpleNamespace(get=lambda url: SimpleNamespace(ok=True, content=xml))
    r = make_service(landevices, fc).system_log(10)
    assert r["source"] == "X_AVM-DE_GetDeviceLogPath" and r["entries"][0]["message"] == "Start"


def test_system_log_unavailable(landevices: LanDeviceClient) -> None:
    fc = FakeFC({("DeviceInfo1", "GetDeviceLog"): FritzActionError("x")})
    with pytest.raises(NotFoundError):
        make_service(landevices, fc).system_log()


@pytest.mark.parametrize("count", [0, 501])
def test_system_log_count_range(landevices: LanDeviceClient, count: int) -> None:
    with pytest.raises(InvalidParameterError):
        make_service(landevices, FakeFC()).system_log(count)


# ------------------------------------------------------------------ dsl / firmware

DSL = {
    "NewEnable": True,
    "NewStatus": "Up",
    "NewDataPath": "Interleaved",
    "NewDownstreamCurrRate": 109999,
    "NewUpstreamCurrRate": 41999,
    "NewDownstreamMaxRate": 130000,
    "NewUpstreamMaxRate": 45000,
    "NewDownstreamNoiseMargin": 95,
    "NewUpstreamNoiseMargin": 81,
    "NewDownstreamAttenuation": 140,
    "NewUpstreamAttenuation": 0,
    "NewATURVendor": "BDCM",
}


def test_dsl_info(landevices: LanDeviceClient) -> None:
    fc = FakeFC(
        {
            ("WANDSLInterfaceConfig1", "GetInfo"): DSL,
            ("WANDSLInterfaceConfig1", "GetStatisticsTotal"): {"NewCRCErrors": 3, "NewFECErrors": 1200},
        }
    )
    r = make_service(landevices, fc).dsl_info()
    assert r["available"] is True and r["down_kbps"] == 109999
    assert r["snr_down_db"] == 9.5 and r["attenuation_down_db"] == 14.0 and r["attenuation_up_db"] == 0.0
    assert r["errors_total"] == {"CRCErrors": 3, "FECErrors": 1200}


def test_dsl_info_without_dsl(landevices: LanDeviceClient) -> None:
    fc = FakeFC(
        {
            ("WANDSLInterfaceConfig1", "GetInfo"): FritzServiceError("no service"),
            ("WANCommonInterfaceConfig1", "GetCommonLinkProperties"): {"NewWANAccessType": "Ethernet"},
        }
    )
    r = make_service(landevices, fc).dsl_info()
    assert r == {"available": False, "access_type": "Ethernet", "note": r["note"]}


UI_CURRENT = {"NewUpgradeAvailable": False, "NewX_AVM-DE_Version": "", "NewX_AVM-DE_UpdateState": "Stopped"}
UI_UPDATE = {"NewUpgradeAvailable": True, "NewX_AVM-DE_Version": "8.30", "NewX_AVM-DE_InfoURL": "http://x"}


def test_firmware_status(landevices: LanDeviceClient) -> None:
    fc = FakeFC(
        {
            ("DeviceInfo1", "GetInfo"): {"NewSoftwareVersion": "164.08.26", "NewModelName": "FRITZ!Box 7583"},
            ("UserInterface1", "GetInfo"): UI_UPDATE,
        }
    )
    r = make_service(landevices, fc).firmware_status()
    assert r["installed"] == "164.08.26" and r["update_available"] is True and r["available_version"] == "8.30"


def test_firmware_status_build_type(landevices: LanDeviceClient) -> None:
    """AVM doc: X_AVM-DE_LaborVersion was renamed to X_AVM-DE_BuildType; old name only as fallback."""
    fc = FakeFC({("UserInterface1", "GetInfo"): {**UI_UPDATE, "NewX_AVM-DE_BuildType": "Labor_Beta"}})
    r = make_service(landevices, fc).firmware_status()
    assert r["build_type"] == "Labor_Beta" and r["labor_version"] == "Labor_Beta"
    fc.responses[("UserInterface1", "GetInfo")] = {**UI_UPDATE, "NewX_AVM-DE_LaborVersion": "phone"}
    assert make_service(landevices, fc).firmware_status()["build_type"] == "phone"


def test_firmware_status_unavailable(landevices: LanDeviceClient) -> None:
    fc = FakeFC({("UserInterface1", "GetInfo"): FritzServiceError("x")})
    with pytest.raises(NotFoundError):
        make_service(landevices, fc).firmware_status()


# ------------------------------------------------------------------ security_check

DNSCFG_DOT = {"dns_over_tls_enabled": "1", "ipv4_use_user_dns": "0", "ipv6_use_user_dns": "0"}


@pytest.fixture(autouse=True)
def _dns_settings(fake_box: FakeBox) -> None:
    """The extended security check reads DNS over TLS from /api/v0/generic/dnscfg."""
    fake_box.generic["dnscfg"] = dict(DNSCFG_DOT)


def secure_box(
    extra: dict[tuple[str, str], Any] | None = None,
    *,
    guest_on: bool = False,
    guest_open: bool = False,
    mappings: list[dict[str, Any]] | None = None,
) -> FakeFC:
    radios = Radios(guest_open=guest_open)
    if guest_on:
        radios.state[3]["NewEnable"] = True
    fc = wlan_fc(radios)
    mappings = mappings or []
    fc.responses.update(
        {
            ("X_AVM-DE_RemoteAccess1", "GetInfo"): {"NewEnabled": "0", "NewPort": 0, "NewUsername": "admin"},
            ("X_AVM-DE_MyFritz1", "GetInfo"): {"NewEnabled": False, "NewDeviceRegistered": False},
            ("WANIPConn1", "GetStatusInfo"): {"NewConnectionStatus": "Connected", "NewUptime": 100},
            ("WANIPConn1", "GetPortMappingNumberOfEntries"): {"NewPortMappingNumberOfEntries": len(mappings)},
            ("WANIPConn1", "GetGenericPortMappingEntry"): lambda NewPortMappingIndex: mappings[NewPortMappingIndex],
            ("X_AVM-DE_UPnP1", "GetInfo"): {"NewEnable": True, "NewUPnPMediaServer": False},
            ("WLANConfiguration1", "X_AVM-DE_GetWPSInfo"): {
                "NewX_AVM-DE_WPSMode": "pbc",
                "NewX_AVM-DE_WPSStatus": "off",
                "NewX_AVM-DE_WPSAPPIN": "12345670",
            },
            ("DeviceInfo1", "GetInfo"): {"NewSoftwareVersion": "164.08.26"},
            ("UserInterface1", "GetInfo"): UI_CURRENT,
            ("UserInterface1", "X_AVM-DE_GetInfo"): {"NewX_AVM-DE_AutoUpdateMode": "important"},
        }
    )
    fc.responses.update(extra or {})
    return fc


def statuses(report: dict[str, Any]) -> dict[str, str]:
    return {c["check"]: c["status"] for c in report["checks"]}


def test_security_check_all_ok(landevices: LanDeviceClient) -> None:
    r = make_service(landevices, secure_box()).security_check()
    assert r["overall"] == "ok", statuses(r)
    assert set(statuses(r)) == {
        "fernzugriff",
        "myfritz",
        "portfreigaben",
        "upnp",
        "tr064",
        "wps",
        "gast_wlan",
        "firmware",
        "wpa_modus",
        "gast_isolierung",
        "fernzugriff_2fa",
        "dns_over_tls",
        "firmware_auto_update",
        "feste_ips",
        "provider_fernwartung",
    }
    assert r["score"] == 100 and r["grade"] == "gut"
    assert all(c["remediation"] and " > " in c["remediation"] for c in r["checks"])
    text = json.dumps(r)
    assert "12345670" not in text and KEY not in text and "admin" not in text


def test_security_check_warnings(landevices: LanDeviceClient) -> None:
    mapping = {
        "NewExternalPort": 443,
        "NewProtocol": "TCP",
        "NewInternalClient": "192.0.2.10",
        "NewInternalPort": 443,
        "NewEnabled": True,
        "NewPortMappingDescription": "NAS",
    }
    fc = secure_box(
        guest_on=True,
        guest_open=True,
        mappings=[mapping],
        extra={
            ("X_AVM-DE_RemoteAccess1", "GetInfo"): {"NewEnabled": "1", "NewPort": 443},
            ("WLANConfiguration1", "X_AVM-DE_GetWPSInfo"): {"NewX_AVM-DE_WPSMode": "pin_ap"},
            ("UserInterface1", "GetInfo"): UI_UPDATE,
        },
    )
    r = make_service(landevices, fc).security_check()
    s = statuses(r)
    assert r["overall"] == "warn"
    assert s["fernzugriff"] == s["portfreigaben"] == s["wps"] == s["gast_wlan"] == s["firmware"] == "warn"
    ports = next(c for c in r["checks"] if c["check"] == "portfreigaben")
    assert ports["details"]["mappings"][0]["internal_client"] == "192.0.2.10"


def test_security_check_tolerates_missing_services(landevices: LanDeviceClient) -> None:
    fc = secure_box(
        {
            ("X_AVM-DE_MyFritz1", "GetInfo"): FritzServiceError("no service"),
            ("X_AVM-DE_UPnP1", "GetInfo"): FritzConnectionException("errorCode: 606"),
        }
    )
    r = make_service(landevices, fc).security_check()
    s = statuses(r)
    assert s["myfritz"] == "unknown" and s["upnp"] == "unknown"
    assert r["overall"] == "unknown" and r["counts"]["unknown"] == 2
    upnp = next(c for c in r["checks"] if c["check"] == "upnp")
    assert upnp["error"]["type"] == "permission_denied"


def test_port_mapping_stops_at_invalid_index(landevices: LanDeviceClient) -> None:
    fc = secure_box()
    fc.responses[("WANIPConn1", "GetPortMappingNumberOfEntries")] = FritzActionError("x")
    fc.responses[("WANIPConn1", "GetGenericPortMappingEntry")] = FritzConnectionException("errorCode: 713")
    r = make_service(landevices, fc).security_check()
    assert statuses(r)["portfreigaben"] == "ok"


# ------------------------------------------------------------------ security_check: score & new checks


@pytest.mark.parametrize(
    "beacon,label",
    [
        ("11i", "WPA2"),
        ("WPAand11i", "WPA+WPA2"),
        ("11iandWPA3", "WPA2+WPA3"),
        ("WPA3", "WPA3"),
        ("None", "offen"),
        ("Basic", "WEP"),
        ("WPA", "WPA"),
        ("", "unbekannt"),
        ("exotic", "unbekannt"),
    ],
)
def test_wpa_label(beacon: str, label: str) -> None:
    from fritzos8_mcp.diagnose import wpa_label

    assert wpa_label(beacon) == label


def test_security_check_new_checks_warn_and_score(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    fake_box.generic["dnscfg"] = {**DNSCFG_DOT, "dns_over_tls_enabled": "0"}
    fc = secure_box(
        guest_on=True,
        extra={
            ("X_AVM-DE_RemoteAccess1", "GetInfo"): {"NewEnabled": "1", "NewPort": 443},
            ("UserInterface1", "X_AVM-DE_GetInfo"): {"NewX_AVM-DE_AutoUpdateMode": "check"},
        },
    )
    fc.responses[("WLANConfiguration1", "GetInfo")] = lambda: {
        "NewEnable": True,
        "NewSSID": "Heim",
        "NewChannel": 6,
        "NewBeaconType": "WPAand11i",
    }
    fc.responses[("WLANConfiguration3", "X_AVM-DE_GetWLANExtInfo")] = {
        "NewX_AVM-DE_APType": "guest",
        "NewX_AVM-DE_UserIsolation": "0",
    }
    r = make_service(landevices, fc).security_check()
    s = statuses(r)
    assert s["wpa_modus"] == "warn" and s["gast_isolierung"] == "warn" and s["dns_over_tls"] == "warn"
    assert s["firmware_auto_update"] == "warn" and s["fernzugriff"] == "warn"
    assert s["fernzugriff_2fa"] == "unknown"  # not detectable via TR-064 → not penalised
    assert s["feste_ips"] == "ok"
    feste = next(c for c in r["checks"] if c["check"] == "feste_ips")
    assert feste["details"]["count"] == 1  # alter-drucker in the fixture
    expected = 100 - (15 + 15 + 5 + 3 + 5)  # fernzugriff, wpa, isolation, DoT, auto-update
    assert r["score"] == expected == 57 and r["grade"] == "kritisch"
    assert "nicht bewertet" in r["score_basis"]
    # backwards compatible fields
    assert {"overall", "counts", "checks", "not_covered"} <= set(r)
    wpa = next(c for c in r["checks"] if c["check"] == "wpa_modus")
    assert "WPA2 + WPA3" in wpa["remediation"] and wpa["weight"] == 15


def test_guest_isolation_unknown_when_field_missing(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    """A box answer without NewX_AVM-DE_UserIsolation must not be scored as 'not isolated'."""
    fake_box.generic["dnscfg"] = DNSCFG_DOT
    fc = secure_box(guest_on=True)
    fc.responses[("WLANConfiguration3", "X_AVM-DE_GetWLANExtInfo")] = {"NewX_AVM-DE_APType": "guest"}
    s = statuses(make_service(landevices, fc).security_check())
    assert s["gast_isolierung"] == "unknown"
    fc.responses[("WLANConfiguration3", "X_AVM-DE_GetWLANExtInfo")] = {
        "NewX_AVM-DE_APType": "guest",
        "NewX_AVM-DE_UserIsolation": "1",
    }
    assert statuses(make_service(landevices, fc).security_check())["gast_isolierung"] == "ok"


def test_security_score_many_warnings(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    mapping = {"NewExternalPort": 22, "NewProtocol": "TCP", "NewInternalClient": "192.0.2.5", "NewEnabled": True}
    fake_box.generic["dnscfg"] = {**DNSCFG_DOT, "dns_over_tls_enabled": "0"}
    fc = secure_box(
        guest_on=True,
        guest_open=True,
        mappings=[mapping],
        extra={
            ("X_AVM-DE_RemoteAccess1", "GetInfo"): {"NewEnabled": "1"},
            ("X_AVM-DE_MyFritz1", "GetInfo"): {"NewEnabled": True},
            ("WLANConfiguration1", "X_AVM-DE_GetWPSInfo"): {"NewX_AVM-DE_WPSMode": "pin_ap"},
            ("UserInterface1", "GetInfo"): UI_UPDATE,
            ("UserInterface1", "X_AVM-DE_GetInfo"): {"NewX_AVM-DE_AutoUpdateMode": "off"},
        },
    )
    r = make_service(landevices, fc).security_check()
    # 15 fernzugriff + 5 myfritz + 15 ports + 10 wps + 15 gast + 15 firmware + 3 DoT + 5 auto-update
    assert r["score"] == 17 and r["grade"] == "kritisch"


def test_security_check_dot_unknown_without_rest(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    fake_box.generic.pop("dnscfg")
    r = make_service(landevices, secure_box()).security_check()
    assert statuses(r)["dns_over_tls"] == "unknown" and r["score"] == 100
