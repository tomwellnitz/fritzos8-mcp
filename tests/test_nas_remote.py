"""Stage 5 – NAS & remote access. Only fakes, no real box."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from fritzconnection.core.exceptions import FritzServiceError

from fritzos8_mcp.errors import ActionDeniedError, InvalidParameterError, PlanError, TierDisabledError
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.myfritz import assess
from fritzos8_mcp.redact import is_secret_field, redact, redact_obj
from fritzos8_mcp.security import Gate, check_generic_action, is_denied
from fritzos8_mcp.server import build_server

from .conftest import FakeFC, make_service

LINK_ID = "020223a3f8d13566"
WEBDAV_USER = "cloud-konto-xy"
REMOTE_USER = "fern-admin"
EMAIL = "owner@example.com"
UPDATE_URL = "https://ddns.example.net/update?user=u1&pass=geheim-ddns&host=<domain>"


class FakeNas:
    """Stateful X_AVM-DE_Storage1 + RemoteAccess SetEnable model."""

    def __init__(self, **state: Any) -> None:
        self.state = {
            "NewFTPEnable": "1",
            "NewFTPStatus": "Enable",
            "NewSMBEnable": "1",
            "NewFTPWANEnable": "0",
            "NewFTPWANSSLOnly": "1",
            "NewFTPWANPort": "49021",
        }
        self.state.update(state)
        self.remote = {"NewEnabled": "0", "NewPort": "0", "NewUsername": REMOTE_USER}
        self.discard = False  # simulate a write that the box silently drops
        self.remote_port_on_enable = "44321"

    def info(self, **_: Any) -> dict[str, Any]:
        return dict(self.state)

    def set_smb(self, NewSMBEnable: int) -> dict[str, Any]:
        if not self.discard:
            self.state["NewSMBEnable"] = str(NewSMBEnable)
        return {}

    def set_ftp(self, NewFTPEnable: int) -> dict[str, Any]:
        if not self.discard:
            self.state["NewFTPEnable"] = str(NewFTPEnable)
        return {}

    def set_wan(self, NewFTPWANEnable: int, NewFTPWANSSLOnly: int) -> dict[str, Any]:
        if not self.discard:
            self.state["NewFTPWANEnable"] = str(NewFTPWANEnable)
            self.state["NewFTPWANSSLOnly"] = str(NewFTPWANSSLOnly)
        return {}

    def remote_info(self, **_: Any) -> dict[str, Any]:
        return {**self.remote, "NewLetsEncryptEnabled": "1", "NewLetsEncryptState": "valid"}

    def remote_set(self, NewEnabled: int) -> dict[str, Any]:
        port = self.remote_port_on_enable if NewEnabled else self.remote["NewPort"]
        if not self.discard and port != "0":
            self.remote["NewEnabled"] = str(NewEnabled)
            self.remote["NewPort"] = port
        return {"NewPort": port}


def _responses(nas: FakeNas) -> dict[tuple[str, str], Any]:
    return {
        ("X_AVM-DE_Storage1", "GetInfo"): nas.info,
        ("X_AVM-DE_Storage1", "SetSMBServer"): nas.set_smb,
        ("X_AVM-DE_Storage1", "SetFTPServer"): nas.set_ftp,
        ("X_AVM-DE_Storage1", "SetFTPServerWAN"): nas.set_wan,
        ("X_AVM-DE_Storage1", "GetUserInfo"): {
            "NewEnable": "1",
            "NewUsername": "ftpuser",
            "NewX_AVM-DE_NetworkAccessReadOnly": "0",
        },
        ("X_AVM-DE_Filelinks1", "GetNumberOfFilelinkEntries"): {"NewNumberOfEntries": "2"},
        ("X_AVM-DE_Filelinks1", "GetGenericFilelinkEntry"): lambda NewIndex: [
            {
                "NewID": LINK_ID,
                "NewValid": "1",
                "NewPath": "/Musik/Lied.mp3",
                "NewIsDirectory": "0",
                "NewUrl": f"/nas/filelink.lua?id={LINK_ID}",
                "NewUsername": "box-user",
                "NewAccessCountLimit": "14",
                "NewAccessCount": "3",
                "NewExpire": "9",
                "NewExpireDate": "2026-12-01T11:29:59Z",
            },
            {
                "NewID": "ffff0000aaaa1111",
                "NewValid": "0",
                "NewPath": "/Fotos/Urlaub",
                "NewIsDirectory": "1",
                "NewUrl": "/nas/filelink.lua?id=ffff0000aaaa1111",
                "NewUsername": "box-user",
                "NewAccessCountLimit": "0",
                "NewAccessCount": "0",
                "NewExpire": "0",
                "NewExpireDate": "",
            },
        ][NewIndex],
        ("X_AVM-DE_WebDAVClient1", "GetInfo"): {
            "NewEnable": "1",
            "NewHostURL": f"https://{WEBDAV_USER}:pw@webdav.example.net/remote.php/dav?token=abc",
            "NewUsername": WEBDAV_USER,
            "NewMountpointName": "Online-Speicher",
        },
        ("X_AVM-DE_UPnP1", "GetInfo"): {"NewEnable": "1", "NewUPnPMediaServer": "1"},
        ("X_AVM-DE_Media1", "GetInfo"): {
            "NewDVBCEnabled": "1",
            "NewStationSearchStatus": "inactive",
            "NewSearchProgress": "0",
        },
        # MyFRITZ!/remote
        ("X_AVM-DE_MyFritz1", "GetInfo"): {
            "NewEnabled": "1",
            "NewDynDNSName": "abcdef123.myfritz.net",
            "NewPort": "443",
            "NewDeviceRegistered": "1",
            "NewState": "dyndns_verified",
            "NewEmail": EMAIL,
        },
        ("X_AVM-DE_MyFritz1", "GetNumberOfServices"): {"NewNumberOfServices": "1"},
        ("X_AVM-DE_MyFritz1", "GetServiceByIndex"): {
            "NewEnabled": "1",
            "NewName": "NAS-Web",
            "NewScheme": "https://",
            "NewPort": "5001",
            "NewURLPath": "/",
            "NewType": "",
            "NewIPv4ForwardingWarning": "1",
            "NewIPv4Addresses": "192.0.2.10",
            "NewIPv6Addresses": "",
            "NewIPv6InterfaceIDs": "",
            "NewMACAddress": "AA:BB:CC:DD:EE:10",
            "NewHostName": "nas",
            "NewDynDnsLabel": "",
            "NewStatus": "301",
        },
        ("X_AVM-DE_RemoteAccess1", "GetInfo"): nas.remote_info,
        ("X_AVM-DE_RemoteAccess1", "SetEnable"): nas.remote_set,
        ("X_AVM-DE_RemoteAccess1", "GetDDNSInfo"): {
            "NewEnabled": "1",
            "NewProviderName": "Benutzerdefiniert",
            "NewDomain": "home.example.net",
            "NewMode": "ddns_both",
            "NewStatusIPv4": "complete",
            "NewStatusIPv6": "complete",
            "NewServerIPv4": "",
            "NewServerIPv6": "",
            "NewUpdateURL": UPDATE_URL,
            "NewUsername": "ddns-user",
        },
        ("X_AVM-DE_USPController1", "GetUSPMyFRITZEnable"): {"NewUSPMyFRITZEnabled": "0"},
        ("X_AVM-DE_USPController1", "GetUSPControllerNumberOfEntries"): {"NewUSPControllerNumberOfEntries": "1"},
        ("X_AVM-DE_USPController1", "GetUSPControllerByIndex"): {
            "NewEnable": "1",
            "NewEndpointID": "proto::controller-1",
            "NewMTP": "websocket",
            "NewHostname": "usp.example.net",
            "NewPort": "443",
            "NewUseTLS": "1",
            "NewAccessRightSmarthome": "1",
            "NewAccessRightMesh": "0",
            "NewAccessRightInternet": "0",
            "NewAccessRightSystem": "1",
            "NewAccessRightController": "0",
            "NewAccessRightWiFi": "0",
            "NewAccessRightVoIP": "0",
            "NewUsername": "usp-login",
        },
        ("X_AVM-DE_AppSetup1", "GetConfig"): {
            "NewConfigRight": "RW",
            "NewAppRight": "RW",
            "NewNasRight": "RW",
            "NewPhoneRight": "NO",
            "NewDialRight": "NO",
            "NewHomeautoRight": "RO",
            "NewInternetRights": "0",
            "NewAccessFromInternet": "0",
        },
    }


def _missing() -> FritzServiceError:
    return FritzServiceError("unknown service")


@pytest.fixture
def nas() -> FakeNas:
    return FakeNas()


@pytest.fixture
def fc5(nas: FakeNas) -> FakeFC:
    return FakeFC(_responses(nas))


def _svc(landevices: LanDeviceClient, fc: FakeFC, **kw: Any) -> Any:
    return make_service(landevices, fc, **kw).nasremote


# ------------------------------------------------------------------ nas_status


def test_nas_status_full_without_secrets(landevices: LanDeviceClient, fc5: FakeFC) -> None:
    out = _svc(landevices, fc5).nas_status()
    assert out["available"] is True
    assert out["protocols"]["smb"] == {"enabled": True}
    assert out["protocols"]["ftp"] == {"enabled": True, "status": "Enable"}
    assert out["protocols"]["ftp_internet"] == {"enabled": False, "ssl_only": True, "port": 49021}
    assert out["capacity"]["status"] == "unknown"
    links = out["shared_links"]
    assert links["count"] == 2
    assert links["links"][0] == {
        "index": 0,
        "name": "Lied.mp3",
        "path": "/Musik/Lied.mp3",
        "is_directory": False,
        "valid": True,
        "expire_days": 9,
        "expire_date": "2026-12-01T11:29:59Z",
        "downloads": 3,
        "download_limit": 14,
    }
    assert links["links"][1]["name"] == "Urlaub" and links["links"][1]["is_directory"] is True
    assert out["online_storage"] == {
        "available": True,
        "enabled": True,
        "host": "webdav.example.net",
        "mountpoint": "Online-Speicher",
        "note": out["online_storage"]["note"],
    }
    assert out["ftpuser"]["enabled"] is True and out["ftpuser"]["read_only"] is False
    assert out["media"]["media_server"] is True
    assert out["media"]["dvbc"]["enabled"] is True
    text = json.dumps(out)
    for secret in (LINK_ID, "filelink.lua", WEBDAV_USER, "token=abc", "remote.php", "box-user"):
        assert secret not in text


def test_nas_status_degrades_per_section(landevices: LanDeviceClient, nas: FakeNas) -> None:
    responses = _responses(nas)
    responses[("X_AVM-DE_Filelinks1", "GetNumberOfFilelinkEntries")] = _missing()
    responses[("X_AVM-DE_WebDAVClient1", "GetInfo")] = _missing()
    responses[("X_AVM-DE_Media1", "GetInfo")] = _missing()
    out = _svc(landevices, FakeFC(responses)).nas_status()
    assert out["available"] is True
    assert out["shared_links"]["available"] is False
    assert out["shared_links"]["error"]["type"] == "not_found"
    assert out["online_storage"]["available"] is False
    assert out["media"]["dvbc"]["available"] is False


def test_nas_status_without_storage_service(landevices: LanDeviceClient, nas: FakeNas) -> None:
    responses = _responses(nas)
    responses[("X_AVM-DE_Storage1", "GetInfo")] = _missing()
    out = _svc(landevices, FakeFC(responses)).nas_status()
    assert out["available"] is False
    assert out["protocols"]["available"] is False


def test_nas_assessments(landevices: LanDeviceClient, nas: FakeNas) -> None:
    nas.state.update(NewFTPWANEnable="1", NewFTPWANSSLOnly="0")
    checks = {c["check"]: c for c in _svc(landevices, FakeFC(_responses(nas))).nas.assessments()}
    assert checks["nas_internet"]["status"] == "warn"
    assert "UNVERSCHLÜSSELT" in checks["nas_internet"]["summary"]
    assert checks["nas_links"]["status"] == "warn"
    assert checks["nas_links"]["details"]["count"] == 1


# ------------------------------------------------------------------ backup_target_check


def test_backup_target_ok_but_incomplete(landevices: LanDeviceClient, fc5: FakeFC) -> None:
    out = _svc(landevices, fc5).backup_target_check(min_free_gb=100)
    assert out["overall"] == "ok"
    assert out["complete"] is False
    assert out["unverified"] == ["freier_speicher"]
    free = next(c for c in out["checks"] if c["check"] == "freier_speicher")
    assert free["status"] == "unknown" and free["details"]["min_free_gb"] == 100
    assert "100 GB" in free["summary"]


def test_backup_target_smb_off_fails(landevices: LanDeviceClient, nas: FakeNas) -> None:
    nas.state["NewSMBEnable"] = "0"
    out = _svc(landevices, FakeFC(_responses(nas))).backup_target_check()
    assert out["overall"] == "fail"
    assert any("set_nas_protocol" in r for r in out["recommendations"])


def test_backup_target_internet_ftp_warns(landevices: LanDeviceClient, nas: FakeNas) -> None:
    nas.state.update(NewFTPWANEnable="1", NewFTPStatus="Error")
    out = _svc(landevices, FakeFC(_responses(nas))).backup_target_check(share="FRITZ.NAS")
    assert out["overall"] == "warn"
    status = {c["check"]: c["status"] for c in out["checks"]}
    assert status == {
        "smb": "ok",
        "speicher": "warn",
        "internet_ftp": "warn",
        "freier_speicher": "unknown",
        "freigabe": "unknown",
    }


def test_backup_target_without_storage(landevices: LanDeviceClient, nas: FakeNas) -> None:
    responses = _responses(nas)
    responses[("X_AVM-DE_Storage1", "GetInfo")] = _missing()
    out = _svc(landevices, FakeFC(responses)).backup_target_check()
    assert out["overall"] == "fail"


def test_backup_target_rejects_negative_threshold(landevices: LanDeviceClient, fc5: FakeFC) -> None:
    with pytest.raises(InvalidParameterError):
        _svc(landevices, fc5).backup_target_check(min_free_gb=-1)


# ------------------------------------------------------------------ myfritz_status


def test_myfritz_status_without_secrets(landevices: LanDeviceClient, fc5: FakeFC) -> None:
    out = _svc(landevices, fc5).myfritz_status()
    acc = out["account"]
    assert acc["enabled"] and acc["registered"]
    assert acc["address"] == "abcdef123.myfritz.net"
    assert acc["state"] == "dyndns_verified" and acc["email_set"] is True
    svc = out["services"]["services"][0]
    assert svc["name"] == "NAS-Web" and svc["port"] == 5001 and svc["target_ipv4"] == "192.0.2.10"
    assert svc["ipv4_forwarding"] == "nicht nötig oder erfolgreich"
    assert out["dyndns"] == {
        "available": True,
        "enabled": True,
        "provider": "Benutzerdefiniert",
        "domain": "home.example.net",
        "mode": "ddns_both",
        "status_ipv4": "complete",
        "status_ipv6": "complete",
    }
    ra = out["remote_access"]
    assert ra["enabled"] is False and ra["https_only"] is True and ra["internet_user_configured"] is True
    cm = out["cloud_management"]
    assert cm["myfritz_cloud_enabled"] is False
    assert cm["controllers"][0]["rights"] == ["smarthome", "system"]
    assert out["apps"]["mcp_user_rights"]["config"] == "RW"
    assert out["apps"]["registered_apps"]["status"] == "unknown"
    text = json.dumps(out)
    for secret in (EMAIL, REMOTE_USER, "ddns-user", "geheim-ddns", "usp-login", "AA:BB:CC:DD:EE:10"):
        assert secret not in text


def test_myfritz_assessments(landevices: LanDeviceClient, fc5: FakeFC) -> None:
    checks = {c["check"]: c["status"] for c in _svc(landevices, fc5).myfritz_status()["assessments"]}
    assert checks == {
        "myfritz_konto": "ok",
        "myfritz_dienste": "warn",
        "dyndns": "ok",
        "fernzugriff": "ok",
        "cloud_fernverwaltung": "warn",  # an active third-party USP controller
        "mcp_benutzer_internet": "ok",
    }


def test_assess_handles_missing_sections() -> None:
    checks = assess({"account": {"available": False}})
    assert {c["status"] for c in checks} == {"unknown"}
    assert len(checks) == 6


def test_assess_flags_errors_and_remote() -> None:
    status = {
        "account": {"available": True, "enabled": True, "state": "dyndns_auth_error", "state_text": "Anmeldefehler"},
        "remote_access": {"available": True, "enabled": True, "port": 44321, "letsencrypt_state": "invalid"},
        "apps": {"available": True, "mcp_user_internet_rights": True},
    }
    checks = {c["check"]: c for c in assess(status)}
    assert checks["myfritz_konto"]["status"] == "warn"
    assert checks["fernzugriff"]["status"] == "warn" and "ungültig" in checks["fernzugriff"]["summary"]
    assert checks["mcp_benutzer_internet"]["status"] == "warn"


def test_usp_flag_falls_back_to_getinfo(landevices: LanDeviceClient, nas: FakeNas) -> None:
    responses = _responses(nas)
    responses[("X_AVM-DE_USPController1", "GetUSPMyFRITZEnable")] = _missing()
    responses[("X_AVM-DE_USPController1", "GetInfo")] = {"NewUSPMyFRITZEnabled": "1", "NewMaxCharsPassword": "256"}
    out = _svc(landevices, FakeFC(responses)).myfritz_status()
    assert out["cloud_management"]["myfritz_cloud_enabled"] is True


def test_security_check_items_combine_both(landevices: LanDeviceClient, fc5: FakeFC) -> None:
    names = [c["check"] for c in _svc(landevices, fc5).security_check_items()]
    assert "fernzugriff" in names and "nas_internet" in names and "nas_links" in names


# ------------------------------------------------------------------ set_nas_protocol (write)


def test_set_nas_protocol_smb_off_verified(landevices: LanDeviceClient, nas: FakeNas, fc5: FakeFC) -> None:
    out = _svc(landevices, fc5).set_nas_protocol("smb", False)
    assert out == {"protocol": "smb", "enabled": False, "changed": True, "read_back": False, "verified": True}
    assert ("X_AVM-DE_Storage1", "SetSMBServer", {"NewSMBEnable": 0}) in fc5.calls


def test_set_nas_protocol_unchanged(landevices: LanDeviceClient, fc5: FakeFC) -> None:
    out = _svc(landevices, fc5).set_nas_protocol("ftp", True)
    assert out["changed"] is False and out["verified"] is True
    assert not any(c[1].startswith("Set") for c in fc5.calls)


def test_set_nas_protocol_discarded_write_not_verified(landevices: LanDeviceClient, nas: FakeNas) -> None:
    nas.discard = True
    out = _svc(landevices, FakeFC(_responses(nas))).set_nas_protocol("smb", False)
    assert out["verified"] is False and out["read_back"] is True


def test_set_nas_protocol_ftp_off_warns_about_wan(landevices: LanDeviceClient, nas: FakeNas) -> None:
    nas.state["NewFTPWANEnable"] = "1"
    out = _svc(landevices, FakeFC(_responses(nas))).set_nas_protocol("ftp", False)
    assert out["verified"] is True and "Internet" in out["warning"]


def test_set_nas_protocol_validation_and_tier(landevices: LanDeviceClient, fc5: FakeFC) -> None:
    with pytest.raises(InvalidParameterError):
        _svc(landevices, fc5).set_nas_protocol("nfs", True)
    with pytest.raises(TierDisabledError):
        _svc(landevices, fc5, write=False).set_nas_protocol("smb", True)


# ------------------------------------------------------------------ set_nas_internet_access (critical)


def test_nas_internet_plan_execute(landevices: LanDeviceClient, nas: FakeNas, fc5: FakeFC) -> None:
    svc = _svc(landevices, fc5)
    plan = svc.set_nas_internet_access_plan(True)
    assert "AUS DEM INTERNET" in plan["consequence"]
    assert plan["target"] == {"enabled": True, "ssl_only": True}
    assert not any(c[1] == "SetFTPServerWAN" for c in fc5.calls)  # plan changes nothing
    out = svc.set_nas_internet_access_execute(plan["token"], True, True)
    assert out["verified"] is True
    assert ("X_AVM-DE_Storage1", "SetFTPServerWAN", {"NewFTPWANEnable": 1, "NewFTPWANSSLOnly": 1}) in fc5.calls
    with pytest.raises(PlanError):  # one-time token
        svc.set_nas_internet_access_execute(plan["token"], True, True)


def test_nas_internet_plan_warns_unencrypted_and_local_ftp_off(landevices: LanDeviceClient, nas: FakeNas) -> None:
    nas.state["NewFTPEnable"] = "0"
    plan = _svc(landevices, FakeFC(_responses(nas))).set_nas_internet_access_plan(True, ssl_only=False)
    text = " ".join(plan["warnings"])
    assert "UNVERSCHLÜSSELT" in text and "set_nas_protocol" in text


def test_nas_internet_token_bound_to_params_and_state(landevices: LanDeviceClient, nas: FakeNas) -> None:
    svc = _svc(landevices, FakeFC(_responses(nas)))
    plan = svc.set_nas_internet_access_plan(True)
    with pytest.raises(PlanError):
        svc.set_nas_internet_access_execute(plan["token"], True, False)
    plan = svc.set_nas_internet_access_plan(True)
    nas.state["NewFTPWANEnable"] = "1"  # changed behind our back
    with pytest.raises(PlanError):
        svc.set_nas_internet_access_execute(plan["token"], True, True)


def test_nas_internet_unchanged_gives_no_token(landevices: LanDeviceClient, fc5: FakeFC) -> None:
    plan = _svc(landevices, fc5).set_nas_internet_access_plan(False)
    assert plan["changed"] is False and "token" not in plan


def test_nas_internet_disable_verified(landevices: LanDeviceClient, nas: FakeNas) -> None:
    nas.state.update(NewFTPWANEnable="1", NewFTPWANSSLOnly="1")
    svc = _svc(landevices, FakeFC(_responses(nas)))
    plan = svc.set_nas_internet_access_plan(False, ssl_only=False)
    out = svc.set_nas_internet_access_execute(plan["token"], False, False)
    assert out["verified"] is True and nas.state["NewFTPWANEnable"] == "0"


def test_nas_internet_requires_critical(landevices: LanDeviceClient, fc5: FakeFC) -> None:
    with pytest.raises(TierDisabledError):
        _svc(landevices, fc5, critical=False).set_nas_internet_access_plan(True)


# ------------------------------------------------------------------ set_remote_access (critical)


def test_remote_access_plan_execute(landevices: LanDeviceClient, nas: FakeNas, fc5: FakeFC) -> None:
    svc = _svc(landevices, fc5)
    plan = svc.set_remote_access_plan(True)
    assert "AUS DEM INTERNET" in plan["consequence"]
    out = svc.set_remote_access_execute(plan["token"], True)
    assert out == {
        "action": "set_remote_access",
        "enabled": True,
        "port": 44321,
        "read_back": True,
        "verified": True,
    }
    assert ("X_AVM-DE_RemoteAccess1", "SetEnable", {"NewEnabled": 1}) in fc5.calls
    assert REMOTE_USER not in json.dumps(plan)


def test_remote_access_port_zero_not_verified(landevices: LanDeviceClient, nas: FakeNas) -> None:
    nas.remote["NewUsername"] = ""
    nas.remote_port_on_enable = "0"
    svc = _svc(landevices, FakeFC(_responses(nas)))
    plan = svc.set_remote_access_plan(True)
    assert any("kein Benutzer" in w for w in plan["warnings"])
    out = svc.set_remote_access_execute(plan["token"], True)
    assert out["verified"] is False and "Port 0" in out["note"]


def test_remote_access_disable_warns_when_coming_from_internet(landevices: LanDeviceClient, nas: FakeNas) -> None:
    nas.remote.update(NewEnabled="1", NewPort="44321")
    responses = _responses(nas)
    responses[("X_AVM-DE_AppSetup1", "GetConfig")] = {"NewAccessFromInternet": "1", "NewInternetRights": "1"}
    svc = _svc(landevices, FakeFC(responses))
    plan = svc.set_remote_access_plan(False)
    assert any("ausgesperrt" in w for w in plan["warnings"])
    out = svc.set_remote_access_execute(plan["token"], False)
    assert out["verified"] is True


def test_remote_access_unchanged_and_tier(landevices: LanDeviceClient, fc5: FakeFC) -> None:
    assert _svc(landevices, fc5).set_remote_access_plan(False)["changed"] is False
    with pytest.raises(TierDisabledError):
        _svc(landevices, fc5, critical=False).set_remote_access_execute("x", True)


def test_remote_access_token_bound_to_state(landevices: LanDeviceClient, nas: FakeNas) -> None:
    svc = _svc(landevices, FakeFC(_responses(nas)))
    plan = svc.set_remote_access_plan(True)
    nas.remote["NewEnabled"] = "1"
    with pytest.raises(PlanError):
        svc.set_remote_access_execute(plan["token"], True)


# ------------------------------------------------------------------ generic caller: denylist + masking


@pytest.mark.parametrize(
    "service,action",
    [
        ("X_AVM-DE_WebDAVClient1", "GetInfo"),
        ("X_AVM-DE_Filelinks1", "GetGenericFilelinkEntry"),
        ("X_AVM-DE_Filelinks1", "GetSpecificFilelinkEntry"),
        ("X_AVM-DE_Filelinks1", "GetFilelinkListPath"),
        ("X_AVM-DE_AppSetup1", "GetBoxSenderId"),
        ("X_AVM-DE_AppSetup1", "X_AVM-DE_GetAppRemoteInfo"),
        ("X_AVM-DE_RemoteAccess1", "X_AVM-DE_GetDDNSInfo"),
        ("X_AVM-DE_RemoteAccess1", "GetDDNSInfo"),  # AVM doc spelling
        ("X_AVM-DE_RemoteAccess1", "X_AVM-DE_GetDDNSProviders"),
    ],
)
def test_stage5_secret_actions_denied(service: str, action: str) -> None:
    assert is_denied(action, service)
    with pytest.raises(ActionDeniedError):
        check_generic_action(service, action)


@pytest.mark.parametrize(
    "service,action",
    [
        ("X_AVM-DE_Storage1", "GetInfo"),
        ("X_AVM-DE_Storage1", "GetUserInfo"),
        ("X_AVM-DE_Filelinks1", "GetNumberOfFilelinkEntries"),
        ("X_AVM-DE_Media1", "GetInfo"),
        ("X_AVM-DE_MyFritz1", "GetServiceByIndex"),
        ("X_AVM-DE_USPController1", "GetUSPControllerByIndex"),
        ("X_AVM-DE_AppSetup1", "GetConfig"),
    ],
)
def test_stage5_harmless_actions_allowed(service: str, action: str) -> None:
    check_generic_action(service, action)


def _add_service(fc: FakeFC, name: str, *actions: str) -> None:
    fc.services[name] = SimpleNamespace(actions={a: SimpleNamespace(arguments={}) for a in actions}, state_variables={})


def test_generic_call_masks_login_names_and_email(landevices: LanDeviceClient, fc5: FakeFC) -> None:
    _add_service(fc5, "X_AVM-DE_RemoteAccess1", "GetInfo")
    _add_service(fc5, "X_AVM-DE_MyFritz1", "GetInfo")
    service = make_service(landevices, fc5)
    r = service.tr064_call("X_AVM-DE_RemoteAccess1", "GetInfo")["result"]
    assert r["NewUsername"] == "***" and r["NewEnabled"] == "0"
    r = service.tr064_call("X_AVM-DE_MyFritz:1", "GetInfo")["result"]
    assert r["NewEmail"] == "***" and r["NewDynDNSName"] == "abcdef123.myfritz.net"


def test_list_services_hides_service_bound_denials(landevices: LanDeviceClient, fc5: FakeFC) -> None:
    _add_service(fc5, "X_AVM-DE_WebDAVClient1", "GetInfo", "SetConfig")
    _add_service(fc5, "X_AVM-DE_Storage1", "GetInfo", "GetUserInfo", "SetSMBServer")
    service = make_service(landevices, fc5)
    by_name = {s["service"]: s for s in service.tr064_list_services()["services"]}
    assert by_name["X_AVM-DE_WebDAVClient1"]["read_actions"] == []
    assert by_name["X_AVM-DE_Storage1"]["read_actions"] == ["GetInfo", "GetUserInfo"]
    assert service.tr064_describe_action("X_AVM-DE_WebDAVClient1", "GetInfo")["denied"] is True


def test_redaction_of_update_url_and_filelink_token() -> None:
    assert is_secret_field("NewUpdateURL")
    assert redact_obj({"NewUpdateURL": UPDATE_URL})["NewUpdateURL"] == "***"
    assert LINK_ID not in redact(f"https://box.example/nas/filelink.lua?id={LINK_ID}")
    # stage-5 output keys must not be mistaken for secrets
    for key in ("mountpoint", "expire_days", "download_limit", "endpoint_id", "internet_user_configured"):
        assert not is_secret_field(key)


# ------------------------------------------------------------------ MCP layer


async def test_stage5_tools_tier_and_annotations() -> None:
    tools = {t.name: t for t in await build_server(MagicMock(), Gate(True, True)).list_tools()}
    assert tools["nas_status"].description.startswith("[Stufe: read]")
    assert tools["set_nas_protocol"].description.startswith("[Stufe: write]")
    assert tools["set_remote_access_execute"].description.startswith("[Stufe: critical]")
    assert tools["set_remote_access_execute"].annotations.destructive_hint is True
    assert tools["set_nas_internet_access_plan"].annotations.read_only_hint is True


async def test_set_nas_protocol_schema_rejects_unknown_protocol() -> None:
    from mcp.server.mcpserver.exceptions import ToolError

    server = build_server(MagicMock(), Gate(True, False))
    with pytest.raises(ToolError):
        await server.call_tool("set_nas_protocol", {"protocol": "nfs", "enabled": True})


async def test_stage5_results_are_redacted() -> None:
    service = MagicMock()
    service.nasremote.myfritz_status.return_value = {"dyndns": {"NewUpdateURL": UPDATE_URL}}
    result = await build_server(service, Gate(False, False)).call_tool("myfritz_status", {})
    assert "geheim-ddns" not in json.dumps(result.structured_content)


async def test_stage5_tool_routes_to_box() -> None:
    a, b = MagicMock(), MagicMock()
    b.nasremote.set_nas_protocol.return_value = {"verified": True}
    server = build_server({"heim": a, "zweit": b}, Gate(True, False))
    await server.call_tool("set_nas_protocol", {"protocol": "smb", "enabled": False, "box": "zweit"})
    b.nasremote.set_nas_protocol.assert_called_once_with("smb", False)
    a.nasremote.set_nas_protocol.assert_not_called()


@pytest.mark.parametrize(
    "remote,status,phrase",
    [
        ({"available": True, "enabled": False}, "ok", "derzeit nicht nutzbar"),
        ({"available": True, "enabled": True, "port": 44321}, "warn", "kann sich von außen anmelden"),
        ({"available": False}, "warn", "nicht lesbar"),
    ],
)
def test_assess_mcp_user_right_vs_enabled_access(remote: dict[str, Any], status: str, phrase: str) -> None:
    """Live finding: 'darf auch aus dem Internet zugreifen' next to access_from_internet: false – the AppSetup
    flag means 'this request came from the internet', not 'internet access enabled'."""
    checks = {
        c["check"]: c
        for c in assess(
            {
                "remote_access": remote,
                "apps": {
                    "available": True,
                    "mcp_user_internet_rights": True,
                    "current_request_from_internet": False,
                },
            }
        )
    }
    c = checks["mcp_benutzer_internet"]
    assert c["status"] == status and phrase in c["summary"]
    assert c["details"]["internet_right"] is True and c["details"]["current_request_from_internet"] is False
    assert "access_from_internet" not in c["details"]


def test_apps_fields_are_named_by_meaning(landevices: LanDeviceClient, nas: FakeNas) -> None:
    responses = _responses(nas)
    responses[("X_AVM-DE_AppSetup1", "GetConfig")] = {"NewInternetRights": "1", "NewAccessFromInternet": "0"}
    apps = _svc(landevices, FakeFC(responses)).myfritz_status()["apps"]
    assert apps["mcp_user_internet_rights"] is True and apps["current_request_from_internet"] is False
    assert "access_from_internet" not in apps
