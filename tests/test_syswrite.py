"""Stage 10.6a – firmware update, static routes, IPv6 pinholes, 2FA status (in-memory TR-064, invented values)."""

from __future__ import annotations

import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fritzconnection.core.exceptions import FritzActionError, FritzConnectionException, FritzSecurityError

from fritzos8_mcp.errors import InvalidParameterError, NotFoundError, PermissionDeniedError, PlanError
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.security import is_denied

from .conftest import FakeFC, _action, _arg, make_service

V6 = "2001:db8::1"  # documentation prefix is NOT global → used for the rejection test
GLOBAL_V6 = "2a00:1450:4001:80b::200e"  # some public address (invented use)


class Box:
    def __init__(self) -> None:
        self.update_available = True
        self.updates: list[str] = []
        self.routes: dict[tuple[str, str], dict[str, Any]] = {}
        self.pinholes: dict[int, dict[str, Any]] = {}
        self.next_uid = 7
        self.deny_pinhole = False

    def _route_get(self, **kw: Any) -> dict[str, Any]:
        r = self.routes.get((kw["NewDestIPAddress"], kw["NewDestSubnetMask"]))
        if r is None:
            raise FritzConnectionException("errorCode: 714\nerrorDescription: NoSuchEntryInArray")
        return r

    def _route_add(self, **kw: Any) -> dict[str, Any]:
        assert kw["NewSourceIPAddress"] == "0.0.0.0"
        self.routes[(kw["NewDestIPAddress"], kw["NewDestSubnetMask"])] = {
            "NewGatewayIPAddress": kw["NewGatewayIPAddress"],
            "NewEnable": "0",  # live: a new entry is read back disabled until SetForwardingEntryEnable
            "NewType": kw["NewType"],
        }
        return {}

    def _route_enable(self, **kw: Any) -> dict[str, Any]:
        assert kw["NewSourceIPAddress"] == "0.0.0.0"
        self.routes[(kw["NewDestIPAddress"], kw["NewDestSubnetMask"])]["NewEnable"] = str(kw["NewEnable"])
        return {}

    def _route_del(self, **kw: Any) -> dict[str, Any]:
        self.routes.pop((kw["NewDestIPAddress"], kw["NewDestSubnetMask"]), None)
        return {}

    def _add_pinhole(self, **kw: Any) -> dict[str, Any]:
        if self.deny_pinhole:
            raise FritzSecurityError("errorCode: 606 Action not authorized")
        assert set(kw) == {"RemoteHost", "RemotePort", "InternalClient", "InternalPort", "Protocol", "LeaseTime"}
        self.next_uid += 1
        self.pinholes[self.next_uid] = kw
        return {"UniqueID": self.next_uid}

    def _update_pinhole(self, UniqueID: int, NewLeaseTime: int) -> dict[str, Any]:
        if UniqueID not in self.pinholes:
            raise FritzActionError("errorCode: 704 NoSuchEntry")
        return {}

    def _delete_pinhole(self, UniqueID: int) -> dict[str, Any]:
        self.pinholes.pop(UniqueID, None)
        return {}

    def fc(self) -> FakeFC:
        fc = FakeFC(
            {
                ("UserInterface1", "GetInfo"): lambda: {
                    "NewUpgradeAvailable": "1" if self.update_available else "0",
                    "NewX_AVM-DE_Version": "8.30",
                    "NewX_AVM-DE_UpdateState": "UpdateAvailable" if self.update_available else "NoUpdate",
                    "NewX_AVM-DE_InfoURL": "https://example.com/info",
                },
                ("UserInterface1", "X_AVM-DE_CheckUpdate"): {},
                ("UserInterface1", "X_AVM-DE_DoUpdate"): lambda: (
                    self.updates.append("go") or {"NewX_AVM-DE_UpdateState": "Started"}
                ),
                ("UserInterface1", "X_AVM-DE_GetInfo"): {"NewX_AVM-DE_UpdateSuccessful": "succeeded"},
                ("DeviceInfo1", "GetInfo"): {"NewSoftwareVersion": "8.25", "NewModelName": "FRITZ!Box 7590"},
                ("Layer3Forwarding1", "GetSpecificForwardingEntry"): self._route_get,
                ("Layer3Forwarding1", "AddForwardingEntry"): self._route_add,
                ("Layer3Forwarding1", "DeleteForwardingEntry"): self._route_del,
                ("Layer3Forwarding1", "SetForwardingEntryEnable"): self._route_enable,
                ("Layer3Forwarding1", "GetDefaultConnectionService"): {
                    "NewDefaultConnectionService": "1.WANPPPConnection.1"
                },
                ("WANIPv6FirewallControl1", "GetFirewallStatus"): {
                    "FirewallEnabled": "1",
                    "InboundPinholeAllowed": "1",
                },
                ("WANIPv6FirewallControl1", "AddPinhole"): self._add_pinhole,
                ("WANIPv6FirewallControl1", "UpdatePinhole"): self._update_pinhole,
                ("WANIPv6FirewallControl1", "DeletePinhole"): self._delete_pinhole,
                ("X_AVM-DE_Auth1", "GetInfo"): {"NewEnabled": "1"},
                ("X_AVM-DE_Auth1", "GetState"): {"NewState": "waitingforauth"},
            }
        )
        names = ("RemoteHost", "RemotePort", "InternalClient", "InternalPort", "Protocol", "LeaseTime")
        fc.services["WANIPv6FirewallControl1"] = SimpleNamespace(
            actions={
                "AddPinhole": _action(*(_arg(n, "in", n) for n in names), _arg("UniqueID", "out", "UniqueID")),
                "UpdatePinhole": _action(_arg("UniqueID", "in", "UniqueID"), _arg("NewLeaseTime", "in", "LeaseTime")),
                "DeletePinhole": _action(_arg("UniqueID", "in", "UniqueID")),
                "GetFirewallStatus": _action(),
            },
            state_variables={},
        )
        return fc


@pytest.fixture
def box() -> Box:
    return Box()


def _svc(landevices: LanDeviceClient, box: Box, tmp_path: Path, critical: bool = True) -> Any:
    svc = make_service(landevices, box.fc(), critical=critical)
    svc.system_write._state_root = tmp_path / "state"
    return svc.system_write


# ------------------------------------------------------------------ firmware


def test_firmware_update_plan_execute(landevices: LanDeviceClient, box: Box, tmp_path: Path) -> None:
    sw = _svc(landevices, box, tmp_path)
    plan = sw.firmware_update_plan()
    assert plan["available_version"] == "8.30" and plan["checked_now"] is True
    assert any("Strom" in w for w in plan["warnings"])
    r = sw.firmware_update_execute(plan["token"])
    assert r == {
        "accepted": True,
        "verified": False,
        "from_version": "8.25",
        "to_version": "8.30",
        "update_state": "Started",
        "note": r["note"],
    }
    assert box.updates == ["go"]
    assert sw.firmware_update_status()["last_update"]["successful"] == "succeeded"
    assert is_denied("X_AVM-DE_DoUpdate")  # generic caller stays closed


def test_firmware_without_update_issues_no_token(landevices: LanDeviceClient, box: Box, tmp_path: Path) -> None:
    box.update_available = False
    plan = _svc(landevices, box, tmp_path).firmware_update_plan(check=False)
    assert "token" not in plan and plan["checked_now"] is False


def test_firmware_token_bound_to_offered_version(landevices: LanDeviceClient, box: Box, tmp_path: Path) -> None:
    sw = _svc(landevices, box, tmp_path)
    plan = sw.firmware_update_plan()
    box.update_available = False  # offer vanished / changed in between
    with pytest.raises(PlanError):
        sw.firmware_update_execute(plan["token"])
    assert box.updates == []


# ------------------------------------------------------------------ static routes


def test_static_route_add_and_delete(landevices: LanDeviceClient, box: Box, tmp_path: Path) -> None:
    sw = _svc(landevices, box, tmp_path)
    plan = sw.static_route_add_plan("10.8.0.0", "255.255.255.0", "192.0.2.20")
    assert plan["route"]["network"] == "10.8.0.0/24"
    r = sw.static_route_add_execute(plan["token"], "10.8.0.0", "255.255.255.0", "192.0.2.20")
    assert r["verified"] is True
    assert box.routes[("10.8.0.0", "255.255.255.0")]["NewType"] == "Network"
    with pytest.raises(InvalidParameterError, match="schon eine Route"):
        sw.static_route_add_plan("10.8.0.0", "255.255.255.0", "192.0.2.21")
    d = sw.static_route_delete_plan("10.8.0.0", "255.255.255.0")
    assert d["route"]["gateway"] == "192.0.2.20"
    assert sw.static_route_delete_execute(d["token"], "10.8.0.0", "255.255.255.0")["verified"] is True
    with pytest.raises(NotFoundError):
        sw.static_route_delete_plan("10.8.0.0", "255.255.255.0")


@pytest.mark.parametrize(
    "dest,mask,gw,match",
    [
        ("10.8.0.1", "255.255.255.0", "192.0.2.20", "Netzadresse"),
        ("0.0.0.0", "0.0.0.0", "192.0.2.20", "Default-Route"),
        ("10.8.0.0", "255.255.255.0", "10.8.0.5", "Zielnetz"),
        ("10.8.0.0", "255.255.255.0", "8.8.8.8", "Heimnetz"),
        ("10.8.0.x", "255.255.255.0", "192.0.2.20", "IPv4"),
    ],
)
def test_static_route_validation(
    landevices: LanDeviceClient, box: Box, tmp_path: Path, dest: str, mask: str, gw: str, match: str
) -> None:
    with pytest.raises(InvalidParameterError, match=match):
        _svc(landevices, box, tmp_path).static_route_add_plan(dest, mask, gw)


def test_route_execute_rejects_changed_params(landevices: LanDeviceClient, box: Box, tmp_path: Path) -> None:
    sw = _svc(landevices, box, tmp_path)
    plan = sw.static_route_add_plan("10.8.0.0", "255.255.255.0", "192.0.2.20")
    with pytest.raises(PlanError):
        sw.static_route_add_execute(plan["token"], "10.8.0.0", "255.255.255.0", "192.0.2.99")
    assert box.routes == {}


# ------------------------------------------------------------------ IPv6 pinholes


def test_pinhole_add_verify_list_delete(landevices: LanDeviceClient, box: Box, tmp_path: Path) -> None:
    sw = _svc(landevices, box, tmp_path)
    plan = sw.ipv6_pinhole_add_plan(GLOBAL_V6, 443, "TCP", 600)
    assert any("GESAMTE Internet" in w for w in plan["warnings"])
    r = sw.ipv6_pinhole_add_execute(plan["token"], GLOBAL_V6, 443, "TCP", 600)
    assert r["verified"] is True and r["pinhole"]["unique_id"] == 8
    assert box.pinholes[8]["Protocol"] == 6 and box.pinholes[8]["LeaseTime"] == 600
    status = sw.firewall_status()
    assert status["firewall_enabled"] is True and status["inbound_pinholes_allowed"] is True
    assert status["pinholes_created_here"][0]["unique_id"] == 8
    path = tmp_path / "state" / "fritz.test" / "pinholes.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    d = sw.ipv6_pinhole_delete_plan(8)
    assert d["pinhole"]["internal_port"] == 443
    assert sw.ipv6_pinhole_delete_execute(d["token"], 8) == {"unique_id": 8, "deleted": True, "verified": True}
    assert sw.firewall_status()["pinholes_created_here"] == []


@pytest.mark.parametrize("client", [V6, "fe80::1", "fd00::1", "192.0.2.5"])
def test_pinhole_requires_global_ipv6(landevices: LanDeviceClient, box: Box, tmp_path: Path, client: str) -> None:
    with pytest.raises(InvalidParameterError):
        _svc(landevices, box, tmp_path).ipv6_pinhole_add_plan(client, 443)


def test_pinhole_denied_by_box_is_explained(landevices: LanDeviceClient, box: Box, tmp_path: Path) -> None:
    box.deny_pinhole = True
    sw = _svc(landevices, box, tmp_path)
    plan = sw.ipv6_pinhole_add_plan(GLOBAL_V6, 22, "TCP", 600)
    with pytest.raises(PermissionDeniedError) as exc:
        sw.ipv6_pinhole_add_execute(plan["token"], GLOBAL_V6, 22, "TCP", 600)
    assert "UPnP" in (exc.value.hint or "")


# ------------------------------------------------------------------ 2FA


def test_two_factor_status_only_detects(landevices: LanDeviceClient, box: Box, tmp_path: Path) -> None:
    fc = box.fc()
    svc = make_service(landevices, fc)
    r = svc.system_write.two_factor_status()
    assert r["enabled"] is True and r["state"] == "waitingforauth"
    assert "Taste" in r["meaning"]
    assert "nie selbst" in r["note"]
    # never starts/stops a second-factor process
    assert not any(a == "SetConfig" for _, a, _ in fc.calls)
