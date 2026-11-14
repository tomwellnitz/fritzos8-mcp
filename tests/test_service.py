from __future__ import annotations

from typing import Any

import pytest
from fritzconnection.core.exceptions import FritzConnectionException

from fritzos8_mcp.errors import InvalidParameterError, PlanError, TierDisabledError
from fritzos8_mcp.landevice import LanDeviceClient

from .conftest import FakeBox, FakeFC, make_service


class HostNames:
    """Simulates the TR-064 host name store of the box."""

    def __init__(self, discard: bool = False) -> None:
        self.names: dict[str, str] = {"AA:BB:CC:DD:EE:01": "pc-buero"}
        self.discard = discard

    def set(self, NewMACAddress: str, NewHostName: str) -> dict[str, Any]:
        if not self.discard:
            self.names[NewMACAddress] = NewHostName
        return {}

    def get(self, NewMACAddress: str) -> dict[str, Any]:
        return {"NewHostName": self.names.get(NewMACAddress, "")}


def fc_with_names(names: HostNames) -> FakeFC:
    return FakeFC(
        {
            ("Hosts1", "X_AVM-DE_SetHostNameByMACAddress"): names.set,
            ("Hosts1", "GetSpecificHostEntry"): names.get,
        }
    )


# ------------------------------------------------------------------ gates


@pytest.mark.parametrize(
    "call",
    [
        lambda s: s.rename_host("AA:BB:CC:DD:EE:01", "x"),
        lambda s: s.set_static_ip("AA:BB:CC:DD:EE:01"),
        lambda s: s.delete_host("AA:BB:CC:DD:EE:02"),
    ],
)
def test_write_tools_need_write_tier(landevices: LanDeviceClient, fake_box: FakeBox, call: Any) -> None:
    svc = make_service(landevices, FakeFC(), write=False, critical=False)
    with pytest.raises(TierDisabledError):
        call(svc)
    assert fake_box.requests == []  # gate checked before any box access


@pytest.mark.parametrize(
    "call",
    [
        lambda s: s.reboot_plan(),
        lambda s: s.reboot_execute("t"),
        lambda s: s.reconnect_wan_plan(),
        lambda s: s.delete_host_force_plan("AA:BB:CC:DD:EE:01"),
    ],
)
def test_critical_tools_need_critical_tier(landevices: LanDeviceClient, call: Any) -> None:
    svc = make_service(landevices, FakeFC(), write=True, critical=False)
    with pytest.raises(TierDisabledError):
        call(svc)


# ------------------------------------------------------------------ rename_host


def test_rename_sets_both_names_and_verifies(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    names = HostNames()
    svc = make_service(landevices, fc_with_names(names))
    r = svc.rename_host("aa-bb-cc-dd-ee-01", "Arbeits-PC")
    assert r["verified"] is True
    assert r["host_name"] == {"ok": True, "verified": True, "read_back": "Arbeits-PC"}
    assert r["friendly_name"]["verified"] is True
    assert names.names["AA:BB:CC:DD:EE:01"] == "Arbeits-PC"
    assert fake_box._find("landevice1001")["friendly_name"] == "Arbeits-PC"


def test_rename_rejects_ambiguous_mac_before_any_write(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    fc = fc_with_names(HostNames())
    svc = make_service(landevices, fc)
    with pytest.raises(InvalidParameterError, match="mehrere"):
        svc.rename_host("AA:BB:CC:DD:EE:03", "neu")
    assert fc.calls == []
    assert not [q for q in fake_box.requests if q.method != "GET"]


def test_rename_with_uid_resolves_ambiguity(landevices: LanDeviceClient) -> None:
    names = HostNames()
    svc = make_service(landevices, fc_with_names(names))
    r = svc.rename_host("AA:BB:CC:DD:EE:03", "neu", uid="landevice2002")
    assert r["uid"] == "landevice2002" and r["friendly_name"]["verified"] is True


def test_rename_reports_unverified_tr064_step(landevices: LanDeviceClient) -> None:
    svc = make_service(landevices, fc_with_names(HostNames(discard=True)))
    r = svc.rename_host("AA:BB:CC:DD:EE:01", "Arbeits-PC")
    assert r["host_name"]["verified"] is False
    assert r["friendly_name"]["verified"] is True
    assert r["verified"] is False  # never claim success


def test_rename_two_factor_on_tr064_step(landevices: LanDeviceClient) -> None:
    fc = FakeFC({("Hosts1", "X_AVM-DE_SetHostNameByMACAddress"): FritzConnectionException("errorCode: 866")})
    svc = make_service(landevices, fc)
    r = svc.rename_host("AA:BB:CC:DD:EE:01", "Arbeits-PC")
    assert r["host_name"]["error"]["type"] == "confirmation_required"
    assert r["verified"] is False


def test_rename_friendly_name_silently_discarded(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    fake_box.discard_writes = True
    svc = make_service(landevices, fc_with_names(HostNames()))
    r = svc.rename_host("AA:BB:CC:DD:EE:01", "Arbeits-PC")
    assert r["friendly_name"]["ok"] is False
    assert r["friendly_name"]["error"]["type"] == "confirmation_required"
    assert r["verified"] is False


# ------------------------------------------------------------------ static ip / delete


def test_set_static_ip(landevices: LanDeviceClient) -> None:
    r = make_service(landevices, FakeFC()).set_static_ip("AA:BB:CC:DD:EE:01")
    assert r["verified"] is True and r["static_dhcp"] is True


def test_delete_host_refuses_active(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    with pytest.raises(InvalidParameterError, match="aktiv") as ei:
        make_service(landevices, FakeFC()).delete_host("AA:BB:CC:DD:EE:01")
    assert "delete_host_force_plan" in (ei.value.hint or "")
    assert not [q for q in fake_box.requests if q.method == "DELETE"]


def test_delete_host_refuses_protected_even_with_force(landevices: LanDeviceClient) -> None:
    svc = make_service(landevices, FakeFC())
    with pytest.raises(InvalidParameterError, match="nicht löschbar"):
        svc.delete_host("AA:BB:CC:DD:EE:00")
    with pytest.raises(InvalidParameterError, match="nicht löschbar"):
        svc.delete_host_force_plan("AA:BB:CC:DD:EE:00")


def test_delete_inactive_host(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    r = make_service(landevices, FakeFC()).delete_host("AA:BB:CC:DD:EE:02")
    assert r["verified"] is True and fake_box._find("landevice1002") is None


def test_force_delete_plan_execute(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    svc = make_service(landevices, FakeFC())
    plan = svc.delete_host_force_plan("AA:BB:CC:DD:EE:01")
    assert plan["target"]["uid"] == "landevice1001"
    assert not [q for q in fake_box.requests if q.method == "DELETE"]  # planning changes nothing
    r = svc.delete_host_force_execute(plan["token"], "AA:BB:CC:DD:EE:01", "landevice1001")
    assert r["verified"] is True
    with pytest.raises(PlanError):  # token is single-use
        svc.delete_host_force_execute(plan["token"], "AA:BB:CC:DD:EE:01", "landevice1001")


def test_force_delete_token_bound_to_target(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    svc = make_service(landevices, FakeFC())
    plan = svc.delete_host_force_plan("AA:BB:CC:DD:EE:01")
    with pytest.raises(PlanError, match="passt nicht"):
        svc.delete_host_force_execute(plan["token"], "AA:BB:CC:DD:EE:02", "landevice1002")
    assert fake_box._find("landevice1002") is not None


def test_force_delete_fails_if_target_changed(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    svc = make_service(landevices, FakeFC())
    plan = svc.delete_host_force_plan("AA:BB:CC:DD:EE:01")
    fake_box._find("landevice1001")["mac"] = "AA:BB:CC:DD:EE:77"  # entry replaced meanwhile
    with pytest.raises(PlanError, match="geändert"):
        svc.delete_host_force_execute(plan["token"], "AA:BB:CC:DD:EE:01", "landevice1001")
    assert fake_box._find("landevice1001") is not None


# ------------------------------------------------------------------ reboot / reconnect


def test_reboot_plan_execute(landevices: LanDeviceClient) -> None:
    fc = FakeFC({("DeviceInfo1", "GetInfo"): {"NewUpTime": 7200}})
    svc = make_service(landevices, fc)
    plan = svc.reboot_plan()
    assert plan["current"]["uptime_s"] == 7200
    assert ("DeviceConfig1", "Reboot", {}) not in fc.calls
    r = svc.reboot_execute(plan["token"])
    assert ("DeviceConfig1", "Reboot", {}) in fc.calls
    assert r["verified"] is False and "system_info" in r["note"]


def test_reboot_execute_without_valid_token(landevices: LanDeviceClient) -> None:
    fc = FakeFC()
    with pytest.raises(PlanError):
        make_service(landevices, fc).reboot_execute("deadbeef")
    assert ("DeviceConfig1", "Reboot", {}) not in fc.calls


def test_reconnect_token_cannot_reboot(landevices: LanDeviceClient) -> None:
    fc = FakeFC({("WANIPConn1", "GetStatusInfo"): {"NewConnectionStatus": "Connected", "NewUptime": 999}})
    svc = make_service(landevices, fc)
    token = svc.reconnect_wan_plan()["token"]
    with pytest.raises(PlanError):
        svc.reboot_execute(token)


def test_reconnect_verified_when_uptime_restarts(landevices: LanDeviceClient) -> None:
    statuses = iter(
        [
            {"NewConnectionStatus": "Connected", "NewUptime": 5000},  # plan
            {"NewConnectionStatus": "Connected", "NewUptime": 5001},  # before execute
            {"NewConnectionStatus": "Connecting", "NewUptime": 0},
            {"NewConnectionStatus": "Connected", "NewUptime": 3},
        ]
    )
    fc = FakeFC({("WANIPConn1", "GetStatusInfo"): lambda: next(statuses)})
    svc = make_service(landevices, fc)
    r = svc.reconnect_wan_execute(svc.reconnect_wan_plan()["token"])
    assert ("WANIPConn1", "ForceTermination", {}) in fc.calls
    assert r["verified"] is True


def test_reconnect_unverified_on_timeout(landevices: LanDeviceClient) -> None:
    fc = FakeFC({("WANIPConn1", "GetStatusInfo"): {"NewConnectionStatus": "Connected", "NewUptime": 5000}})
    svc = make_service(landevices, fc)
    r = svc.reconnect_wan_execute(svc.reconnect_wan_plan()["token"])
    assert r["verified"] is False and "note" in r
