from __future__ import annotations

import json
from typing import Any

import pytest
from fritzconnection.core.exceptions import FritzConnectionException, FritzSecurityError

from fritzos8_mcp.access import HostResolver, validate_ipv4
from fritzos8_mcp.errors import (
    ConfirmationRequiredError,
    InvalidParameterError,
    NotFoundError,
    PermissionDeniedError,
    PlanError,
    TierDisabledError,
)
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.security import Gate, PlanStore
from fritzos8_mcp.service import FritzService
from fritzos8_mcp.tr064 import Tr064Client

from .conftest import PASSWORD, FakeFC

BOX = "192.0.2.1"
SERVER = "192.0.2.50"

HOSTS = [
    {"NewHostName": "fritz.box", "NewIPAddress": BOX, "NewMACAddress": "AA:BB:CC:DD:EE:00", "NewActive": True},
    {
        "NewHostName": "pc-buero",
        "NewIPAddress": "192.0.2.20",
        "NewMACAddress": "AA:BB:CC:DD:EE:01",
        "NewActive": True,
    },
    {
        "NewHostName": "tablet-kind",
        "NewIPAddress": "192.0.2.30",
        "NewMACAddress": "aa:bb:cc:dd:ee:02",
        "NewActive": False,
    },
    {"NewHostName": "mac-mini", "NewIPAddress": SERVER, "NewMACAddress": "AA:BB:CC:DD:EE:05", "NewActive": True},
    {"NewHostName": "ohne-ip", "NewIPAddress": "", "NewMACAddress": "AA:BB:CC:DD:EE:06", "NewActive": False},
    {
        "NewHostName": "dual-a",
        "NewIPAddress": "192.0.2.40",
        "NewMACAddress": "AA:BB:CC:DD:EE:07",
        "NewActive": True,
    },
    {
        "NewHostName": "dual-b",
        "NewIPAddress": "192.0.2.41",
        "NewMACAddress": "AA:BB:CC:DD:EE:07",
        "NewActive": False,
    },
]


class Box:
    """In-memory host list, host filter and WAN port mappings."""

    def __init__(self, *, discard: bool = False, public_ip: str = "203.0.113.7") -> None:
        self.blocked: dict[str, bool] = {}
        self.mappings: list[dict[str, Any]] = [
            {
                "NewRemoteHost": "",
                "NewExternalPort": 8443,
                "NewProtocol": "TCP",
                "NewInternalPort": 443,
                "NewInternalClient": "192.0.2.20",
                "NewEnabled": "1",
                "NewPortMappingDescription": "nas",
                "NewLeaseDuration": 0,
            }
        ]
        self.discard = discard
        self.public_ip = public_ip

    def _entry(self, NewPortMappingIndex: int) -> dict[str, Any]:
        if NewPortMappingIndex >= len(self.mappings):
            raise FritzConnectionException("errorCode: 713\nerrorDescription: SpecifiedArrayIndexInvalid")
        return self.mappings[NewPortMappingIndex]

    def _specific(self, NewRemoteHost: str, NewExternalPort: int, NewProtocol: str) -> dict[str, Any]:
        for m in self.mappings:
            if m["NewExternalPort"] == NewExternalPort and m["NewProtocol"] == NewProtocol:
                return m
        raise FritzConnectionException("errorCode: 714\nerrorDescription: NoSuchEntryInArray")

    def _add(self, **kw: Any) -> dict[str, Any]:
        if not self.discard:
            self.mappings.append(dict(kw))
        return {}

    def _delete(self, NewRemoteHost: str, NewExternalPort: int, NewProtocol: str) -> dict[str, Any]:
        if not self.discard:
            self.mappings = [
                m for m in self.mappings if (m["NewExternalPort"], m["NewProtocol"]) != (NewExternalPort, NewProtocol)
            ]
        return {}

    def _disallow(self, NewIPv4Address: str, NewDisallow: int) -> dict[str, Any]:
        if not self.discard:
            self.blocked[NewIPv4Address] = bool(NewDisallow)
        return {}

    def responses(self) -> dict[tuple[str, str], Any]:
        return {
            ("Hosts1", "X_AVM-DE_GetHostListPath"): {},
            ("Hosts1", "GetHostNumberOfEntries"): {"NewHostNumberOfEntries": len(HOSTS)},
            ("Hosts1", "GetGenericHostEntry"): lambda NewIndex: HOSTS[NewIndex],
            ("LANHostConfigManagement1", "GetIPRoutersList"): {"NewIPRouters": BOX},
            ("X_AVM-DE_HostFilter1", "GetWANAccessByIP"): lambda NewIPv4Address: {
                "NewDisallow": "1" if self.blocked.get(NewIPv4Address) else "0",
                "NewWANAccess": "denied" if self.blocked.get(NewIPv4Address) else "granted",
            },
            ("X_AVM-DE_HostFilter1", "DisallowWANAccessByIP"): self._disallow,
            ("WANIPConn1", "GetStatusInfo"): {"NewConnectionStatus": "Connected", "NewUptime": 100},
            ("WANIPConn1", "GetExternalIPAddress"): lambda: {"NewExternalIPAddress": self.public_ip},
            ("WANIPConn1", "GetPortMappingNumberOfEntries"): lambda: {
                "NewPortMappingNumberOfEntries": len(self.mappings)
            },
            ("WANIPConn1", "GetGenericPortMappingEntry"): self._entry,
            ("WANIPConn1", "GetSpecificPortMappingEntry"): self._specific,
            ("WANIPConn1", "AddPortMapping"): self._add,
            ("WANIPConn1", "DeletePortMapping"): self._delete,
        }


def service(
    landevices: LanDeviceClient, box: Box, *, write: bool = True, critical: bool = True
) -> tuple[FritzService, FakeFC]:
    fc = FakeFC(box.responses())
    fc.address = f"http://{BOX}"
    svc = FritzService(
        Tr064Client(lambda: fc, (PASSWORD,)),  # type: ignore[arg-type,return-value]
        landevices,
        Gate(write, critical),
        PlanStore(),
        local_ips=lambda: {SERVER},
        sleep=lambda s: None,
    )
    return svc, fc


def calls(fc: FakeFC, action: str) -> list[Any]:
    return [c for c in fc.calls if c[1] == action]


# ------------------------------------------------------------------ resolver


def test_validate_ipv4() -> None:
    assert validate_ipv4(" 192.0.2.20 ") == "192.0.2.20"
    with pytest.raises(InvalidParameterError):
        validate_ipv4("fe80::1")


def test_resolve_by_mac_and_ip(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, Box())
    h = svc.resolver.resolve(mac="aa-bb-cc-dd-ee-02")
    assert (h.name, h.ip, h.mac, h.active) == ("tablet-kind", "192.0.2.30", "AA:BB:CC:DD:EE:02", False)
    assert svc.resolver.resolve(ip="192.0.2.20").mac == "AA:BB:CC:DD:EE:01"


@pytest.mark.parametrize(
    "kwargs,exc",
    [
        ({}, InvalidParameterError),
        ({"mac": "AA:BB:CC:DD:EE:01", "ip": "192.0.2.20"}, InvalidParameterError),
        ({"mac": "AA:BB:CC:DD:EE:99"}, NotFoundError),
        ({"mac": "AA:BB:CC:DD:EE:06"}, NotFoundError),  # no IPv4
        ({"mac": "AA:BB:CC:DD:EE:07"}, InvalidParameterError),  # two IPs
        ({"ip": "192.0.2.99"}, NotFoundError),
    ],
)
def test_resolve_errors(landevices: LanDeviceClient, kwargs: dict[str, str], exc: type) -> None:
    svc, _ = service(landevices, Box())
    with pytest.raises(exc):
        svc.resolver.resolve(**kwargs)


def test_box_ips_from_address_and_routers(landevices: LanDeviceClient) -> None:
    svc, fc = service(landevices, Box())
    fc.address = "http://fritz.box"
    assert svc.resolver.box_ips() == {BOX}


def test_no_local_ips_without_detector(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, Box())
    assert HostResolver(svc.tr064).server_ips() == set()


# ------------------------------------------------------------------ internet access


def test_internet_access_status(landevices: LanDeviceClient) -> None:
    box = Box()
    box.blocked["192.0.2.30"] = True
    svc, _ = service(landevices, box)
    r = svc.internet_access_status(mac="AA:BB:CC:DD:EE:02")
    assert r["blocked"] is True and r["wan_access"] == "denied" and r["name"] == "tablet-kind"
    assert svc.internet_access_status(ip="192.0.2.20")["blocked"] is False


def test_set_internet_access_needs_write(landevices: LanDeviceClient) -> None:
    svc, fc = service(landevices, Box(), write=False, critical=False)
    with pytest.raises(TierDisabledError):
        svc.set_internet_access("AA:BB:CC:DD:EE:02", False)
    assert fc.calls == []


def test_block_and_unblock_verified(landevices: LanDeviceClient) -> None:
    box = Box()
    svc, fc = service(landevices, box)
    r = svc.set_internet_access("AA:BB:CC:DD:EE:02", False)
    assert r["verified"] is True and r["changed"] is True and r["wan_access"] == "denied"
    assert calls(fc, "DisallowWANAccessByIP")[0][2] == {"NewIPv4Address": "192.0.2.30", "NewDisallow": 1}
    r = svc.set_internet_access("AA:BB:CC:DD:EE:02", True)
    assert r["verified"] is True and box.blocked["192.0.2.30"] is False


def test_block_unchanged(landevices: LanDeviceClient) -> None:
    box = Box()
    box.blocked["192.0.2.30"] = True
    svc, fc = service(landevices, box)
    r = svc.set_internet_access("AA:BB:CC:DD:EE:02", False)
    assert r["changed"] is False and r["verified"] is True
    assert calls(fc, "DisallowWANAccessByIP") == []


@pytest.mark.parametrize("mac,reason", [("AA:BB:CC:DD:EE:00", "FRITZ!Box selbst"), ("AA:BB:CC:DD:EE:05", "MCP-Server")])
def test_never_block_box_or_server(landevices: LanDeviceClient, mac: str, reason: str) -> None:
    svc, fc = service(landevices, Box())
    with pytest.raises(InvalidParameterError, match=reason):
        svc.set_internet_access(mac, False)
    assert calls(fc, "DisallowWANAccessByIP") == []


def test_unblocking_server_is_allowed(landevices: LanDeviceClient) -> None:
    box = Box()
    box.blocked[SERVER] = True
    svc, _ = service(landevices, box)
    assert svc.set_internet_access("AA:BB:CC:DD:EE:05", True)["verified"] is True


def test_block_silently_discarded(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, Box(discard=True))
    r = svc.set_internet_access("AA:BB:CC:DD:EE:02", False)
    assert r["verified"] is False and r["read_back_blocked"] is False


def test_block_two_factor(landevices: LanDeviceClient) -> None:
    svc, fc = service(landevices, Box())
    fc.responses[("X_AVM-DE_HostFilter1", "DisallowWANAccessByIP")] = FritzConnectionException("errorCode: 866")
    with pytest.raises(ConfirmationRequiredError):
        svc.set_internet_access("AA:BB:CC:DD:EE:02", False)


# ------------------------------------------------------------------ port forwards: read


def test_list_port_forwards_with_names(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, Box())
    r = svc.list_port_forwards()
    assert r["count"] == 1 and r["active"] == 1 and r["service"] == "WANIPConn1"
    assert r["port_forwards"][0]["internal_name"] == "pc-buero"


# ------------------------------------------------------------------ add (critical)

ADD = {"protocol": "TCP", "external_port": 2222, "internal_port": 22, "description": "ssh test"}


def test_add_needs_critical(landevices: LanDeviceClient) -> None:
    svc, fc = service(landevices, Box(), write=True, critical=False)
    with pytest.raises(TierDisabledError):
        svc.add_port_forward_plan(**ADD, mac="AA:BB:CC:DD:EE:05")
    with pytest.raises(TierDisabledError):
        svc.add_port_forward_execute("t", **ADD, mac="AA:BB:CC:DD:EE:05")
    assert fc.calls == []


def test_add_plan_execute_verified(landevices: LanDeviceClient) -> None:
    box = Box()
    svc, fc = service(landevices, box)
    plan = svc.add_port_forward_plan(**ADD, mac="AA:BB:CC:DD:EE:05")
    assert "203.0.113.7:2222/TCP" in plan["consequence"] and "INTERNET" in plan["consequence"]
    assert any("SSH" in w for w in plan["warnings"])
    assert plan["execute_with"]["ip"] == SERVER
    assert calls(fc, "AddPortMapping") == []  # planning changes nothing
    r = svc.add_port_forward_execute(plan["token"], **ADD, mac="AA:BB:CC:DD:EE:05")
    assert r["verified"] is True and r["internal_client"] == SERVER
    args = calls(fc, "AddPortMapping")[0][2]
    assert args["NewInternalClient"] == SERVER and args["NewLeaseDuration"] == 0 and args["NewEnabled"] == 1
    with pytest.raises(PlanError):
        svc.add_port_forward_execute(plan["token"], **ADD, mac="AA:BB:CC:DD:EE:05")


def test_add_execute_with_ip_from_plan(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, Box())
    plan = svc.add_port_forward_plan(**ADD, mac="AA:BB:CC:DD:EE:05")
    r = svc.add_port_forward_execute(plan["token"], **ADD, ip=plan["execute_with"]["ip"])
    assert r["verified"] is True


def test_add_token_bound_to_params(landevices: LanDeviceClient) -> None:
    svc, fc = service(landevices, Box())
    plan = svc.add_port_forward_plan(**ADD, mac="AA:BB:CC:DD:EE:05")
    with pytest.raises(PlanError, match="passt nicht"):
        svc.add_port_forward_execute(plan["token"], **{**ADD, "internal_port": 23}, mac="AA:BB:CC:DD:EE:05")
    assert calls(fc, "AddPortMapping") == []


def test_add_fails_if_port_taken_meanwhile(landevices: LanDeviceClient) -> None:
    box = Box()
    svc, fc = service(landevices, box)
    plan = svc.add_port_forward_plan(**ADD, mac="AA:BB:CC:DD:EE:05")
    box.mappings.append({**box.mappings[0], "NewExternalPort": 2222, "NewInternalPort": 22})
    with pytest.raises(PlanError, match="geändert"):
        svc.add_port_forward_execute(plan["token"], **ADD, mac="AA:BB:CC:DD:EE:05")
    assert calls(fc, "AddPortMapping") == []


def test_add_rejects_existing_port_and_box_target(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, Box())
    with pytest.raises(InvalidParameterError, match="schon freigegeben"):
        svc.add_port_forward_plan("TCP", 8443, 443, "x", ip=SERVER)
    with pytest.raises(InvalidParameterError, match="eigenes Gerät") as ei:
        svc.add_port_forward_plan("TCP", 2222, 22, "x", ip="192.0.2.20")
    assert "7.3" in (ei.value.hint or "")
    with pytest.raises(InvalidParameterError, match="FRITZ!Box selbst"):
        svc.add_port_forward_plan("TCP", 8080, 80, "x", ip=BOX)


@pytest.mark.parametrize(
    "override",
    [{"protocol": "ICMP"}, {"external_port": 0}, {"internal_port": 70000}, {"description": ""}, {"description": "<x>"}],
)
def test_add_validation(landevices: LanDeviceClient, override: dict[str, Any]) -> None:
    svc, fc = service(landevices, Box())
    with pytest.raises(InvalidParameterError):
        svc.add_port_forward_plan(**{**ADD, **override}, mac="AA:BB:CC:DD:EE:05")
    assert fc.calls == []


def test_add_plan_warns_without_public_ipv4(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, Box(public_ip=""))
    plan = svc.add_port_forward_plan("UDP", 51820, 51820, "wireguard", mac="AA:BB:CC:DD:EE:05")
    assert any("DS-Lite" in w for w in plan["warnings"])


def test_add_refused_by_box_explains_self_portforward(landevices: LanDeviceClient) -> None:
    svc, fc = service(landevices, Box())
    fc.responses[("WANIPConn1", "AddPortMapping")] = FritzSecurityError(
        "errorCode: 606\nerrorDescription: Action not authorized"
    )
    plan = svc.add_port_forward_plan(**ADD, mac="AA:BB:CC:DD:EE:05")
    with pytest.raises(PermissionDeniedError) as ei:
        svc.add_port_forward_execute(plan["token"], **ADD, mac="AA:BB:CC:DD:EE:05")
    assert "Selbstständige Portfreigaben" in (ei.value.hint or "")


def test_add_conflict_code_translated(landevices: LanDeviceClient) -> None:
    svc, fc = service(landevices, Box())
    fc.responses[("WANIPConn1", "AddPortMapping")] = FritzConnectionException(
        "errorCode: 718\nerrorDescription: ConflictInMappingEntry"
    )
    plan = svc.add_port_forward_plan(**ADD, mac="AA:BB:CC:DD:EE:05")
    with pytest.raises(InvalidParameterError, match="schon belegt") as ei:
        svc.add_port_forward_execute(plan["token"], **ADD, mac="AA:BB:CC:DD:EE:05")
    assert ei.value.tr064_code == "718"


def test_add_not_verified_when_discarded(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, Box(discard=True))
    plan = svc.add_port_forward_plan(**ADD, mac="AA:BB:CC:DD:EE:05")
    r = svc.add_port_forward_execute(plan["token"], **ADD, mac="AA:BB:CC:DD:EE:05")
    assert r["verified"] is False and "note" in r


def test_add_execute_rechecks_own_device(landevices: LanDeviceClient) -> None:
    """V-8: even with a token, execute refuses a foreign target (the check runs again)."""
    svc, fc = service(landevices, Box())
    with pytest.raises(InvalidParameterError, match="eigenes Gerät"):
        svc.add_port_forward_execute("t", **ADD, mac="AA:BB:CC:DD:EE:02")
    assert calls(fc, "AddPortMapping") == []


# ------------------------------------------------------------------ delete (critical)


def test_delete_plan_execute_verified(landevices: LanDeviceClient) -> None:
    box = Box()
    svc, fc = service(landevices, box)
    plan = svc.delete_port_forward_plan("tcp", 8443)
    assert plan["target"]["internal_client"] == "192.0.2.20"
    assert calls(fc, "DeletePortMapping") == []
    r = svc.delete_port_forward_execute(plan["token"], "TCP", 8443)
    assert r["verified"] is True and box.mappings == []
    assert calls(fc, "DeletePortMapping")[0][2] == {"NewRemoteHost": "", "NewExternalPort": 8443, "NewProtocol": "TCP"}


def test_delete_unknown_mapping(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, Box())
    with pytest.raises(NotFoundError):
        svc.delete_port_forward_plan("UDP", 8443)


def test_delete_fails_if_mapping_changed(landevices: LanDeviceClient) -> None:
    box = Box()
    svc, fc = service(landevices, box)
    plan = svc.delete_port_forward_plan("TCP", 8443)
    box.mappings[0]["NewInternalClient"] = "192.0.2.30"
    with pytest.raises(PlanError, match="geändert"):
        svc.delete_port_forward_execute(plan["token"], "TCP", 8443)
    assert calls(fc, "DeletePortMapping") == []


def test_delete_not_verified_when_still_there(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, Box(discard=True))
    plan = svc.delete_port_forward_plan("TCP", 8443)
    r = svc.delete_port_forward_execute(plan["token"], "TCP", 8443)
    assert r["verified"] is False and "weiterhin" in r["note"]


def test_port_forward_output_has_no_secrets(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, Box())
    assert PASSWORD not in json.dumps(svc.list_port_forwards())
