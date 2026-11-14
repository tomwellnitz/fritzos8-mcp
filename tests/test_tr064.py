from __future__ import annotations

from types import SimpleNamespace

import pytest
from fritzconnection.core.exceptions import (
    FritzActionError,
    FritzAuthorizationError,
    FritzConnectionException,
    FritzServiceError,
)

from fritzos8_mcp.errors import (
    ActionDeniedError,
    AuthError,
    ConfirmationRequiredError,
    InvalidParameterError,
    NotFoundError,
)
from fritzos8_mcp.redact import MASK
from fritzos8_mcp.tr064 import Tr064Client, _norm_service, map_exception, parse_host_list_xml

from .conftest import PASSWORD, FakeFC


def client(fc: FakeFC) -> Tr064Client:
    return Tr064Client(lambda: fc, (PASSWORD,))  # type: ignore[arg-type,return-value]


@pytest.mark.parametrize(
    "raw,norm",
    [("Hosts", "Hosts1"), ("Hosts:1", "Hosts1"), ("Hosts1", "Hosts1"), ("WLANConfiguration:3", "WLANConfiguration3")],
)
def test_norm_service(raw: str, norm: str) -> None:
    assert _norm_service(raw) == norm


# ------------------------------------------------------------------ error mapping / 2FA


@pytest.mark.parametrize(
    "exc,cls",
    [
        (
            FritzConnectionException(
                "UPnPError:\nerrorCode: 866\nerrorDescription: second factor authentication required"
            ),
            ConfirmationRequiredError,
        ),
        (FritzConnectionException("errorCode: 867"), ConfirmationRequiredError),
        (FritzAuthorizationError("401"), AuthError),
        (FritzServiceError("unknown service"), NotFoundError),
        (FritzActionError("unknown action"), NotFoundError),
    ],
)
def test_map_exception(exc: Exception, cls: type) -> None:
    assert isinstance(map_exception(exc, "X:Y"), cls)


def test_two_factor_on_write_reports_nothing_changed() -> None:
    fc = FakeFC({("Hosts1", "X_AVM-DE_SetHostNameByMACAddress"): FritzConnectionException("errorCode: 866")})
    with pytest.raises(ConfirmationRequiredError) as ei:
        client(fc).set_host_name("AA:BB:CC:DD:EE:01", "neu")
    assert "NICHTS geändert" in (ei.value.hint or "")


# ------------------------------------------------------------------ generic layer


def test_list_services_hides_denied_and_write_actions() -> None:
    services = {s["service"]: s for s in client(FakeFC()).list_services()}
    wlan = services["WLANConfiguration1"]["read_actions"]
    assert "GetInfo" in wlan and "GetSecurityKeys" not in wlan and "SetEnable" not in wlan
    assert services["DeviceConfig1"]["read_actions"] == []


def test_describe_action_reads_scpd() -> None:
    d = client(FakeFC()).describe_action("Hosts:1", "GetSpecificHostEntry")
    assert d["read_only"] and d["callable_via_tr064_call"] and not d["denied"]
    assert d["arguments"][0] == {
        "name": "NewMACAddress",
        "direction": "in",
        "type": "string",
        "allowed_values": None,
        "default": None,
    }
    reboot = client(FakeFC()).describe_action("DeviceConfig1", "Reboot")
    assert reboot["denied"] and not reboot["callable_via_tr064_call"]


def test_describe_unknown() -> None:
    with pytest.raises(NotFoundError):
        client(FakeFC()).describe_action("Nope1", "GetInfo")
    with pytest.raises(NotFoundError):
        client(FakeFC()).describe_action("Hosts1", "GetNothing")


@pytest.mark.parametrize(
    "service,action",
    [
        ("DeviceConfig1", "Reboot"),
        ("DeviceConfig1", "FactoryReset"),
        ("WANIPConn1", "ForceTermination"),
        ("DeviceConfig1", "X_AVM-DE_GetConfigFile"),
    ],
)
def test_generic_call_denylist_never_reaches_box(service: str, action: str) -> None:
    fc = FakeFC()
    with pytest.raises(ActionDeniedError):
        client(fc).generic_call(service, action)
    assert fc.calls == []


def test_generic_call_rejects_write_action() -> None:
    fc = FakeFC()
    with pytest.raises(ActionDeniedError, match="nicht lesend"):
        client(fc).generic_call("WLANConfiguration1", "SetEnable", {"NewEnable": 0})
    assert fc.calls == []


def test_generic_call_rejects_unknown_arguments() -> None:
    fc = FakeFC()
    with pytest.raises(InvalidParameterError, match="NewFoo"):
        client(fc).generic_call("WLANConfiguration1", "X_AVM-DE_GetWLANExtInfo", {"NewFoo": 1})
    assert fc.calls == []


def test_generic_call_redacts_secrets() -> None:
    fc = FakeFC(
        {
            ("WLANConfiguration1", "GetInfo"): {
                "NewSSID": "Heim",
                "NewKeyPassphrase": "wlan-secret",
                "NewX": f"x {PASSWORD}",
            }
        }
    )
    r = client(fc).generic_call("WLANConfiguration:1", "GetInfo")
    assert r["result"]["NewSSID"] == "Heim"
    assert r["result"]["NewKeyPassphrase"] == MASK
    assert PASSWORD not in r["result"]["NewX"]
    assert fc.calls == [("WLANConfiguration1", "GetInfo", {})]


# ------------------------------------------------------------------ curated


HOSTLIST = b"""<?xml version="1.0"?><List>
<Item><Index>1</Index><IPAddress>192.0.2.20</IPAddress><MACAddress>AA:BB:CC:DD:EE:01</MACAddress>
<Active>1</Active><HostName>pc-buero</HostName><InterfaceType>Ethernet</InterfaceType><AddressSource>DHCP</AddressSource><X_AVM-DE_Guest>0</X_AVM-DE_Guest></Item>
<Item><Index>2</Index><IPAddress></IPAddress><MACAddress>AA:BB:CC:DD:EE:02</MACAddress>
<Active>0</Active><HostName>alter-drucker</HostName><InterfaceType>802.11</InterfaceType><AddressSource>DHCP</AddressSource></Item>
</List>"""


def test_parse_host_list_xml() -> None:
    items = parse_host_list_xml(HOSTLIST)
    assert len(items) == 2 and items[0]["HostName"] == "pc-buero"


def test_list_hosts_via_host_list_path() -> None:
    fc = FakeFC({("Hosts1", "X_AVM-DE_GetHostListPath"): {"NewX_AVM-DE_HostListPath": "/devicehostlist.lua?sid=abc"}})
    seen: list[str] = []

    def get(url: str) -> SimpleNamespace:
        seen.append(url)
        return SimpleNamespace(ok=True, content=HOSTLIST)

    fc.session = SimpleNamespace(get=get)
    hosts = client(fc).list_hosts()
    assert seen == ["http://fritz.test:49000/devicehostlist.lua?sid=abc"]
    assert hosts[0] == {
        "name": "pc-buero",
        "ip": "192.0.2.20",
        "mac": "AA:BB:CC:DD:EE:01",
        "active": True,
        "interface": "Ethernet",
        "address_source": "DHCP",
        "guest": False,
    }
    assert hosts[1]["active"] is False


def test_list_hosts_fallback_generic_entries() -> None:
    entries = [{"NewHostName": "a", "NewMACAddress": "AA:BB:CC:DD:EE:01", "NewActive": True}]
    fc = FakeFC(
        {
            ("Hosts1", "X_AVM-DE_GetHostListPath"): FritzActionError("unknown"),
            ("Hosts1", "GetHostNumberOfEntries"): {"NewHostNumberOfEntries": 1},
            ("Hosts1", "GetGenericHostEntry"): lambda NewIndex: entries[NewIndex],
        }
    )
    hosts = client(fc).list_hosts()
    assert hosts[0]["name"] == "a" and hosts[0]["active"] is True


def test_get_lan_dns_with_fallback() -> None:
    fc = FakeFC({("LANHostConfigManagement1", "GetDNSServer"): {"NewDNSServers": "192.0.2.2, 192.0.2.1"}})
    assert client(fc).get_lan_dns() == {"dns_servers": ["192.0.2.2", "192.0.2.1"], "source": "GetDNSServer"}
    fc2 = FakeFC(
        {
            ("LANHostConfigManagement1", "GetDNSServer"): FritzActionError("x"),
            ("LANHostConfigManagement1", "GetInfo"): {"NewDNSServers": "192.0.2.1"},
        }
    )
    assert client(fc2).get_lan_dns()["source"] == "GetInfo"


def test_system_info_and_wan_status() -> None:
    fc = FakeFC(
        {
            ("DeviceInfo1", "GetInfo"): {
                "NewModelName": "FRITZ!Box 7583",
                "NewSoftwareVersion": "256.08.26",
                "NewUpTime": 3600,
            },
            ("WANIPConn1", "GetStatusInfo"): {"NewConnectionStatus": "Connected", "NewUptime": 100},
            ("WANIPConn1", "GetExternalIPAddress"): {"NewExternalIPAddress": "203.0.113.7"},
            ("WANIPConn1", "X_AVM_DE_GetExternalIPv6Address"): FritzActionError("x"),
            ("WANCommonInterfaceConfig1", "GetCommonLinkProperties"): {
                "NewWANAccessType": "DSL",
                "NewPhysicalLinkStatus": "Up",
            },
        }
    )
    c = client(fc)
    assert c.system_info()["software_version"] == "256.08.26"
    wan = c.wan_status()
    assert wan["connection"]["status"] == "Connected"
    assert wan["external_ipv4"] == "203.0.113.7" and wan["external_ipv6"] is None
    assert wan["link"]["access_type"] == "DSL"


def test_wan_falls_back_to_ppp() -> None:
    fc = FakeFC(
        {
            ("WANIPConn1", "GetStatusInfo"): FritzServiceError("x"),
            ("WANPPPConnection1", "GetStatusInfo"): {"NewConnectionStatus": "Connected", "NewUptime": 5},
        }
    )
    assert client(fc).wan_connection_status()["service"] == "WANPPPConnection1"


def test_wan_status_explains_missing_ipv4_on_ds_lite() -> None:
    """Live auf 7583/8.26: verbunden, IPv6 vorhanden, GetExternalIPAddress liefert ""."""
    from unittest.mock import MagicMock

    from fritzos8_mcp.tr064 import Tr064Client

    client = Tr064Client.__new__(Tr064Client)
    client.wan_connection_status = MagicMock(  # type: ignore[method-assign]
        return_value={"service": "WANIPConn1", "status": "Connected"}
    )

    def fake_try(service: str, action: str, **_: object) -> dict[str, str] | None:
        return {
            "GetCommonLinkProperties": None,
            "GetExternalIPAddress": {"NewExternalIPAddress": ""},
            "X_AVM_DE_GetExternalIPv6Address": {"NewExternalIPv6Address": "2001:db8::1"},
        }.get(action)

    client.try_call = fake_try  # type: ignore[method-assign]
    wan = client.wan_status()
    assert wan["external_ipv4"] is None
    assert "DS-Lite" in wan["ipv4_note"]


def test_wan_status_rejects_ipv6_in_ipv4_field() -> None:
    """Live korrigiert (7583/8.26, WANPPPConnection1): GetExternalIPAddress lieferte die IPv6-Adresse."""
    fc = FakeFC(
        {
            ("WANIPConnection1", "GetStatusInfo"): FritzServiceError("x"),
            ("WANPPPConnection1", "GetStatusInfo"): {"NewConnectionStatus": "Connected", "NewUptime": 5},
            ("WANPPPConnection1", "GetExternalIPAddress"): {"NewExternalIPAddress": "2001:db8::42"},
            ("WANIPConn1", "X_AVM_DE_GetExternalIPv6Address"): {"NewExternalIPv6Address": "2001:db8::42"},
        }
    )
    wan = client(fc).wan_status()
    assert wan["external_ipv4"] is None
    assert wan["external_ipv6"] == "2001:db8::42"
    assert "keine öffentliche IPv4" in wan["ipv4_note"]


def test_map_exception_keeps_soap_error_code() -> None:
    err = map_exception(FritzConnectionException("errorCode: 718\nerrorDescription: ConflictInMappingEntry"), "X:Y")
    assert err.tr064_code == "718"
    assert map_exception(FritzActionError("unknown action"), "X:Y").tr064_code is None


def test_fetch_relative_path_uses_tr064_base_and_hides_url() -> None:
    fc = FakeFC()
    seen: list[str] = []

    def get(url: str) -> SimpleNamespace:
        seen.append(url)
        return SimpleNamespace(ok=False, status_code=500, content=b"")

    fc.session = SimpleNamespace(get=get)
    with pytest.raises(Exception) as ei:
        client(fc).fetch("/calllist.lua?sid=0123456789abcdef")
    assert seen == ["http://fritz.test:49000/calllist.lua?sid=0123456789abcdef"]
    assert "0123456789abcdef" not in str(ei.value)


def test_connection_timeout_is_not_reported_as_missing_feature() -> None:
    """Live auf einer überlasteten Box: fritzconnection meldet einen Read-Timeout als
    FritzConnectionException. Das darf nicht als 'Service fehlt' (→ try_call liefert None) enden."""
    import pytest
    from fritzconnection.core.exceptions import FritzConnectionException

    from fritzos8_mcp.errors import FritzConnectionError
    from fritzos8_mcp.tr064 import Tr064Client, map_exception

    exc = FritzConnectionException(
        "Unable to get a connection: HTTPConnectionPool(host='192.0.2.1', port=49000): Read timed out."
    )
    mapped = map_exception(exc, "WANDSLInterfaceConfig1:GetInfo")
    assert isinstance(mapped, FritzConnectionError)

    client = Tr064Client.__new__(Tr064Client)

    def boom(service: str, action: str, **_: object) -> dict[str, object]:
        raise mapped

    client.call = boom  # type: ignore[method-assign]
    with pytest.raises(FritzConnectionError):
        client.try_call("WANDSLInterfaceConfig1", "GetInfo")


def test_wan_connection_prefers_tr064_service_over_igd() -> None:
    """V-7: TR-064 WANIPConnection1 before the IGD service id WANIPConn1; source is reported."""
    fc = FakeFC(
        {
            ("WANIPConnection1", "GetStatusInfo"): {"NewConnectionStatus": "Connected", "NewUptime": 7},
            ("WANIPConn1", "GetStatusInfo"): {"NewConnectionStatus": "Connected", "NewUptime": 7},
        }
    )
    r = client(fc).wan_connection_status()
    assert r["service"] == "WANIPConnection1" and r["source"] == "tr064"


def test_wan_connection_prefers_connected_service() -> None:
    """DSL/PPPoE: WANIPConnection1 exists but is idle – the connected PPP service wins."""
    fc = FakeFC(
        {
            ("WANIPConnection1", "GetStatusInfo"): {"NewConnectionStatus": "Unconfigured"},
            ("WANPPPConnection1", "GetStatusInfo"): {"NewConnectionStatus": "Connected", "NewUptime": 5},
        }
    )
    assert client(fc).wan_connection_status()["service"] == "WANPPPConnection1"


def test_wan_connection_igd_only_and_ipv6_via_igd() -> None:
    fc = FakeFC(
        {
            ("WANIPConnection1", "GetStatusInfo"): FritzServiceError("x"),
            ("WANPPPConnection1", "GetStatusInfo"): FritzServiceError("x"),
            ("WANIPConn1", "GetStatusInfo"): {"NewConnectionStatus": "Disconnected"},
        }
    )
    r = client(fc).wan_connection_status()
    assert r["service"] == "WANIPConn1" and r["source"] == "igd" and r["status"] == "Disconnected"

    fc2 = FakeFC(
        {
            ("WANIPConnection1", "GetStatusInfo"): {"NewConnectionStatus": "Connected"},
            ("WANIPConnection1", "X_AVM_DE_GetExternalIPv6Address"): FritzActionError("x"),
            ("WANIPConn1", "X_AVM_DE_GetExternalIPv6Address"): {"NewExternalIPv6Address": "2001:db8::7"},
        }
    )
    assert client(fc2).wan_status()["external_ipv6"] == "2001:db8::7"


def test_wan_connection_none_answers() -> None:
    fc = FakeFC(
        {(s, "GetStatusInfo"): FritzServiceError("x") for s in ("WANIPConnection1", "WANPPPConnection1", "WANIPConn1")}
    )
    with pytest.raises(NotFoundError):
        client(fc).wan_connection_status()
