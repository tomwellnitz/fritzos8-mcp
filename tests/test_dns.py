from __future__ import annotations

import httpx
from fritzconnection.core.exceptions import FritzActionError

from fritzos8_mcp.landevice import LanDeviceClient

from .conftest import FakeBox, FakeFC, make_service

UNSET = ".".join(["0"] * 4)  # the box's "not set" marker

DNSCFG = {
    "ipv4_use_user_dns": "1",
    "ipv4_user_firstdns": "9.9.9.9",
    "ipv4_user_seconddns": UNSET,
    "ipv6_use_user_dns": "0",
    "ipv6_user_firstdns": "::",
    "ipv6_user_seconddns": "::",
    "ipv4_dhcpserver_lan_dns": "192.0.2.1",
    "dns_over_tls_enabled": "1",
    "public_dns_servers_use_as_fallback": "0",
}
IPV6 = {"lan_dns6_server": "fd00::53", "radv_advdns": "1", "other": "x"}


def dns_fc() -> FakeFC:
    return FakeFC(
        {
            ("LANHostConfigManagement1", "GetDNSServer"): {"NewDNSServers": "192.0.2.1"},
            ("WANIPConn1", "GetStatusInfo"): {"NewConnectionStatus": "Connected"},
            ("WANIPConn1", "X_AVM_DE_GetDNSServer"): {"NewIPv4DNSServer1": "9.9.9.9", "NewIPv4DNSServer2": UNSET},
            ("WANIPConn1", "X_AVM_DE_GetIPv6DNSServer"): {
                "NewIPv6DNSServer1": "2001:db8::53",
                "NewPreferedLifetime1": 3600,
                "NewIPv6DNSServer2": "2001:db8::54",
            },
        }
    )


def test_dns_settings_all_sources(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    fake_box.generic = {"dnscfg": DNSCFG, "ipv6": IPV6}
    r = make_service(landevices, dns_fc()).get_dns_settings()
    assert r["write_supported"] is False
    assert r["lan_dhcp"]["dns_servers"] == ["192.0.2.1"]
    up = r["upstream"]
    assert up["ipv4_servers"] == ["9.9.9.9"] and up["ipv6_servers"] == ["2001:db8::53", "2001:db8::54"]
    web = r["web_settings"]
    assert web["internet_ipv4"] == {"custom": True, "dns1": "9.9.9.9", "dns2": None}
    assert web["internet_ipv6"] == {"custom": False, "dns1": None, "dns2": None}
    assert web["home_ipv6_dns"] == "fd00::53" and web["home_ipv6_via_router_advertisement"] is True
    assert web["dns_over_tls"] is True and web["fields_missing"] == [] and web["verified_endpoint"] is True
    assert "other" not in str(web)


def test_dns_upstream_fallback_action(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    fc = dns_fc()
    fc.responses[("WANIPConn1", "X_AVM_DE_GetDNSServer")] = FritzActionError("x")
    fc.responses[("WANIPConn1", "X_GetDNSServers")] = {"NewDNSServers": "1.1.1.1, 8.8.8.8"}
    r = make_service(landevices, fc).get_dns_settings()
    assert r["upstream"]["ipv4_servers"] == ["1.1.1.1", "8.8.8.8"]
    assert r["upstream"]["ipv4_source"] == "X_GetDNSServers"


def test_dns_rest_missing_is_reported_not_fatal(landevices: LanDeviceClient) -> None:
    r = make_service(landevices, dns_fc()).get_dns_settings()  # FakeBox answers 404 for dnscfg
    assert r["web_settings"]["available"] is False
    assert r["web_settings"]["error"]["type"] == "unsupported_firmware"
    assert r["lan_dhcp"]["available"] is True


def test_dns_ipv6_endpoint_missing(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    fake_box.generic = {"dnscfg": {"ipv4_use_user_dns": "0"}}
    web = make_service(landevices, dns_fc()).get_dns_settings()["web_settings"]
    assert web["available"] is True and "home_ipv6_error" in web
    assert "ipv4_user_firstdns" in web["fields_missing"]


def test_dns_never_writes(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    fake_box.generic = {"dnscfg": DNSCFG, "ipv6": IPV6}
    fc = dns_fc()
    make_service(landevices, fc).get_dns_settings()
    assert all(r.method == "GET" for r in fake_box.requests if isinstance(r, httpx.Request))
    assert all(c[1].startswith(("Get", "X_AVM-DE_Get", "X_AVM_DE_Get", "X_Get")) for c in fc.calls)


def test_dns_upstream_uses_documented_names_first(landevices: LanDeviceClient) -> None:
    """IGD doc: X_AVM_DE_GetDNSServer / X_AVM_DE_GetIPv6DNSServer (underscores). The hyphenated spelling is
    only a last resort – live it was missing on both test boxes."""
    fc = dns_fc()
    up = make_service(landevices, fc).get_dns_settings()["upstream"]
    assert up["ipv4_source"] == "X_AVM_DE_GetDNSServer" and up["ipv6_source"] == "X_AVM_DE_GetIPv6DNSServer"
    assert not any(c[1].startswith("X_AVM-DE_") for c in fc.calls)


def test_dns_upstream_legacy_spelling_last(landevices: LanDeviceClient) -> None:
    fc = dns_fc()
    for action in ("X_AVM_DE_GetDNSServer", "X_GetDNSServers", "X_AVM_DE_GetIPv6DNSServer"):
        fc.responses[("WANIPConn1", action)] = FritzActionError("x")
    fc.responses[("WANIPConn1", "X_AVM-DE_GetDNSServer")] = {"NewIPv4DNSServer1": "9.9.9.9"}
    fc.responses[("WANIPConn1", "X_AVM-DE_GetIPv6DNSServer")] = {"NewIPv6DNSServer1": "2001:db8::53"}
    up = make_service(landevices, fc).get_dns_settings()["upstream"]
    assert up["ipv4_source"] == "X_AVM-DE_GetDNSServer" and up["ipv4_servers"] == ["9.9.9.9"]
    assert up["ipv6_source"] == "X_AVM-DE_GetIPv6DNSServer"
