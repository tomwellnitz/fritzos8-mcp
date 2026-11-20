"""Stage 10.5 – anonymizer for community fixtures (invented 'real' values only)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fritzos8_mcp.anonymize import anonymize, build_fixture, find_leftovers

COMMUNITY = Path(__file__).parent / "fixtures" / "community"

# Invented values that LOOK real (private range, foreign OUI, real-looking names) – nothing from a real home network.
HOSTS = {
    "NewHostName": "laptop-erika",
    "NewIPAddress": "192.168.42.17",
    "NewMACAddress": "3C:22:FB:12:34:56",
    "NewInterfaceType": "802.11",
    "NewActive": True,
    "NewX_AVM-DE_FriendlyName": "Laptop Erika",
}
DEVICE_INFO = {
    "NewModelName": "FRITZ!Box 7590",
    "NewSerialNumber": "3C22FB123456",
    "NewSoftwareVersion": "154.08.20",
    "NewDeviceLog": "12.11.26 10:00:01 Anmeldung an der FRITZ!Box von 192.168.42.17 (3C:22:FB:12:34:56).",
}


def test_tr064_host_entry_is_anonymized_consistently() -> None:
    out, a = anonymize([HOSTS, {**HOSTS, "NewHostName": "laptop-erika-2"}])
    assert out[0]["NewMACAddress"] == out[1]["NewMACAddress"] == "AA:BB:CC:00:00:01"
    assert out[0]["NewIPAddress"] == "192.0.2.1"
    assert out[0]["NewHostName"] == "Gerät 1" and out[1]["NewHostName"] == "Gerät 3"
    assert out[0]["NewInterfaceType"] == "802.11" and out[0]["NewActive"] is True
    assert a.counts["mac"] == 1
    assert find_leftovers(out) == []


def test_log_text_serial_model_kept() -> None:
    out, _ = anonymize(DEVICE_INFO)
    assert out["NewModelName"] == "FRITZ!Box 7590"
    assert out["NewSoftwareVersion"] == "154.08.20"
    assert out["NewSerialNumber"] == "SERIAL0001"
    assert "192.0.2.1" in out["NewDeviceLog"] and "AA:BB:CC:00:00:01" in out["NewDeviceLog"]
    assert "10:00:01" in out["NewDeviceLog"]  # times are not IPv6 addresses


def test_secrets_are_redacted() -> None:
    out, _ = anonymize({"NewX_AVM-DE_WANPassword": "geheim123", "NewKeyPassphrase": "wlan-key-1"})
    assert set(out.values()) == {"***"}
    rest, _ = anonymize({"wg_preshared_key": "abc", "name": "VPN Oma"}, "rest")
    assert rest["wg_preshared_key"] == "***" and rest["name"] == "Gerät 1"


def test_ipv6_public_private_and_kept() -> None:
    out, _ = anonymize(
        {"ExternalIPv6": "2a02:8070:1234:5600::1", "LinkLocal": "fe80::3e22:fbff:fe12:3456%eth0", "Any": "::"}
    )
    assert out["ExternalIPv6"] == "2001:db8::1"
    assert out["LinkLocal"] == "fe80::1"
    assert out["Any"] == "::"


def test_public_ipv4_goes_to_second_doc_range() -> None:
    out, _ = anonymize({"NewExternalIPAddress": "93.184.216.34", "NewSubnetMask": "255.255.255.0", "x": "0.0.0.0"})
    assert out == {"NewExternalIPAddress": "198.51.100.1", "NewSubnetMask": "255.255.255.0", "x": "0.0.0.0"}


def test_aha_xml_names_ain_and_tam_numbers() -> None:
    aha = (
        '<devicelist version="1"><device identifier="11630 0123456" id="16" functionbitmask="2944" '
        'fwversion="04.25" manufacturer="AVM" productname="FRITZ!DECT 200"><present>1</present>'
        "<name>Steckdose Arbeitszimmer Erika</name></device></devicelist>"
    )
    out, _ = anonymize(aha, "aha")
    assert 'identifier="12345 0000001"' in out
    assert "<name>Gerät 1</name>" in out and 'productname="FRITZ!DECT 200"' in out
    tam = "<Root><Message><Index>0</Index><Number>01701234567</Number><Name>Mama</Name></Message></Root>"
    out2, _ = anonymize(tam, "xml")
    assert "<Number>03012340001</Number>" in out2 and "<Name>Gerät 1</Name>" in out2


def test_rest_smarthome_location_mail_and_dyndns() -> None:
    data = {
        "location": {"latitude": 52.52, "longitude": 13.4},
        "recipient": "erika@example.org",
        "myfritz": "abcdef123.myfritz.net",
        "phoneNumber": "+49 30 98765432",
    }
    out, _ = anonymize(data, "rest")
    text = json.dumps(out)
    assert "52.52" not in text and "erika" not in text and "abcdef123" not in text and "98765432" not in text
    assert find_leftovers(out) == []


def test_mesh_name_references_are_replaced_everywhere() -> None:
    # Live finding (mesh_overview, 6660 Cable/8.25): node/client names stayed in from/to/connected_to/mesh_master,
    # as dict keys of clients_per_node and in weak_signal_clients – room names in a public fixture
    mesh = {
        "mesh_master": "FritzBoxGartenweg",
        "nodes": [{"name": "FritzBoxGartenweg"}, {"name": "Repeater-Kinderzimmer"}],
        "backbone": [{"from": "FritzBoxGartenweg", "to": "Repeater-Kinderzimmer", "type": "WLAN"}],
        "clients": [{"name": "Sauna-Steckdose", "connected_to": "Repeater-Kinderzimmer", "type": "WLAN"}],
        "summary": {
            "clients_per_node": {"FritzBoxGartenweg": 3, "Repeater-Kinderzimmer": 1},
            "weak_signal_clients": ["Sauna-Steckdose"],
        },
        "units": "Raten in Mbit/s",
        "note": "Sauna-Steckdose im Text bleibt Text",  # no substring replacement
    }
    out, _ = anonymize(mesh, kind="rest")
    dumped = json.dumps(out, ensure_ascii=False)
    for real in ("FritzBoxGartenweg", "Repeater-Kinderzimmer"):
        assert real not in dumped
    assert out["backbone"][0]["from"] == out["nodes"][0]["name"] == out["mesh_master"]
    assert out["clients"][0]["connected_to"] == out["nodes"][1]["name"]
    assert set(out["summary"]["clients_per_node"]) == {out["nodes"][0]["name"], out["nodes"][1]["name"]}
    assert out["summary"]["weak_signal_clients"] == [out["clients"][0]["name"]]
    assert out["units"] == "Raten in Mbit/s" and out["backbone"][0]["type"] == "WLAN"


def test_find_leftovers_flags_real_looking_values() -> None:
    left = find_leftovers(
        {"mac": "3C:22:FB:12:34:56", "ip": "10.0.0.5", "mail": "a@b.de", "ain": "11630 0123456", "v6": "2a02:8070::5"}
    )
    assert left == ["AIN 11630 0123456", "E-Mail a@b.de", "IPv4 10.0.0.5", "IPv6 2a02:8070::5", "MAC 3C:22:FB:12:34:56"]
    assert find_leftovers({"ll": "fe80::1", "doc": "2001:db8::7", "t": "10:00:01"}) == []


def test_build_fixture_carries_meta_without_mapping() -> None:
    fixture, left = build_fixture(HOSTS, "tr064", model="FRITZ!Box 7590", fritzos="8.20", name="hosts")
    assert left == []
    assert fixture["fixture"]["model"] == "FRITZ!Box 7590"
    assert fixture["fixture"]["replaced"]["mac"] == 1
    assert "3C:22:FB" not in json.dumps(fixture) and "laptop-erika" not in json.dumps(fixture)


@pytest.mark.parametrize("path", sorted(COMMUNITY.glob("*.json")), ids=lambda p: p.name)
def test_committed_community_fixtures_are_clean(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert set(data) == {"fixture", "data"}
    assert data["fixture"]["anonymized_with"] == "fritzos8-anonymize"
    assert find_leftovers(data) == [], f"{path.name} enthält noch echte Werte"


def test_there_is_at_least_one_example_fixture() -> None:
    assert list(COMMUNITY.glob("*.json"))
