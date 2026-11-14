"""Stage 8.11 – device & update overview (mock answers after the AVM TR-064 documents, invented values)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from fritzconnection.core.exceptions import FritzActionError, FritzConnectionException, FritzServiceError

from fritzos8_mcp.errors import FritzConnectionError
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.redact import redact_obj

from .conftest import FakeFC, make_service

HOST_XML = b"""<List>
<Item><Index>1</Index><IPAddress>192.0.2.2</IPAddress><MACAddress>AA:BB:CC:00:00:02</MACAddress><Active>1</Active>
<HostName>fritz.repeater</HostName><X_AVM-DE_Model>FRITZ!Repeater 2400</X_AVM-DE_Model>
<X_AVM-DE_UpdateAvailable>1</X_AVM-DE_UpdateAvailable><X_AVM-DE_UpdateSuccessful>failed</X_AVM-DE_UpdateSuccessful>
<X_AVM-DE_URLParameters>token=0123456789abcdef</X_AVM-DE_URLParameters><X_AVM-DE_IsMeshable>1</X_AVM-DE_IsMeshable>
<X_AVM-DE_FriendlyName>Repeater Flur</X_AVM-DE_FriendlyName></Item>
<Item><Index>2</Index><IPAddress>192.0.2.20</IPAddress><MACAddress>AA:BB:CC:00:00:20</MACAddress><Active>1</Active>
<HostName>pc-buero</HostName><X_AVM-DE_Model></X_AVM-DE_Model><X_AVM-DE_UpdateAvailable>0</X_AVM-DE_UpdateAvailable>
<X_AVM-DE_IsMeshable>0</X_AVM-DE_IsMeshable></Item>
</List>"""

DECT = [
    {
        "NewID": "1",
        "NewActive": "1",
        "NewName": "Mobilteil 1",
        "NewModel": "FRITZ!Fon C6",
        "NewUpdateAvailable": "1",
        "NewUpdateSuccessful": "unknown",
        "NewUpdateInfo": "",
    },
    {
        "NewID": "16",
        "NewActive": "1",
        "NewName": "Heizung",
        "NewModel": "FRITZ!Smart Thermo 301",
        "NewUpdateAvailable": "0",
        "NewUpdateSuccessful": "succeeded",
    },
]
PLC = [
    {
        "NewMACAddress": "aa:bb:cc:00:00:30",
        "NewActive": "1",
        "NewName": "Powerline Keller",
        "NewModel": "FRITZ!Powerline 1260",
        "NewUpdateAvailable": "0",
        "NewUpdateSuccessful": "unknown",
    }
]


def box_fc(overrides: dict[tuple[str, str], Any] | None = None) -> FakeFC:
    responses: dict[tuple[str, str], Any] = {
        ("Hosts1", "X_AVM-DE_GetHostListPath"): {
            "NewX_AVM-DE_HostListPath": "/devicehostlist.lua?sid=abcdef0123456789"
        },
        ("Hosts1", "X_AVM-DE_GetChangeCounter"): {"NewX_AVM-DE_ChangeCounter": "42"},
        ("DeviceInfo1", "GetInfo"): {"NewSoftwareVersion": "164.08.26", "NewModelName": "FRITZ!Box 7583"},
        ("UserInterface1", "GetInfo"): {"NewUpgradeAvailable": "1", "NewX_AVM-DE_Version": "164.08.30"},
        ("X_AVM-DE_Dect1", "GetNumberOfDectEntries"): {"NewNumberOfEntries": len(DECT)},
        ("X_AVM-DE_Dect1", "GetGenericDectEntry"): lambda NewIndex: DECT[NewIndex],
        ("X_AVM-DE_Homeplug1", "GetNumberOfDeviceEntries"): {"NewNumberOfEntries": 1},
        ("X_AVM-DE_Homeplug1", "GetGenericDeviceEntry"): lambda NewIndex: PLC[NewIndex],
        ("X_AVM-DE_OnTel1", "GetDECTHandsetList"): {"NewDectIDList": "1,2"},
        ("X_AVM-DE_OnTel1", "GetDECTHandsetInfo"): lambda NewDectID: {
            "NewHandsetName": f"MT {NewDectID}",
            "NewPhonebookID": "0",
        },
    }
    responses.update(overrides or {})
    fc = FakeFC(responses)
    fc.session = SimpleNamespace(get=lambda url: SimpleNamespace(ok=True, content=HOST_XML))
    return fc


def test_updates_overview_collects_all_device_kinds(landevices: LanDeviceClient) -> None:
    r = make_service(landevices, box_fc()).devices.updates_overview()
    assert r["box"]["update_available"] is True and r["box"]["available_version"] == "164.08.30"
    mesh = r["mesh"]["devices"]
    assert [d["name"] for d in mesh] == ["Repeater Flur"]  # pc-buero is no AVM device
    assert mesh[0]["update_available"] is True and mesh[0]["last_update"] == "failed"
    assert r["dect"]["devices"][0]["kind"] == "handset" and r["dect"]["devices"][1]["kind"] == "dect_ule"
    assert r["powerline"]["devices"][0]["mac"] == "AA:BB:CC:00:00:30"
    s = r["summary"]
    assert s["update_count"] == 3 and any("Repeater Flur" in x for x in s["updates_available"])
    assert s["last_update_failed"] == ["Repeater Flur"] and s["not_readable"] == []


def test_updates_overview_never_leaks_repeater_token(landevices: LanDeviceClient) -> None:
    r = make_service(landevices, box_fc()).devices.updates_overview()
    text = str(redact_obj(r))
    assert "0123456789abcdef" not in text and "URLParameters" not in text


def test_updates_overview_degrades_per_section(landevices: LanDeviceClient) -> None:
    fc = box_fc(
        {
            ("X_AVM-DE_Dect1", "GetNumberOfDectEntries"): FritzServiceError("x"),
            ("X_AVM-DE_Homeplug1", "GetNumberOfDeviceEntries"): FritzActionError("x"),
            ("UserInterface1", "GetInfo"): FritzActionError("x"),
        }
    )
    fc.session = SimpleNamespace(get=lambda url: SimpleNamespace(ok=False, content=b""))
    r = make_service(landevices, fc).devices.updates_overview()
    assert set(r["summary"]["not_readable"]) == {"box", "mesh", "dect", "powerline"}
    assert r["dect"]["error"]["type"] and r["box"]["status"] == "unknown"


def test_updates_overview_connection_error_is_raised(landevices: LanDeviceClient) -> None:
    fc = box_fc({("X_AVM-DE_Dect1", "GetNumberOfDectEntries"): FritzConnectionException("Read timed out")})
    with pytest.raises(FritzConnectionError):
        make_service(landevices, fc).devices.updates_overview()


def test_dect_handsets_merge_dect_and_telephony(landevices: LanDeviceClient) -> None:
    r = make_service(landevices, box_fc()).devices.dect_handsets()
    assert r["count"] == 2  # handset 1 from both sources, handset 2 only from OnTel
    h1, h2 = r["handsets"]
    assert h1["model"] == "FRITZ!Fon C6" and h1["update_available"] is True and h1["phonebook_id"] == 0
    assert h2 == {"id": 2, "kind": "handset", "name": "MT 2", "phonebook_id": 0}
    assert r["sources"] == {"dect": True, "telephony": True}


def test_dect_handsets_without_phone_right(landevices: LanDeviceClient) -> None:
    fc = box_fc({("X_AVM-DE_OnTel1", "GetDECTHandsetList"): FritzActionError("x")})
    r = make_service(landevices, fc).devices.dect_handsets()
    assert r["count"] == 1 and r["sources"]["telephony"] is False and "telephony" in r["errors"]


def test_change_counter(landevices: LanDeviceClient) -> None:
    assert make_service(landevices, box_fc()).devices.change_counter()["change_counter"] == 42
    fc = box_fc({("Hosts1", "X_AVM-DE_GetChangeCounter"): FritzActionError("x")})
    r = make_service(landevices, fc).devices.change_counter()
    assert r["available"] is False and r["change_counter"] is None
    # Live korrigiert (7583/8.26): Zähler dauerhaft 0 → "liefert keinen Zähler"
    fc0 = box_fc({("Hosts1", "X_AVM-DE_GetChangeCounter"): {"NewX_AVM-DE_ChangeCounter": "0"}})
    r0 = make_service(landevices, fc0).devices.change_counter()
    assert r0["available"] is False and "keinen Zähler" in r0["note"]
