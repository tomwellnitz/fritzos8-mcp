"""Stage 8.10 – telephony read (fixtures after the AVM TR-064 documents, invented numbers)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fritzconnection.core.exceptions import FritzActionError

from fritzos8_mcp.errors import InvalidParameterError
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.phone import alarm_time, digits, parse_phonebook

from .conftest import FakeFC, make_service

NUMBERS = (
    "<List><Item><Number>0301234567</Number><Type>eVoIP</Type><Index>0</Index><Name>Festnetz</Name></Item>"
    "<Item><Number>0307654321</Number><Type>eVoIP</Type><Index>1</Index><Name>Büro</Name></Item>"
    "<Item><Number>4711</Number><Type>eISDN</Type><Index>0</Index><Name>ISDN1</Name></Item></List>"
)
# exactly like the malformed AVM example (</PhonebookID></>)
DEFLECTIONS = (
    "<List><Item><DeflectionId>0</DeflectionId><Enable>1</Enable><Type>fromAll</Type><Number></Number>"
    "<DeflectionToNumber>01701234567</DeflectionToNumber><Mode>eImmediately</Mode><Outgoing></Outgoing>"
    "<PhonebookID></PhonebookID></></Item></List>"
)
PHONEBOOK = b"""<phonebooks><phonebook owner="0" name="Telefonbuch">
<contact><person><realName>Oma Erna</realName></person><telephony>
<number type="home" prio="1">+49 30 1112223</number><number type="mobile">0170 9998887</number></telephony>
<uniqueid>12</uniqueid></contact>
<contact><person><realName>Praxis Dr. Beispiel</realName></person><telephony><number type="work">0305556667</number>
</telephony><uniqueid>13</uniqueid></contact>
</phonebook></phonebooks>"""
BARRING = b"""<phonebooks><phonebook name="Rufsperre"><contact><person><realName>Spam</realName></person>
<telephony><number type="home">0900123456</number></telephony><uniqueid>5</uniqueid></contact>
</phonebook></phonebooks>"""
CALLS = b"""<root><Call><Id>1</Id><Type>2</Type><Caller>0301112223</Caller><Called>0301234567</Called><Name></Name>
<Date>14.11.26 10:00</Date><Duration>0:00</Duration></Call>
<Call><Id>2</Id><Type>3</Type><Caller>0301234567</Caller><Called>0305556667</Called><Name></Name>
<Date>14.11.26 09:00</Date><Duration>0:05</Duration></Call>
<Call><Id>3</Id><Type>1</Type><Caller>0309990000</Caller><Name>Bekannt</Name><Date>14.11.26 08:00</Date></Call>
</root>"""


def phone_fc(extra: dict[tuple[str, str], Any] | None = None) -> FakeFC:
    r: dict[tuple[str, str], Any] = {
        ("X_VoIP1", "X_AVM-DE_GetNumbers"): {"NewNumberList": NUMBERS},
        ("X_VoIP1", "X_AVM-DE_GetVoIPStatus"): lambda NewVoIPAccountIndex: {
            "NewX_AVM-DE_VoIPStatus": "registered" if NewVoIPAccountIndex == 0 else "not registered"
        },
        ("X_VoIP1", "X_AVM-DE_GetNumberOfAlarmClocks"): {"NewX_AVM-DE_NumberOfAlarmClocks": 2},
        ("X_VoIP1", "X_AVM-DE_GetAlarmClock"): lambda NewIndex: [
            {
                "NewX_AVM-DE_AlarmClockEnable": "1",
                "NewX_AVM-DE_AlarmClockName": "Wecker",
                "NewX_AVM-DE_AlarmClockTime": "0630",
                "NewX_AVM-DE_AlarmClockWeekdays": "MO,TU,WE,TH,FR",
                "NewX_AVM-DE_AlarmClockPhoneName": "DECT: Mobilteil 1",
            },
            {
                "NewX_AVM-DE_AlarmClockEnable": "0",
                "NewX_AVM-DE_AlarmClockTime": "0900",
                "NewX_AVM-DE_AlarmClockWeekdays": "",
            },
        ][NewIndex],
        ("X_AVM-DE_OnTel1", "GetDeflections"): {"NewDeflectionList": DEFLECTIONS},
        ("X_AVM-DE_OnTel1", "GetCallBarringList"): {"NewPhonebookURL": "/barring?sid=0123456789abcdef"},
        ("X_AVM-DE_OnTel1", "GetPhonebookList"): {"NewPhonebookList": "0"},
        ("X_AVM-DE_OnTel1", "GetPhonebook"): {
            "NewPhonebookURL": "/pb0?sid=0123456789abcdef",
            "NewPhonebookName": "Telefonbuch",
        },
        ("X_AVM-DE_OnTel1", "GetCallList"): {"NewCallListURL": "/calls?sid=0123456789abcdef"},
    }
    r.update(extra or {})
    fc = FakeFC(r)
    docs = {"/barring": BARRING, "/pb0": PHONEBOOK, "/calls": CALLS}

    def get(url: str) -> Any:
        key = next(k for k in docs if k in url)
        return SimpleNamespace(ok=True, content=docs[key])

    fc.session = SimpleNamespace(get=get)
    return fc


def test_numbers_status(landevices: LanDeviceClient) -> None:
    r = make_service(landevices, phone_fc()).phone.numbers_status()
    assert r["count"] == 3 and r["all_registered"] is False
    assert r["not_registered"] == ["0307654321 (not registered)"]
    assert r["numbers"][2] == {"number": "4711", "type": "isdn", "name": "ISDN1", "index": 0, "status": "n/a"}


def test_alarm_clocks(landevices: LanDeviceClient) -> None:
    r = make_service(landevices, phone_fc()).phone.alarm_clocks()
    assert r["count"] == 2 and r["active"] == 1
    a = r["alarm_clocks"][0]
    assert (
        a["time"] == "06:30" and a["weekdays"] == ["Mo", "Di", "Mi", "Do", "Fr"] and a["phone"] == "DECT: Mobilteil 1"
    )
    assert r["alarm_clocks"][1]["weekdays"] == ["einmalig"] and r["alarm_clocks"][1]["phone"] == "alle Telefone"


def test_deflections_repairs_avm_xml(landevices: LanDeviceClient) -> None:
    r = make_service(landevices, phone_fc()).phone.deflections()
    d = r["deflections"][0]
    assert d["applies_to"] == "alle Anrufe" and d["to"] == "01701234567" and d["when"] == "sofort"
    assert r["active"] == 1 and "Kosten" in r["note"]


def test_deflections_fallback_per_entry(landevices: LanDeviceClient) -> None:
    fc = phone_fc(
        {
            ("X_AVM-DE_OnTel1", "GetDeflections"): FritzActionError("x"),
            ("X_AVM-DE_OnTel1", "GetNumberOfDeflections"): {"NewNumberOfDeflections": 1},
            ("X_AVM-DE_OnTel1", "GetDeflection"): lambda NewDeflectionId: {
                "NewEnable": "0",
                "NewType": "fromNumber",
                "NewNumber": "0301",
                "NewDeflectionToNumber": "0302",
                "NewMode": "eBusy",
            },
        }
    )
    r = make_service(landevices, fc).phone.deflections()
    assert r["deflections"][0]["when"] == "bei besetzt" and r["active"] == 0 and r["note"] is None


def test_call_barring_no_sid_in_output(landevices: LanDeviceClient) -> None:
    r = make_service(landevices, phone_fc()).phone.call_barring()
    assert r["entries"][0]["numbers"][0]["number"] == "0900123456"
    assert "0123456789abcdef" not in str(r)


@pytest.mark.parametrize(
    "query,expected",
    [("erna", ["Oma Erna"]), ("+49 30 1112223", ["Oma Erna"]), ("5556667", ["Praxis Dr. Beispiel"]), ("Nobody", [])],
)
def test_phonebook_search(landevices: LanDeviceClient, query: str, expected: list[str]) -> None:
    r = make_service(landevices, phone_fc()).phone.phonebook_search(query)
    assert [h["name"] for h in r["hits"]] == expected


def test_phonebook_search_too_short(landevices: LanDeviceClient) -> None:
    with pytest.raises(InvalidParameterError):
        make_service(landevices, phone_fc()).phone.phonebook_search("a")


def test_call_list_resolve_names(landevices: LanDeviceClient) -> None:
    svc = make_service(landevices, phone_fc())
    plain = svc.call_list()
    assert plain["calls"][0]["name"] == "" and "names_from_phonebook" not in plain
    r = svc.call_list(resolve_names=True)
    names = [c["name"] for c in r["calls"]]
    assert names == ["Oma Erna", "Praxis Dr. Beispiel", "Bekannt"] and r["names_from_phonebook"] == 2
    assert r["calls"][0]["name_source"] == "phonebook"


def test_registration_alarm_via_alarms_check(landevices: LanDeviceClient, tmp_path: Path) -> None:
    svc = make_service(landevices, phone_fc())
    r = svc.alarms.check()
    assert any(a["type"] == "number_not_registered" and "0307654321" in a["message"] for a in r["alarms"])
    assert r["sources"]["telephony"] == "ok"


def test_helpers() -> None:
    assert digits("+49 (30) 123-45") == "03012345" and digits("0049301") == "0301"
    assert alarm_time("0705") == "07:05" and alarm_time("") is None
    assert parse_phonebook(PHONEBOOK)[0]["numbers"][1] == {"number": "0170 9998887", "type": "mobile"}
