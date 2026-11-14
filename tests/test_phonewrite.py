"""Stage 8.8 – telephony write (in-memory telephony, invented numbers)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from fritzconnection.core.exceptions import FritzConnectionException

from fritzos8_mcp.errors import InvalidParameterError, PlanError, TierDisabledError
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.phonewrite import barring_entry_xml, validate_number

from .conftest import FakeFC, make_service


class Phone:
    def __init__(self, discard: bool = False) -> None:
        self.alarm = {0: {"NewX_AVM-DE_AlarmClockEnable": "0", "NewX_AVM-DE_AlarmClockName": "Wecker"}}
        self.defl = {0: {"NewEnable": "0", "NewType": "fromAll", "NewDeflectionToNumber": "01701234567"}}
        self.barring: dict[str, dict[str, Any]] = {}
        self.next_uid = 40
        self.messages = [
            {"Index": 0, "New": "1", "Date": "14.11.26 10:00", "Number": "0301112223", "Name": ""},
            {"Index": 1, "New": "0", "Date": "13.11.26 09:00", "Number": "0305556667", "Name": "Praxis"},
        ]
        self.discard = discard
        self.dialed: list[str] = []

    def _barring_by_num(self, NewNumber: str) -> dict[str, Any]:
        e = self.barring.get(NewNumber)
        if e is None:
            raise FritzConnectionException("errorCode: 714\nerrorDescription: NoSuchEntryInArray")
        return {
            "NewPhonebookEntryData": f"<contact><person><realName>{e['name']}</realName></person>"
            f"<uniqueid>{e['uid']}</uniqueid></contact>"
        }

    def _barring_set(self, NewPhonebookEntryData: str) -> dict[str, Any]:
        import re

        number = re.search(r">([0-9+*#]+)</number>", NewPhonebookEntryData).group(1)  # type: ignore[union-attr]
        name = re.search(r"<realName>(.*?)</realName>", NewPhonebookEntryData).group(1)  # type: ignore[union-attr]
        if not self.discard:
            self.barring[number] = {"uid": self.next_uid, "name": name}
        self.next_uid += 1
        return {"NewPhonebookEntryUniqueID": self.next_uid - 1}

    def _barring_del(self, NewPhonebookEntryUniqueID: int) -> dict[str, Any]:
        self.barring = {k: v for k, v in self.barring.items() if v["uid"] != NewPhonebookEntryUniqueID}
        return {}

    def _mark(self, NewIndex: int, NewMessageIndex: int, NewMarkedAsRead: int) -> dict[str, Any]:
        for m in self.messages:
            if m["Index"] == NewMessageIndex and not self.discard:
                m["New"] = "0" if NewMarkedAsRead else "1"
        return {}

    def _delete(self, NewIndex: int, NewMessageIndex: int) -> dict[str, Any]:
        self.messages = [m for m in self.messages if m["Index"] != NewMessageIndex]
        return {}

    def xml(self) -> bytes:
        items = "".join(
            "<Message>" + "".join(f"<{k}>{v}</{k}>" for k, v in m.items()) + "</Message>" for m in self.messages
        )
        return f"<Root>{items}</Root>".encode()

    def fc(self) -> FakeFC:
        r: dict[tuple[str, str], Any] = {
            ("X_VoIP1", "X_AVM-DE_GetAlarmClock"): lambda NewIndex: self.alarm[NewIndex],
            ("X_VoIP1", "X_AVM-DE_SetAlarmClockEnable"): lambda NewIndex, **kw: (
                (
                    None
                    if self.discard
                    else self.alarm[NewIndex].update(
                        {"NewX_AVM-DE_AlarmClockEnable": str(kw["NewX_AVM-DE_AlarmClockEnable"])}
                    )
                )
                or {}
            ),
            ("X_AVM-DE_OnTel1", "GetDeflection"): lambda NewDeflectionId: self.defl[NewDeflectionId],
            ("X_AVM-DE_OnTel1", "SetDeflectionEnable"): lambda NewDeflectionId, NewEnable: (
                self.defl[NewDeflectionId].update({"NewEnable": str(NewEnable)}) or {}
            ),
            ("X_AVM-DE_OnTel1", "GetCallBarringEntryByNum"): self._barring_by_num,
            ("X_AVM-DE_OnTel1", "SetCallBarringEntry"): self._barring_set,
            ("X_AVM-DE_OnTel1", "DeleteCallBarringEntryUID"): self._barring_del,
            ("X_AVM-DE_TAM1", "GetMessageList"): {"NewURL": "/tam?sid=0123456789abcdef"},
            ("X_AVM-DE_TAM1", "MarkMessage"): self._mark,
            ("X_AVM-DE_TAM1", "DeleteMessage"): self._delete,
            ("X_VoIP1", "X_AVM-DE_DialGetConfig"): {"NewX_AVM-DE_PhoneName": "DECT: Mobilteil 1"},
            ("X_VoIP1", "X_AVM-DE_DialNumber"): lambda **kw: self.dialed.append(kw["NewX_AVM-DE_PhoneNumber"]) or {},
            ("X_VoIP1", "X_AVM-DE_DialHangup"): {},
        }
        fc = FakeFC(r)
        fc.session = SimpleNamespace(get=lambda url: SimpleNamespace(ok=True, content=self.xml()))
        return fc


def writer(landevices: LanDeviceClient, phone: Phone, **kw: Any) -> Any:
    return make_service(landevices, phone.fc(), **kw).phone_write


def test_alarm_clock_and_deflection(landevices: LanDeviceClient) -> None:
    phone = Phone()
    w = writer(landevices, phone)
    r = w.set_alarm_clock(0, True)
    assert r["verified"] is True and r["changed"] is True and r["name"] == "Wecker"
    assert w.set_alarm_clock(0, True)["changed"] is False
    r = w.set_deflection(0, True)
    assert r["verified"] is True and "Kosten" in r["warning"]
    assert w.set_deflection(0, False)["warning"] is None


def test_alarm_clock_not_verified_when_discarded(landevices: LanDeviceClient) -> None:
    w = writer(landevices, Phone(discard=True))
    assert w.set_alarm_clock(0, True)["verified"] is False


def test_call_barring_add_remove(landevices: LanDeviceClient) -> None:
    phone = Phone()
    w = writer(landevices, phone)
    r = w.barring_add("0900 123-456", "Spam <AG>")
    assert r["verified"] is True and phone.barring["0900123456"]["name"] == "Spam &lt;AG&gt;"
    assert w.barring_add("0900123456")["changed"] is False
    r = w.barring_remove("0900123456")
    assert r["verified"] is True and phone.barring == {}
    assert w.barring_remove("0900123456")["changed"] is False
    with pytest.raises(InvalidParameterError):
        w.barring_add("abc")


def test_tam_mark_message(landevices: LanDeviceClient) -> None:
    phone = Phone()
    w = writer(landevices, phone)
    r = w.mark_message(0, 0, True)
    assert r["verified"] is True and phone.messages[0]["New"] == "0" and "V-9" in r["note"]
    assert w.mark_message(0, 1, True)["changed"] is False


def test_tam_delete_plan_execute(landevices: LanDeviceClient) -> None:
    phone = Phone()
    w = writer(landevices, phone)
    plan = w.delete_message_plan(0, 0)
    assert "ungehört" in " ".join(plan["warnings"]) and phone.messages[0]["Index"] == 0
    r = w.delete_message_execute(plan["token"], 0, 0)
    assert r["verified"] is True and len(phone.messages) == 1
    with pytest.raises(PlanError):
        w.delete_message_execute(plan["token"], 0, 0)


def test_tam_delete_refuses_changed_target(landevices: LanDeviceClient) -> None:
    phone = Phone()
    w = writer(landevices, phone)
    plan = w.delete_message_plan(0, 1)
    phone.messages[1]["Date"] = "15.11.26 08:00"  # another message now has this index
    with pytest.raises(PlanError, match="geändert"):
        w.delete_message_execute(plan["token"], 0, 1)
    assert len(phone.messages) == 2


def test_dial_plan_execute(landevices: LanDeviceClient) -> None:
    phone = Phone()
    w = writer(landevices, phone)
    plan = w.dial_plan("+44 20 1234567")
    assert plan["phone"] == "DECT: Mobilteil 1" and any("Ausland" in x for x in plan["warnings"])
    with pytest.raises(PlanError):
        w.dial_execute(plan["token"], "0301234567")  # number differs from plan
    plan = w.dial_plan("0301234567")
    r = w.dial_execute(plan["token"], "030 1234567")
    assert phone.dialed == ["0301234567"] and r["verified"] is False
    assert w.hangup()["hung_up"] is True
    assert any("NOTRUF" in x for x in w.dial_plan("112")["warnings"])


def test_tiers(landevices: LanDeviceClient) -> None:
    w = writer(landevices, Phone(), write=True, critical=False)
    with pytest.raises(TierDisabledError):
        w.dial_plan("0301234567")
    with pytest.raises(TierDisabledError):
        w.delete_message_plan(0, 0)
    w2 = writer(landevices, Phone(), write=False, critical=False)
    with pytest.raises(TierDisabledError):
        w2.barring_add("0900123456")


def test_helpers() -> None:
    assert validate_number("+49 (30) 123-456") == "+4930123456"
    assert "<realName>a&amp;b</realName>" in barring_entry_xml("0301", "a&b")
