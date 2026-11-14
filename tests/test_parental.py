"""Stage 7.5 – parental control with access profiles and tickets (TR-064 X_AVM-DE_HostFilter, AVM doc v8)."""

from __future__ import annotations

from typing import Any

import pytest
from fritzconnection.core.exceptions import FritzConnectionException

from fritzos8_mcp.errors import InvalidParameterError, NotFoundError, PlanError, TierDisabledError
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.parental import parse_profiles

from .test_access_ports import SERVER, Box, calls, service

PROFILES_XML = """<FilterProfileList>
<FilterProfile><FilterProfileID>filtprof1</FilterProfileID><Name>Standard</Name>
<FilterProfileType>Standard</FilterProfileType><Monday>0</Monday><Tuesday>0</Tuesday><Wednesday>0</Wednesday>
<Thursday>0</Thursday><Friday>0</Friday><Saturday>0</Saturday><Sunday>0</Sunday><Shared>0</Shared>
<TimeTable></TimeTable></FilterProfile>
<FilterProfile><FilterProfileID>filtprof2</FilterProfileID><Name>Unbeschränkt</Name>
<FilterProfileType>Unrestricted</FilterProfileType><Shared>0</Shared></FilterProfile>
<FilterProfile><FilterProfileID>filtprof1234</FilterProfileID><Name>Kind3Stunden</Name>
<FilterProfileType>Personal</FilterProfileType><Monday>180</Monday><Sunday>240</Sunday><Shared>1</Shared>
<TimeTable><TimeValue><Time>420</Time><Action>1</Action></TimeValue>
<TimeValue><Time>1260</Time><Action>0</Action></TimeValue>
<TimeValue><Time>4200</Time><Action>1</Action></TimeValue></TimeTable></FilterProfile>
</FilterProfileList>"""


class ParentalBox(Box):
    def __init__(self, **kw: Any) -> None:
        super().__init__(**kw)
        self.profile: dict[str, str] = {"192.0.2.30": "filtprof1", SERVER: "filtprof2", "192.0.2.20": "filtprof1"}
        self.tickets: dict[str, str] = {}
        self.ticket_minutes: dict[str, int] = {}
        self.ignore_profile = False
        self.next_ticket = 123456

    def responses(self) -> dict[tuple[str, str], Any]:
        out = super().responses()
        hf = "X_AVM-DE_HostFilter1"
        out[(hf, "GetFilterProfiles")] = {"NewFilterProfileList": PROFILES_XML}
        out[(hf, "GetHostEntryByIP")] = self._entry_by_ip
        out[(hf, "AddHostEntryToFilterProfile")] = self._assign
        out[(hf, "MarkTicket")] = self._mark
        out[(hf, "GetTicketIDStatus")] = lambda NewTicketID: {
            "NewTicketIDStatus": self.tickets.get(NewTicketID, "invalid")
        }
        out[(hf, "AddTicketTimeToHostEntryByIP")] = self._ticket_time
        out[(hf, "DiscardAllTickets")] = self._discard
        return out

    def _entry_by_ip(self, NewIPv4Address: str) -> dict[str, Any]:
        if NewIPv4Address not in self.profile:
            raise FritzConnectionException("errorCode: 714\nerrorDescription: NoSuchEntryInArray")
        return {
            "NewHostName": "x",
            "NewFilterProfileID": self.profile[NewIPv4Address],
            "NewTimeUsed": 3600,
            "NewTimeMax": 10800,
            "NewTicketsInAdvance": 0,
            "NewTicketValid": self.ticket_minutes.get(NewIPv4Address, 0),
            "NewIsTimeShared": "0",
            "NewWANAccess": "granted",
        }

    def _assign(self, NewIPv4Address: str, NewFilterProfileID: str) -> dict[str, Any]:
        if NewIPv4Address == "192.0.2.1":
            raise FritzConnectionException("errorCode: 880\nerrorDescription: Action is not allowed for this device")
        if not self.ignore_profile:
            self.profile[NewIPv4Address] = NewFilterProfileID
        return {}

    def _mark(self) -> dict[str, Any]:
        if len([t for t in self.tickets.values() if t == "marked"]) >= 12:
            raise FritzConnectionException("errorCode: 714\nerrorDescription: NoSuchEntryInArray")
        t = str(self.next_ticket)
        self.next_ticket += 1
        self.tickets[t] = "marked"
        return {"NewTicketID": t}

    def _ticket_time(self, NewIPv4Address: str) -> dict[str, Any]:
        self.ticket_minutes[NewIPv4Address] = self.ticket_minutes.get(NewIPv4Address, 0) + 45
        return {}

    def _discard(self) -> dict[str, Any]:
        self.tickets = {k: "invalid" for k in self.tickets}
        return {}


# ------------------------------------------------------------------ parsing


def test_parse_profiles_with_timetable() -> None:
    profiles = parse_profiles(PROFILES_XML)
    assert [p["id"] for p in profiles] == ["filtprof1", "filtprof2", "filtprof1234"]
    kid = profiles[2]
    assert kid["type"] == "Personal" and kid["budget_shared"] is True
    assert kid["budgets"]["mon"] == 180 and kid["budgets"]["tue"] is None
    assert kid["timetable"][0] == {
        "minute_of_week": 420,
        "action_raw": "1",
        "allow": True,
        "weekday": "Mo",
        "time": "07:00",
    }
    assert kid["timetable"][2]["weekday"] == "Mi" and kid["timetable"][2]["time"] == "22:00"


def test_parse_profiles_single_element_and_doc_typo() -> None:
    # The AVM document's own example has "</Action" without ">": repaired, nothing else.
    xml = (
        "<FilterProfile><FilterProfileID>filtprof9</FilterProfileID><Name>Doku</Name>"
        "<TimeTable><TimeValue><Time>90</Time><Action>0</Action\n</TimeValue></TimeTable></FilterProfile>"
    )
    p = parse_profiles(xml)[0]
    assert p["id"] == "filtprof9" and p["timetable"][0]["time"] == "01:30" and p["timetable"][0]["allow"] is False
    assert parse_profiles("") == []


# ------------------------------------------------------------------ read


def test_parental_profiles(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, ParentalBox())
    r = svc.parental.parental_profiles()
    assert r["count"] == 3
    assert "unverifiziert" in r["units"]["budgets"]


def test_parental_device_status(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, ParentalBox())
    r = svc.parental.parental_device_status(mac="AA:BB:CC:DD:EE:02")
    assert r["ip"] == "192.0.2.30"
    assert r["profile"] == {"id": "filtprof1", "name": "Standard", "type": "Standard"}
    assert r["time_left_s"] == 7200
    assert r["blocked"] is False and r["wan_access"] == "granted"


# ------------------------------------------------------------------ set profile


def test_set_profile_verified(landevices: LanDeviceClient) -> None:
    box = ParentalBox()
    svc, fc = service(landevices, box)
    r = svc.parental.set_parental_profile("AA:BB:CC:DD:EE:02", "filtprof1234")
    assert r["verified"] is True and r["changed"] is True
    assert r["profile"]["name"] == "Kind3Stunden" and r["before_profile_id"] == "filtprof1"
    assert calls(fc, "AddHostEntryToFilterProfile") == [
        (
            "X_AVM-DE_HostFilter1",
            "AddHostEntryToFilterProfile",
            {"NewIPv4Address": "192.0.2.30", "NewFilterProfileID": "filtprof1234"},
        )
    ]


def test_set_profile_unchanged(landevices: LanDeviceClient) -> None:
    svc, fc = service(landevices, ParentalBox())
    r = svc.parental.set_parental_profile("AA:BB:CC:DD:EE:02", "filtprof1")
    assert r["changed"] is False and r["verified"] is True
    assert not calls(fc, "AddHostEntryToFilterProfile")


def test_set_profile_not_taken_over(landevices: LanDeviceClient) -> None:
    box = ParentalBox()
    box.ignore_profile = True
    svc, _ = service(landevices, box)
    r = svc.parental.set_parental_profile("AA:BB:CC:DD:EE:02", "filtprof1234")
    assert r["verified"] is False and "nicht übernommen" in r["note"]


def test_set_profile_unknown_profile(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, ParentalBox())
    with pytest.raises(NotFoundError, match="filtprof1234"):
        svc.parental.set_parental_profile("AA:BB:CC:DD:EE:02", "filtprof77")


def test_set_profile_protects_box_and_server(landevices: LanDeviceClient) -> None:
    svc, fc = service(landevices, ParentalBox())
    with pytest.raises(InvalidParameterError, match="FRITZ!Box selbst"):
        svc.parental.set_parental_profile("AA:BB:CC:DD:EE:00", "filtprof1234")
    with pytest.raises(InvalidParameterError, match="MCP-Server"):
        svc.parental.set_parental_profile("AA:BB:CC:DD:EE:05", "filtprof1234")
    assert not calls(fc, "AddHostEntryToFilterProfile")
    # the server machine may only get an unrestricted profile
    r = svc.parental.set_parental_profile("AA:BB:CC:DD:EE:05", "filtprof2")
    assert r["verified"] is True


def test_set_profile_needs_write(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, ParentalBox(), write=False, critical=False)
    with pytest.raises(TierDisabledError):
        svc.parental.set_parental_profile("AA:BB:CC:DD:EE:02", "filtprof1234")


# ------------------------------------------------------------------ tickets


def test_ticket_create_and_status(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, ParentalBox())
    r = svc.parental.parental_ticket_create()
    assert r["ticket_id"] == "123456" and r["verified"] is True
    assert svc.parental.parental_ticket_status("123456")["status"] == "marked"
    assert svc.parental.parental_ticket_status("999999")["status"] == "invalid"
    with pytest.raises(InvalidParameterError):
        svc.parental.parental_ticket_status("12ab")


def test_ticket_limit_reached(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, ParentalBox())
    for _ in range(12):
        svc.parental.parental_ticket_create()
    with pytest.raises(NotFoundError, match="Keine freien Tickets") as exc:
        svc.parental.parental_ticket_create()
    assert "discard" in (exc.value.hint or "")


def test_add_ticket_time(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, ParentalBox())
    r = svc.parental.parental_add_ticket_time("AA:BB:CC:DD:EE:02")
    assert r["verified"] is True
    assert r["before"]["ticket_valid_min"] == 0 and r["after"]["ticket_valid_min"] == 45


def test_add_ticket_time_refuses_box(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, ParentalBox())
    with pytest.raises(InvalidParameterError):
        svc.parental.parental_add_ticket_time("AA:BB:CC:DD:EE:00")


def test_discard_tickets_plan_execute(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, ParentalBox())
    t = svc.parental.parental_ticket_create()["ticket_id"]
    plan = svc.parental.parental_tickets_discard_plan()
    assert "ALLE" in plan["consequence"]
    r = svc.parental.parental_tickets_discard_execute(plan["token"])
    assert r["accepted"] is True and r["verified"] is False
    assert svc.parental.parental_ticket_status(t)["status"] == "invalid"
    with pytest.raises(PlanError):
        svc.parental.parental_tickets_discard_execute(plan["token"])


def test_discard_needs_critical(landevices: LanDeviceClient) -> None:
    svc, _ = service(landevices, ParentalBox(), critical=False)
    with pytest.raises(TierDisabledError):
        svc.parental.parental_tickets_discard_plan()
