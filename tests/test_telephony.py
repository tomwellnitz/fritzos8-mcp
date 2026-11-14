from __future__ import annotations

import json
import logging
from types import SimpleNamespace
from typing import Any

import pytest
from fritzconnection.core.exceptions import FritzActionError, FritzConnectionException

from fritzos8_mcp.errors import (
    ConfirmationRequiredError,
    InvalidParameterError,
    NotFoundError,
    TierDisabledError,
)
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.telephony import (
    count_tam_messages,
    parse_call_list,
    parse_duration_minutes,
    parse_fritz_datetime,
    parse_tam_list,
)

from .conftest import FakeFC, make_service

# Example documents modelled on AVM's TR-064 specification (structure as in the
# fixtures of the78mole/fritzmoles-mcp, MIT); numbers are fictitious.
CALL_URL = "http://fritz.test:49000/calllist.lua?sid=0123456789abcdef"
CALLS = b"""<?xml version="1.0"?><root><timestamp>123456</timestamp>
<Call><Id>124</Id><Type>2</Type><Caller>030111222</Caller><Called>SIP: 98765</Called><Name></Name>
<Device></Device><Port>-1</Port><Date>14.11.26 09:05</Date><Duration>0:00</Duration><Path/></Call>
<Call><Id>123</Id><Type>3</Type><Called>0123456789</Called><Caller>SIP: 98765</Caller><Name>Max Mustermann</Name>
<Device>Mobilteil 1</Device><Port>10</Port><Date>13.11.26 08:13</Date><Duration>1:05</Duration><Path/></Call>
<Call><Id>122</Id><Type>1</Type><Caller>012456789</Caller><Called>SIP: 56789</Called><Name>Erika</Name>
<Device>Anrufbeantworter 1</Device><Port>40</Port><Date>12.11.26 14:19</Date><Duration>0:01</Duration>
<Path>/download.lua?path=/var/media/ftp/USB/FRITZ/voicebox/rec/rec.0.000</Path></Call>
<Call><Id>121</Id><Type>10</Type><Caller>0900666</Caller><Called>SIP: 56789</Called><Port>-1</Port>
<Date>11.11.26 10:00</Date><Duration>0:00</Duration></Call>
</root>"""

TAM_LIST = """<?xml version="1.0"?><List><TAMRunning>1</TAMRunning><Stick>0</Stick><Status>2</Status>
<Capacity>77</Capacity>
<Item><Index>0</Index><Display>1</Display><Enable>1</Enable><Name>Anrufbeantworter</Name></Item>
<Item><Index>1</Index><Display>1</Display><Enable>0</Enable><Name>Büro</Name></Item>
<Item><Index>2</Index><Display>0</Display><Enable>0</Enable><Name></Name></Item>
</List>"""
TAM_MSG_URL = "http://fritz.test:49000/tamcalls.lua?sid=0123456789abcdef&tamindex=0"
TAM_MESSAGES = b"""<Root><Message><Index>1</Index><Tam>0</Tam><New>1</New><Number>030111222</Number>
<Path>/download.lua?path=/x</Path></Message><Message><Index>0</Index><Tam>0</Tam><New>0</New>
<Number>0123</Number></Message></Root>"""
PB_URL = "http://fritz.test:49000/phonebook.lua?sid=0123456789abcdef&pbid=0"
PHONEBOOK = b"""<phonebooks><phonebook name="Telefonbuch"><contact><person><realName>A</realName></person>
<telephony><number>01</number></telephony></contact><contact><person><realName>B</realName></person></contact>
</phonebook></phonebooks>"""


class Session:
    def __init__(self, docs: dict[str, bytes]) -> None:
        self.docs = docs
        self.urls: list[str] = []

    def get(self, url: str) -> SimpleNamespace:
        self.urls.append(url)
        for prefix, content in self.docs.items():
            if url.startswith(prefix):
                return SimpleNamespace(ok=True, status_code=200, content=content)
        return SimpleNamespace(ok=False, status_code=404, content=b"")


class Tam:
    def __init__(self, discard: bool = False) -> None:
        self.enabled = {0: True, 1: False, 2: False}
        self.discard = discard

    def responses(self) -> dict[tuple[str, str], Any]:
        return {
            ("X_AVM-DE_TAM1", "GetList"): lambda: {"NewTAMList": TAM_LIST},
            ("X_AVM-DE_TAM1", "GetInfo"): lambda NewIndex: {"NewEnable": self.enabled[NewIndex], "NewName": "x"},
            ("X_AVM-DE_TAM1", "SetEnable"): self._set,
            ("X_AVM-DE_TAM1", "GetMessageList"): lambda NewIndex: {"NewURL": TAM_MSG_URL if NewIndex == 0 else ""},
        }

    def _set(self, NewIndex: int, NewEnable: int) -> dict[str, Any]:
        if not self.discard:
            self.enabled[NewIndex] = bool(NewEnable)
        return {}


def tel_fc(tam: Tam | None = None) -> tuple[FakeFC, Session]:
    responses: dict[tuple[str, str], Any] = {
        ("X_AVM-DE_OnTel1", "GetCallList"): {"NewCallListURL": CALL_URL},
        ("X_AVM-DE_OnTel1", "GetPhonebookList"): {"NewPhonebookList": "0,1"},
        ("X_AVM-DE_OnTel1", "GetPhonebook"): lambda NewPhonebookID: {
            "NewPhonebookName": ["Telefonbuch", "Familie"][NewPhonebookID],
            "NewPhonebookURL": PB_URL if NewPhonebookID == 0 else "",
        },
        **(tam or Tam()).responses(),
    }
    fc = FakeFC(responses)
    session = Session({CALL_URL: CALLS, TAM_MSG_URL: TAM_MESSAGES, PB_URL: PHONEBOOK})
    fc.session = session  # type: ignore[assignment]
    return fc, session


# ------------------------------------------------------------------ parsers


def test_parse_helpers() -> None:
    assert parse_fritz_datetime("13.11.26 08:13") == "2026-11-13T08:13"
    assert parse_fritz_datetime("kaputt") == "kaputt"
    assert parse_fritz_datetime("") is None
    assert parse_duration_minutes("1:05") == 65
    assert parse_duration_minutes("") is None


def test_parse_call_list_drops_recording_path() -> None:
    calls = parse_call_list(CALLS)
    assert [c["type"] for c in calls] == ["missed", "outgoing", "incoming", "rejected"]
    assert calls[1]["called"] == "0123456789" and calls[1]["duration_min"] == 65
    assert calls[2]["is_answering_machine"] is True
    assert "download.lua" not in json.dumps(calls)


def test_parse_tam_list_and_messages() -> None:
    tam = parse_tam_list(TAM_LIST)
    assert tam["running"] and tam["no_space_left"] and not tam["busy"] and tam["remaining_minutes"] == 77
    assert [m["index"] for m in tam["machines"]] == [0, 1, 2]
    assert count_tam_messages(TAM_MESSAGES) == {"total": 2, "new": 1}


# ------------------------------------------------------------------ call_list


def test_call_list_filters_and_limits(landevices: LanDeviceClient) -> None:
    fc, session = tel_fc()
    svc = make_service(landevices, fc)
    r = svc.call_list(call_type="missed")
    assert r["matched"] == 1 and r["calls"][0]["caller"] == "030111222"
    r = svc.call_list(days=7, max_entries=2)
    assert r["matched"] == 4 and r["returned"] == 2 and [c["id"] for c in r["calls"]] == [124, 123]
    assert session.urls[-1] == CALL_URL + "&days=7"  # max is applied locally, after the filter
    out = json.dumps(r)
    assert "0123456789abcdef" not in out and "download.lua" not in out


def test_call_list_numbers_never_logged(landevices: LanDeviceClient, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    fc, _ = tel_fc()
    make_service(landevices, fc).call_list()
    assert "030111222" not in caplog.text and "0123456789" not in caplog.text


@pytest.mark.parametrize("kwargs", [{"call_type": "spam"}, {"days": 0}, {"max_entries": 1001}])
def test_call_list_validation(landevices: LanDeviceClient, kwargs: dict[str, Any]) -> None:
    fc, _ = tel_fc()
    with pytest.raises(InvalidParameterError):
        make_service(landevices, fc).call_list(**kwargs)
    assert fc.calls == []


def test_call_list_disabled(landevices: LanDeviceClient) -> None:
    fc, _ = tel_fc()
    fc.responses[("X_AVM-DE_OnTel1", "GetCallList")] = {"NewCallListURL": ""}
    with pytest.raises(NotFoundError) as ei:
        make_service(landevices, fc).call_list()
    assert "Anrufliste" in (ei.value.hint or "")


def test_call_list_fetch_error_hides_url(landevices: LanDeviceClient) -> None:
    fc, session = tel_fc()
    session.docs.clear()
    with pytest.raises(Exception) as ei:
        make_service(landevices, fc).call_list()
    assert "0123456789abcdef" not in str(ei.value) and "HTTP 404" in str(ei.value)


# ------------------------------------------------------------------ TAM


def test_tam_list_counts_new_messages(landevices: LanDeviceClient) -> None:
    fc, _ = tel_fc()
    r = make_service(landevices, fc).tam_list()
    assert r["count"] == 2  # unused slot 2 hidden
    tams = {m["index"]: m for m in r["machines"]}
    assert tams[0]["messages"] == {"total": 2, "new": 1} and tams[0]["enabled"] is True
    assert tams[1]["messages"] is None and tams[1]["name"] == "Büro"
    assert r["new_messages_total"] == 1
    assert "download.lua" not in json.dumps(r) and "030111222" not in json.dumps(r)


def test_set_tam_enabled_needs_write(landevices: LanDeviceClient) -> None:
    fc, _ = tel_fc()
    with pytest.raises(TierDisabledError):
        make_service(landevices, fc, write=False, critical=False).set_tam_enabled(1, True)
    assert fc.calls == []


def test_set_tam_enabled_verified(landevices: LanDeviceClient) -> None:
    tam = Tam()
    fc, _ = tel_fc(tam)
    r = make_service(landevices, fc).set_tam_enabled(1, True)
    assert r == {"index": 1, "name": "Büro", "enabled": True, "changed": True, "verified": True}
    assert ("X_AVM-DE_TAM1", "SetEnable", {"NewIndex": 1, "NewEnable": 1}) in fc.calls
    assert tam.enabled == {0: True, 1: True, 2: False}


def test_set_tam_enabled_unchanged(landevices: LanDeviceClient) -> None:
    fc, _ = tel_fc()
    r = make_service(landevices, fc).set_tam_enabled(0, True)
    assert r["changed"] is False and r["verified"] is True
    assert not [c for c in fc.calls if c[1] == "SetEnable"]


def test_set_tam_enabled_discarded(landevices: LanDeviceClient) -> None:
    fc, _ = tel_fc(Tam(discard=True))
    r = make_service(landevices, fc).set_tam_enabled(1, True)
    assert r["verified"] is False and r["read_back"] is False


def test_set_tam_enabled_unknown_index(landevices: LanDeviceClient) -> None:
    fc, _ = tel_fc()
    with pytest.raises(NotFoundError):
        make_service(landevices, fc).set_tam_enabled(7, True)
    with pytest.raises(InvalidParameterError):
        make_service(landevices, fc).set_tam_enabled(10, True)


def test_set_tam_enabled_two_factor(landevices: LanDeviceClient) -> None:
    fc, _ = tel_fc()
    fc.responses[("X_AVM-DE_TAM1", "SetEnable")] = FritzConnectionException("errorCode: 866")
    with pytest.raises(ConfirmationRequiredError):
        make_service(landevices, fc).set_tam_enabled(1, True)


def test_set_tam_enabled_unreadable(landevices: LanDeviceClient) -> None:
    tam = Tam()
    fc, _ = tel_fc(tam)
    svc = make_service(landevices, fc)
    fc.responses[("X_AVM-DE_TAM1", "GetInfo")] = FritzActionError("x")
    r = svc.set_tam_enabled(1, True)
    assert r["verified"] is False and r["changed"] is None


# ------------------------------------------------------------------ phonebooks


def test_phonebook_list_names_and_counts(landevices: LanDeviceClient) -> None:
    fc, session = tel_fc()
    svc = make_service(landevices, fc)
    r = svc.phonebook_list()
    assert r["phonebooks"] == [{"id": 0, "name": "Telefonbuch"}, {"id": 1, "name": "Familie"}]
    assert session.urls == []  # no download without with_counts
    r = svc.phonebook_list(with_counts=True)
    assert r["phonebooks"][0]["contacts"] == 2 and r["phonebooks"][1]["contacts"] is None
    assert "realName" not in json.dumps(r) and "01" not in json.dumps(r["phonebooks"])
