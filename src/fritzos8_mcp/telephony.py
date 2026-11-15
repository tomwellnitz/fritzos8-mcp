"""Telephony via TR-064 ``X_AVM-DE_OnTel1`` (call list, phonebooks) and ``X_AVM-DE_TAM1``
(answering machines).

The XML parsers (call list, TAM list, TAM message list, date/duration helpers, call type
table) are adapted from the78mole/fritzmoles-mcp (src/fritzmoles_mcp/parsers.py and
client.py, MIT License, Copyright (c) 2026 Daniel Glaser); switched to defusedxml and
reduced to the fields this server returns.

Privacy: phone numbers are the owner's own data and are returned in tool results, but they
are never written to logs. Recording paths/audio are never returned or downloaded. Box URLs
carry a session id and never appear in results, errors or logs.
"""

from __future__ import annotations

import datetime as dt
from typing import Any
from urllib.parse import urlencode

from defusedxml import ElementTree as ET

from .errors import FritzError, InvalidParameterError, NotFoundError
from .tr064 import Tr064Client
from .util import decimal_int, truthy

ONTEL = "X_AVM-DE_OnTel1"
TAM = "X_AVM-DE_TAM1"

MAX_CALLS = 1000
MAX_DAYS = 999
MAX_TAM_INDEX = 9

CALL_TYPES: dict[int, str] = {
    1: "incoming",
    2: "missed",
    3: "outgoing",
    9: "active_incoming",
    10: "rejected",
    11: "active_outgoing",
}

CALL_FILTERS: dict[str, frozenset[int]] = {
    "all": frozenset(),
    "incoming": frozenset({1, 9}),
    "outgoing": frozenset({3, 11}),
    "missed": frozenset({2}),
    "rejected": frozenset({10}),
}


# ---------------------------------------------------------------- parsers (pure)


def _text(node: Any, name: str) -> str:
    if node is None:
        return ""
    child = node.find(name)
    return (child.text or "").strip() if child is not None else ""


def _int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_fritz_datetime(value: str) -> str | None:
    """``dd.mm.yy HH:MM`` → ISO 8601 ``YYYY-MM-DDTHH:MM`` (unparsable values unchanged)."""
    value = (value or "").strip()
    if not value:
        return None
    try:
        return dt.datetime.strptime(value, "%d.%m.%y %H:%M").isoformat(timespec="minutes")
    except ValueError:
        return value


def parse_duration_minutes(value: str) -> int | None:
    """``h:mm`` (the box rounds up to whole minutes) → minutes."""
    value = (value or "").strip()
    if ":" not in value:
        return None
    hours, minutes = value.split(":", 1)
    h, m = _int(hours), _int(minutes)
    return None if h is None or m is None else h * 60 + m


def parse_call_list(xml: bytes | str) -> list[dict[str, Any]]:
    root = ET.fromstring(xml)
    calls: list[dict[str, Any]] = []
    for node in root.iter("Call"):
        type_id = _int(_text(node, "Type"))
        port = _text(node, "Port")
        port_id = _int(port)
        calls.append(
            {
                "id": _int(_text(node, "Id")),
                "type": CALL_TYPES.get(type_id, "unknown") if type_id is not None else "unknown",
                "type_id": type_id,
                "date": parse_fritz_datetime(_text(node, "Date")),
                "caller": _text(node, "Caller") or _text(node, "CallerNumber"),
                "called": _text(node, "Called") or _text(node, "CalledNumber"),
                "name": _text(node, "Name"),
                "device": _text(node, "Device"),
                "port": port,
                "duration_min": parse_duration_minutes(_text(node, "Duration")),
                "is_fax": port_id == 5,
                "is_answering_machine": port_id is not None and (port_id == 6 or 40 <= port_id <= 49),
                # <Path> (recording) is deliberately dropped: no audio access via this server.
            }
        )
    return calls


def parse_tam_list(xml: bytes | str) -> dict[str, Any]:
    root = ET.fromstring(xml)
    machines = [
        {
            "index": _int(_text(item, "Index")),
            "name": _text(item, "Name"),
            "enabled": _text(item, "Enable") == "1",
            "displayed": _text(item, "Display") == "1",
        }
        for item in root.iter("Item")
    ]
    status = _int(_text(root, "Status")) or 0
    return {
        "running": _text(root, "TAMRunning") == "1",
        "storage": "usb" if _text(root, "Stick") in {"1", "2"} else "internal",
        "busy": bool(status & 0b01),
        "no_space_left": bool(status & 0b10),
        "remaining_minutes": _int(_text(root, "Capacity")),
        "machines": machines,
    }


def count_tam_messages(xml: bytes | str) -> dict[str, int]:
    """Count messages of one TAM. AVM's spec documents <New> inverted; real boxes send 1 = new
    (observation from the78mole/fritzmoles-mcp)."""
    root = ET.fromstring(xml)
    messages = list(root.iter("Message"))
    return {"total": len(messages), "new": sum(1 for m in messages if _text(m, "New") == "1")}


def count_phonebook_contacts(xml: bytes | str) -> int:
    return sum(1 for _ in ET.fromstring(xml).iter("contact"))


def _with_query(url: str, **params: Any) -> str:
    extra = {k: v for k, v in params.items() if v not in (None, "", 0)}
    if not extra:
        return url
    return f"{url}{'&' if '?' in url else '?'}{urlencode(extra)}"


# ---------------------------------------------------------------- client


class TelephonyClient:
    def __init__(self, tr064: Tr064Client) -> None:
        self.tr064 = tr064

    # ------------------------------------------------------------ call list

    def call_list(self, days: int | None = None, max_entries: int = 50, call_type: str = "all") -> dict[str, Any]:
        if call_type not in CALL_FILTERS:
            raise InvalidParameterError(f'Unbekannter Anruftyp "{call_type}" – erlaubt: {", ".join(CALL_FILTERS)}.')
        if days is not None and not 1 <= days <= MAX_DAYS:
            raise InvalidParameterError(f"days muss 1–{MAX_DAYS} sein.")
        if not 1 <= max_entries <= MAX_CALLS:
            raise InvalidParameterError(f"max_entries muss 1–{MAX_CALLS} sein.")
        url = str(self.tr064.call(ONTEL, "GetCallList").get("NewCallListURL") or "")
        if not url:
            raise NotFoundError(
                "Die Box liefert keine Anrufliste.",
                hint="Der FRITZ!Box-Benutzer braucht das Recht "
                "'Sprachnachrichten, Faxnachrichten, FRITZ!App Fon und Anrufliste'.",
            )
        # `max` is not passed to the box: it would cut BEFORE the type filter.
        calls = parse_call_list(self.tr064.fetch(_with_query(url, days=days)))
        wanted = CALL_FILTERS[call_type]
        if wanted:
            calls = [c for c in calls if c["type_id"] in wanted]
        matched = len(calls)
        return {
            "type": call_type,
            "days": days,
            "matched": matched,
            "returned": min(matched, max_entries),
            "order": "neueste zuerst (wie von der Box geliefert)",
            "calls": calls[:max_entries],
        }

    # ------------------------------------------------------------ answering machines

    def _tam_raw(self) -> dict[str, Any]:
        xml = str(self.tr064.call(TAM, "GetList").get("NewTAMList") or "")
        if not xml.strip():
            raise NotFoundError("Die Box liefert keine Anrufbeantworter-Liste.")
        return parse_tam_list(xml)

    def tam_list(self) -> dict[str, Any]:
        data = self._tam_raw()
        machines = []
        for m in data["machines"]:
            if not (m["enabled"] or m["displayed"]):
                continue  # unused slot
            entry = dict(m)
            entry["messages"] = None
            try:
                r = self.tr064.call(TAM, "GetMessageList", NewIndex=m["index"])
                url = str(r.get("NewURL") or "")
                if url:
                    entry["messages"] = count_tam_messages(self.tr064.fetch(url))
            except FritzError as exc:
                entry["messages_error"] = exc.to_dict()
            machines.append(entry)
        data["machines"] = machines
        data["count"] = len(machines)
        data["new_messages_total"] = sum((m["messages"] or {}).get("new", 0) for m in machines)
        data["note"] = "Nur Zähler – keine Sprachnachrichten-Audios."
        return data

    def _tam_enabled(self, index: int) -> bool | None:
        r = self.tr064.try_call(TAM, "GetInfo", NewIndex=index)
        if r is None or r.get("NewEnable") is None:
            return None
        return truthy(r.get("NewEnable"))

    def set_tam_enabled(self, index: int, enabled: bool) -> dict[str, Any]:
        if not 0 <= index <= MAX_TAM_INDEX:
            raise InvalidParameterError(f"index muss 0–{MAX_TAM_INDEX} sein.")
        known = {m["index"]: m for m in self._tam_raw()["machines"]}
        if index not in known:
            raise NotFoundError(f"Anrufbeantworter {index} gibt es nicht – siehe tam_list.")
        name = known[index]["name"]
        before = self._tam_enabled(index)
        if before is None:
            before = known[index]["enabled"]
        base = {"index": index, "name": name, "enabled": enabled}
        if before == enabled:
            return {**base, "changed": False, "verified": True}
        self.tr064.call(TAM, "SetEnable", NewIndex=index, NewEnable=1 if enabled else 0)
        after = self._tam_enabled(index)
        if after is None:
            return {
                **base,
                "changed": None,
                "verified": False,
                "note": "Schreiben angenommen, Zustand aber nicht rücklesbar – in der Web-UI unter Telefonie prüfen.",
            }
        if after != enabled:
            return {
                **base,
                "read_back": after,
                "changed": False,
                "verified": False,
                "note": "Die Box meldet weiterhin den alten Zustand – nicht übernommen (evtl. Zusatzbestätigung).",
            }
        return {**base, "changed": True, "verified": True}

    # ------------------------------------------------------------ phonebooks

    def phonebook_list(self, with_counts: bool = False) -> dict[str, Any]:
        raw = str(self.tr064.call(ONTEL, "GetPhonebookList").get("NewPhonebookList") or "")
        ids = [n for n in map(decimal_int, raw.replace(" ", "").split(",")) if n is not None]
        books = []
        for pid in ids:
            info = self.tr064.call(ONTEL, "GetPhonebook", NewPhonebookID=pid)
            book: dict[str, Any] = {"id": pid, "name": info.get("NewPhonebookName") or ""}
            if with_counts:
                url = str(info.get("NewPhonebookURL") or "")
                try:
                    book["contacts"] = count_phonebook_contacts(self.tr064.fetch(url)) if url else None
                except FritzError as exc:
                    book["contacts"] = None
                    book["contacts_error"] = exc.to_dict()
            books.append(book)
        return {"count": len(books), "phonebooks": books, "note": "Nur Namen/Anzahl – keine Kontakte."}
