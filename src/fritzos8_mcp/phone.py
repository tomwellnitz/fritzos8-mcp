"""Stage 8.10 – telephony read: number registration, alarm clocks, call deflections, call barring, phone book search
and caller names for the call list. Own implementation after the AVM TR-064 documents:

* ``X_VoIP``: ``X_AVM-DE_GetNumbers`` (NumberList XML: Number, Type eVoIP/eISDN/ePOTS/…, Index, Name),
  ``X_AVM-DE_GetVoIPStatus(VoIPAccountIndex)`` → unknown/disabled/not registered/registered/connected,
  ``X_AVM-DE_GetNumberOfAlarmClocks``, ``X_AVM-DE_GetAlarmClock(Index)`` → Enable, Name, Time "HHMM",
  Weekdays "MO,TU,…,HO", PhoneName. SIP accounts/credentials (``X_AVM-DE_GetVoIPAccount(s)``) stay denied.
* ``X_AVM-DE_OnTel``: ``GetDeflections`` (DeflectionList XML; the AVM example itself is malformed → repaired),
  fallback ``GetNumberOfDeflections``/``GetDeflection``; ``GetCallBarringList`` (URL → phone book XML);
  ``GetPhonebookList``/``GetPhonebook`` (URL → XML with contact/person/realName, telephony/number@type, uniqueid).

Phone numbers are the owner's data: shown in results, never logged. Box URLs carry a session id and never appear.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated, Any

from defusedxml import ElementTree as ET
from pydantic import Field

from .alerts import Alarm
from .errors import AuthError, ConfirmationRequiredError, FritzConnectionError, FritzError, InvalidParameterError
from .nasremote import ToolDecorator
from .security import Tier
from .toolargs import READ, BoxArg
from .util import decimal_int, truthy

if TYPE_CHECKING:
    from .tr064 import Tr064Client

VOIP = "X_VoIP1"
ONTEL = "X_AVM-DE_OnTel1"
MAX_ITEMS = 64
MAX_HITS = 20
WEEKDAYS = {"MO": "Mo", "TU": "Di", "WE": "Mi", "TH": "Do", "FR": "Fr", "SA": "Sa", "SU": "So", "HO": "Feiertag"}
NUMBER_TYPES = {"evoip": "voip", "eisdn": "isdn", "epots": "analog", "emobile": "mobil"}
DEFLECTION_TYPES = {
    "fromAll": "alle Anrufe",
    "fromNumber": "von bestimmter Nummer",
    "fromAnonymous": "anonyme Anrufe",
    "fromVIP": "VIP-Anrufer",
    "fromNotVIP": "Nicht-VIP-Anrufer",
    "fromPB": "Anrufer aus Telefonbuch",
    "fromNotInPhonebook": "Anrufer nicht im Telefonbuch",
    "toMSN": "an bestimmte Rufnummer",
    "toPOTS": "an Festnetz (analog)",
    "toVoIP": "an Internetrufnummer",
}
DEFLECTION_MODES = {
    "eImmediately": "sofort",
    "eShortDelayed": "nach kurzer Verzögerung",
    "eLongDelayed": "nach längerer Verzögerung",
    "eDelayedOrBusy": "verzögert oder bei besetzt",
    "eBusy": "bei besetzt",
    "eDirectCall": "Direktruf",
    "eParallelCall": "parallel",
    "eNoSignal": "ohne Signal",
    "eVIP": "VIP",
    "eOff": "aus",
}
_BROKEN_CLOSE = re.compile(r"</>")


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _xml(text: str) -> Any:
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        try:
            return ET.fromstring(_BROKEN_CLOSE.sub("", text))
        except ET.ParseError:
            raise FritzError("Antwort der Box ist kein gültiges XML.") from None


def _items(root: Any) -> list[dict[str, str]]:
    return [{c.tag: (c.text or "").strip() for c in item} for item in root.iter("Item")]


def digits(number: str) -> str:
    """Normalise a phone number for comparison: digits only, +49/0049 → 0."""
    n = re.sub(r"[^\d+]", "", number or "")
    n = re.sub(r"^(\+|00)49", "0", n)
    return n.lstrip("+")


def parse_phonebook(xml: bytes | str) -> list[dict[str, Any]]:
    root = _xml(xml.decode("utf-8", errors="replace") if isinstance(xml, bytes) else xml)
    contacts = []
    for c in root.iter("contact"):
        name = (c.findtext("person/realName") or "").strip()
        numbers = [
            {"number": (n.text or "").strip(), "type": n.get("type") or None}
            for n in c.iter("number")
            if (n.text or "").strip()
        ]
        contacts.append({"name": name, "numbers": numbers, "uid": _int(c.findtext("uniqueid"))})
    return contacts


def alarm_time(raw: Any) -> str | None:
    s = str(raw or "").strip()
    return f"{s[:2]}:{s[2:4]}" if re.fullmatch(r"\d{4}", s) else (s or None)


class PhoneClient:
    def __init__(self, tr064: Tr064Client) -> None:
        self.tr064 = tr064

    # ------------------------------------------------------------ numbers / registration (K-27)

    def numbers_status(self) -> dict[str, Any]:
        raw = str(self.tr064.call(VOIP, "X_AVM-DE_GetNumbers").get("NewNumberList") or "")
        items = _items(_xml(raw)) if raw.strip() else []
        numbers = []
        for item in items[:MAX_ITEMS]:
            kind = NUMBER_TYPES.get(item.get("Type", "").lower(), item.get("Type") or None)
            entry: dict[str, Any] = {
                "number": item.get("Number") or None,
                "type": kind,
                "name": item.get("Name") or None,
                "index": _int(item.get("Index")),
                "status": "n/a",
            }
            if kind == "voip" and entry["index"] is not None:
                r = self.tr064.try_call(VOIP, "X_AVM-DE_GetVoIPStatus", NewVoIPAccountIndex=entry["index"])
                entry["status"] = str((r or {}).get("NewX_AVM-DE_VoIPStatus") or "unknown")
            numbers.append(entry)
        problems = [n for n in numbers if n["type"] == "voip" and n["status"] not in ("registered", "connected")]
        return {
            "count": len(numbers),
            "numbers": numbers,
            "not_registered": [f"{n['number']} ({n['status']})" for n in problems],
            "all_registered": not problems,
            "note": "Status nur für Internetrufnummern (VoIP); ISDN/analog = n/a. SIP-Zugangsdaten werden nie gelesen.",
        }

    # ------------------------------------------------------------ alarm clocks (K-3)

    def alarm_clocks(self) -> dict[str, Any]:
        n = self.tr064.call(VOIP, "X_AVM-DE_GetNumberOfAlarmClocks")
        count = min(_int(n.get("NewX_AVM-DE_NumberOfAlarmClocks")) or 0, MAX_ITEMS)
        clocks = []
        for idx in range(count):
            r = self.tr064.try_call(VOIP, "X_AVM-DE_GetAlarmClock", NewIndex=idx)
            if r is None:
                break
            days = [
                d.strip().upper() for d in str(r.get("NewX_AVM-DE_AlarmClockWeekdays") or "").split(",") if d.strip()
            ]
            clocks.append(
                {
                    "index": idx,
                    "enabled": truthy(r.get("NewX_AVM-DE_AlarmClockEnable")),
                    "name": r.get("NewX_AVM-DE_AlarmClockName") or None,
                    "time": alarm_time(r.get("NewX_AVM-DE_AlarmClockTime")),
                    "weekdays": [WEEKDAYS.get(d, d) for d in days] or ["einmalig"],
                    "phone": r.get("NewX_AVM-DE_AlarmClockPhoneName") or "alle Telefone",
                }
            )
        return {"count": len(clocks), "active": sum(1 for c in clocks if c["enabled"]), "alarm_clocks": clocks}

    # ------------------------------------------------------------ deflections (K-4)

    def deflections(self) -> dict[str, Any]:
        items: list[dict[str, str]] = []
        r = self.tr064.try_call(ONTEL, "GetDeflections")
        raw = str((r or {}).get("NewDeflectionList") or "")
        if raw.strip():
            items = _items(_xml(raw))
        else:
            n = self.tr064.call(ONTEL, "GetNumberOfDeflections")
            for idx in range(min(_int(n.get("NewNumberOfDeflections")) or 0, MAX_ITEMS)):
                d = self.tr064.try_call(ONTEL, "GetDeflection", NewDeflectionId=idx)
                if d is None:
                    break
                items.append({k.removeprefix("New"): str(v) for k, v in d.items()} | {"DeflectionId": str(idx)})
        out = []
        for i in items[:MAX_ITEMS]:
            out.append(
                {
                    "id": _int(i.get("DeflectionId")),
                    "enabled": truthy(i.get("Enable")),
                    "applies_to": DEFLECTION_TYPES.get(i.get("Type", ""), i.get("Type") or None),
                    "number": i.get("Number") or None,
                    "to": i.get("DeflectionToNumber") or None,
                    "when": DEFLECTION_MODES.get(i.get("Mode", ""), i.get("Mode") or None),
                    "outgoing_number": i.get("Outgoing") or None,
                }
            )
        active = [d for d in out if d["enabled"]]
        return {
            "count": len(out),
            "active": len(active),
            "deflections": out,
            "note": "Aktive Rufumleitungen nach außen können Kosten verursachen und machen den Anschluss für "
            "Anrufer ggf. unerreichbar."
            if active
            else None,
        }

    # ------------------------------------------------------------ call barring (K-5)

    def call_barring(self) -> dict[str, Any]:
        url = str(self.tr064.call(ONTEL, "GetCallBarringList").get("NewPhonebookURL") or "")
        contacts = parse_phonebook(self.tr064.fetch(url)) if url else []
        return {
            "count": len(contacts),
            "entries": [{"name": c["name"] or None, "numbers": c["numbers"], "uid": c["uid"]} for c in contacts],
        }

    # ------------------------------------------------------------ phone books (K-2)

    def _phonebooks(self) -> list[tuple[int, str, list[dict[str, Any]]]]:
        def load() -> list[tuple[int, str, list[dict[str, Any]]]]:
            raw = str(self.tr064.call(ONTEL, "GetPhonebookList").get("NewPhonebookList") or "")
            books = []
            for pid in [n for n in map(decimal_int, raw.replace(" ", "").split(",")) if n is not None][:16]:
                info = self.tr064.call(ONTEL, "GetPhonebook", NewPhonebookID=pid)
                url = str(info.get("NewPhonebookURL") or "")
                books.append((pid, str(info.get("NewPhonebookName") or ""), parse_phonebook(self.tr064.fetch(url))))
            return books

        books: list[tuple[int, str, list[dict[str, Any]]]] = self.tr064.cached("phonebooks", load)
        return books

    def phonebook_search(self, query: str, phonebook_id: int | None = None) -> dict[str, Any]:
        q = (query or "").strip()
        if len(q) < 2:
            raise InvalidParameterError("Suchbegriff mindestens 2 Zeichen (Name oder Nummer).")
        qd = digits(q)
        by_number = len(qd) >= 3 and len(qd) >= len(re.sub(r"\s", "", q)) - 2
        hits = []
        for pid, pname, contacts in self._phonebooks():
            if phonebook_id is not None and pid != phonebook_id:
                continue
            for c in contacts:
                if by_number:
                    match = any(
                        digits(n["number"]).endswith(qd) or qd.endswith(digits(n["number"]) or "#")
                        for n in c["numbers"]
                        if len(digits(n["number"])) >= 3
                    )
                else:
                    match = q.lower() in c["name"].lower()
                if match:
                    hits.append({"phonebook_id": pid, "phonebook": pname, **c})
        return {
            "query": q,
            "by": "number" if by_number else "name",
            "count": len(hits),
            "hits": hits[:MAX_HITS],
            "truncated": len(hits) > MAX_HITS,
        }

    def name_for(self, number: str) -> str | None:
        nd = digits(number)
        if len(nd) < 5:
            return None
        for _, _, contacts in self._phonebooks():
            for c in contacts:
                for n in c["numbers"]:
                    d = digits(n["number"])
                    if len(d) >= 5 and (d == nd or (d.endswith(nd[-9:]) and nd.endswith(d[-9:]))):
                        return str(c["name"]) or None
        return None

    def enrich_call_list(self, result: dict[str, Any]) -> dict[str, Any]:
        """Fill empty caller names from the phone books (number of the other party)."""
        filled = 0
        try:
            for call in result.get("calls") or []:
                if call.get("name"):
                    continue
                other = (
                    call.get("caller")
                    if call.get("type") in ("incoming", "missed", "rejected", "active_incoming")
                    else call.get("called")
                )
                name = self.name_for(str(other or ""))
                if name:
                    call["name"] = name
                    call["name_source"] = "phonebook"
                    filled += 1
        except (AuthError, ConfirmationRequiredError, FritzConnectionError):
            raise
        except FritzError as exc:
            result["name_lookup_error"] = exc.to_dict()
        result["names_from_phonebook"] = filled
        return result

    # ------------------------------------------------------------ alarm hook (stage 8.3)

    def registration_alarms(self) -> list[Alarm]:
        status = self.numbers_status()
        return [
            Alarm(f"voip:{n}", "number_not_registered", "warn", f"Rufnummer nicht registriert: {n}")
            for n in status["not_registered"]
        ]


def register_phone_tools(tool: ToolDecorator, svc: Callable[[str | None], PhoneClient]) -> None:
    @tool(Tier.READ, READ)
    def phone_numbers_status(box: BoxArg = None) -> dict[str, Any]:
        """Rufnummern der Box (TR-064 X_VoIP:X_AVM-DE_GetNumbers) mit Registrierungsstatus je Internetrufnummer
        (X_AVM-DE_GetVoIPStatus: registered/not registered/disabled/connected). Ohne SIP-Zugangsdaten."""
        return svc(box).numbers_status()

    @tool(Tier.READ, READ)
    def alarm_clocks(box: BoxArg = None) -> dict[str, Any]:
        """Weckrufe der Telefonanlage (TR-064 X_VoIP:X_AVM-DE_GetAlarmClock): an/aus, Name, Uhrzeit, Wochentage,
        Telefon."""
        return svc(box).alarm_clocks()

    @tool(Tier.READ, READ)
    def call_deflections(box: BoxArg = None) -> dict[str, Any]:
        """Rufumleitungen (TR-064 X_AVM-DE_OnTel:GetDeflections): an/aus, für welche Anrufe, Ziel, wann."""
        return svc(box).deflections()

    @tool(Tier.READ, READ)
    def call_barring_list(box: BoxArg = None) -> dict[str, Any]:
        """Rufsperren (TR-064 X_AVM-DE_OnTel:GetCallBarringList): gesperrte Nummern mit Name und uid."""
        return svc(box).call_barring()

    @tool(Tier.READ, READ)
    def phonebook_search(
        query: Annotated[str, Field(description="Name (Teilstring) oder Rufnummer (auch ohne Vorwahl/+49)")],
        phonebook_id: Annotated[
            int | None, Field(description="Nur in diesem Telefonbuch (ID aus phonebook_list)")
        ] = None,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Sucht Kontakte in den Telefonbüchern der Box nach Name oder Nummer (Rückwärtssuche): Name, Nummern mit Typ,
        Telefonbuch. Höchstens 20 Treffer."""
        return svc(box).phonebook_search(query, phonebook_id)
