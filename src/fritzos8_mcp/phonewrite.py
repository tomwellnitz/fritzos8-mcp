"""Stage 8.8 – telephony write: alarm clock on/off, call deflection on/off, call barring add/remove, answering machine
message read/unread and delete (critical), click-to-dial (critical). After the AVM TR-064 documents:

* ``X_VoIP:X_AVM-DE_SetAlarmClockEnable(Index, AlarmClockEnable)``; read back via ``X_AVM-DE_GetAlarmClock``.
* ``X_AVM-DE_OnTel:SetDeflectionEnable(DeflectionId, Enable)``; read back via ``GetDeflection``.
* ``X_AVM-DE_OnTel:SetCallBarringEntry(PhonebookEntryData)`` → PhonebookEntryUniqueID; ``DeleteCallBarringEntryUID``;
  read back via ``GetCallBarringEntryByNum`` (714 = not in the call barring list).
* ``X_AVM-DE_TAM:MarkMessage(Index, MessageIndex, MarkedAsRead)``, ``DeleteMessage(Index, MessageIndex)``; read back via
  the message list (``GetMessageList`` → URL → XML). AVM documents ``<New>`` inverted to common practice (V-9) – the
  read-back follows the existing assumption 1 = new and says so.
* ``X_VoIP:X_AVM-DE_DialNumber(PhoneNumber)`` (on the generic denylist – only this critical tool),
  ``X_AVM-DE_DialHangup``, ``X_AVM-DE_DialGetConfig`` (phone of the dial helper). The call is not verifiable.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated, Any
from xml.sax.saxutils import escape

from defusedxml import ElementTree as ET
from pydantic import Field

from .errors import FritzError, InvalidParameterError, NotFoundError
from .nasremote import ToolDecorator
from .phone import ONTEL, VOIP, digits
from .security import Gate, PlanStore, Tier
from .toolargs import DESTRUCTIVE, READ, WRITE, BoxArg, TokenArg
from .util import decimal_int, truthy

if TYPE_CHECKING:
    from .tr064 import Tr064Client

TAM = "X_AVM-DE_TAM1"
_NUMBER = re.compile(r"^\+?[0-9*#]{3,30}$")
MAX_NAME = 39


def validate_number(number: str) -> str:
    n = re.sub(r"[\s()/-]", "", number or "")
    if not _NUMBER.match(n):
        raise InvalidParameterError("Rufnummer: 3–30 Zeichen aus 0–9, *, #, optional führendes +.")
    return n


def barring_entry_xml(number: str, name: str) -> str:
    return (
        '<?xml version="1.0" encoding="utf-8"?><contact><category>0</category><person><realName>'
        f'{escape(name)}</realName></person><telephony><number type="home" prio="1" id="0">{escape(number)}'
        "</number></telephony></contact>"
    )


class PhoneWriter:
    def __init__(self, tr064: Tr064Client, gate: Gate, plans: PlanStore) -> None:
        self.tr064 = tr064
        self.gate = gate
        self.plans = plans

    # ------------------------------------------------------------ alarm clock / deflection

    def set_alarm_clock(self, index: int, enabled: bool) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)

        def read() -> dict[str, Any]:
            try:
                return self.tr064.call(VOIP, "X_AVM-DE_GetAlarmClock", NewIndex=index)
            except NotFoundError:
                raise NotFoundError(f"Weckruf {index} gibt es nicht – siehe alarm_clocks.") from None

        before = read()
        base = {"index": index, "name": before.get("NewX_AVM-DE_AlarmClockName") or None, "enabled": enabled}
        if truthy(before.get("NewX_AVM-DE_AlarmClockEnable")) == enabled:
            return {**base, "changed": False, "verified": True}
        self.tr064.call(
            VOIP, "X_AVM-DE_SetAlarmClockEnable", NewIndex=index, **{"NewX_AVM-DE_AlarmClockEnable": int(enabled)}
        )
        after = truthy(read().get("NewX_AVM-DE_AlarmClockEnable"))
        return {**base, "changed": True, "verified": after == enabled, "read_back": after}

    def set_deflection(self, deflection_id: int, enabled: bool) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        before = self.tr064.call(ONTEL, "GetDeflection", NewDeflectionId=deflection_id)
        base = {
            "id": deflection_id,
            "to": before.get("NewDeflectionToNumber") or None,
            "type": before.get("NewType") or None,
            "enabled": enabled,
        }
        warning = (
            "Rufumleitung nach außen: Weitergeleitete Gespräche können Kosten verursachen; Anrufer erreichen den "
            "Anschluss je nach Modus nicht mehr direkt."
            if enabled
            else None
        )
        if truthy(before.get("NewEnable")) == enabled:
            return {**base, "changed": False, "verified": True, "warning": warning}
        self.tr064.call(ONTEL, "SetDeflectionEnable", NewDeflectionId=deflection_id, NewEnable=int(enabled))
        after = truthy(self.tr064.call(ONTEL, "GetDeflection", NewDeflectionId=deflection_id).get("NewEnable"))
        return {**base, "changed": True, "verified": after == enabled, "read_back": after, "warning": warning}

    # ------------------------------------------------------------ call barring

    def _barred(self, number: str) -> dict[str, Any] | None:
        try:
            r = self.tr064.call(ONTEL, "GetCallBarringEntryByNum", NewNumber=number)
        except FritzError as exc:
            if exc.tr064_code == "714" or isinstance(exc, NotFoundError):
                return None
            raise
        data = str(r.get("NewPhonebookEntryData") or "")
        if not data.strip():
            return None
        try:
            root = ET.fromstring(data)
            uid = (root.findtext(".//uniqueid") or "").strip()
            name = (root.findtext(".//realName") or "").strip()
        except ET.ParseError:
            uid, name = "", ""
        return {"uid": decimal_int(uid), "name": name or None}

    def barring_add(self, number: str, name: str | None = None) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        n = validate_number(number)
        label = (name or "Gesperrt").strip()[:MAX_NAME] or "Gesperrt"
        existing = self._barred(n)
        if existing is not None:
            return {"number": n, **existing, "changed": False, "verified": True}
        r = self.tr064.call(ONTEL, "SetCallBarringEntry", NewPhonebookEntryData=barring_entry_xml(n, label))
        after = self._barred(n)
        return {
            "number": n,
            "name": label,
            "uid": r.get("NewPhonebookEntryUniqueID") or (after or {}).get("uid"),
            "changed": True,
            "verified": after is not None,
        }

    def barring_remove(self, number: str) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        n = validate_number(number)
        existing = self._barred(n)
        if existing is None:
            return {"number": n, "changed": False, "verified": True, "note": "Nummer war nicht gesperrt."}
        if existing.get("uid") is None:
            raise FritzError("Sperreintrag gefunden, aber ohne uniqueid – bitte in der Web-UI entfernen.")
        self.tr064.call(ONTEL, "DeleteCallBarringEntryUID", NewPhonebookEntryUniqueID=existing["uid"])
        gone = self._barred(n) is None
        return {"number": n, "uid": existing["uid"], "changed": True, "verified": gone}

    # ------------------------------------------------------------ answering machine messages

    def _messages(self, tam: int) -> list[dict[str, Any]]:
        url = str(self.tr064.call(TAM, "GetMessageList", NewIndex=tam).get("NewURL") or "")
        if not url:
            raise NotFoundError(f"Anrufbeantworter {tam} liefert keine Nachrichtenliste.")
        root = ET.fromstring(self.tr064.fetch(url))
        return [
            {
                "index": int((m.findtext("Index") or "-1").strip() or -1),
                "new": (m.findtext("New") or "").strip() == "1",
                "date": (m.findtext("Date") or "").strip(),
                "caller": (m.findtext("Number") or m.findtext("Called") or "").strip(),
                "name": (m.findtext("Name") or "").strip(),
            }
            for m in root.iter("Message")
        ]

    def _message(self, tam: int, index: int) -> dict[str, Any]:
        msg = next((m for m in self._messages(tam) if m["index"] == index), None)
        if msg is None:
            raise NotFoundError(f"Nachricht {index} auf Anrufbeantworter {tam} gibt es nicht.")
        return msg

    def mark_message(self, tam: int, index: int, read: bool) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        before = self._message(tam, index)
        base = {"tam": tam, "index": index, "date": before["date"], "read": read}
        if before["new"] is (not read):
            return {**base, "changed": False, "verified": True}
        self.tr064.call(TAM, "MarkMessage", NewIndex=tam, NewMessageIndex=index, NewMarkedAsRead=int(read))
        after = self._message(tam, index)
        return {
            **base,
            "changed": True,
            "verified": after["new"] is (not read),
            "note": "Rücklesen nimmt <New>1</New> = neu an (AVM-Doku sagt das Gegenteil, V-9) – live prüfen.",
        }

    def delete_message_plan(self, tam: int, index: int) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        msg = self._message(tam, index)
        identity = f"{tam}|{index}|{msg['date']}|{msg['caller']}"
        token = self.plans.issue("tam_delete_message", {"tam": tam, "index": index}, identity)
        who = msg["name"] or msg["caller"] or "unbekannt"
        return {
            "action": "tam_delete_message",
            "message": {"tam": tam, "index": index, "date": msg["date"], "from": who, "new": msg["new"]},
            "consequence": f"Die Sprachnachricht vom {msg['date']} ({who}) wird endgültig gelöscht.",
            "warnings": ["Löschen ist nicht rückgängig zu machen."]
            + (["Die Nachricht ist noch ungehört."] if msg["new"] else []),
            "token": token,
            "token_valid_s": int(self.plans.ttl),
        }

    def delete_message_execute(self, token: str, tam: int, index: int) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        found: dict[str, Any] = {}

        def identity() -> str:
            try:
                msg = self._message(tam, index)
                found.update(msg)
                return f"{tam}|{index}|{msg['date']}|{msg['caller']}"
            except FritzError:
                return ""

        self.plans.redeem(token, "tam_delete_message", {"tam": tam, "index": index}, identity)
        self.tr064.call(TAM, "DeleteMessage", NewIndex=tam, NewMessageIndex=index)
        still = any(m["date"] == found.get("date") and m["caller"] == found.get("caller") for m in self._messages(tam))
        return {"tam": tam, "index": index, "date": found.get("date"), "deleted": True, "verified": not still}

    # ------------------------------------------------------------ click to dial

    def dial_plan(self, number: str) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        n = validate_number(number)
        phone = None
        cfg = self.tr064.try_call(VOIP, "X_AVM-DE_DialGetConfig")
        if cfg:
            phone = cfg.get("NewX_AVM-DE_PhoneName") or None
        warnings = ["Ein echter Anruf wird aufgebaut – je nach Ziel kostenpflichtig."]
        d = digits(n)
        if d.startswith(("0900", "0137", "0180", "118")) or (n.startswith("+") and not n.startswith("+49")):
            warnings.append("Sonderrufnummer/Ausland – möglicherweise teuer.")
        if d in ("110", "112"):
            warnings.append("NOTRUF – nur im echten Notfall.")
        if not phone:
            warnings.append(
                "Wählhilfe ohne konfiguriertes Telefon (Web-UI: Telefonie > Anrufe > Wählhilfe) – der Anruf "
                "klingelt evtl. nirgends."
            )
        token = self.plans.issue("dial_number", {"number": n})
        return {
            "action": "dial_number",
            "number": n,
            "phone": phone,
            "consequence": f"Das Telefon '{phone or '?'}' klingelt; nach dem Abheben wird {n} gewählt.",
            "warnings": warnings,
            "token": token,
            "token_valid_s": int(self.plans.ttl),
        }

    def dial_execute(self, token: str, number: str) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        n = validate_number(number)
        self.plans.redeem(token, "dial_number", {"number": n})
        self.tr064.call(VOIP, "X_AVM-DE_DialNumber", **{"NewX_AVM-DE_PhoneNumber": n})
        return {
            "number": n,
            "dialing": True,
            "verified": False,
            "note": "Wählvorgang gestartet; ob das Gespräch zustande kommt, ist nicht rücklesbar. "
            "Beenden mit dial_hangup.",
        }

    def hangup(self) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        self.tr064.call(VOIP, "X_AVM-DE_DialHangup")
        return {"hung_up": True, "verified": False, "note": "Auflegen gesendet (nicht rücklesbar)."}


TamArg = Annotated[int, Field(description="Index des Anrufbeantworters aus tam_list (0–9)", ge=0, le=9)]
MsgArg = Annotated[int, Field(description="Index der Nachricht (aus der Nachrichtenliste des AB)", ge=0, le=999)]
NumberArg = Annotated[str, Field(description="Rufnummer, z. B. 0301234567 oder +49301234567")]


def register_phone_write_tools(tool: ToolDecorator, svc: Callable[[str | None], PhoneWriter]) -> None:
    @tool(Tier.WRITE, WRITE)
    def set_alarm_clock(
        index: Annotated[int, Field(description="Index aus alarm_clocks", ge=0, le=9)],
        enabled: Annotated[bool, Field(description="true = an, false = aus")],
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Weckruf an/aus (TR-064 X_VoIP:X_AVM-DE_SetAlarmClockEnable) mit Rücklesen."""
        return svc(box).set_alarm_clock(index, enabled)

    @tool(Tier.WRITE, WRITE)
    def set_call_deflection(
        deflection_id: Annotated[int, Field(description="id aus call_deflections", ge=0, le=99)],
        enabled: Annotated[bool, Field(description="true = an, false = aus")],
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Rufumleitung an/aus (TR-064 X_AVM-DE_OnTel:SetDeflectionEnable) mit Rücklesen. Warnt vor Kosten und
        Erreichbarkeit beim Einschalten."""
        return svc(box).set_deflection(deflection_id, enabled)

    @tool(Tier.WRITE, WRITE)
    def call_barring_add(
        number: NumberArg,
        name: Annotated[str | None, Field(description="Bezeichnung, z. B. 'Spam' (max. 39 Zeichen)")] = None,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Sperrt eine Rufnummer (TR-064 SetCallBarringEntry) und prüft per GetCallBarringEntryByNum, dass sie in der
        Rufsperre steht. Schon gesperrt = unverändert."""
        return svc(box).barring_add(number, name)

    @tool(Tier.WRITE, WRITE)
    def call_barring_remove(number: NumberArg, box: BoxArg = None) -> dict[str, Any]:
        """Hebt die Sperre einer Rufnummer auf (TR-064 DeleteCallBarringEntryUID) und prüft, dass sie weg ist."""
        return svc(box).barring_remove(number)

    @tool(Tier.WRITE, WRITE)
    def tam_mark_message(
        tam: TamArg,
        index: MsgArg,
        read: Annotated[bool, Field(description="true = als gehört markieren, false = als neu")] = True,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Markiert eine Anrufbeantworter-Nachricht als gehört/neu (TR-064 X_AVM-DE_TAM:MarkMessage) mit Rücklesen."""
        return svc(box).mark_message(tam, index, read)

    @tool(Tier.CRITICAL, READ)
    def tam_delete_message_plan(tam: TamArg, index: MsgArg, box: BoxArg = None) -> dict[str, Any]:
        """Plant das endgültige Löschen einer Anrufbeantworter-Nachricht: Vorschau (Datum, Anrufer) + Token (5 min)."""
        return svc(box).delete_message_plan(tam, index)

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def tam_delete_message_execute(token: TokenArg, tam: TamArg, index: MsgArg, box: BoxArg = None) -> dict[str, Any]:
        """Löscht die geplante Nachricht (TR-064 DeleteMessage) und prüft, dass sie weg ist. Nur nach Zustimmung."""
        return svc(box).delete_message_execute(token, tam, index)

    @tool(Tier.CRITICAL, READ)
    def dial_number_plan(number: NumberArg, box: BoxArg = None) -> dict[str, Any]:
        """Plant einen Anruf per Wählhilfe (Telefon klingelt, dann wird gewählt): Telefon, Kosten-/Notruf-Warnungen,
        Token (5 min)."""
        return svc(box).dial_plan(number)

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def dial_number_execute(token: TokenArg, number: NumberArg, box: BoxArg = None) -> dict[str, Any]:
        """Startet den geplanten Anruf (TR-064 X_VoIP:X_AVM-DE_DialNumber). Nicht rücklesbar. Nur nach Zustimmung."""
        return svc(box).dial_execute(token, number)

    @tool(Tier.WRITE, WRITE)
    def dial_hangup(box: BoxArg = None) -> dict[str, Any]:
        """Beendet einen per Wählhilfe gestarteten Wählvorgang (TR-064 X_AVM-DE_DialHangup)."""
        return svc(box).hangup()
