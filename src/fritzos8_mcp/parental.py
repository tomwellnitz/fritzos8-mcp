"""Stage 7.5 – Kindersicherung mit Zugangsprofilen und Tickets: service logic and MCP tool registration.

Own implementation after AVM "TR-064 Support – X_AVM-DE_HostFilter" (version 8, 2025-09-11):

* ``GetFilterProfiles`` → ``NewFilterProfileList`` (XML; the document only shows one ``<FilterProfile>``
  element: FilterProfileID, Name, FilterProfileType Standard/Guest/Unrestricted/Personal, budgets per
  weekday, Shared, TimeTable of ``<TimeValue><Time>`` minutes since Monday 0:00 + ``<Action>``
  allow/disallow) and ``GetFilterProfileByID``.
* ``GetHostEntryByIP`` → HostName, FilterProfileID, TimeUsed/TimeMax (seconds), TicketsInAdvance,
  TicketValid (minutes), IsTimeShared, WANAccess.
* ``AddHostEntryToFilterProfile`` (IPv4Address, FilterProfileID), ``AddTicketTimeToHostEntryByIP``
  (adds TicketTime, 45 min by default), ``MarkTicket`` → 6-digit TicketID (at most 12 marked),
  ``GetTicketIDStatus`` unmarked/marked/invalid, ``DiscardAllTickets``.
* Return code 880: not allowed for FRITZ!OS (the box itself) and Powerline devices; 714: no such entry
  (or no unmarked ticket left).

Unverified (no live box yet): the wrapper element of the profile list, the unit of the weekday budgets
and whether ``Action`` 1 means "allow". The output says so. Protection rules as for
``set_internet_access``: the box itself is never touched, the machine of this server only gets an
"Unrestricted" profile.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated, Any

from defusedxml import ElementTree as ET
from mcp.types import ToolAnnotations
from pydantic import Field

from .errors import FritzError, InvalidParameterError, NotFoundError
from .nasremote import ToolDecorator
from .security import Gate, PlanStore, Tier
from .util import truthy

if TYPE_CHECKING:
    from .access import Host, HostResolver
    from .tr064 import Tr064Client

HOSTFILTER = "X_AVM-DE_HostFilter1"
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
WEEKDAYS_DE = ("Mo", "Di", "Mi", "Do", "Fr", "Sa", "So")
_TICKET = re.compile(r"^\d{6}$")
_UNCLOSED_END_TAG = re.compile(r"</([A-Za-z_][\w.-]*)(?=\s*<)")

_READ = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)
_WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False)
_DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False)


def _int(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _xml_root(text: str) -> Any:
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        # The AVM document itself shows "</Action" without ">" – repair that one pattern, nothing else.
        try:
            return ET.fromstring(_UNCLOSED_END_TAG.sub(r"</\1>", text))
        except ET.ParseError:
            raise FritzError("Filterprofil-Liste der Box ist kein gültiges XML.") from None


def _time_entry(node: Any) -> dict[str, Any]:
    minutes = _int(node.findtext("Time"))
    action = (node.findtext("Action") or "").strip()
    entry: dict[str, Any] = {"minute_of_week": minutes, "action_raw": action, "allow": truthy(action)}
    if minutes is not None and 0 <= minutes < 7 * 24 * 60:
        day, rest = divmod(minutes, 24 * 60)
        entry["weekday"] = WEEKDAYS_DE[day]
        entry["time"] = f"{rest // 60:02d}:{rest % 60:02d}"
    return entry


def parse_profile(node: Any) -> dict[str, Any]:
    budgets = {day[:3].lower(): _int(node.findtext(day)) for day in WEEKDAYS}
    table = node.find("TimeTable")
    timetable = [_time_entry(tv) for tv in table.iter("TimeValue")] if table is not None else []
    shared = node.findtext("Shared")
    return {
        "id": (node.findtext("FilterProfileID") or "").strip(),
        "name": (node.findtext("Name") or "").strip(),
        "type": (node.findtext("FilterProfileType") or "").strip() or None,
        "budgets": budgets,
        "budget_shared": truthy(shared) if shared is not None else None,
        "timetable": timetable,
    }


def parse_profiles(xml_text: str) -> list[dict[str, Any]]:
    if not (xml_text or "").strip():
        return []
    root = _xml_root(xml_text)
    nodes = [root] if root.tag == "FilterProfile" else list(root.iter("FilterProfile"))
    return [parse_profile(n) for n in nodes]


class ParentalClient:
    def __init__(
        self,
        tr064: Tr064Client,
        resolver: HostResolver,
        *,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.tr064 = tr064
        self.resolver = resolver
        self._sleep = sleep

    # ------------------------------------------------------------ helpers

    def _call(self, action: str, **args: Any) -> dict[str, Any]:
        try:
            return self.tr064.call(HOSTFILTER, action, **args)
        except FritzError as exc:
            if exc.tr064_code == "880":
                raise InvalidParameterError(
                    "Für die FRITZ!Box selbst und Powerline-Geräte nicht erlaubt (TR-064 880)."
                ) from None
            if exc.tr064_code == "714" and action == "MarkTicket":
                raise NotFoundError(
                    "Keine freien Tickets: höchstens 12 können gleichzeitig ausgegeben sein (TR-064 714).",
                    hint="Ein Ticket einlösen oder alle verwerfen (parental_tickets_discard_plan/_execute).",
                ) from None
            if exc.tr064_code == "714":
                raise NotFoundError(f"{action}: Gerät/Profil der Box nicht bekannt (TR-064 714).") from None
            raise

    def _entry(self, ip: str) -> dict[str, Any]:
        r = self._call("GetHostEntryByIP", NewIPv4Address=ip)
        used, limit = _int(r.get("NewTimeUsed")), _int(r.get("NewTimeMax"))
        shared = r.get("NewIsTimeShared")
        return {
            "host_name": r.get("NewHostName"),
            "profile_id": (str(r.get("NewFilterProfileID") or "").strip() or None),
            "time_used_s": used,
            "time_max_s": limit,
            "time_left_s": max(0, limit - (used or 0)) if limit else None,
            "tickets_in_advance": _int(r.get("NewTicketsInAdvance")),
            "ticket_valid_min": _int(r.get("NewTicketValid")),
            "time_shared": truthy(shared) if shared is not None else None,
            "wan_access": r.get("NewWANAccess"),
        }

    # ------------------------------------------------------------ read

    def profiles(self) -> list[dict[str, Any]]:
        r = self._call("GetFilterProfiles")
        return parse_profiles(str(r.get("NewFilterProfileList") or ""))

    def profiles_report(self) -> dict[str, Any]:
        items = self.profiles()
        return {
            "count": len(items),
            "profiles": items,
            "units": {
                "budgets": "Wert je Wochentag wie von der Box geliefert – Einheit laut AVM-Doku nicht angegeben "
                "(unverifiziert, vermutlich Minuten; 0 = kein Budget gesetzt)",
                "timetable": "minute_of_week ab Montag 0:00; allow = Internet ab diesem Zeitpunkt erlaubt "
                "(Bedeutung von Action laut Doku 'Allow or disallow', 1 = erlauben unverifiziert)",
            },
            "source": "TR-064 X_AVM-DE_HostFilter:GetFilterProfiles (AVM-Doku 2025-09-11)",
        }

    def device(self, mac: str | None = None, ip: str | None = None) -> dict[str, Any]:
        host = self.resolver.resolve(mac, ip)
        entry = self._entry(host.ip)
        disallow = self.tr064.try_call(HOSTFILTER, "GetWANAccessByIP", NewIPv4Address=host.ip) or {}
        profile: dict[str, Any] | None = None
        profiles_error: dict[str, Any] | None = None
        try:
            profile = next((p for p in self.profiles() if p["id"] == entry["profile_id"]), None)
        except FritzError as exc:
            profiles_error = exc.to_dict()
        result: dict[str, Any] = {
            **host.as_dict(),
            **entry,
            "profile": {"id": entry["profile_id"], "name": profile["name"], "type": profile["type"]}
            if profile
            else {"id": entry["profile_id"], "name": None, "type": None},
            "blocked": truthy(disallow.get("NewDisallow")) if disallow.get("NewDisallow") is not None else None,
            "note": "blocked = manuelle Internetsperre (set_internet_access), hat Vorrang vor dem Profil. "
            "wan_access = Ergebnis aus Sperre und Profil. Zeiten in Sekunden, ticket_valid_min in Minuten.",
        }
        if profiles_error:
            result["profiles_error"] = profiles_error
        return result

    def ticket_status(self, ticket_id: str) -> dict[str, Any]:
        t = validate_ticket(ticket_id)
        r = self._call("GetTicketIDStatus", NewTicketID=t)
        return {"ticket_id": t, "status": r.get("NewTicketIDStatus")}

    # ------------------------------------------------------------ write

    def _protect(self, host: Host, profile: dict[str, Any]) -> None:
        if host.ip in self.resolver.box_ips():
            raise InvalidParameterError("Abgelehnt: Das ist die FRITZ!Box selbst.")
        if host.ip in self.resolver.server_ips() and (profile.get("type") or "").lower() != "unrestricted":
            raise InvalidParameterError(
                "Abgelehnt: Das ist das Gerät, auf dem dieser MCP-Server läuft (Aussperr-Gefahr) – nur ein "
                "Profil vom Typ 'Unrestricted' ist erlaubt.",
                hint="Dieses Gerät wird nie eingeschränkt.",
            )

    def set_profile(self, mac: str, profile_id: str, *, attempts: int = 3, wait: float = 1.0) -> dict[str, Any]:
        host = self.resolver.resolve(mac=mac)
        wanted = (profile_id or "").strip()
        profiles = self.profiles()
        profile = next((p for p in profiles if p["id"] == wanted), None)
        if profile is None:
            known = ", ".join(f"{p['id']} ({p['name']})" for p in profiles) or "–"
            raise NotFoundError(f'Profil "{wanted}" gibt es auf dieser Box nicht (vorhanden: {known}).')
        self._protect(host, profile)
        before = self._entry(host.ip)
        base = {
            **host.as_dict(),
            "profile": {"id": profile["id"], "name": profile["name"], "type": profile["type"]},
            "before_profile_id": before["profile_id"],
        }
        if before["profile_id"] == wanted:
            return {**base, "changed": False, "verified": True}
        self._call("AddHostEntryToFilterProfile", NewIPv4Address=host.ip, NewFilterProfileID=wanted)
        after: dict[str, Any] = before
        for i in range(attempts):
            after = self._entry(host.ip)
            if after["profile_id"] == wanted:
                break
            if i < attempts - 1:
                self._sleep(wait)
        verified = after["profile_id"] == wanted
        result = {**base, "read_back_profile_id": after["profile_id"], "changed": verified, "verified": verified}
        if not verified:
            result["note"] = (
                "Die Box meldet weiterhin ein anderes Profil – nicht übernommen (evtl. Zusatzbestätigung/2FA)."
            )
        else:
            result["wan_access"] = after["wan_access"]
        return result

    def ticket_create(self) -> dict[str, Any]:
        r = self._call("MarkTicket")
        ticket = str(r.get("NewTicketID") or "").strip()
        if not ticket:
            raise FritzError("MarkTicket lieferte kein Ticket.")
        status = self._call("GetTicketIDStatus", NewTicketID=ticket).get("NewTicketIDStatus")
        return {
            "ticket_id": ticket,
            "status": status,
            "verified": status == "marked",
            "note": "Das Ticket schaltet bei Eingabe auf der Sperrseite zusätzliche Online-Zeit frei (laut AVM 45 min) "
            "– nur an die gewünschte Person weitergeben. Höchstens 12 Tickets gleichzeitig.",
        }

    def add_ticket_time(self, mac: str) -> dict[str, Any]:
        host = self.resolver.resolve(mac=mac)
        if host.ip in self.resolver.box_ips():
            raise InvalidParameterError("Abgelehnt: Das ist die FRITZ!Box selbst.")
        before = self._entry(host.ip)
        self._call("AddTicketTimeToHostEntryByIP", NewIPv4Address=host.ip)
        after = self._entry(host.ip)
        keys = ("time_max_s", "tickets_in_advance", "ticket_valid_min", "time_left_s")
        changed = any(before[k] != after[k] for k in keys)
        result: dict[str, Any] = {
            **host.as_dict(),
            "before": {k: before[k] for k in keys},
            "after": {k: after[k] for k in keys},
            "changed": changed,
            "verified": changed,
        }
        if not changed:
            result["note"] = (
                "Keine Änderung an Budget/Tickets rücklesbar – das geht laut AVM nur bei Profilen mit Zeitbudget "
                "oder Zeitplan."
            )
        return result

    def discard_tickets(self) -> None:
        self._call("DiscardAllTickets")


def validate_ticket(ticket_id: str) -> str:
    t = (ticket_id or "").strip()
    if not _TICKET.match(t):
        raise InvalidParameterError("Ticket-ID muss aus genau 6 Ziffern bestehen.")
    return t


class ParentalService:
    """Tier checks + plan/execute around ``ParentalClient`` (one per box, ``service.parental``)."""

    def __init__(self, client: ParentalClient, gate: Gate, plans: PlanStore) -> None:
        self.client = client
        self.gate = gate
        self.plans = plans

    def parental_profiles(self) -> dict[str, Any]:
        return self.client.profiles_report()

    def parental_device_status(self, mac: str | None = None, ip: str | None = None) -> dict[str, Any]:
        return self.client.device(mac, ip)

    def parental_ticket_status(self, ticket_id: str) -> dict[str, Any]:
        return self.client.ticket_status(ticket_id)

    def set_parental_profile(self, mac: str, profile_id: str) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        return self.client.set_profile(mac, profile_id)

    def parental_ticket_create(self) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        return self.client.ticket_create()

    def parental_add_ticket_time(self, mac: str) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        return self.client.add_ticket_time(mac)

    def parental_tickets_discard_plan(self) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        token = self.plans.issue("parental_tickets_discard", {})
        return {
            "action": "parental_tickets_discard",
            "consequence": "ALLE ausgegebenen, noch nicht eingelösten Tickets der Kindersicherung werden ungültig "
            "(auch solche, die schon weitergegeben wurden). Danach können neue Tickets erzeugt werden. "
            "Nicht umkehrbar.",
            "token": token,
            "token_valid_s": int(self.plans.ttl),
            "execute_with": {"tool": "parental_tickets_discard_execute"},
        }

    def parental_tickets_discard_execute(self, token: str) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        self.plans.redeem(token, "parental_tickets_discard", {})
        self.client.discard_tickets()
        return {
            "action": "parental_tickets_discard",
            "accepted": True,
            "verified": False,
            "note": "Von der Box angenommen. Nicht direkt rücklesbar – eine alte Ticket-ID mit "
            "parental_ticket_status prüfen (muss 'invalid' sein).",
        }


BoxArg = Annotated[
    str | None, Field(description="Name der FRITZ!Box bei Mehrbox-Betrieb (Standard: erste Box, siehe server_status)")
]
MacArg = Annotated[str, Field(description="MAC-Adresse, z. B. AA:BB:CC:DD:EE:FF")]
OptMacArg = Annotated[str | None, Field(description="MAC-Adresse des Geräts (alternativ ip)")]
OptIpArg = Annotated[str | None, Field(description="IPv4-Adresse des Geräts (alternativ mac)")]
TokenArg = Annotated[str, Field(description="Freigabe-Token aus dem zugehörigen *_plan-Aufruf")]


def register_parental_tools(tool: ToolDecorator, svc: Callable[[str | None], ParentalService]) -> None:
    """Register the stage-7.5 tools with the tier-aware ``tool`` decorator of ``build_server``."""

    @tool(Tier.READ, _READ)
    def parental_profiles(box: BoxArg = None) -> dict[str, Any]:
        """Zugangsprofile der Kindersicherung (TR-064 X_AVM-DE_HostFilter:GetFilterProfiles): ID, Name, Typ
        (Standard/Guest/Unrestricted/Personal), Budget je Wochentag, Budget geteilt, Zeitplan (Wochentag, Uhrzeit,
        erlauben/sperren). Einheiten teils unverifiziert (siehe units)."""
        return svc(box).parental_profiles()

    @tool(Tier.READ, _READ)
    def parental_device_status(mac: OptMacArg = None, ip: OptIpArg = None, box: BoxArg = None) -> dict[str, Any]:
        """Kindersicherung eines Geräts (TR-064 GetHostEntryByIP): Zugangsprofil, genutzte/maximale Online-Zeit
        (s), Restzeit, Tickets im Voraus, Ticket-Gültigkeit, Internetzugang granted/denied, manuelle Sperre.
        Gerät per mac ODER ip."""
        return svc(box).parental_device_status(mac, ip)

    @tool(Tier.READ, _READ)
    def parental_ticket_status(
        ticket_id: Annotated[str, Field(description="6-stellige Ticket-ID")], box: BoxArg = None
    ) -> dict[str, Any]:
        """Status eines Kindersicherungs-Tickets (TR-064 GetTicketIDStatus): unmarked, marked (ausgegeben, nicht
        eingelöst) oder invalid (eingelöst/ungültig)."""
        return svc(box).parental_ticket_status(ticket_id)

    @tool(Tier.WRITE, _WRITE)
    def set_parental_profile(
        mac: MacArg,
        profile_id: Annotated[str, Field(description="Profil-ID aus parental_profiles, z. B. filtprof1")],
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Weist einem Gerät ein Zugangsprofil zu (TR-064 AddHostEntryToFilterProfile, MAC→IP aus der
        Geräteliste) und liest es zurück. Die FRITZ!Box selbst wird nie geändert, das Gerät dieses Servers nur auf
        ein Profil vom Typ 'Unrestricted'."""
        return svc(box).set_parental_profile(mac, profile_id)

    @tool(Tier.WRITE, _WRITE)
    def parental_ticket_create(box: BoxArg = None) -> dict[str, Any]:
        """Erzeugt ein Kindersicherungs-Ticket (TR-064 MarkTicket): 6-stellige ID, die auf der Sperrseite
        zusätzliche Online-Zeit freischaltet; Status wird zurückgelesen (marked). Höchstens 12 gleichzeitig."""
        return svc(box).parental_ticket_create()

    @tool(Tier.WRITE, _WRITE)
    def parental_add_ticket_time(mac: MacArg, box: BoxArg = None) -> dict[str, Any]:
        """Schenkt einem Gerät direkt Ticket-Zeit (TR-064 AddTicketTimeToHostEntryByIP, laut AVM 45 min) und
        vergleicht Budget/Tickets vorher/nachher. Nur bei Profilen mit Zeitbudget oder Zeitplan wirksam."""
        return svc(box).parental_add_ticket_time(mac)

    @tool(Tier.CRITICAL, _READ)
    def parental_tickets_discard_plan(box: BoxArg = None) -> dict[str, Any]:
        """Plant das Verwerfen ALLER Kindersicherungs-Tickets (TR-064 DiscardAllTickets): Folgen + einmaliges
        Token (5 min)."""
        return svc(box).parental_tickets_discard_plan()

    @tool(Tier.CRITICAL, _DESTRUCTIVE)
    def parental_tickets_discard_execute(token: TokenArg, box: BoxArg = None) -> dict[str, Any]:
        """Verwirft alle Kindersicherungs-Tickets laut Plan. Nur nach ausdrücklicher Zustimmung."""
        return svc(box).parental_tickets_discard_execute(token)
