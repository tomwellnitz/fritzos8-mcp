"""MCP server: registers the tools per enabled security tier."""

from __future__ import annotations

import functools
import inspect
import json
import logging
import typing
from collections.abc import Callable, Mapping
from typing import Annotated, Any, Literal, TypeVar

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field, ValidationError

from . import __version__, health, multibox, prompts
from .access import local_ips_towards
from .alerts import register_alert_tools
from .anomaly import register_anomaly_tools
from .auth import SessionManager
from .config import DEFAULT_BOX, Config
from .confirm import with_confirmation, with_plan_summary
from .connectivity import register_connectivity_tools
from .devices import register_device_tools
from .errors import FritzError, InvalidParameterError
from .family import register_family_tools
from .fritzcode import register_code_tools
from .guard import BoxGuard
from .guestwifi import register_guest_tools
from .history import register_history_tools
from .ispreport import register_report_tools
from .landevice import LanDeviceClient
from .line import register_line_tools
from .nasremote import register_nas_tools
from .optimizer import register_optimizer_tools
from .parental import register_parental_tools
from .phone import register_phone_tools
from .phonewrite import register_phone_write_tools
from .redact import redact, redact_obj, redact_serials
from .rest import RestClient
from .schemas import OUTPUT_MODELS
from .security import Gate, PlanStore, Tier
from .service import FritzService
from .setupcheck import SetupChecker
from .smarthome import AhaClient
from .smarthome_config import register_smarthome_config_tools
from .smarthome_rest import register_smarthome_rest_tools
from .syswrite import register_system_write_tools
from .tr064 import Tr064Client, default_connect
from .transparency import register_transparency_tools

log = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

INSTRUCTIONS = """\
Plattform-MCP für eine AVM FRITZ!Box mit FRITZ!OS 8.
Stufen: read (immer), write (FRITZ_ALLOW_WRITE=1), critical (zusätzlich FRITZ_ALLOW_CRITICAL=1,
nur über *_plan → Token → *_execute). Kritische Aktionen nur ausführen, wenn der Mensch dem Plan
ausdrücklich zugestimmt hat. Jeder Schreibvorgang meldet 'verified'; ist es false, NICHT als
Erfolg darstellen. 'confirmation_required' heißt: Box verlangt 2FA, nichts geändert.
Geräte haben zwei Namen: TR-064-Hostname (name) und friendly_name (Anzeige der Web-UI).
WLAN-Schlüssel, Passwörter und PINs werden nie ausgegeben.
Portfreigaben öffnen Dienste ins Internet: Plan dem Menschen vollständig zeigen (consequence, warnings).
Rufnummern in Anrufliste/AB sind Daten des Eigentümers: zeigen ja, nicht weitergeben.
Mehrere Boxen: optionaler Parameter box (Namen in server_status); Tokens gelten nur für ihre Box.
Unterstützt der Client Elicitation, fragt jedes *_execute vor dem Ausführen zusätzlich den Menschen direkt
(Ja/Nein mit Plan-Zusammenfassung); 'declined' heißt: abgelehnt, nichts geändert, Token verworfen.
"""

MacArg = Annotated[str, Field(description="MAC-Adresse, z. B. AA:BB:CC:DD:EE:FF")]
UidArg = Annotated[
    str | None,
    Field(description="Nur nötig, wenn die MAC auf mehrere Einträge passt (landeviceNNNN aus list_landevices)"),
]
TokenArg = Annotated[str, Field(description="Freigabe-Token aus dem zugehörigen *_plan-Aufruf")]
AinArg = Annotated[str, Field(description='AIN des Smart-Home-Geräts, z. B. "08761 0000434"')]
BandArg = Annotated[str, Field(description="WLAN-Band: 2.4, 5 oder 6 (GHz)")]
OptMacArg = Annotated[str | None, Field(description="MAC-Adresse des Geräts (alternativ ip)")]
OptIpArg = Annotated[str | None, Field(description="IPv4-Adresse des Geräts (alternativ mac)")]
ProtocolArg = Annotated[Literal["TCP", "UDP"], Field(description="TCP oder UDP")]
ExtPortArg = Annotated[int, Field(description="Externer Port (1–65535)", ge=1, le=65535)]
IntPortArg = Annotated[int, Field(description="Interner Port am Zielgerät (1–65535)", ge=1, le=65535)]
DescArg = Annotated[str, Field(description="Bezeichnung der Freigabe (1–64 Zeichen)")]
BoxArg = Annotated[
    str | None, Field(description="Name der FRITZ!Box bei Mehrbox-Betrieb (Standard: erste Box, siehe server_status)")
]


class CleanupAction(BaseModel):
    action: Annotated[Literal["delete", "rename"], Field(description="delete = Eintrag löschen, rename = umbenennen")]
    mac: Annotated[str, Field(description="MAC-Adresse des Eintrags")]
    name: Annotated[str | None, Field(description="Neuer Name (nur bei rename)")] = None
    uid: Annotated[str | None, Field(description="Nur bei mehreren Einträgen mit derselben MAC")] = None


READ = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)
WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False)
DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False)


def _wrap[W: Callable[..., Any]](fn: W, secrets: tuple[str, ...], serials: bool = False) -> W:
    """Turn FritzErrors into structured, redacted tool errors; redact every result (serials only on request)."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            result = redact_obj(fn(*args, **kwargs), secrets)
            return redact_serials(result) if serials else result
        except FritzError as exc:
            payload = {"ok": False, "error": exc.to_dict()}
            raise ToolError(json.dumps(redact_obj(payload, secrets), ensure_ascii=False)) from None
        except ToolError:
            raise
        except Exception as exc:
            log.exception("Unerwarteter Fehler in %s", fn.__name__)
            payload = {
                "ok": False,
                "error": {"type": "internal_error", "message": redact(f"{type(exc).__name__}: {exc}", secrets)},
            }
            raise ToolError(json.dumps(payload, ensure_ascii=False)) from None

    return wrapper  # type: ignore[return-value]


def _with_output[W: Callable[..., Any]](fn: W, original: Callable[..., Any], model: type[BaseModel]) -> W:
    """Stage 7.7: publish ``model`` as outputSchema. A result that does not fit is passed on unvalidated
    (``model_construct``, fields unchanged) and logged – a schema must never cost the caller a result."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        result = fn(*args, **kwargs)
        if not isinstance(result, dict):
            return result
        try:
            return model.model_validate(result)
        except ValidationError as exc:
            log.warning(
                "%s: Ergebnis passt nicht zum Ausgabeschema (%d Abweichung(en)) – unvalidiert weitergegeben",
                original.__name__,
                exc.error_count(),
            )
            return model.model_construct(**result)

    sig = inspect.signature(original, eval_str=True)
    wrapper.__signature__ = sig.replace(return_annotation=model)  # type: ignore[attr-defined]
    wrapper.__annotations__ = {**typing.get_type_hints(original, include_extras=True), "return": model}
    return wrapper  # type: ignore[return-value]


def _guard_of(service: FritzService) -> BoxGuard | None:
    guard = getattr(getattr(service, "tr064", None), "guard", None)
    return guard if isinstance(guard, BoxGuard) else None


def _guard_status(service: FritzService) -> dict[str, Any]:
    guard = getattr(getattr(service, "tr064", None), "guard", None)
    if not isinstance(guard, BoxGuard):
        return {"enabled": False}
    return {"enabled": True, **guard.status()}


def build_server(
    service: FritzService | Mapping[str, FritzService],
    gate: Gate,
    secrets: tuple[str, ...] = (),
    *,
    redact_serial_numbers: bool = False,
) -> MCPServer:
    """`service` is one FritzService (single box, name 'default') or a mapping box name → service.
    The first entry is the default box for every tool's optional `box` parameter."""
    services: dict[str, FritzService] = dict(service) if isinstance(service, Mapping) else {DEFAULT_BOX: service}
    if not services:
        raise ValueError("Mindestens eine Box nötig.")
    box_names = list(services)
    server = MCPServer(name="fritzos8-mcp", instructions=INSTRUCTIONS, version=__version__)
    registered: dict[str, str] = {}

    def svc(box: str | None) -> FritzService:
        name = (box or "").strip().lower() or box_names[0]
        if name not in services:
            raise InvalidParameterError(f'Unbekannte Box "{box}" – konfiguriert: {", ".join(box_names)}.')
        return services[name]

    def plans_for(box: str | None) -> PlanStore:
        plans = svc(box).plans
        return plans if isinstance(plans, PlanStore) else PlanStore()

    def box_label(box: str | None) -> str:
        return (box or "").strip().lower() or box_names[0]

    def tool(tier: Tier, annotations: ToolAnnotations) -> Callable[[F], F]:
        def decorator(fn: F) -> F:
            if gate.enabled(tier):
                doc = (fn.__doc__ or "").strip()
                registered_fn: Callable[..., Any]
                if tier is Tier.CRITICAL and fn.__name__.endswith("_plan"):
                    registered_fn = _wrap(with_plan_summary(fn, plans_for), secrets, redact_serial_numbers)
                elif tier is Tier.CRITICAL and fn.__name__.endswith("_execute"):
                    # stage 7.6: ask the human via elicitation if the client supports it; token stays fallback
                    registered_fn = with_confirmation(
                        _wrap(fn, secrets, redact_serial_numbers), fn, plans_for, box_label
                    )
                else:
                    registered_fn = _wrap(fn, secrets, redact_serial_numbers)
                    if fn.__name__ in OUTPUT_MODELS:  # stage 7.7: structured output with outputSchema
                        registered_fn = _with_output(registered_fn, fn, OUTPUT_MODELS[fn.__name__])
                server.add_tool(
                    registered_fn,
                    name=fn.__name__,
                    description=f"[Stufe: {tier.value}] {doc}",
                    annotations=annotations,
                )
                registered[fn.__name__] = tier.value
            return fn

        return decorator

    # ------------------------------------------------------------ read

    @tool(Tier.READ, READ)
    def server_status(
        probe: Annotated[
            bool, Field(description="Je Schnittstelle genau EINE billige Leseanfrage an jede Box (über den Box-Schutz)")
        ] = False,
    ) -> dict[str, Any]:
        """Zeigt, welche Sicherheitsstufen aktiv und welche Tools registriert sind, den Box-Schutz je Box
        (Drosselung, Cache, Schutzschalter) und die Gesundheit je Box: health ok/degraded/down mit Begründung,
        je Schnittstelle (TR-064, /api/v0, Smart-Home-REST, AHA) letzte erfolgreiche Anfrage und letzter Fehler,
        Re-Logins und Alter der Web-Sitzung. Ohne probe keine Box-Abfrage (nur bekannter Zustand)."""
        out: dict[str, Any] = {
            "version": __version__,
            "tiers": {t.value: gate.enabled(t) for t in Tier},
            "boxes": box_names,
            "default_box": box_names[0],
            "box_protection": {name: _guard_status(s) for name, s in services.items()},
        }
        probes = {name: health.probe(s) for name, s in services.items()} if probe else {}
        out["health"] = {
            name: {**health.health(_guard_of(s)), **({"probe": probes[name]} if probe else {})}
            for name, s in services.items()
        }
        out["tools"] = dict(registered)
        return out

    @tool(Tier.READ, READ)
    def setup_check(box: BoxArg = None) -> dict[str, Any]:
        """Einrichtungs-Check (nur lesend): TR-064 erreichbar, Rechte des MCP-Benutzers, anonyme Anmeldung,
        Standardkennwort, Zusatzbestätigung (2FA), /api/v0, AHA und Smart-Home-REST erreichbar, aktive Stufen –
        und je fehlendem Recht die Tools, die deshalb nicht funktionieren. Erster Aufruf nach der Installation."""
        return SetupChecker(svc(box)).check(set(registered))

    @tool(Tier.READ, READ)
    def boxes_overview() -> dict[str, Any]:
        """Alle konfigurierten FRITZ!Boxen auf einen Blick: Modell, FRITZ!OS, Update verfügbar, Internet
        verbunden, Kurz-Sicherheitsstatus. Eine nicht erreichbare Box bricht die Übersicht nicht ab."""
        return multibox.overview(services)

    @tool(Tier.READ, READ)
    def compare_boxes(
        aspect: Annotated[
            Literal["dns", "security", "firmware", "wlan", "system", "wan"], Field(description="Was verglichen wird")
        ],
    ) -> dict[str, Any]:
        """Vergleicht einen Aspekt über alle Boxen (dns, security, firmware, wlan, system, wan): Werte je Box
        und die Felder, in denen sich die Boxen unterscheiden."""
        return multibox.compare(services, aspect)

    @tool(Tier.READ, READ)
    def system_info(box: BoxArg = None) -> dict[str, Any]:
        """Modell, FRITZ!OS-Version, Hardware-Version und Laufzeit (TR-064 DeviceInfo:GetInfo)."""
        return svc(box).system_info()

    @tool(Tier.READ, READ)
    def wan_status(box: BoxArg = None) -> dict[str, Any]:
        """Internet-Verbindung: Status, Laufzeit, Zugangsart, Leitungsrate, externe IPv4/IPv6 (TR-064)."""
        return svc(box).wan_status()

    @tool(Tier.READ, READ)
    def list_hosts(
        only_active: Annotated[bool, Field(description="Nur aktive Geräte")] = False,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Bekannte Hosts laut TR-064 (Hosts): Name, IP, MAC, aktiv, Anschlussart."""
        return svc(box).list_hosts(only_active)

    @tool(Tier.READ, READ)
    def list_landevices(
        only_active: Annotated[bool, Field(description="Nur aktive/online Geräte")] = False,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Geräteeinträge der FRITZ!OS-8-REST-API: uid, name (TR-064), friendly_name (Web-UI), mac, ip,
        static_dhcp, active, online, deleteable."""
        return svc(box).list_landevices(only_active)

    @tool(Tier.READ, READ)
    def get_lan_dns(box: BoxArg = None) -> dict[str, Any]:
        """DNS-Server, die die FRITZ!Box per DHCP an LAN-Clients verteilt (LANHostConfigManagement:GetDNSServer)."""
        return svc(box).get_lan_dns()

    @tool(Tier.READ, READ)
    def tr064_list_services(box: BoxArg = None) -> dict[str, Any]:
        """Alle TR-064-Services der Box mit den per tr064_call erlaubten lesenden Actions."""
        return svc(box).tr064_list_services()

    @tool(Tier.READ, READ)
    def tr064_describe_action(
        service_name: Annotated[str, Field(description="z. B. Hosts1 oder Hosts:1")],
        action: Annotated[str, Field(description="z. B. GetSpecificHostEntry")],
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Argumente (Richtung, Datentyp, erlaubte Werte) einer TR-064-Action aus der SCPD."""
        return svc(box).tr064_describe_action(service_name, action)

    @tool(Tier.READ, READ)
    def tr064_call(
        service_name: Annotated[str, Field(description="z. B. WLANConfiguration1")],
        action: Annotated[str, Field(description="Nur lesende Actions (Get*, X_AVM-DE_Get*)")],
        arguments: Annotated[
            dict[str, str | int | bool] | None, Field(description='Eingabe-Argumente, z. B. {"NewIndex": 0}')
        ] = None,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Generischer TR-064-Aufruf – in Stufe 1 nur lesende Actions; Neustart, Reset, Reconnect,
        Konfig-Import/-Export und Zugangsdaten-Abfragen sind gesperrt. Geheimnisse werden geschwärzt."""
        return svc(box).tr064_call(service_name, action, dict(arguments or {}))

    @tool(Tier.READ, READ)
    def wlan_status(box: BoxArg = None) -> dict[str, Any]:
        """Alle WLANs (TR-064 WLANConfiguration1..n): aktiv, SSID, Band, Kanal, Standard, Verschlüsselung,
        Anzahl verbundener Clients, Gast ja/nein. Gibt NIE WLAN-Schlüssel aus."""
        return svc(box).wlan_status()

    @tool(Tier.READ, READ)
    def guest_wifi_status(box: BoxArg = None) -> dict[str, Any]:
        """Gast-WLAN: aktiv, SSID, Verschlüsselung, Clients, Zeitbegrenzung (TR-064). Ohne Schlüssel."""
        return svc(box).guest_wifi_status()

    @tool(Tier.READ, READ)
    def wlan_settings(
        include_web_ui: Annotated[
            bool,
            Field(description="Zusätzlich Kanal-/Band-/Zeitplan-Felder aus /api/v0 wlan_light (unverifiziert)"),
        ] = False,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """WLAN-Einstellungen je Funkband (TR-064 WLANConfiguration): Kanal, Autokanal, mögliche Kanäle,
        DFS-Kanal ja/nein, Standard; WLAN global an/aus; Nachtschaltung/WLAN-Zeitplan (X_AVM-DE_GetNightControl).
        Bandsteuerung und Kanalbandbreite sind per TR-064 nicht lesbar (unknown). Keine Schlüssel."""
        return svc(box).wlan_settings(include_web_ui)

    @tool(Tier.READ, READ)
    def smarthome_list_devices(box: BoxArg = None) -> dict[str, Any]:
        """Smart-Home-Geräte und -Gruppen (AHA-HTTP getdevicelistinfos): Name, AIN, Typ, Funktionen, erreichbar,
        Schaltzustand, Temperatur, Leistung/Energie, Thermostat-Soll/Ist. Leere Liste = keine Geräte."""
        return svc(box).smarthome_list_devices()

    @tool(Tier.READ, READ)
    def smarthome_device_stats(ain: AinArg, box: BoxArg = None) -> dict[str, Any]:
        """Verlaufsstatistik eines Smart-Home-Geräts (AHA getbasicdevicestats): Temperatur, Spannung, Leistung,
        Energie, Luftfeuchte – in °C/V/W/Wh/% umgerechnet."""
        return svc(box).smarthome_device_stats(ain)

    @tool(Tier.READ, READ)
    def system_log(
        count: Annotated[int, Field(description="Anzahl Einträge (1–500), neueste zuerst", ge=1, le=500)] = 50,
        text_filter: Annotated[
            str | None, Field(description="Nur Einträge, deren Text das enthält (ohne Groß-/Kleinschreibung)")
        ] = None,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Ereignisprotokoll der FRITZ!Box (TR-064 DeviceInfo:GetDeviceLog), optional nach Text gefiltert."""
        return svc(box).system_log(count, text_filter)

    @tool(Tier.READ, READ)
    def dsl_info(box: BoxArg = None) -> dict[str, Any]:
        """DSL-Leitung (TR-064 WANDSLInterfaceConfig:GetInfo): Sync-Raten, max. Raten, SNR-Marge, Dämpfung,
        Fehlerzähler. Ohne DSL-Anschluss: available=false."""
        return svc(box).dsl_info()

    @tool(Tier.READ, READ)
    def firmware_status(box: BoxArg = None) -> dict[str, Any]:
        """Installiertes FRITZ!OS und ob ein Update verfügbar ist (TR-064 UserInterface:GetInfo)."""
        return svc(box).firmware_status()

    @tool(Tier.READ, READ)
    def security_check(box: BoxArg = None) -> dict[str, Any]:
        """Sicherheits-Check mit Score 0–100 und je Befund ok/warn/unknown + remediation (Menüpfad):
        Fernzugriff (+2FA), MyFRITZ!, Portfreigaben, UPnP, TR-064, WPS, WPA-Modus, Gast-WLAN (Verschlüsselung,
        Isolierung), Firmware (aktuell, Auto-Update), DNS over TLS, feste IPs. Nur lesend."""
        return svc(box).security_check()

    @tool(Tier.READ, READ)
    def network_doctor(
        symptom: Annotated[
            str | None, Field(description="Optional: Symptom in eigenen Worten, z. B. 'WLAN abends langsam'")
        ] = None,
        flap_check_seconds: Annotated[
            int,
            Field(
                description="0 = aus; sonst LAN-Ports/Geräte so viele Sekunden (≤60) auf Link-Flapping abtasten",
                ge=0,
                le=60,
            ),
        ] = 0,
        client_measurement: Annotated[
            dict[str, Any] | None,
            Field(description="Optional: Ergebnis von test_my_device (oder dessen for_network_doctor) einbeziehen"),
        ] = None,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Netz-Doktor (nur lesend): kombiniert WAN/DSL-Werte (SNR, Dämpfung, Fehler), Ereignisprotokoll
        (Sync-Verlust, Abbrüche, DNS-Störung, Radar, LAN-Link-Wechsel), WLAN, Mesh, Online-Monitor, LAN-Ports
        (Link-Flapping, EEE + Raspberry Pi), DNS als Single Point of Failure und optional eine test_my_device-
        Messung zu Befunden mit Schweregrad, wahrscheinlicher Ursache und Empfehlung. Schwellen = Faustregeln."""
        return svc(box).network_doctor(symptom, flap_check_seconds, client_measurement)

    @tool(Tier.READ, READ)
    def call_list(
        days: Annotated[int | None, Field(description="Nur die letzten N Tage (1–999)", ge=1, le=999)] = None,
        max_entries: Annotated[int, Field(description="Höchstens so viele Anrufe (1–1000)", ge=1, le=1000)] = 50,
        call_type: Annotated[
            Literal["all", "incoming", "outgoing", "missed", "rejected"], Field(description="Filter nach Anruftyp")
        ] = "all",
        resolve_names: Annotated[
            bool, Field(description="Fehlende Namen per Rückwärtssuche in den Telefonbüchern der Box ergänzen")
        ] = False,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Anrufliste (TR-064 X_AVM-DE_OnTel:GetCallList): Datum, Typ, Gegenstelle, Name, Gerät, Dauer.
        Neueste zuerst; Filter incoming/outgoing/missed/rejected; optional Namen aus den Telefonbüchern. Keine
        Aufnahmen."""
        return svc(box).call_list(days, max_entries, call_type, resolve_names)

    @tool(Tier.READ, READ)
    def tam_list(box: BoxArg = None) -> dict[str, Any]:
        """Anrufbeantworter (TR-064 X_AVM-DE_TAM): Name, aktiv, Anzahl Nachrichten/neue Nachrichten,
        Speicher. Keine Audio-Downloads."""
        return svc(box).tam_list()

    @tool(Tier.READ, READ)
    def phonebook_list(
        with_counts: Annotated[bool, Field(description="Zusätzlich Anzahl Kontakte je Telefonbuch")] = False,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Telefonbücher (TR-064 X_AVM-DE_OnTel): nur ID, Name und optional Anzahl Kontakte."""
        return svc(box).phonebook_list(with_counts)

    @tool(Tier.READ, READ)
    def internet_access_status(mac: OptMacArg = None, ip: OptIpArg = None, box: BoxArg = None) -> dict[str, Any]:
        """Kindersicherung: ist der Internetzugang eines Geräts gesperrt? (TR-064 X_AVM-DE_HostFilter:
        GetWANAccessByIP). Gerät per mac ODER ip."""
        return svc(box).internet_access_status(mac, ip)

    @tool(Tier.READ, READ)
    def list_port_forwards(
        include_web_ui_lists: Annotated[
            bool,
            Field(
                description="Zusätzlich /api/v0 forwardrules + ipv6firewall roh (geschwärzt, Struktur unverifiziert)"
            ),
        ] = False,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """IPv4-Portfreigaben (TR-064 WAN-Portmapping): Protokoll, externer Port, Ziel-IP/-Name, interner
        Port, aktiv, Bezeichnung. Optional die Freigabe-/IPv6-Firewall-Listen der Web-UI (roh, unverifiziert)."""
        return svc(box).list_port_forwards(include_web_ui_lists)

    @tool(Tier.READ, READ)
    def get_dns_settings(box: BoxArg = None) -> dict[str, Any]:
        """DNS-Einstellungen nur lesend: per DHCP verteilter DNS (TR-064), aktuell genutzte Upstream-DNS
        IPv4/IPv6 (TR-064), eigene DNS-Server, lokaler DNSv6-Server und DoT laut /api/v0 (unverifiziert).
        Ändern ist nicht möglich."""
        return svc(box).get_dns_settings()

    @tool(Tier.READ, READ)
    def devices_cleanup_report(
        offline_days: Annotated[
            int,
            Field(
                description="Ab so vielen Tagen offline Löschkandidat (nur wenn die Box 'zuletzt online' liefert)",
                ge=1,
                le=3650,
            ),
        ] = 90,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Aufräum-Assistent (nur lesend): Löschkandidaten (Zufalls-MACs, lange offline, ohne MAC, Namens-Duplikate
        mit Zufalls-MAC, verwaiste feste IPs; gleiche IP nur als Hinweis, Hersteller-MACs nur bei bekanntem
        'zuletzt online' ab der Grenze) und Umbenennungsvorschläge (Hersteller per MAC/IEEE-OUI, Schema Typ-Raum bzw.
        Hersteller-Modell, nur A–Z a–z 0–9 -), jeweils mit Begründung. Nie vorgeschlagen: Box, geschützte und
        aktive Geräte, VPN-Gegenstellen (IP im entfernten Netz einer VPN-Verbindung), AVM-Geräte/Mesh-Knoten
        (auch lokal administrierte AVM-MACs, keine Umbenennung); Einträge ohne MAC nur offline und ohne VPN-Bezug."""
        return svc(box).devices_cleanup_report(offline_days)

    @tool(Tier.READ, READ)
    def mesh_overview(box: BoxArg = None) -> dict[str, Any]:
        """Mesh-Übersicht (TR-064 Hosts:X_AVM-DE_GetMeshListPath): Mesh-Master, Knoten (Box, Repeater,
        Powerline), Verbindungen zwischen Knoten, je Gerät Zugangspunkt, LAN/WLAN-Band, Linkrate, Signal (dBm aus
        der Mesh-Liste bzw. Signal-% aus der WLAN-Geräteliste X_AVM-DE_GetWLANDeviceListPath)."""
        return svc(box).mesh_overview()

    @tool(Tier.READ, READ)
    def online_monitor(box: BoxArg = None) -> dict[str, Any]:
        """Aktueller Up-/Down-Durchsatz (TR-064 X_AVM-DE_GetOnlineMonitor) und übertragenes Volumen seit
        Verbindungsaufbau, mit Einheiten. Tages-/Monatsvolumen ist per TR-064 nicht lesbar."""
        return svc(box).online_monitor()

    @tool(Tier.READ, READ)
    def vpn_status(box: BoxArg = None) -> dict[str, Any]:
        """MyFRITZ!-, Fernzugriffs- und DynDNS-Status (TR-064) plus WireGuard/IPSec-Verbindungen aus
        /api/v0/generic/vpn (wie vpn_connections; ohne /api/v0 = unknown). Gibt nie Schlüssel, Passwörter oder
        VPN-Konfigurationen aus."""
        return svc(box).vpn_status()

    @tool(Tier.READ, READ)
    def snapshot_create(
        label: Annotated[str | None, Field(description="Optionale Bezeichnung, z. B. 'vor Firmware-Update'")] = None,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Konfigurations-Schnappschuss: liest Einstellungen (System/Firmware, WAN-Typ, DNS, WLAN ohne Schlüssel,
        Gastnetz, Portfreigaben, Fernzugriff/MyFRITZ!/UPnP/WPS, feste IPs, Internetsperren, Smart-Home-Liste,
        Geräteinventar) und speichert sie NUR LOKAL als JSON (0600). Ändert an der Box nichts; keine Messwerte."""
        return svc(box).snapshot_create(label)

    @tool(Tier.READ, READ)
    def snapshot_list(box: BoxArg = None) -> dict[str, Any]:
        """Lokal gespeicherte Schnappschüsse dieser Box (neueste zuerst)."""
        return svc(box).snapshot_list()

    @tool(Tier.READ, READ)
    def snapshot_diff(
        a: Annotated[str | None, Field(description="Schnappschuss-ID (Standard: letzter)")] = None,
        b: Annotated[
            str | None, Field(description="Schnappschuss-ID oder 'live' (Standard: aktueller Zustand)")
        ] = None,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Vergleicht zwei Schnappschüsse bzw. Schnappschuss und Live-Zustand: geändert/neu/entfernt je Kategorie
        plus Kurzfassung in Klartext (neue Portfreigabe, unbekanntes Gerät, DNSv6 geändert …). Messwerte und
        Zähler zählen nicht als Änderung."""
        return svc(box).snapshot_diff(a, b)

    # ------------------------------------------------------------ write

    @tool(Tier.WRITE, WRITE)
    def rename_host(
        mac: MacArg,
        name: Annotated[str, Field(description="Neuer Name (1–63 Zeichen)")],
        uid: UidArg = None,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Benennt ein Gerät um und setzt BEIDE Namen: TR-064-Hostname (X_AVM-DE_SetHostNameByMACAddress)
        und friendly_name der Web-UI (REST). Beide Schritte werden zurückgelesen und einzeln gemeldet."""
        return svc(box).rename_host(mac, name, uid)

    @tool(Tier.WRITE, WRITE)
    def set_static_ip(
        mac: MacArg,
        uid: UidArg = None,
        enabled: Annotated[bool, Field(description="true = aktuelle IPv4 fest zuweisen, false = aufheben")] = True,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """'Diesem Netzwerkgerät immer die gleiche IPv4-Adresse zuweisen': pinnt die AKTUELLE IP (REST),
        mit Rücklesen."""
        return svc(box).set_static_ip(mac, uid, enabled)

    @tool(Tier.WRITE, DESTRUCTIVE)
    def delete_host(mac: MacArg, uid: UidArg = None, box: BoxArg = None) -> dict[str, Any]:
        """Löscht einen inaktiven Geräteeintrag. Lehnt aktive/online und geschützte Einträge ab
        (Erzwingen nur über delete_host_force_plan/_execute). Prüft danach, ob er weg ist."""
        return svc(box).delete_host(mac, uid)

    @tool(Tier.WRITE, WRITE)
    def set_guest_wifi(
        enabled: Annotated[bool, Field(description="true = Gast-WLAN an, false = aus")],
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Schaltet das Gast-WLAN an/aus (TR-064 SetEnable) und liest den Zustand zurück."""
        return svc(box).set_guest_wifi(enabled)

    @tool(Tier.WRITE, WRITE)
    def set_wlan_channel(
        band: BandArg,
        channel: Annotated[
            int, Field(description="Funkkanal (z. B. 1, 6, 11, 36, 100) oder 0 = automatisch", ge=0, le=233)
        ],
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Setzt den Funkkanal eines WLAN-Bands (TR-064 WLANConfiguration:SetChannel, 0 = automatische
        Kanalwahl) und liest ihn zurück. Prüft gegen die möglichen Kanäle der Box, warnt bei DFS-Kanälen.
        Geräte in diesem Band verbinden sich kurz neu."""
        return svc(box).set_wlan_channel(band, channel)

    @tool(Tier.WRITE, WRITE)
    def smarthome_set_switch(
        ain: AinArg,
        on: Annotated[bool, Field(description="true = einschalten, false = ausschalten")],
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Schaltet eine Smart-Home-Steckdose (AHA setswitchon/off) und liest den Zustand zurück."""
        return svc(box).smarthome_set_switch(ain, on)

    @tool(Tier.WRITE, WRITE)
    def smarthome_set_thermostat(
        ain: AinArg,
        target_c: Annotated[float | None, Field(description="Solltemperatur 8–28 °C (0,5-°C-Schritte)")] = None,
        mode: Annotated[
            Literal["off", "max"] | None, Field(description="Statt target_c: 'off' = aus/Frostschutz, 'max' = an")
        ] = None,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Setzt die Solltemperatur eines Heizkörperthermostats (AHA sethkrtsoll) und liest sie zurück.
        Genau eins von target_c oder mode angeben."""
        return svc(box).smarthome_set_thermostat(ain, target_c, mode)

    @tool(Tier.WRITE, WRITE)
    def set_tam_enabled(
        index: Annotated[int, Field(description="Index des Anrufbeantworters aus tam_list (0–9)", ge=0, le=9)],
        enabled: Annotated[bool, Field(description="true = einschalten, false = ausschalten")],
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Schaltet einen Anrufbeantworter an/aus (TR-064 X_AVM-DE_TAM:SetEnable) und liest zurück."""
        return svc(box).set_tam_enabled(index, enabled)

    @tool(Tier.WRITE, WRITE)
    def set_internet_access(
        mac: MacArg,
        allowed: Annotated[bool, Field(description="false = Internet sperren, true = Sperre aufheben")],
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Sperrt/entsperrt den Internetzugang eines Geräts (TR-064 X_AVM-DE_HostFilter:
        DisallowWANAccessByIP, MAC→IP aus der Geräteliste) und liest zurück. Die FRITZ!Box selbst und das
        Gerät dieses Servers werden nie gesperrt."""
        return svc(box).set_internet_access(mac, allowed)

    @tool(Tier.WRITE, WRITE)
    def wake_on_lan(mac: MacArg, box: BoxArg = None) -> dict[str, Any]:
        """Weckt ein Gerät per Wake-on-LAN über die FRITZ!Box (TR-064 Hosts:X_AVM-DE_WakeOnLANByMACAddress).
        Das Aufwachen ist nicht rücklesbar (verified=false) – danach list_hosts prüfen."""
        return svc(box).wake_on_lan(mac)

    @tool(Tier.WRITE, READ)
    def devices_cleanup_plan(
        actions: Annotated[list[CleanupAction], Field(description="Auswahl aus devices_cleanup_report (höchstens 50)")],
        offline_days: Annotated[
            int,
            Field(
                description="Wie im Report: Geräte mit Hersteller-MAC erst ab so vielen Tagen offline löschbar",
                ge=1,
                le=3650,
            ),
        ] = 90,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Plant Aufräum-Aktionen (Löschen/Umbenennen per MAC): Vorschau, abgelehnte Aktionen mit Grund
        (Mehrfachtreffer, aktiv, geschützt, VPN-Gegenstelle, AVM-Gerät/Mesh-Knoten, Hersteller-MAC ohne bekanntes
        bzw. zu junges 'zuletzt online', neuester Eintrag einer Duplikatgruppe, Name doppelt) und einmaliges Token
        (5 min). Warnt, wenn Löschen eine feste IP oder ein Kindersicherungsprofil verliert. Ändert nichts."""
        return svc(box).devices_cleanup_plan([a.model_dump() for a in actions], offline_days)

    @tool(Tier.WRITE, DESTRUCTIVE)
    def devices_cleanup_execute(token: TokenArg, box: BoxArg = None) -> dict[str, Any]:
        """Führt den Aufräum-Plan aus (Token aus devices_cleanup_plan). Prüft jede Aktion erneut, bricht bei
        Fehlern nicht ab und meldet je Aktion ok/verified. Nur nach ausdrücklicher Zustimmung."""
        return svc(box).devices_cleanup_execute(token)

    # ------------------------------------------------------------ critical

    @tool(Tier.CRITICAL, READ)
    def add_port_forward_plan(
        protocol: ProtocolArg,
        external_port: ExtPortArg,
        internal_port: IntPortArg,
        description: DescArg,
        mac: OptMacArg = None,
        ip: OptIpArg = None,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Plant eine neue IPv4-Portfreigabe ins Internet (sicherheitskritisch): zeigt, was von außen
        erreichbar wird, Warnungen + einmaliges Token (5 min). Ziel per mac ODER ip."""
        return svc(box).add_port_forward_plan(protocol, external_port, internal_port, description, mac, ip)

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def add_port_forward_execute(
        token: TokenArg,
        protocol: ProtocolArg,
        external_port: ExtPortArg,
        internal_port: IntPortArg,
        description: DescArg,
        mac: OptMacArg = None,
        ip: OptIpArg = None,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Legt die geplante Portfreigabe an (TR-064 AddPortMapping) und liest sie zurück.
        Nur nach ausdrücklicher Zustimmung."""
        return svc(box).add_port_forward_execute(token, protocol, external_port, internal_port, description, mac, ip)

    @tool(Tier.CRITICAL, READ)
    def delete_port_forward_plan(
        protocol: ProtocolArg, external_port: ExtPortArg, box: BoxArg = None
    ) -> dict[str, Any]:
        """Plant das Löschen einer IPv4-Portfreigabe: Vorschau + einmaliges Token (5 min)."""
        return svc(box).delete_port_forward_plan(protocol, external_port)

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def delete_port_forward_execute(
        token: TokenArg,
        protocol: ProtocolArg,
        external_port: ExtPortArg,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Löscht die geplante Portfreigabe (TR-064 DeletePortMapping) und prüft, dass sie weg ist.
        Nur nach ausdrücklicher Zustimmung."""
        return svc(box).delete_port_forward_execute(token, protocol, external_port)

    @tool(Tier.CRITICAL, READ)
    def set_wlan_enabled_plan(
        band: BandArg,
        enabled: Annotated[bool, Field(description="true = einschalten, false = ausschalten")],
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Plant das Ein-/Ausschalten eines WLAN-Bands (Aussperr-Gefahr!): Vorschau + einmaliges Token (5 min)."""
        return svc(box).set_wlan_enabled_plan(band, enabled)

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def set_wlan_enabled_execute(token: TokenArg, band: BandArg, enabled: bool, box: BoxArg = None) -> dict[str, Any]:
        """Schaltet ein WLAN-Band laut Plan (Token aus set_wlan_enabled_plan) und liest zurück.
        Nur nach ausdrücklicher Zustimmung."""
        return svc(box).set_wlan_enabled_execute(token, band, enabled)

    @tool(Tier.CRITICAL, READ)
    def delete_host_force_plan(mac: MacArg, uid: UidArg = None, box: BoxArg = None) -> dict[str, Any]:
        """Plant das Löschen eines (auch aktiven) Geräteeintrags: Vorschau + einmaliges Token (5 min)."""
        return svc(box).delete_host_force_plan(mac, uid)

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def delete_host_force_execute(
        token: TokenArg,
        mac: MacArg,
        uid: Annotated[str, Field(description="uid aus dem Plan")],
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Führt einen geplanten erzwungenen Löschvorgang aus. Nur nach ausdrücklicher Zustimmung."""
        return svc(box).delete_host_force_execute(token, mac, uid)

    @tool(Tier.CRITICAL, READ)
    def reboot_plan(box: BoxArg = None) -> dict[str, Any]:
        """Plant einen Neustart der FRITZ!Box: Folgen + einmaliges Token (5 min)."""
        return svc(box).reboot_plan()

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def reboot_execute(token: TokenArg, box: BoxArg = None) -> dict[str, Any]:
        """Startet die FRITZ!Box neu (Token aus reboot_plan). Nur nach ausdrücklicher Zustimmung."""
        return svc(box).reboot_execute(token)

    @tool(Tier.CRITICAL, READ)
    def reconnect_wan_plan(box: BoxArg = None) -> dict[str, Any]:
        """Plant eine Neueinwahl (Internet trennen/neu verbinden): Folgen + einmaliges Token (5 min)."""
        return svc(box).reconnect_wan_plan()

    @tool(Tier.CRITICAL, DESTRUCTIVE)
    def reconnect_wan_execute(token: TokenArg, box: BoxArg = None) -> dict[str, Any]:
        """Trennt die Internetverbindung und prüft den Neuaufbau (Token aus reconnect_wan_plan)."""
        return svc(box).reconnect_wan_execute(token)

    # ------------------------------------------------------------ resources (read-only)

    def _resource_json(fn: Callable[[], Any]) -> str:
        try:
            data = redact_obj(fn(), secrets)
            if redact_serial_numbers:
                data = redact_serials(data)
        except FritzError as exc:
            data = {"ok": False, "error": redact_obj(exc.to_dict(), secrets)}
        return json.dumps(data, ensure_ascii=False, indent=1)

    @server.resource(
        "fritz://{box}/landevices",
        name="landevices",
        description="Geräteliste (/api/v0 landevice) einer Box, nur lesend. box = Name aus server_status.",
        mime_type="application/json",
    )
    def landevices_resource(box: str) -> str:
        return _resource_json(lambda: svc(box).list_landevices())

    @server.resource(
        "fritz://{box}/snapshot/latest",
        name="snapshot-latest",
        description="Letzter lokal gespeicherter Konfigurations-Schnappschuss einer Box (ohne Geheimnisse).",
        mime_type="application/json",
    )
    def snapshot_resource(box: str) -> str:
        def latest() -> Any:
            store = svc(box).snapshots
            snap_id = store.latest()
            if snap_id is None:
                return {"ok": False, "note": "Noch kein Schnappschuss – snapshot_create aufrufen."}
            return {"id": snap_id, **store.load(snap_id)}

        return _resource_json(latest)

    # ------------------------------------------------------------ prompts

    def _box_hint(box: str | None) -> str:
        return f' Verwende bei jedem Tool box="{box}".' if box else ""

    @server.prompt(name="netz_doktor", description="Führt durch die Fehlersuche bei Internet-/WLAN-Problemen.")
    def netz_doktor(symptom: str = "", box: str = "") -> str:
        return prompts.NETZ_DOKTOR.format(symptom=symptom or "nicht angegeben", box_hint=_box_hint(box))

    @server.prompt(name="geraete_aufraeumen", description="Räumt die Geräteliste der FRITZ!Box sicher auf.")
    def geraete_aufraeumen(box: str = "") -> str:
        return prompts.GERAETE_AUFRAEUMEN.format(box_hint=_box_hint(box))

    @server.prompt(name="sicherheits_check", description="Prüft die Sicherheit der FRITZ!Box und erklärt Maßnahmen.")
    def sicherheits_check(box: str = "") -> str:
        return prompts.SICHERHEITS_CHECK.format(box_hint=_box_hint(box))

    # ------------------------------------------------------------ stage 5: NAS & remote access

    register_nas_tools(tool, lambda box: svc(box).nasremote)

    # ------------------------------------------------------------ stage 6: LAN ports, VPN, quality

    register_connectivity_tools(tool, lambda box: svc(box).connectivity)

    # ------------------------------------------------------------ stage 7.5: parental control profiles/tickets

    register_parental_tools(tool, lambda box: svc(box).parental)

    # ------------------------------------------------------------ stage 8.11: device & update overview

    register_device_tools(tool, lambda box: svc(box).devices)

    # ------------------------------------------------------------ stage 8.1: measurement series

    register_history_tools(tool, lambda box: svc(box).history)
    register_anomaly_tools(tool, lambda box: svc(box).anomalies)  # stage 10.1

    # ------------------------------------------------------------ stage 8.9: line diagnostics

    register_line_tools(tool, lambda box: svc(box).line)

    # ------------------------------------------------------------ stage 8.2: Störungsprotokoll

    register_report_tools(tool, lambda box: svc(box).isp)

    # ------------------------------------------------------------ stage 8.3: alarms

    register_alert_tools(tool, lambda box: svc(box).alarms)

    # ------------------------------------------------------------ stage 8.12: system transparency

    register_transparency_tools(tool, lambda box: svc(box).transparency)

    # ------------------------------------------------------------ stage 8.10: telephony read

    register_phone_tools(tool, lambda box: svc(box).phone)
    register_phone_write_tools(tool, lambda box: svc(box).phone_write)  # stage 8.8

    # ------------------------------------------------------------ stage 8.7: family admin report (all boxes)

    register_family_tools(tool, lambda: services)

    # ------------------------------------------------------------ stage 8.5: Smart-Home-REST

    register_smarthome_rest_tools(tool, lambda box: svc(box).smarthome_rest)

    # ------------------------------------------------------------ stage 8.6: FRITZ as Code

    register_code_tools(tool, lambda box: svc(box).code)

    # ------------------------------------------------------------ stage 8.4: guest WLAN session, QR, WPS

    register_guest_tools(tool, lambda box: svc(box).guest)

    # ------------------------------------------------------------ stage 10.2: network optimizer

    register_optimizer_tools(tool, lambda box: svc(box).optimizer)

    # ------------------------------------------------------------ stage 10.6: critical system writes, 2FA status

    register_system_write_tools(tool, lambda box: svc(box).system_write)
    register_smarthome_config_tools(tool, lambda box: svc(box).smarthome_config)  # stage 10.6b

    return server


def create_services(configs: list[Config]) -> dict[str, FritzService]:
    return {cfg.name: create_service(cfg) for cfg in configs}


def create_service(config: Config) -> FritzService:
    http = httpx.Client(
        base_url=config.web_base_url,
        timeout=config.timeout,
        verify=not config.use_tls,  # box uses a self-signed certificate
    )
    session = SessionManager(http, config.user, config.password)
    guard = BoxGuard(config.guard)  # stage 7.1: one guard per box for TR-064, /api/v0 and AHA
    guard.health.session = session  # web login counters / session age for server_status
    rest = RestClient(http, session, guard)
    return FritzService(
        Tr064Client(default_connect(config), config.secrets, guard),
        LanDeviceClient(rest),
        Gate.from_config(config),
        PlanStore(ttl=config.plan_ttl),
        smarthome=AhaClient(http, session, guard),
        local_ips=lambda: local_ips_towards(config.host),
        box_host=config.host,
        secrets=config.secrets,
        snapshot_keep=config.snapshot_keep,
    )
