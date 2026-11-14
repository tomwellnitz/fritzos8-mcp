"""Stage 5 – NAS & remote access: service logic (tiers, plan/execute) and MCP tool registration.

Kept in its own module so the stage stays a self-contained block: ``FritzService`` holds one
``NasRemoteService`` instance (``service.nasremote``) and ``build_server`` calls
``register_nas_tools`` once.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Annotated, Any, Literal, Protocol, TypeVar

from mcp.types import ToolAnnotations
from pydantic import Field

from .errors import FritzError
from .myfritz import MyFritzClient
from .nas import DEFAULT_MIN_FREE_GB, NasClient
from .security import Gate, PlanStore, Tier
from .tr064 import Tr064Client

F = TypeVar("F", bound=Callable[..., Any])


class ToolDecorator(Protocol):
    """The tier-aware ``tool(tier, annotations)`` decorator factory of ``build_server``."""

    def __call__(self, tier: Tier, annotations: ToolAnnotations) -> Callable[[F], F]: ...


_READ = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)
_WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False)
_DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False)


class NasRemoteService:
    def __init__(
        self, tr064: Tr064Client, gate: Gate, plans: PlanStore, *, sleep: Callable[[float], None] = time.sleep
    ) -> None:
        self.gate = gate
        self.plans = plans
        self.nas = NasClient(tr064, sleep=sleep)
        self.myfritz = MyFritzClient(tr064, sleep=sleep)

    # ================================================================ read

    def nas_status(self) -> dict[str, Any]:
        return self.nas.status()

    def backup_target_check(self, share: str | None = None, min_free_gb: float = DEFAULT_MIN_FREE_GB) -> dict[str, Any]:
        return self.nas.backup_target_check(share, min_free_gb)

    def myfritz_status(self) -> dict[str, Any]:
        return self.myfritz.status()

    def security_check_items(self) -> list[dict[str, Any]]:
        """All stage-5 assessments (MyFRITZ!/remote/USP/apps + NAS internet/links) in the
        ``security_check`` item format – for stage 4 to merge into ``security_check``."""
        items: list[dict[str, Any]] = self.myfritz.status()["assessments"]
        return items + self.nas.assessments()

    # ================================================================ write

    def set_nas_protocol(self, protocol: str, enabled: bool) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        return self.nas.set_protocol(protocol, enabled)

    # ================================================================ critical

    def _ftp_wan_identity(self) -> str:
        try:
            wan = self.nas.storage_info()["ftp_internet"]
        except FritzError:
            return ""
        return f"{wan['enabled']}|{wan['ssl_only']}"

    def set_nas_internet_access_plan(self, enabled: bool, ssl_only: bool = True) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        info = self.nas.storage_info()
        wan = info["ftp_internet"]
        target = {"enabled": enabled, "ssl_only": ssl_only}
        if wan["enabled"] == enabled and (not enabled or wan["ssl_only"] == ssl_only):
            return {
                "action": "set_nas_internet_access",
                "current": wan,
                "changed": False,
                "note": "Bereits in diesem Zustand.",
            }
        warnings: list[str] = []
        if enabled:
            consequence = (
                f"Der FTP-Server der FRITZ!Box-NAS wird AUS DEM INTERNET erreichbar (IPv4 und – falls vorhanden – "
                f"IPv6, Port {wan['port'] or 'laut Box'}). Jeder FRITZ!Box-Benutzer mit NAS-Recht und "
                "'Zugang aus dem Internet' kann sich von überall anmelden; Angreifer können Passwörter durchprobieren."
            )
            if not ssl_only:
                warnings.append(
                    "ssl_only=false: Anmeldungen und Dateien dürfen UNVERSCHLÜSSELT übertragen werden "
                    "(Passwörter im Klartext). Dringend ssl_only=true verwenden."
                )
            if not info["ftp"]["enabled"]:
                warnings.append(
                    "Der FTP-Server im Heimnetz ist aus – ohne ihn bleibt Internet-FTP wirkungslos "
                    "(erst set_nas_protocol(protocol='ftp', enabled=true))."
                )
            warnings.append("Nur Benutzer mit starkem Passwort (und möglichst ohne Konfigurationsrecht) freigeben.")
        else:
            consequence = (
                "FTP aus dem Internet wird abgeschaltet: Zugriffe von außen auf die NAS per FTP/FTPS enden sofort; "
                "im Heimnetz bleibt alles wie es ist."
            )
        token = self.plans.issue("set_nas_internet_access", target, self._ftp_wan_identity())
        return {
            "action": "set_nas_internet_access",
            "current": wan,
            "target": target,
            "consequence": consequence,
            "warnings": warnings,
            "token": token,
            "token_valid_s": int(self.plans.ttl),
            "execute_with": {"tool": "set_nas_internet_access_execute", **target},
        }

    def set_nas_internet_access_execute(self, token: str, enabled: bool, ssl_only: bool = True) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        self.plans.redeem(
            token, "set_nas_internet_access", {"enabled": enabled, "ssl_only": ssl_only}, self._ftp_wan_identity
        )
        return self.nas.set_internet(enabled, ssl_only)

    def _remote_identity(self) -> str:
        try:
            return str(self.myfritz.remote_enabled())
        except FritzError:
            return ""

    def set_remote_access_plan(self, enabled: bool) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        current = self.myfritz.remote_access()
        if current["enabled"] == enabled:
            return {"action": "set_remote_access", "current": current, "changed": False, "note": "Bereits so."}
        warnings: list[str] = []
        if enabled:
            consequence = (
                "Die Benutzeroberfläche der FRITZ!Box wird AUS DEM INTERNET per HTTPS erreichbar (ebenso TR-064 "
                "unter /tr064). Wer Benutzername und Passwort eines Benutzers mit Internet-Zugang kennt, kann die "
                "Box von überall konfigurieren. War der Fernzugriff aus, vergibt die Box einen zufälligen HTTPS-Port."
            )
            if not current["internet_user_configured"]:
                warnings.append(
                    "Es ist kein Benutzer für den Zugang aus dem Internet eingerichtet – die Box meldet dann Port 0 "
                    "und der Fernzugriff bleibt unbenutzbar (Passwörter setzt dieser Server bewusst nicht)."
                )
            warnings.append("Nur mit Zusatzbestätigung (2FA) und starken Passwörtern betreiben.")
        else:
            consequence = (
                "Der Internetzugriff auf die FRITZ!Box (HTTPS-Fernzugriff) wird abgeschaltet: Zugriffe von außen "
                "über Browser oder MyFRITZ!App auf die Box-Oberfläche enden sofort."
            )
            if self.myfritz.access_from_internet():
                warnings.append(
                    "ACHTUNG: Dieser Server spricht gerade selbst ÜBER DAS INTERNET mit der Box – nach dem "
                    "Abschalten ist er ausgesperrt; Wiedereinschalten nur noch aus dem Heimnetz."
                )
        token = self.plans.issue("set_remote_access", {"enabled": enabled}, self._remote_identity())
        return {
            "action": "set_remote_access",
            "current": current,
            "target": {"enabled": enabled},
            "consequence": consequence,
            "warnings": warnings,
            "token": token,
            "token_valid_s": int(self.plans.ttl),
            "execute_with": {"tool": "set_remote_access_execute", "enabled": enabled},
        }

    def set_remote_access_execute(self, token: str, enabled: bool) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        self.plans.redeem(token, "set_remote_access", {"enabled": enabled}, self._remote_identity)
        return self.myfritz.set_remote(enabled)


TokenArg = Annotated[str, Field(description="Freigabe-Token aus dem zugehörigen *_plan-Aufruf")]
EnabledArg = Annotated[bool, Field(description="true = einschalten, false = ausschalten")]
BoxArg = Annotated[
    str | None, Field(description="Name der FRITZ!Box bei Mehrbox-Betrieb (Standard: erste Box, siehe server_status)")
]
SslOnlyArg = Annotated[bool, Field(description="true = nur verschlüsselte Verbindungen (FTPS) zulassen – empfohlen")]


def register_nas_tools(tool: ToolDecorator, svc: Callable[[str | None], NasRemoteService]) -> None:
    """Register the stage-5 tools with the tier-aware ``tool`` decorator of ``build_server``.

    ``svc(box)`` resolves the optional ``box`` parameter (multi-box mode) to that box's service."""

    @tool(Tier.READ, _READ)
    def nas_status(box: BoxArg = None) -> dict[str, Any]:
        """NAS der FRITZ!Box (TR-064 X_AVM-DE_Storage/Filelinks/WebDAVClient/Media): SMB, FTP, FTP aus dem
        Internet, Online-Speicher, geteilte Links (Name/Pfad/Ablauf/Downloads, ohne Link-Token), Mediaserver,
        DVB-C. Speicherplatz ist per TR-064 nicht lesbar (unknown). Keine Zugangsdaten, kein Dateizugriff."""
        return svc(box).nas_status()

    @tool(Tier.READ, _READ)
    def backup_target_check(
        share: Annotated[str | None, Field(description="Optional: Name der SMB-Freigabe (nur Hinweis)")] = None,
        min_free_gb: Annotated[
            float, Field(description="Mindestens so viel freier Platz in GB", ge=0, le=100000)
        ] = DEFAULT_MIN_FREE_GB,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Bewertet die FRITZ!Box-NAS als Backup-Ziel: SMB aktiv, NAS-Dienst erreichbar, Internet-FTP aus,
        freier Platz (per TR-064 nicht lesbar → unknown) → overall ok/warn/fail mit Empfehlungen."""
        return svc(box).backup_target_check(share, min_free_gb)

    @tool(Tier.READ, _READ)
    def myfritz_status(box: BoxArg = None) -> dict[str, Any]:
        """MyFRITZ!-Konto (aktiv/registriert/Adresse), über MyFRITZ! freigegebene Dienste, DynDNS (Anbieter,
        Domain, Status), Fernzugriff (aktiv, Port, HTTPS, Let's Encrypt), Cloud-Fernverwaltung (USP), Rechte des
        MCP-Benutzers – plus Bewertungen ok/warn/unknown. Nie Passwörter, Benutzernamen oder E-Mail."""
        return svc(box).myfritz_status()

    @tool(Tier.WRITE, _WRITE)
    def set_nas_protocol(
        protocol: Annotated[Literal["smb", "ftp"], Field(description="smb (Heimnetzfreigabe) oder ftp")],
        enabled: EnabledArg,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Schaltet SMB oder FTP der NAS im Heimnetz an/aus (TR-064 X_AVM-DE_Storage:SetSMBServer/SetFTPServer)
        und liest zurück. Ändert nichts am Zugriff aus dem Internet."""
        return svc(box).set_nas_protocol(protocol, enabled)

    @tool(Tier.CRITICAL, _READ)
    def set_nas_internet_access_plan(
        enabled: EnabledArg, ssl_only: SslOnlyArg = True, box: BoxArg = None
    ) -> dict[str, Any]:
        """Plant FTP-Zugriff auf die NAS AUS DEM INTERNET an/aus (sicherheitskritisch): zeigt Konsequenz
        (Erreichbarkeit von außen), Warnungen und ein einmaliges Token (5 min). Ändert nichts."""
        return svc(box).set_nas_internet_access_plan(enabled, ssl_only)

    @tool(Tier.CRITICAL, _DESTRUCTIVE)
    def set_nas_internet_access_execute(
        token: TokenArg,
        enabled: EnabledArg,
        ssl_only: SslOnlyArg = True,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Schaltet FTP aus dem Internet laut Plan (TR-064 X_AVM-DE_Storage:SetFTPServerWAN) und liest zurück.
        Nur nach ausdrücklicher Zustimmung."""
        return svc(box).set_nas_internet_access_execute(token, enabled, ssl_only)

    @tool(Tier.CRITICAL, _READ)
    def set_remote_access_plan(enabled: EnabledArg, box: BoxArg = None) -> dict[str, Any]:
        """Plant den HTTPS-Fernzugriff auf die FRITZ!Box-Oberfläche an/aus (sicherheitskritisch): Konsequenz
        (Box aus dem Internet konfigurierbar bzw. Aussperr-Gefahr), Warnungen, einmaliges Token (5 min)."""
        return svc(box).set_remote_access_plan(enabled)

    @tool(Tier.CRITICAL, _DESTRUCTIVE)
    def set_remote_access_execute(token: TokenArg, enabled: EnabledArg, box: BoxArg = None) -> dict[str, Any]:
        """Schaltet den Fernzugriff laut Plan (TR-064 X_AVM-DE_RemoteAccess:SetEnable, ohne Passwort) und liest
        zurück. Nur nach ausdrücklicher Zustimmung."""
        return svc(box).set_remote_access_execute(token, enabled)
