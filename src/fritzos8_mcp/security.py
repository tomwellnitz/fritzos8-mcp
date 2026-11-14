"""Security tiers, plan/execute tokens and the TR-064 deny/allow lists.

`PlanStore` is adapted from Schimmilab/fritzbox-mcp-server
(src/fritzbox_mcp/write.py, MIT License, Copyright (c) 2026 Schimmilab):
one-time tokens bound to action + parameters (+ optional target identity), 5 min TTL.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .config import Config
from .errors import ActionDeniedError, PlanError, TierDisabledError


class Tier(StrEnum):
    READ = "read"
    WRITE = "write"
    CRITICAL = "critical"
    # stage 8.4: opt-in for tools that hand out a secret in a non-text form (WLAN key only inside a QR image file).
    # Independent of write/critical: FRITZ_ALLOW_SECRETS=1.
    SECRETS = "secrets"


class Gate:
    """Decides which tiers are enabled (from the environment)."""

    def __init__(self, allow_write: bool, allow_critical: bool, allow_secrets: bool = False) -> None:
        self.allow_write = allow_write
        self.allow_critical = allow_write and allow_critical
        self.allow_secrets = allow_secrets

    @classmethod
    def from_config(cls, config: Config) -> Gate:
        return cls(config.allow_write, config.allow_critical, config.allow_secrets)

    def enabled(self, tier: Tier) -> bool:
        if tier is Tier.READ:
            return True
        if tier is Tier.WRITE:
            return self.allow_write
        if tier is Tier.SECRETS:
            return self.allow_secrets
        return self.allow_critical

    def require(self, tier: Tier) -> None:
        if self.enabled(tier):
            return
        if tier is Tier.WRITE:
            raise TierDisabledError(
                "Schreibende Tools sind deaktiviert.", hint="Zum Aktivieren FRITZ_ALLOW_WRITE=1 setzen."
            )
        if tier is Tier.SECRETS:
            raise TierDisabledError(
                "Tools, die ein Geheimnis (z. B. WLAN-Schlüssel als QR-Bild) erzeugen, sind deaktiviert.",
                hint="Bewusstes Opt-in: FRITZ_ALLOW_SECRETS=1 setzen.",
            )
        raise TierDisabledError(
            "Kritische Tools sind deaktiviert.",
            hint="Zum Aktivieren FRITZ_ALLOW_WRITE=1 UND FRITZ_ALLOW_CRITICAL=1 setzen.",
        )


@dataclass
class _Plan:
    action: str
    params_key: str
    expires: float
    identity: str = ""
    payload: Any = None
    summary: str = ""  # stage 7.6: human-readable plan summary for the elicitation question


class PlanStore:
    def __init__(self, ttl: float = 300.0, now: Callable[[], float] = time.time) -> None:
        self.ttl = ttl
        self.now = now
        self._plans: dict[str, _Plan] = {}
        self._lock = threading.Lock()  # sync tools run in a thread pool

    @staticmethod
    def _key(params: dict[str, Any]) -> str:
        return json.dumps(params, sort_keys=True, ensure_ascii=False, default=str)

    def issue(self, action: str, params: dict[str, Any], identity: str = "", payload: Any = None) -> str:
        with self._lock:
            t = self.now()
            self._plans = {k: p for k, p in self._plans.items() if p.expires >= t}
            token = secrets.token_hex(8)
            self._plans[token] = _Plan(action, self._key(params), t + self.ttl, identity, payload)
            return token

    def annotate(self, token: str, summary: str) -> None:
        """Attach the plan's human-readable summary (consequence/warnings) to an issued token."""
        with self._lock:
            plan = self._plans.get(token)
            if plan is not None:
                plan.summary = summary[:2000]

    def peek(self, token: str) -> tuple[str, str] | None:
        """(action, summary) of a valid, unexpired token WITHOUT redeeming it – for the confirmation question."""
        with self._lock:
            plan = self._plans.get(token)
        if plan is None or self.now() > plan.expires:
            return None
        return plan.action, plan.summary

    def discard(self, token: str) -> None:
        with self._lock:
            self._plans.pop(token, None)

    def redeem_payload(self, token: str, action: str) -> Any:
        """Redeem a token exactly once and return the payload stored at plan time.

        For plans whose execute step takes only the token (e.g. a batch of device actions):
        the parameters are bound server-side, the caller cannot alter them. Targets are
        re-checked per item by the caller."""
        with self._lock:
            plan = self._plans.pop(token, None)
        if plan is None:
            raise PlanError("Freigabe-Token ungültig oder schon benutzt – erst neu planen.")
        if self.now() > plan.expires:
            raise PlanError("Freigabe-Token abgelaufen (5 min) – erst neu planen.")
        if plan.action != action:
            raise PlanError("Token passt nicht zu dieser Aktion – erst neu planen.")
        return plan.payload

    def redeem(
        self,
        token: str,
        action: str,
        params: dict[str, Any],
        identity: Callable[[], str] | None = None,
    ) -> None:
        """Redeem a token exactly once. `identity` is evaluated only after the token checks
        and must still match the identity recorded at plan time (target unchanged)."""
        with self._lock:
            plan = self._plans.pop(token, None)
        if plan is None:
            raise PlanError("Freigabe-Token ungültig oder schon benutzt – erst neu planen.")
        if self.now() > plan.expires:
            raise PlanError("Freigabe-Token abgelaufen (5 min) – erst neu planen.")
        if plan.action != action or plan.params_key != self._key(params):
            raise PlanError("Token passt nicht zu dieser Aktion bzw. diesen Parametern – erst neu planen.")
        if identity is not None and identity() != plan.identity:
            raise PlanError("Das Ziel hat sich seit dem Plan geändert – erst neu planen.")


# ------------------------------------------------------------------ TR-064 generic caller

# Never callable through tr064_call, regardless of tier. Only dedicated critical tools.
DENYLIST: frozenset[str] = frozenset(
    {
        # restart / reset / connection
        "Reboot",
        "FactoryReset",
        "ForceTermination",
        "RequestTermination",
        "RequestConnection",
        "X_AVM-DE_DisconnectAll",
        # configuration import/export, firmware
        "X_AVM-DE_GetConfigFile",
        "X_AVM-DE_SetConfigFile",
        "X_AVM-DE_DoUpdate",
        "X_AVM-DE_DoManualUpdate",
        "X_AVM-DE_SetUpdate",
        # session / credential material
        "X_AVM-DE_CreateUrlSID",
        "GetSecurityKeys",
        "X_AVM-DE_GetWLANHybridMode",  # returns the WLAN key (NewKeyPassphrase)
        "X_AVM-DE_GetWLANDeviceListPath",
        "GetDDNSInfo",  # AVM doc name (RemoteAccess): user name + update URL
        "X_AVM-DE_GetDDNSInfo",
        "X_AVM-DE_GetClient",
        "X_AVM-DE_GetClient2",
        "X_AVM-DE_GetClient3",
        "X_AVM-DE_GetClientByClientId",
        "X_AVM-DE_GetVoIPAccount",  # NewVoIPPassword (SIP)
        "X_AVM-DE_GetClients",  # X_VoIP: client list incl. SIP credentials
        "X_AVM-DE_GetAppRemoteInfo",
        "X_AVM-DE_GetAppVPNInfo",
        "X_AVM-DE_GetWireguardConfig",
        "X_AVM-DE_GetAppVPN",
        "X_AVM-DE_GetAppVPNwithPFS",
        "X_AVM-DE_GetBoxVPN",
        "X_AVM-DE_GetWireGuardConfig",
        "X_AVM-DE_GetVPNConfig",
        # Abgleich mit den AVM-Dokumenten (2026-11-14, docs/COVERAGE.md):
        "GetAppRemoteInfo",  # AppSetup – documented spelling of the entry above
        "X_AVM-DE_GetVoIPAccounts",  # X_VoIP: XML list with SIP user names + registrars of all accounts
        "X_AVM-DE_DoPrepareCGI",  # UserInterface: hands out a session ID for /cgi-bin/firmwarecfg
        # firmware updates of attached devices, support data upload to the manufacturer
        "DectDoUpdate",
        "DeviceDoUpdate",
        "X_AVM-DE_HostDoUpdate",
        "X_AVM-DE_SendSupportData",
        # lock-out / outage risks (blocked as non-Get anyway – listed so a future write allowlist can't open them)
        "SetPIN",  # mobile: SIM PIN – wrong tries lock the SIM
        "SetPUK",
        "X_AVM-DE_SetWLANGlobalEnable",  # switches off every WLAN
        "SetDVBCEnable",  # the box restarts
        "X_AVM-DE_SetInternationalConfig",  # country/annex → DSL link may be lost
        "X_AVM-DE_SetWANAccessType",
        "SetConnectionType",
        "SetDHCPServerEnable",
        "SetIPInterface",
        "SetSubnetMask",
        "SetIPRouter",
        "SetAddressRange",
        "X_SetTR069Enable",  # TR-069 remote management by the provider
        "SetManagementServerURL",
        "SetUpgradeManagement",
        "X_AVM_DE_SetTR069FirmwareDownloadEnabled",
        "X_AVM-DE_DialNumber",  # places a real (possibly costly) call
    }
)

# Additionally denied by name pattern (any spelling/version): VPN, WireGuard and DynDNS actions
# return keys, pre-shared secrets or account passwords.
_DENY_PATTERN = re.compile(r"(vpn|wireguard|ddns|password|passwd|secret|presharedkey|psk)", re.I)


# Stage 5 (NAS & remote access, after the AVM TR-064 documents): actions that only leak secrets in a
# specific service – the action names alone (e.g. "GetInfo") are too generic for DENYLIST.
SERVICE_DENYLIST: frozenset[tuple[str, str]] = frozenset(
    {
        ("X_AVM-DE_WebDAVClient1", "GetInfo"),  # online storage account: host URL + user name
        ("X_AVM-DE_Filelinks1", "GetGenericFilelinkEntry"),  # NewID/NewUrl = download token of a shared link
        ("X_AVM-DE_Filelinks1", "GetSpecificFilelinkEntry"),
        ("X_AVM-DE_Filelinks1", "GetFilelinkListPath"),  # XML list with every link token
        ("X_AVM-DE_AppSetup1", "GetBoxSenderId"),  # key id for encrypted app messages
        ("WANPPPConnection1", "GetUserName"),  # PPP login name = half of the internet access credentials
        ("LANEthernetInterfaceConfig1", "SetEnable"),  # switches the LAN interface off (lock-out)
    }
)
# Result fields masked per service + action in tr064_call: login names of accounts reachable from the
# internet, the MyFRITZ! account e-mail. (Password fields are masked globally by redact.SECRET_FIELD.)
SERVICE_SECRET_FIELDS: dict[tuple[str, str], frozenset[str]] = {
    ("X_AVM-DE_RemoteAccess1", "GetInfo"): frozenset({"NewUsername"}),
    ("X_AVM-DE_USPController1", "GetUSPControllerByIndex"): frozenset({"NewUsername"}),
    ("X_AVM-DE_MyFritz1", "GetInfo"): frozenset({"NewEmail"}),
    # Abgleich mit den AVM-Dokumenten (2026-11-14):
    ("WANPPPConnection1", "GetInfo"): frozenset({"NewUserName"}),  # PPP login name
    ("ManagementServer1", "GetInfo"): frozenset({"NewUsername", "NewConnectionRequestUsername"}),  # TR-069 ACS
    ("X_AVM-DE_WANMobileConnection1", "GetInfoEx"): frozenset({"NewPPPUsername", "NewPPPUsernameVoIP", "NewIMSI"}),
    ("X_AVM-DE_OnTel1", "GetInfo"): frozenset({"NewUsername"}),  # online phone book account
    ("X_AVM-DE_OnTel1", "GetInfoByIndex"): frozenset({"NewUsername"}),
}


def mask_service_fields(service: str, action: str, result: dict[str, Any]) -> dict[str, Any]:
    fields = SERVICE_SECRET_FIELDS.get((service, action), frozenset())
    return {k: ("***" if k in fields and v not in (None, "") else v) for k, v in result.items()}


def is_denied(action: str, service: str | None = None) -> bool:
    if service is not None and (service, action) in SERVICE_DENYLIST:
        return True
    return action in DENYLIST or bool(_DENY_PATTERN.search(action))


# Stage 1: no writing actions through the generic caller. Extended explicitly later.
WRITE_ALLOWLIST: frozenset[tuple[str, str]] = frozenset()

_READ_ONLY = re.compile(r"^(X_AVM-DE_|X_AVM_DE_|X_)?Get[A-Z0-9_]", re.ASCII)


def is_read_only_action(action: str) -> bool:
    return bool(_READ_ONLY.match(action))


def check_generic_action(service: str, action: str) -> None:
    """Raise ActionDeniedError unless `action` may be called via tr064_call (stage 1)."""
    if is_denied(action, service):
        raise ActionDeniedError(
            f"Action {action} ist im generischen TR-064-Caller gesperrt.",
            hint="Neustart/Reconnect nur über die kritischen Tools reboot_* / reconnect_wan_*; "
            "Konfig-Import/-Export, Firmware und Zugangsdaten-Abfragen sind nicht freigegeben.",
        )
    if is_read_only_action(action):
        return
    if (service, action) in WRITE_ALLOWLIST:  # pragma: no cover - empty in stage 1
        return
    raise ActionDeniedError(
        f"Action {action} ist nicht lesend. Der generische TR-064-Caller erlaubt in Stufe 1 nur Get*-Actions.",
        hint="Schreibende Aktionen gibt es nur über die kuratierten Tools (z. B. rename_host).",
    )
