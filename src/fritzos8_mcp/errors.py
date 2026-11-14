"""Exception hierarchy. Messages are German, never contain secrets."""

from __future__ import annotations

from typing import Any


class FritzError(Exception):
    """Base class for all expected errors of this server."""

    code = "fritz_error"
    hint: str | None = None
    # UPnP/TR-064 errorCode of the underlying SOAP fault (e.g. "718"), if any. Internal only.
    tr064_code: str | None = None

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        if hint is not None:
            self.hint = hint

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"type": self.code, "message": str(self)}
        if self.hint:
            data["hint"] = self.hint
        return data


class ConfigError(FritzError):
    code = "config_error"


class FritzConnectionError(FritzError):
    """Box not reachable / transport failure."""

    code = "connection_error"


class AuthError(FritzError):
    """Login failed or session rejected even after re-login."""

    code = "auth_error"
    hint = "Benutzer/Passwort prüfen (FRITZ_USER, FRITZ_PASSWORD bzw. FRITZ_PASSWORD_FILE)."


class PermissionDeniedError(FritzError):
    """Logged in, but the account lacks the required right."""

    code = "permission_denied"
    hint = (
        "Der FRITZ!Box-Benutzer braucht das Recht 'FRITZ!Box Einstellungen' "
        "(System > FRITZ!Box-Benutzer); für TR-064 muss 'Zugriff für Anwendungen zulassen' aktiv sein."
    )


class ConfirmationRequiredError(FritzError):
    """The box demands a second factor (Zusatzbestätigung / 2FA). Nothing was changed."""

    code = "confirmation_required"
    hint = (
        "Die FRITZ!Box verlangt eine Zusatzbestätigung (2FA). Es wurde NICHTS geändert. "
        "Änderung an der Box (Taste) bzw. in der FRITZ!App bestätigen oder in der Web-Oberfläche ausführen; "
        "two_factor_status zeigt den Zustand der Zusatzbestätigung."
    )


class NotFoundError(FritzError):
    code = "not_found"


class UnsupportedFirmwareError(FritzError):
    """/api/v0 endpoint missing (404) — FRITZ!OS older than 8 or endpoint renamed."""

    code = "unsupported_firmware"
    hint = "Diese Funktion nutzt die FRITZ!OS-8-REST-API (/api/v0) und braucht FRITZ!OS 8.x."


class InvalidParameterError(FritzError):
    code = "invalid_parameter"


class TierDisabledError(FritzError):
    """Tool belongs to a security tier that is not enabled."""

    code = "tier_disabled"


class ActionDeniedError(FritzError):
    """Action is on the denylist of the generic TR-064 caller."""

    code = "action_denied"


class PlanError(FritzError):
    """Plan/execute token invalid, expired, reused or bound to other parameters."""

    code = "plan_error"


class VerificationError(FritzError):
    """The box accepted a write, but reading back shows a different value."""

    code = "verification_failed"


class DeclinedError(FritzError):
    """The human declined/cancelled the confirmation question (MCP elicitation). Nothing was changed."""

    code = "declined"
    hint = "Im Client abgelehnt – es wurde NICHTS geändert, das Token ist verworfen. Bei Bedarf neu planen."
