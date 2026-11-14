"""Stage 9.3 / K-13 – setup check for new users: is everything in place, which rights does the MCP user have, and which
tools will fail because a right is missing?

Checks (each fails independently, read-only):

* TR-064 reachable (``DeviceInfo:GetInfo``: model, FRITZ!OS),
* rights of the configured user: ``LANConfigSecurity:X_AVM-DE_GetCurrentUser`` (rights XML) and, as fallback,
  ``X_AVM-DE_AppSetup:GetConfig`` (``ConfigRight``, ``AppRight``, ``NasRight``, ``PhoneRight``, ``DialRight``,
  ``HomeautoRight`` = RW/RO/NO),
* anonymous login (``X_AVM-DE_GetAnonymousLogin``) and default passwords (``GetInfo.X_AVM-DE_IsDefaultPasswordActive``)
  as security hints,
* second factor (``X_AVM-DE_Auth:GetInfo``) – writes may need a confirmation at the box,
* the web interfaces: ``/api/v0`` (device list), AHA (smart home), Smart-Home REST (FRITZ!OS ≥ 8.2),
* enabled tiers.

For every missing right the tools that need it are listed (``rights.TOOL_RIGHTS``).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from defusedxml import ElementTree as ET

from .errors import AuthError, FritzError, PermissionDeniedError, UnsupportedFirmwareError
from .rights import AVM_RIGHT_PATHS, RIGHT_LABELS, affected_tools
from .security import Tier
from .util import truthy

if TYPE_CHECKING:
    from .service import FritzService

LCS = "LANConfigSecurity1"
APPSETUP_RIGHTS = {
    "ConfigRight": "settings",
    "AppRight": "app",
    "NasRight": "nas",
    "PhoneRight": "phone",
    "DialRight": "dial",
    "HomeautoRight": "smarthome",
}


def parse_rights_xml(xml: str) -> dict[str, str]:
    """``<rights><path>BoxAdmin</path><access>readwrite</access>…`` → {code: access}."""
    out: dict[str, str] = {}
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return out
    path: str | None = None
    for el in root:
        tag = el.tag.lower()
        if tag == "path":
            path = (el.text or "").strip().lower()
        elif tag == "access" and path is not None:
            code = AVM_RIGHT_PATHS.get(path)
            if code:
                out[code] = (el.text or "").strip().lower()
            path = None
    return out


def _field(r: dict[str, Any], name: str) -> Any:
    return r.get(f"New{name}", r.get(name))


class SetupChecker:
    def __init__(self, service: FritzService) -> None:
        self.svc = service

    def _rights(self) -> tuple[dict[str, str], str, str | None]:
        tr = self.svc.tr064
        r = tr.try_call(LCS, "X_AVM-DE_GetCurrentUser")
        if r:
            rights = parse_rights_xml(str(r.get("NewX_AVM-DE_CurrentUserRights") or ""))
            if rights:
                return rights, "X_AVM-DE_GetCurrentUser", str(r.get("NewX_AVM-DE_CurrentUsername") or "") or None
        cfg = tr.try_call("X_AVM-DE_AppSetup1", "GetConfig") or {}
        rights = {}
        for name, code in APPSETUP_RIGHTS.items():
            v = str(_field(cfg, name) or "").upper()
            if v:
                rights[code] = {"RW": "readwrite", "RO": "readonly", "NO": "none"}.get(v, v.lower())
        return rights, "AppSetup:GetConfig", None

    def check(self, registered: set[str] | None = None) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        hints: list[str] = []

        def add(name: str, status: str, detail: str, **extra: Any) -> None:
            checks.append({"check": name, "status": status, "detail": detail, **extra})

        def attempt(name: str, fn: Callable[[], None]) -> None:
            try:
                fn()
            except AuthError as exc:
                add(name, "fail", str(exc), hint=exc.hint)
            except PermissionDeniedError as exc:
                add(name, "fail", f"keine Berechtigung ({exc})", hint=exc.hint)
            except UnsupportedFirmwareError as exc:
                add(name, "unavailable", str(exc))
            except FritzError as exc:
                add(name, "fail", str(exc), hint=exc.hint)

        tr = self.svc.tr064

        def tr064() -> None:
            info = tr.system_info()
            add("tr064", "ok", f"{info.get('model')} mit FRITZ!OS {info.get('software_version')}")

        attempt("tr064", tr064)
        have: set[str] = set()
        rights_raw: dict[str, str] = {}

        def rights() -> None:
            raw, source, user = self._rights()
            rights_raw.update(raw)
            have.update(k for k, v in raw.items() if v in ("readwrite", "readonly"))
            if not raw:
                add("rights", "unknown", "Rechte des Benutzers nicht lesbar.")
                return
            add(
                "rights",
                "ok",
                ", ".join(f"{RIGHT_LABELS.get(k, k)}: {v}" for k, v in sorted(raw.items())),
                source=source,
                user=user,
            )

        attempt("rights", rights)

        def anonymous() -> None:
            r = tr.call(LCS, "X_AVM-DE_GetAnonymousLogin")
            if truthy(r.get("NewX_AVM-DE_AnonymousLoginEnabled")):
                add("anonymous_login", "warn", "Anmeldung ohne Benutzername ist erlaubt.")
                hints.append("System > FRITZ!Box-Benutzer > Anmeldung im Heimnetz: Anmeldung mit Benutzername wählen.")
            else:
                add("anonymous_login", "ok", "Anmeldung nur mit Benutzername.")

        attempt("anonymous_login", anonymous)

        def default_pw() -> None:
            r = tr.call(LCS, "GetInfo")
            v = r.get("NewX_AVM-DE_IsDefaultPasswordActive")
            if v is None:
                return
            if truthy(v):
                add("default_password", "warn", "Mindestens ein Benutzer hat noch das Standardkennwort.")
                hints.append("Standardkennwort (Geräteaufkleber) für alle Benutzer ändern.")
            else:
                add("default_password", "ok", "Kein Benutzer mit Standardkennwort.")

        attempt("default_password", default_pw)

        def two_factor() -> None:
            r = tr.call("X_AVM-DE_Auth1", "GetInfo")
            if truthy(r.get("NewEnabled")):
                add(
                    "two_factor",
                    "info",
                    "Zusatzbestätigung aktiv: manche Schreibvorgänge melden confirmation_required und müssen an der "
                    "Box bestätigt bzw. in der Web-UI ausgeführt werden (two_factor_status).",
                )
            else:
                add("two_factor", "info", "Zusatzbestätigung aus.")

        attempt("two_factor", two_factor)

        def api_v0() -> None:
            n = len(self.svc.landevices.list())
            add("api_v0", "ok", f"/api/v0 erreichbar ({n} Geräte).")

        attempt("api_v0", api_v0)

        def aha() -> None:
            n = len(self.svc.smarthome.list_devices())
            add("aha", "ok", f"AHA-HTTP-Interface erreichbar ({n} Smart-Home-Geräte).")

        attempt("aha", aha)

        def sh_rest() -> None:
            self.svc.smarthome_rest._get("/overview/globals")
            add("smarthome_rest", "ok", "Smart-Home-REST-API vorhanden (FRITZ!OS ≥ 8.2).")

        attempt("smarthome_rest", sh_rest)

        tiers = {t.value: self.svc.gate.enabled(t) for t in Tier}
        missing = affected_tools(have, registered) if rights_raw else {}
        if missing:
            for code, tools in missing.items():
                hints.append(
                    f"Recht „{RIGHT_LABELS.get(code, code)}“ fehlt → {len(tools)} Tool(s) funktionieren nicht: "
                    + ", ".join(tools[:12])
                    + (" …" if len(tools) > 12 else "")
                )
        if not tiers["write"]:
            hints.append(
                "Nur lesend: für Schreib-Tools FRITZ_ALLOW_WRITE=1, für kritische zusätzlich FRITZ_ALLOW_CRITICAL=1."
            )
        fails = [c for c in checks if c["status"] == "fail"]
        warns = [c for c in checks if c["status"] == "warn"]
        return {
            "ready": not fails and checks[0]["check"] == "tr064" and checks[0]["status"] == "ok",
            "summary": f"{len(fails)} Fehler, {len(warns)} Warnung(en)",
            "checks": checks,
            "tiers": tiers,
            "missing_rights": {RIGHT_LABELS.get(k, k): v for k, v in missing.items()},
            "hints": hints,
            "note": "Nur lesend. Rechte werden in der Box unter System > FRITZ!Box-Benutzer vergeben; TR-064 unter "
            "Heimnetz > Netzwerk > Netzwerkeinstellungen > „Zugriff für Anwendungen zulassen“.",
        }
