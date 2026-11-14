"""Client for the (undocumented) FRITZ!OS 8 web REST API under /api/v0.

Header ``AUTHORIZATION: AVM-SID <sid>``; re-login once on 401/403/INVALID-SID;
TWO-FACTOR markers → ConfirmationRequiredError; 404 → UnsupportedFirmware/NotFound.
Every parsed answer passes ``redact_api`` (stage 6): /api/v0 hands out VPN keys and configurations in
plain text (e.g. ``generic/vpn``), so secrets are masked here, before any caller sees them.
Ported from the author's own TypeScript implementation (mcp-fritzbox, landevice.ts).
"""

from __future__ import annotations

import json
import logging
from typing import Any, Literal

import httpx

from .auth import SessionManager
from .errors import (
    AuthError,
    ConfirmationRequiredError,
    FritzConnectionError,
    FritzError,
    NotFoundError,
    PermissionDeniedError,
    UnsupportedFirmwareError,
)
from .guard import BoxGuard, guarded
from .health import record as record_health
from .redact import redact, redact_api

log = logging.getLogger(__name__)

Method = Literal["GET", "PUT", "POST", "DELETE"]

# Expensive /api/v0 reads kept briefly in the box guard's cache (stage 7.1); any write empties it.
CACHEABLE_GETS = frozenset({"/api/v0/generic/landevice", "/api/v0/generic/eth_ports", "/api/v0/generic/vpn"})

TWO_FACTOR_MARKERS = ("TWO-FACTOR", "TWO_FACTOR", "SECOND-FACTOR", "2FA_REQUIRED")


def looks_like_two_factor(text: str) -> bool:
    upper = text.upper()
    return any(m in upper for m in TWO_FACTOR_MARKERS)


class RestClient:
    def __init__(self, http: httpx.Client, session: SessionManager, guard: BoxGuard | None = None) -> None:
        self._http = http
        self._session = session
        self.guard = guard  # stage 7.1: throttling, cache, breaker (None = unguarded)

    def request(
        self,
        method: Method,
        path: str,
        body: Any = None,
        *,
        missing: Literal["firmware", "not_found"] = "not_found",
        cache: bool = True,
    ) -> Any:
        iface = "smarthome_rest" if path.startswith("/api/v0/smarthome") else "api_v0"

        def do() -> Any:
            try:
                result = guarded(
                    self.guard,
                    lambda: self._request(method, path, body, missing),
                    what=f"{method} {path}",
                    idempotent=method == "GET",
                )
            except FritzError as exc:
                record_health(self.guard, iface, exc)
                raise
            record_health(self.guard, iface, None)
            return result

        if self.guard is None:
            return do()
        if cache and method == "GET" and path in CACHEABLE_GETS:
            return self.guard.cached(f"rest:{path}", do)
        try:
            return do()
        finally:
            if method != "GET":
                self.guard.invalidate()  # a write (even a failed one) may have changed the box

    def _request(
        self,
        method: Method,
        path: str,
        body: Any,
        missing: Literal["firmware", "not_found"],
    ) -> Any:
        for attempt in range(2):
            sid = self._session.get_sid() if attempt == 0 else self._session.relogin()
            try:
                response = self._http.request(
                    method,
                    path,
                    headers={"AUTHORIZATION": f"AVM-SID {sid}", "Content-Type": "application/json"},
                    content=json.dumps(body) if body is not None else None,
                )
            except httpx.HTTPError as exc:
                raise FritzConnectionError(f"{method} {path}: {type(exc).__name__}") from None

            text = response.text or ""
            status = response.status_code
            ok = 200 <= status < 300
            data: Any
            try:
                data = json.loads(text) if text.strip() else {}
            except ValueError:
                data = None
            suspicious = not ok or (isinstance(data, dict) and "errors" in data)

            if suspicious and looks_like_two_factor(text):
                raise ConfirmationRequiredError(f"{method} {path}: Zusatzbestätigung verlangt.")

            invalid_sid = suspicious and "INVALID-SID" in text.upper()
            # Live (FRITZ!OS 8.25): eine abgelaufene/verdrängte Sitzung beantwortet /api/v0 mit HTTP 400 statt 401.
            if status == 400 and attempt == 0:
                log.info("%s %s: HTTP 400 – Sitzung vermutlich ungültig, neuer Login", method, path)
                continue
            if status in (401, 403) or invalid_sid:
                if attempt == 0:
                    log.info("%s %s: Sitzung abgelehnt (HTTP %s) – neuer Login", method, path, status)
                    continue
                if status == 403 and not invalid_sid:
                    raise PermissionDeniedError(f"{method} {path}: Zugriff verweigert (HTTP 403).")
                raise AuthError(f"{method} {path}: Sitzung auch nach erneutem Login abgelehnt (HTTP {status}).")

            if status == 404:
                if missing == "firmware":
                    raise UnsupportedFirmwareError(f"{method} {path}: Endpunkt nicht vorhanden (HTTP 404).")
                raise NotFoundError(f"{method} {path}: nicht gefunden (HTTP 404).")
            if not ok:
                detail = redact(" ".join(text.split())[:160]) if text.strip() else ""
                raise FritzError(f"{method} {path}: HTTP {status}" + (f" – {detail}" if detail else ""))
            if data is None:
                if method == "GET":
                    raise FritzError(f"{method} {path}: Antwort ist kein JSON.")
                return {}
            return redact_api(data)
        raise AssertionError("unreachable")  # pragma: no cover
