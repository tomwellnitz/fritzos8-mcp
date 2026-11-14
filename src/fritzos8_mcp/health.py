"""Light-weight health state per box and interface for ``server_status`` – no box request needed.

The MCP client only shows whether the server PROCESS is connected; a broken ``/api/v0`` session or a box that
times out is invisible there. Every client (TR-064, ``/api/v0``, Smart-Home REST, AHA) reports the outcome of
each request to the ``HealthTracker`` of its box (attached to the box guard, so one tracker per box):

* success = the box answered on that interface (also "not found"/"invalid argument"/2FA – the interface works);
* failure = connection problems/timeouts, rejected session/rights, unexpected HTTP status (``FritzError`` base).

``SessionManager`` counts web logins/re-logins and the age of the current session. ``health()`` derives
``ok | degraded | down`` from that state plus the circuit breaker of the guard. Error texts are redacted and short.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from .errors import (
    ActionDeniedError,
    ConfirmationRequiredError,
    FritzError,
    InvalidParameterError,
    NotFoundError,
    UnsupportedFirmwareError,
)
from .redact import redact

if TYPE_CHECKING:
    from .auth import SessionManager
    from .guard import BoxGuard

INTERFACES = ("tr064", "api_v0", "smarthome_rest", "aha")
MESSAGE_LIMIT = 160
SETUP_HINT = "setup_check für einen aktiven Test; server_status(probe=true) für je eine Leseanfrage pro Schnittstelle."

# Answers that prove the interface works (the box understood the request).
_ANSWERED = (
    NotFoundError,
    InvalidParameterError,
    UnsupportedFirmwareError,
    ConfirmationRequiredError,
    ActionDeniedError,
)


def _iso(ts: float | None) -> str | None:
    return None if ts is None else datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds")


def is_failure(exc: BaseException | None) -> bool:
    if exc is None or isinstance(exc, _ANSWERED):
        return False
    return isinstance(exc, FritzError)


@dataclass
class _Iface:
    last_ok: float | None = None
    last_error: dict[str, Any] | None = None
    last_error_at: float | None = None
    ok: int = 0
    errors: int = 0


@dataclass
class HealthTracker:
    clock: Callable[[], float] = time.time
    started: float = field(default_factory=time.time)
    _ifaces: dict[str, _Iface] = field(default_factory=lambda: {name: _Iface() for name in INTERFACES})
    _lock: threading.Lock = field(default_factory=threading.Lock)
    session: SessionManager | None = None

    def record(self, iface: str, exc: BaseException | None) -> None:
        if exc is not None and not isinstance(exc, FritzError):
            return  # programming errors etc. say nothing about the box
        now = self.clock()
        with self._lock:
            entry = self._ifaces.setdefault(iface, _Iface())
            if is_failure(exc):
                entry.errors += 1
                entry.last_error_at = now
                text = " ".join(str(exc).split())
                entry.last_error = {
                    "type": getattr(exc, "code", type(exc).__name__),
                    "message": redact(text)[:MESSAGE_LIMIT],
                    "at": _iso(now),
                }
            else:
                entry.ok += 1
                entry.last_ok = now

    def interfaces(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            out = {}
            for name, e in self._ifaces.items():
                if e.last_ok is None and e.last_error_at is None:
                    state = "unused"
                elif e.last_error_at is not None and (e.last_ok is None or e.last_error_at > e.last_ok):
                    state = "error"
                else:
                    state = "ok"
                out[name] = {
                    "state": state,
                    "last_success": _iso(e.last_ok),
                    "last_error": dict(e.last_error) if e.last_error else None,
                    "requests_ok": e.ok,
                    "requests_failed": e.errors,
                }
            return out


def record(guard: BoxGuard | None, iface: str, exc: BaseException | None) -> None:
    """Report one request outcome to the box's tracker (no-op without guard, e.g. in tests or library use)."""
    tracker = getattr(guard, "health", None)
    if isinstance(tracker, HealthTracker):
        tracker.record(iface, exc)


def health(guard: BoxGuard | None) -> dict[str, Any]:
    """Health block of one box from known state only (no box request)."""
    tracker = getattr(guard, "health", None)
    if guard is None or not isinstance(tracker, HealthTracker):
        return {"health": "unknown", "reason": "ohne Box-Schutz kein Zustand erfasst", "hint": SETUP_HINT}
    now = tracker.clock()
    ifaces = tracker.interfaces()
    guard_status = guard.status()
    breaker = {
        "state": guard_status["breaker"],
        "open_for_s": guard_status["breaker_open_for_s"],
        "open_until": _iso(now + guard_status["breaker_open_for_s"]) if guard_status["breaker"] == "open" else None,
        "consecutive_connection_errors": guard_status["consecutive_connection_errors"],
    }
    session: dict[str, Any] = {"tracked": False}
    if tracker.session is not None:
        session = {"tracked": True, **tracker.session.stats(now)}

    used = {k: v for k, v in ifaces.items() if v["state"] != "unused"}
    failing = sorted(k for k, v in used.items() if v["state"] == "error")
    if breaker["state"] == "open":
        state = "down"
        reason = f"Schutzschalter offen – Anfragen werden noch ca. {int(breaker['open_for_s']) + 1} s abgelehnt."
    elif used and len(failing) == len(used):
        state = "down"
        reason = "Letzte Anfrage auf allen genutzten Schnittstellen fehlgeschlagen: " + ", ".join(failing) + "."
    elif failing or breaker["state"] == "half_open":
        state = "degraded"
        parts = [f"{k}: {used[k]['last_error']['type']}" for k in failing if used[k]["last_error"]]
        if breaker["state"] == "half_open":
            parts.append("Schutzschalter halb offen (nächste Anfrage ist der Test)")
        reason = "Gestört: " + "; ".join(parts) + "."
    elif not used:
        state = "ok"
        reason = "Seit dem Start noch keine Box-Anfrage – Zustand unbekannt."
    else:
        state = "ok"
        reason = "Letzte Anfrage auf allen genutzten Schnittstellen erfolgreich."
    return {
        "health": state,
        "reason": reason,
        "hint": SETUP_HINT,
        "since_start_s": int(now - tracker.started),
        "interfaces": ifaces,
        "breaker": breaker,
        "web_session": session,
    }


def probe(service: Any) -> dict[str, Any]:
    """Exactly ONE cheap read per interface, through the normal clients (guard, health recording)."""
    from .errors import AuthError, ConfirmationRequiredError

    def run(fn: Callable[[], Any]) -> dict[str, Any]:
        try:
            fn()
        except (AuthError, ConfirmationRequiredError) as exc:
            return {"ok": False, "error": exc.to_dict()}
        except UnsupportedFirmwareError as exc:
            return {"ok": None, "note": "auf dieser Box/Firmware nicht vorhanden", "error": exc.to_dict()}
        except FritzError as exc:
            return {"ok": False, "error": exc.to_dict()}
        return {"ok": True}

    rest = getattr(getattr(service, "landevices", None), "rest", None)
    out: dict[str, Any] = {"tr064": run(lambda: service.tr064.call("DeviceInfo1", "GetInfo"))}
    if rest is not None:
        out["api_v0"] = run(lambda: rest.request("GET", "/api/v0/generic/landevice", missing="firmware", cache=False))
        out["smarthome_rest"] = run(
            lambda: rest.request("GET", "/api/v0/smarthome/overview/globals", missing="firmware", cache=False)
        )
    try:
        aha = service.smarthome
    except FritzError:
        aha = None
    if aha is not None:
        out["aha"] = run(lambda: aha.command("getswitchlist"))
    return out
