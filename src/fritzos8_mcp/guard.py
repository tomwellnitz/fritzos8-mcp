"""Box protection (stage 7.1): throttling, short-lived read cache, backoff and circuit breaker per box.

Live observed: an overloaded FRITZ!Box 7583 let TR-064 run into timeouts; the clean-up assistant,
snapshots and the network doctor fire many requests in a row. Every box gets one ``BoxGuard`` that
sits below the TR-064, ``/api/v0`` and AHA clients:

* **Throttling** – at most ``max_parallel`` requests at the same time and a token bucket
  (``rate_per_s`` with ``burst``) for the start of every request.
* **Cache** – a few expensive reads (host list, landevice, mesh JSON, eth_ports, vpn) are kept for
  ``cache_ttl`` seconds. Every write – successful or not – empties the whole cache of that box,
  so read-backs always see the box, never the cache.
* **Backoff** – only *reads* are retried after a connection error/timeout (exponential:
  ``backoff_base * 2**n``, capped). Writes are never repeated: a timed-out write may have been
  applied.
* **Circuit breaker** – after ``breaker_threshold`` connection errors in a row the box is left alone
  for ``breaker_cooldown`` seconds: every request fails at once with ``connection_error``
  "Box überlastet/nicht erreichbar". After the cooldown one trial request is let through
  (half-open); success closes the breaker, another failure opens it again.

Only ``FritzConnectionError`` counts as failure – auth, permission, 2FA or "not found" answers prove
the box is alive. The clock is injectable so tests run without real waiting.
"""

from __future__ import annotations

import copy
import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from .errors import FritzConnectionError
from .health import HealthTracker

log = logging.getLogger(__name__)


class Clock(Protocol):
    def monotonic(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...


class SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)


@dataclass(frozen=True)
class GuardSettings:
    max_parallel: int = 2
    rate_per_s: float = 8.0
    burst: int = 4
    cache_ttl: float = 15.0
    retries: int = 1
    backoff_base: float = 1.0
    backoff_max: float = 8.0
    breaker_threshold: int = 3
    breaker_cooldown: float = 30.0
    slot_timeout: float = 120.0  # max. wait for a free parallel slot (real seconds)


BREAKER_HINT = (
    "Schutz der FRITZ!Box: nach mehreren Zeitüberschreitungen in Folge werden Anfragen kurz ausgesetzt. "
    "Etwas warten und erneut versuchen; prüfen, ob die Box erreichbar ist (Web-Oberfläche) und ob gerade "
    "viele Anfragen laufen (Aufräum-Assistent, Schnappschuss, Netz-Doktor)."
)


class BoxGuard:
    def __init__(self, settings: GuardSettings | None = None, clock: Clock | None = None) -> None:
        self.settings = settings or GuardSettings()
        self.clock: Clock = clock or SystemClock()
        self._slots = threading.BoundedSemaphore(max(1, self.settings.max_parallel))
        self._lock = threading.Lock()
        # token bucket
        self._tokens = float(max(1, self.settings.burst))
        self._refilled = self.clock.monotonic()
        # circuit breaker
        self._failures = 0
        self._open_until: float | None = None
        self._trial_running = False
        # cache
        self._cache: dict[str, tuple[float, Any]] = {}
        # per-interface health of this box for server_status (filled by the clients, no own requests)
        self.health = HealthTracker()
        self.stats = {
            "requests": 0,
            "retries": 0,
            "connection_errors": 0,
            "rejected_by_breaker": 0,
            "throttle_wait_s": 0.0,
            "cache_hits": 0,
            "cache_misses": 0,
            "cache_invalidations": 0,
        }

    # ------------------------------------------------------------------ throttling

    def _take_token(self) -> float:
        """Reserve one start token; returns how long the caller has to wait for it."""
        rate = self.settings.rate_per_s
        if rate <= 0:
            return 0.0
        with self._lock:
            now = self.clock.monotonic()
            capacity = float(max(1, self.settings.burst))
            self._tokens = min(capacity, self._tokens + (now - self._refilled) * rate)
            self._refilled = now
            self._tokens -= 1.0
            return 0.0 if self._tokens >= 0 else -self._tokens / rate

    # ------------------------------------------------------------------ circuit breaker

    def _breaker_check(self, what: str) -> bool:
        """Raise while the breaker is open. Returns True if this call is the half-open trial."""
        with self._lock:
            if self._open_until is None:
                return False
            now = self.clock.monotonic()
            if now < self._open_until or self._trial_running:
                self.stats["rejected_by_breaker"] += 1
                wait = max(0.0, self._open_until - now)
                raise FritzConnectionError(
                    f"{what}: FRITZ!Box überlastet/nicht erreichbar – nach {self._failures} Verbindungsfehlern in "
                    f"Folge werden Anfragen noch ca. {int(wait) + 1} s sofort abgelehnt.",
                    hint=BREAKER_HINT,
                )
            self._trial_running = True
            return True

    def _record(self, ok: bool, trial: bool) -> None:
        with self._lock:
            if trial:
                self._trial_running = False
            if ok:
                if self._open_until is not None:
                    log.info("FRITZ!Box antwortet wieder – Schutzschalter geschlossen")
                self._failures = 0
                self._open_until = None
                return
            self._failures += 1
            self.stats["connection_errors"] += 1
            if self._failures >= self.settings.breaker_threshold:
                self._open_until = self.clock.monotonic() + self.settings.breaker_cooldown
                log.warning(
                    "FRITZ!Box: %d Verbindungsfehler in Folge – Anfragen für %.0f s ausgesetzt",
                    self._failures,
                    self.settings.breaker_cooldown,
                )

    @property
    def breaker_open(self) -> bool:
        with self._lock:
            return self._open_until is not None and self.clock.monotonic() < self._open_until

    # ------------------------------------------------------------------ main entry

    def call[R](self, fn: Callable[[], R], *, what: str, idempotent: bool) -> R:
        """Run one box request under throttling/breaker. Reads (``idempotent``) are retried with backoff."""
        attempt = 0
        while True:
            trial = self._breaker_check(what)
            if not self._slots.acquire(timeout=self.settings.slot_timeout):
                if trial:
                    with self._lock:
                        self._trial_running = False
                raise FritzConnectionError(
                    f"{what}: zu viele gleichzeitige Anfragen an die FRITZ!Box – abgebrochen.", hint=BREAKER_HINT
                )
            try:
                wait = self._take_token()
                if wait > 0:
                    self.stats["throttle_wait_s"] = round(float(self.stats["throttle_wait_s"]) + wait, 3)
                    self.clock.sleep(wait)
                self.stats["requests"] += 1
                try:
                    result = fn()
                except FritzConnectionError as exc:
                    self._record(False, trial)
                    error = exc
                except BaseException:
                    # Any other answer (auth, 2FA, not found …) proves the box is alive.
                    self._record(True, trial)
                    raise
                else:
                    self._record(True, trial)
                    return result
            finally:
                self._slots.release()
            if self.breaker_open and not error.hint:
                error.hint = BREAKER_HINT
            if not idempotent or attempt >= self.settings.retries or self.breaker_open:
                raise error
            delay = min(self.settings.backoff_max, self.settings.backoff_base * (2**attempt))
            attempt += 1
            self.stats["retries"] += 1
            log.info("%s: Verbindungsfehler – neuer Versuch %d in %.1f s", what, attempt, delay)
            self.clock.sleep(delay)

    # ------------------------------------------------------------------ cache

    def cached[R](self, key: str, loader: Callable[[], R]) -> R:
        """Return a copy of a fresh cached value or load (and cache a copy of) it."""
        ttl = self.settings.cache_ttl
        if ttl <= 0:
            return loader()
        now = self.clock.monotonic()
        with self._lock:
            hit = self._cache.get(key)
            if hit is not None and now - hit[0] < ttl:
                self.stats["cache_hits"] += 1
                return copy.deepcopy(hit[1])  # type: ignore[no-any-return]
            self.stats["cache_misses"] += 1
            generation = self.stats["cache_invalidations"]
        value = loader()
        with self._lock:
            # A write during the load may have changed the box – then do not keep the (maybe stale) value.
            if self.stats["cache_invalidations"] == generation:
                self._cache[key] = (self.clock.monotonic(), copy.deepcopy(value))
        return value

    def invalidate(self) -> None:
        with self._lock:
            self._cache.clear()
            self.stats["cache_invalidations"] += 1

    # ------------------------------------------------------------------ status

    def status(self) -> dict[str, Any]:
        s = self.settings
        with self._lock:
            now = self.clock.monotonic()
            open_for = max(0.0, self._open_until - now) if self._open_until is not None else 0.0
            state = "open" if open_for > 0 else ("half_open" if self._open_until is not None else "closed")
            return {
                "breaker": state,
                "breaker_open_for_s": round(open_for, 1),
                "consecutive_connection_errors": self._failures,
                "cached_entries": len(self._cache),
                "settings": {
                    "max_parallel": s.max_parallel,
                    "rate_per_s": s.rate_per_s,
                    "burst": s.burst,
                    "cache_ttl_s": s.cache_ttl,
                    "retries": s.retries,
                    "breaker_threshold": s.breaker_threshold,
                    "breaker_cooldown_s": s.breaker_cooldown,
                },
                "stats": dict(self.stats),
            }


def guarded[R](guard: BoxGuard | None, fn: Callable[[], R], *, what: str, idempotent: bool) -> R:
    """``guard.call`` if a guard is configured, else just ``fn()`` (tests, library use)."""
    return fn() if guard is None else guard.call(fn, what=what, idempotent=idempotent)
