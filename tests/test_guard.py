"""Stage 7.1 – box protection: throttling, cache, backoff, circuit breaker. Fake clock, no real waiting."""

from __future__ import annotations

import threading
import time
from typing import Any

import httpx
import pytest
from fritzconnection.core.exceptions import FritzConnectionException

from fritzos8_mcp.auth import SessionManager
from fritzos8_mcp.config import load
from fritzos8_mcp.errors import ConfigError, FritzConnectionError, NotFoundError
from fritzos8_mcp.guard import BoxGuard, GuardSettings
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.rest import RestClient
from fritzos8_mcp.security import Gate, PlanStore
from fritzos8_mcp.service import FritzService
from fritzos8_mcp.tr064 import Tr064Client

from .conftest import PASSWORD, FakeBox, FakeFC


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(round(seconds, 3))
        self.now += seconds


def guard(clock: FakeClock, **kw: Any) -> BoxGuard:
    base: dict[str, Any] = {"rate_per_s": 0, "retries": 0, "breaker_threshold": 3, "breaker_cooldown": 30}
    base.update(kw)
    return BoxGuard(GuardSettings(**base), clock)


def timeout() -> None:
    raise FritzConnectionError("X:Y: FRITZ!Box antwortet nicht (Read timed out).")


# ------------------------------------------------------------------ throttling


def test_token_bucket_spaces_requests_after_burst() -> None:
    clock = FakeClock()
    g = guard(clock, rate_per_s=2, burst=2)
    for _ in range(4):
        g.call(lambda: 1, what="x", idempotent=True)
    # burst of 2 free, then one token every 0.5 s
    assert clock.slept == [0.5, 0.5]
    assert g.status()["stats"]["throttle_wait_s"] == 1.0


def test_parallel_requests_are_limited() -> None:
    g = BoxGuard(GuardSettings(max_parallel=2, rate_per_s=0))
    running = 0
    peak = 0
    lock = threading.Lock()

    def work() -> int:
        nonlocal running, peak
        with lock:
            running += 1
            peak = max(peak, running)
        time.sleep(0.01)
        with lock:
            running -= 1
        return 1

    threads = [threading.Thread(target=lambda: g.call(work, what="x", idempotent=True)) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert peak <= 2
    assert g.status()["stats"]["requests"] == 12


# ------------------------------------------------------------------ backoff


def test_reads_are_retried_with_exponential_backoff() -> None:
    clock = FakeClock()
    g = guard(clock, retries=2, backoff_base=1, breaker_threshold=10)
    attempts = []

    def flaky() -> str:
        attempts.append(1)
        if len(attempts) < 3:
            timeout()
        return "ok"

    assert g.call(flaky, what="x", idempotent=True) == "ok"
    assert clock.slept == [1, 2]
    assert g.status()["stats"]["retries"] == 2
    assert g.status()["consecutive_connection_errors"] == 0


def test_writes_are_never_retried() -> None:
    clock = FakeClock()
    g = guard(clock, retries=3, breaker_threshold=10)
    attempts = []

    def write() -> None:
        attempts.append(1)
        timeout()

    with pytest.raises(FritzConnectionError):
        g.call(write, what="x", idempotent=False)
    assert attempts == [1]
    assert clock.slept == []


def test_backoff_is_capped() -> None:
    clock = FakeClock()
    g = guard(clock, retries=4, backoff_base=3, backoff_max=8, breaker_threshold=10)
    with pytest.raises(FritzConnectionError):
        g.call(timeout, what="x", idempotent=True)
    assert clock.slept == [3, 6, 8, 8]


# ------------------------------------------------------------------ circuit breaker


def test_breaker_opens_after_threshold_and_rejects_without_calling() -> None:
    clock = FakeClock()
    g = guard(clock)
    for _ in range(3):
        with pytest.raises(FritzConnectionError):
            g.call(timeout, what="x", idempotent=True)
    assert g.status()["breaker"] == "open"
    called = []
    with pytest.raises(FritzConnectionError) as exc:
        g.call(lambda: called.append(1), what="Hosts1:GetInfo", idempotent=True)
    assert called == []
    assert "überlastet/nicht erreichbar" in str(exc.value)
    assert exc.value.code == "connection_error"
    assert exc.value.hint
    assert g.status()["stats"]["rejected_by_breaker"] == 1


def test_breaker_half_open_trial_closes_on_success() -> None:
    clock = FakeClock()
    g = guard(clock)
    for _ in range(3):
        with pytest.raises(FritzConnectionError):
            g.call(timeout, what="x", idempotent=True)
    clock.now += 31
    assert g.status()["breaker"] == "half_open"
    assert g.call(lambda: "ok", what="x", idempotent=True) == "ok"
    assert g.status()["breaker"] == "closed"
    assert g.status()["consecutive_connection_errors"] == 0


def test_breaker_half_open_trial_failure_reopens() -> None:
    clock = FakeClock()
    g = guard(clock, retries=2)
    for _ in range(3):
        with pytest.raises(FritzConnectionError):
            g.call(timeout, what="x", idempotent=True)
    clock.now += 31
    attempts = []

    def fail() -> None:
        attempts.append(1)
        timeout()

    with pytest.raises(FritzConnectionError):
        g.call(fail, what="x", idempotent=True)
    assert attempts == [1]  # no retries while the breaker is open again
    assert g.status()["breaker"] == "open"


def test_other_errors_prove_the_box_is_alive() -> None:
    clock = FakeClock()
    g = guard(clock)
    for _ in range(2):
        with pytest.raises(FritzConnectionError):
            g.call(timeout, what="x", idempotent=True)

    def not_found() -> None:
        raise NotFoundError("gibt es nicht")

    with pytest.raises(NotFoundError):
        g.call(not_found, what="x", idempotent=True)
    assert g.status()["consecutive_connection_errors"] == 0
    with pytest.raises(FritzConnectionError):
        g.call(timeout, what="x", idempotent=True)
    assert g.status()["breaker"] == "closed"


# ------------------------------------------------------------------ cache


def test_cache_ttl_copies_and_invalidation() -> None:
    clock = FakeClock()
    g = guard(clock, cache_ttl=15)
    loads = []

    def load_value() -> dict[str, Any]:
        loads.append(1)
        return {"devices": [1, 2]}

    a = g.cached("k", load_value)
    a["devices"].append(99)  # callers may mutate their copy
    b = g.cached("k", load_value)
    assert b == {"devices": [1, 2]}
    assert len(loads) == 1
    clock.now += 16
    g.cached("k", load_value)
    assert len(loads) == 2
    g.invalidate()
    g.cached("k", load_value)
    assert len(loads) == 3
    stats = g.status()["stats"]
    assert stats["cache_hits"] == 1 and stats["cache_misses"] == 3


def test_cache_disabled_with_ttl_zero() -> None:
    g = guard(FakeClock(), cache_ttl=0)
    loads = []
    for _ in range(3):
        g.cached("k", lambda: loads.append(1))
    assert len(loads) == 3


def test_write_during_load_is_not_cached() -> None:
    g = guard(FakeClock(), cache_ttl=15)

    def load_with_write() -> int:
        g.invalidate()
        return 1

    g.cached("k", load_with_write)
    assert g.status()["cached_entries"] == 0


# ------------------------------------------------------------------ TR-064 integration


def _hosts_fc() -> FakeFC:
    fc = FakeFC(
        {
            ("Hosts1", "GetHostNumberOfEntries"): {"NewHostNumberOfEntries": 1},
            ("Hosts1", "GetGenericHostEntry"): {
                "NewHostName": "pc",
                "NewIPAddress": "192.0.2.20",
                "NewMACAddress": "AA:BB:CC:DD:EE:01",
                "NewActive": True,
            },
        }
    )
    return fc


def test_tr064_host_list_cached_and_write_invalidates() -> None:
    fc = _hosts_fc()
    g = guard(FakeClock(), cache_ttl=15)
    tr = Tr064Client(lambda: fc, (PASSWORD,), g)  # type: ignore[arg-type,return-value]
    tr.list_hosts()
    n = len(fc.calls)
    tr.list_hosts()
    assert len(fc.calls) == n  # served from cache
    tr.set_host_name("AA:BB:CC:DD:EE:01", "neu")
    tr.list_hosts()
    assert len(fc.calls) > n + 1  # write emptied the cache → fresh read-back


def test_tr064_timeouts_open_breaker_and_writes_not_retried() -> None:
    fc = FakeFC({("Hosts1", "X_AVM-DE_SetHostNameByMACAddress"): FritzConnectionException("Read timed out")})
    g = guard(FakeClock(), retries=3)
    tr = Tr064Client(lambda: fc, (PASSWORD,), g)  # type: ignore[arg-type,return-value]
    with pytest.raises(FritzConnectionError):
        tr.set_host_name("AA:BB:CC:DD:EE:01", "x")
    assert len(fc.calls) == 1


def test_overloaded_box_snapshot_stops_after_breaker(tmp_path: Any) -> None:
    """Snapshot against a box that only times out: after the breaker opens, no further requests reach it."""

    class TimeoutFC(FakeFC):
        def call_action(self, service_name: str, action_name: str, *, arguments: Any = None) -> dict[str, Any]:
            self.calls.append((service_name, action_name, arguments or {}))
            raise FritzConnectionException("Unable to get a connection: Read timed out")

    fc = TimeoutFC()
    clock = FakeClock()
    g = guard(clock, retries=1, breaker_threshold=3, cache_ttl=15)
    landevices = LanDeviceClient(RestClient(httpx.Client(base_url="http://fritz.test"), _NoLogin(), g))
    svc = FritzService(
        Tr064Client(lambda: fc, (PASSWORD,), g),  # type: ignore[arg-type,return-value]
        landevices,
        Gate(False, False),
        PlanStore(),
        sleep=lambda s: None,
        box_host="fritz.test",
        state_root=tmp_path,
    )
    result = svc.snapshot_create("Lasttest")
    assert result["sections_failed"]
    # 3 failures open the breaker; everything afterwards is rejected locally
    assert len(fc.calls) <= 3
    assert g.status()["stats"]["rejected_by_breaker"] > 0


class _NoLogin(SessionManager):
    def __init__(self) -> None:  # never talks to a box
        pass

    def get_sid(self) -> str:
        raise FritzConnectionError("Login: FRITZ!Box antwortet nicht.")

    def relogin(self) -> str:
        return self.get_sid()


# ------------------------------------------------------------------ REST integration


def test_rest_landevice_cached_put_invalidates_and_read_back_is_fresh(http: httpx.Client, fake_box: FakeBox) -> None:
    g = guard(FakeClock(), cache_ttl=15)
    rest = RestClient(http, SessionManager(http, "mcp", PASSWORD), g)
    client = LanDeviceClient(rest)
    client.list()
    client.list()
    gets = [r for r in fake_box.requests if r.method == "GET" and r.url.path == "/api/v0/generic/landevice"]
    assert len(gets) == 1
    result = client.set_friendly_name("AA:BB:CC:DD:EE:01", "Neuer-Name", None)
    assert result["verified"] is True
    assert client.find("AA:BB:CC:DD:EE:01", None).friendly_name == "Neuer-Name"
    gets = [r for r in fake_box.requests if r.method == "GET" and r.url.path == "/api/v0/generic/landevice"]
    assert len(gets) >= 2


# ------------------------------------------------------------------ configuration


def _env(**extra: str) -> dict[str, str]:
    return {"FRITZ_USER": "mcp", "FRITZ_PASSWORD": PASSWORD, **extra}


def test_guard_defaults_and_env_overrides() -> None:
    assert load(_env()).guard == GuardSettings()
    cfg = load(_env(FRITZ_MAX_PARALLEL="1", FRITZ_CACHE_TTL="0", FRITZ_BREAKER_COOLDOWN="60", FRITZ_RATE_LIMIT="2.5"))
    assert cfg.guard.max_parallel == 1
    assert cfg.guard.cache_ttl == 0
    assert cfg.guard.breaker_cooldown == 60
    assert cfg.guard.rate_per_s == 2.5


@pytest.mark.parametrize(
    "var,value", [("FRITZ_MAX_PARALLEL", "0"), ("FRITZ_CACHE_TTL", "abc"), ("FRITZ_RETRIES", "1.5")]
)
def test_guard_env_validation(var: str, value: str) -> None:
    with pytest.raises(ConfigError):
        load(_env(**{var: value}))
