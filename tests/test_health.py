"""server_status health block: state from the clients, no box request unless probe=true."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from fritzconnection.core.exceptions import FritzActionError, FritzConnectionException

from fritzos8_mcp import health
from fritzos8_mcp.auth import SessionManager
from fritzos8_mcp.errors import AuthError, FritzConnectionError, FritzError, NotFoundError
from fritzos8_mcp.guard import BoxGuard, GuardSettings
from fritzos8_mcp.health import HealthTracker
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.rest import RestClient
from fritzos8_mcp.security import Gate, PlanStore
from fritzos8_mcp.server import build_server
from fritzos8_mcp.service import FritzService
from fritzos8_mcp.tr064 import Tr064Client

from .conftest import BASE, CHALLENGE_XML, PASSWORD, SID, FakeBox, FakeFC, session_xml


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def _guard(clock: FakeClock | None = None, **kw: Any) -> BoxGuard:
    settings: dict[str, Any] = {"rate_per_s": 0, "retries": 0, "breaker_threshold": 3, "breaker_cooldown": 30}
    settings.update(kw)
    g = BoxGuard(GuardSettings(**settings), clock or FakeClock())
    ticks = iter(range(2_000_000_000, 2_000_100_000))
    g.health = HealthTracker(clock=lambda: float(next(ticks)), started=1_999_999_990.0)
    return g


def test_no_requests_yet_is_ok_but_says_so() -> None:
    h = health.health(_guard())
    assert h["health"] == "ok" and "noch keine Box-Anfrage" in h["reason"]
    assert all(v["state"] == "unused" for v in h["interfaces"].values())
    assert "setup_check" in h["hint"] and h["breaker"]["state"] == "closed"


def test_failure_on_one_interface_is_degraded_and_redacted() -> None:
    g = _guard()
    health.record(g, "tr064", None)
    health.record(g, "api_v0", AuthError("GET /api/v0/generic/landevice: abgelehnt sid=0123456789abcdef"))
    health.record(g, "aha", NotFoundError("Smart Home x: nicht gefunden"))  # an answer, not a failure
    h = health.health(g)
    assert h["health"] == "degraded" and "api_v0: auth_error" in h["reason"]
    api = h["interfaces"]["api_v0"]
    assert api["state"] == "error" and api["last_error"]["type"] == "auth_error"
    assert "0123456789abcdef" not in api["last_error"]["message"]
    assert h["interfaces"]["aha"]["state"] == "ok" and h["interfaces"]["tr064"]["last_success"]
    # a later success heals the interface
    health.record(g, "api_v0", None)
    assert health.health(g)["health"] == "ok"


def test_all_used_interfaces_failing_is_down() -> None:
    g = _guard()
    health.record(g, "tr064", FritzConnectionError("antwortet nicht"))
    health.record(g, "api_v0", FritzConnectionError("antwortet nicht"))
    h = health.health(g)
    assert h["health"] == "down" and "tr064" in h["reason"] and "api_v0" in h["reason"]


def test_open_breaker_is_down_with_until() -> None:
    clock = FakeClock()
    g = _guard(clock)
    fc = FakeFC({("DeviceInfo1", "GetInfo"): FritzConnectionException("Read timed out")})
    tr = Tr064Client(lambda: fc, (PASSWORD,), g)  # type: ignore[arg-type,return-value]
    for _ in range(4):
        with pytest.raises(FritzConnectionError):
            tr.call("DeviceInfo1", "GetInfo")
    h = health.health(g)
    assert h["health"] == "down" and "Schutzschalter offen" in h["reason"]
    assert h["breaker"]["state"] == "open" and h["breaker"]["open_until"]
    assert h["interfaces"]["tr064"]["requests_failed"] == 4  # incl. the locally rejected one


def test_tr064_not_found_counts_as_answer() -> None:
    g = _guard()
    fc = FakeFC({("X1", "GetFoo"): FritzActionError("x")})
    tr = Tr064Client(lambda: fc, (PASSWORD,), g)  # type: ignore[arg-type,return-value]
    assert tr.try_call("X1", "GetFoo") is None
    assert health.health(g)["interfaces"]["tr064"]["state"] == "ok"


def test_rest_records_interface_and_relogins(respx_mock: Any) -> None:
    respx_mock.get(f"{BASE}/login_sid.lua?version=2").mock(return_value=httpx.Response(200, text=CHALLENGE_XML))
    respx_mock.post(f"{BASE}/login_sid.lua?version=2").mock(return_value=httpx.Response(200, text=session_xml(SID)))
    respx_mock.get(f"{BASE}/api/v0/generic/plc").mock(return_value=httpx.Response(400, text="bad"))
    respx_mock.get(f"{BASE}/api/v0/smarthome/overview/globals").mock(return_value=httpx.Response(200, json={}))
    http = httpx.Client(base_url=BASE)
    session = SessionManager(http, "mcp", PASSWORD)
    g = _guard()
    g.health.session = session
    rest = RestClient(http, session, g)
    with pytest.raises(FritzError, match="HTTP 400"):
        rest.request("GET", "/api/v0/generic/plc")
    rest.request("GET", "/api/v0/smarthome/overview/globals")
    h = health.health(g)
    assert h["interfaces"]["api_v0"]["state"] == "error"
    assert h["interfaces"]["smarthome_rest"]["state"] == "ok"
    ws = h["web_session"]
    assert ws["tracked"] and ws["relogins_since_start"] == 1 and ws["logins"] == 2
    assert ws["session_age_s"] is not None and SID not in str(h)


async def test_server_status_health_without_box_requests(http: httpx.Client, fake_box: FakeBox) -> None:
    fc = FakeFC({("DeviceInfo1", "GetInfo"): {"NewModelName": "FRITZ!Box 7583"}})
    g = _guard()
    session = SessionManager(http, "mcp", PASSWORD)
    g.health.session = session
    svc = FritzService(
        Tr064Client(lambda: fc, (PASSWORD,), g),  # type: ignore[arg-type,return-value]
        LanDeviceClient(RestClient(http, session, g)),
        Gate(False, False),
        PlanStore(),
    )
    server = build_server(svc, Gate(False, False))
    status = (await server.call_tool("server_status", {})).structured_content
    assert fc.calls == [] and fake_box.requests == []
    assert status["health"]["default"]["health"] == "ok" and "probe" not in status["health"]["default"]

    status = (await server.call_tool("server_status", {"probe": True})).structured_content
    box = status["health"]["default"]
    assert box["probe"]["tr064"] == {"ok": True}
    assert [c[:2] for c in fc.calls] == [("DeviceInfo1", "GetInfo")]
    gets = [r.url.path for r in fake_box.requests if r.method == "GET" and r.url.path.startswith("/api/v0")]
    assert gets.count("/api/v0/generic/landevice") == 1
    assert box["interfaces"]["tr064"]["state"] == "ok" and box["interfaces"]["api_v0"]["state"] == "ok"
