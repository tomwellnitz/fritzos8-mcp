"""Shared fakes. No test ever talks to a real FRITZ!Box."""

from __future__ import annotations

import copy
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from fritzos8_mcp.auth import SessionManager
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.rest import RestClient
from fritzos8_mcp.security import Gate, PlanStore
from fritzos8_mcp.service import FritzService
from fritzos8_mcp.tr064 import Tr064Client

BASE = "http://fritz.test"
PASSWORD = "geheim-Passwort!"  # test value only
SID = "a1b2c3d4e5f60718"

CHALLENGE_XML = (
    "<?xml version='1.0' encoding='utf-8'?><SessionInfo><SID>0000000000000000</SID>"
    "<Challenge>2$10000$5A1711$2000$5A1722</Challenge><BlockTime>0</BlockTime><Rights></Rights>"
    "<Users><User last='1'>mcp</User></Users></SessionInfo>"
)


def session_xml(sid: str = SID, block: int = 0) -> str:
    return (
        f"<SessionInfo><SID>{sid}</SID><Challenge>2$10000$5A1711$2000$5A1722</Challenge>"
        f"<BlockTime>{block}</BlockTime><Rights><Name>BoxAdmin</Name><Access>2</Access>"
        "<Name>Dial</Name><Access>2</Access></Rights></SessionInfo>"
    )


LANDEVICES = {
    "landevice": [
        {
            "UID": "landevice1001",
            "name": "pc-buero",
            "friendly_name": "PC Büro",
            "mac": "aa:bb:cc:dd:ee:01",
            "ip": "192.0.2.20",
            "static_dhcp": "0",
            "active": "1",
            "online": "1",
            "deleteable": "1",
            "flags": "",
        },
        {
            "UID": "landevice1002",
            "name": "alter-drucker",
            "friendly_name": "",
            "mac": "AA-BB-CC-DD-EE-02",
            "ip": "192.0.2.30",
            "static_dhcp": "1",
            "active": "0",
            "online": "0",
            "deleteable": "1",
            "flags": "",
        },
        {
            "UID": "landevice1",
            "name": "fritz.box",
            "friendly_name": "fritz.box",
            "mac": "AA:BB:CC:DD:EE:00",
            "ip": "192.0.2.1",
            "static_dhcp": "0",
            "active": "1",
            "online": "1",
            "deleteable": "0",
            "flags": "ownentry",
        },
        # same MAC twice (e.g. LAN + WLAN entry)
        {"UID": "landevice2001", "name": "dup-a", "mac": "AA:BB:CC:DD:EE:03", "ip": "", "active": "0"},
        {"UID": "landevice2002", "name": "dup-b", "mac": "aabbccddee03", "ip": "", "active": "0"},
    ]
}


class FakeBox:
    """Very small in-memory model of the /api/v0 landevice endpoints, for respx side effects."""

    def __init__(self) -> None:
        self.devices: list[dict[str, Any]] = copy.deepcopy(LANDEVICES["landevice"])
        self.discard_writes = False  # simulate 2FA silently discarding changes
        self.requests: list[httpx.Request] = []
        # other /api/v0/generic/<name> documents (e.g. dnscfg, ipv6) for GET
        self.generic: dict[str, Any] = {}
        # eth_ports writes: True = EEE acts box-wide (as live on a 7583), raw = answer to every PUT
        self.eee_box_wide = False
        self.put_response: httpx.Response | None = None
        # optional extra routes (e.g. /api/v0/smarthome writes): return a Response or None to fall through
        self.extra_handler: Any = None

    def _find(self, uid: str) -> dict[str, Any] | None:
        return next((d for d in self.devices if d["UID"] == uid), None)

    def _put_eth(self, uid: str, request: httpx.Request) -> httpx.Response:
        import json

        if self.put_response is not None:
            return self.put_response
        ports = (self.generic.get("eth_ports") or {}).get("eth") or []
        port = next((p for p in ports if p["UID"] == uid), None)
        if port is None:
            return httpx.Response(404, text="not found")
        if not self.discard_writes:
            body = json.loads(request.content)
            targets = ports if self.eee_box_wide and "eee_mode" in body else [port]
            for p in targets:
                p.update(body)
        return httpx.Response(200, json={})

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.headers.get("AUTHORIZATION") != f"AVM-SID {SID}":
            return httpx.Response(401, text='{"errors":["INVALID-SID"]}')
        path = request.url.path
        if self.extra_handler is not None:
            extra = self.extra_handler(request)
            if extra is not None:
                return extra
        if path == "/api/v0/generic/landevice":
            return httpx.Response(200, json={"landevice": self.devices})
        name = path.removeprefix("/api/v0/generic/")
        if request.method == "GET" and name in self.generic:
            return httpx.Response(200, json=self.generic[name])
        if name.startswith("eth_ports/eth/") and request.method == "PUT":
            return self._put_eth(name.rsplit("/", 1)[-1], request)
        uid = path.rsplit("/", 1)[-1]
        dev = self._find(uid)
        if dev is None:
            return httpx.Response(404, text="not found")
        if request.method == "GET":
            return httpx.Response(200, json={"landevice": dev})
        if request.method == "PUT":
            if not self.discard_writes:
                import json

                dev.update(json.loads(request.content))
            return httpx.Response(200, json={})
        if request.method == "DELETE":
            if not self.discard_writes:
                self.devices.remove(dev)
            return httpx.Response(200, json={})
        return httpx.Response(405)


# ------------------------------------------------------------------ TR-064 fakes


def _arg(name: str, direction: str, var: str) -> SimpleNamespace:
    return SimpleNamespace(name=name, direction=direction, relatedStateVariable=var)


def _action(*args: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(arguments={a.name: a for a in args})


def make_services() -> dict[str, Any]:
    sv = {
        "MACAddress": SimpleNamespace(dataType="string", allowed_values=None, defaultValue=None),
        "HostName": SimpleNamespace(dataType="string", allowed_values=None, defaultValue=None),
        "Index": SimpleNamespace(dataType="ui2", allowed_values=None, defaultValue=None),
        "KeyPassphrase": SimpleNamespace(dataType="string", allowed_values=None, defaultValue=None),
    }
    return {
        "Hosts1": SimpleNamespace(
            actions={
                "GetSpecificHostEntry": _action(
                    _arg("NewMACAddress", "in", "MACAddress"), _arg("NewHostName", "out", "HostName")
                ),
                "X_AVM-DE_SetHostNameByMACAddress": _action(
                    _arg("NewMACAddress", "in", "MACAddress"), _arg("NewHostName", "in", "HostName")
                ),
                "X_AVM-DE_GetHostListPath": _action(),
                "GetHostNumberOfEntries": _action(),
            },
            state_variables=sv,
        ),
        "DeviceConfig1": SimpleNamespace(
            actions={"Reboot": _action(), "FactoryReset": _action(), "X_AVM-DE_GetConfigFile": _action()},
            state_variables={},
        ),
        "WLANConfiguration1": SimpleNamespace(
            actions={
                "GetInfo": _action(),
                "GetSecurityKeys": _action(),
                "SetEnable": _action(),
                "X_AVM-DE_GetWLANExtInfo": _action(_arg("NewIndex", "in", "Index")),
            },
            state_variables=sv,
        ),
        "WANIPConn1": SimpleNamespace(
            actions={"GetStatusInfo": _action(), "ForceTermination": _action()}, state_variables={}
        ),
    }


class FakeFC:
    """Stands in for fritzconnection.FritzConnection."""

    address = "http://fritz.test"
    port = 49000

    def __init__(self, responses: dict[tuple[str, str], Any] | None = None) -> None:
        self.services = make_services()
        self.responses = responses or {}
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.session = SimpleNamespace(get=lambda url: SimpleNamespace(ok=False, content=b""))

    def call_action(
        self, service_name: str, action_name: str, *, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        args = arguments or {}
        self.calls.append((service_name, action_name, args))
        r = self.responses.get((service_name, action_name), {})
        if isinstance(r, Exception):
            raise r
        if callable(r):
            return r(**args)
        return r


@pytest.fixture(autouse=True)
def _isolated_dirs(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Never touch the real cache/state directories and never download the OUI registry."""
    monkeypatch.setenv("FRITZ_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("FRITZ_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("FRITZ_OUI_DOWNLOAD", "0")
    # never read the real OS keychain (stage 9.3)
    monkeypatch.setattr("fritzos8_mcp.config.keyring_password", lambda *a, **k: "")
    monkeypatch.setattr("fritzos8_mcp.httpserve._keyring_token", lambda service: "")


@pytest.fixture
def fake_box() -> FakeBox:
    return FakeBox()


@pytest.fixture
def http(respx_mock: Any, fake_box: FakeBox) -> httpx.Client:
    respx_mock.get(f"{BASE}/login_sid.lua?version=2").mock(return_value=httpx.Response(200, text=CHALLENGE_XML))
    respx_mock.post(f"{BASE}/login_sid.lua?version=2").mock(return_value=httpx.Response(200, text=session_xml()))
    respx_mock.route(host="fritz.test", path__startswith="/api/v0/").mock(side_effect=fake_box.handle)
    return httpx.Client(base_url=BASE)


@pytest.fixture
def landevices(http: httpx.Client) -> LanDeviceClient:
    return LanDeviceClient(RestClient(http, SessionManager(http, "mcp", PASSWORD)))


@pytest.fixture
def fc() -> FakeFC:
    return FakeFC()


def make_service(
    landevices: LanDeviceClient,
    fc: FakeFC,
    *,
    write: bool = True,
    critical: bool = True,
    now: Any = None,
) -> FritzService:
    plans = PlanStore(now=now) if now else PlanStore()
    return FritzService(
        Tr064Client(lambda: fc, (PASSWORD,)),  # type: ignore[arg-type,return-value]
        landevices,
        Gate(write, critical),
        plans,
        sleep=lambda s: None,
        reconnect_wait=20,
        reconnect_poll=5,
    )
