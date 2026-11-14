"""Terminal demo for the README GIF (docs/demo.gif, recorded with `make demo` from docs/demo.tape).

Runs the REAL MCP server in-process (MCP client ↔ server over the SDK's in-memory transport) against a
SIMULATED FRITZ!Box built from the test fakes in tests/ – no network access, invented data only
(documentation addresses 192.0.2.x, MACs AA:BB:CC:…, generic device names).

The tools answer with structured JSON whose texts are German; an assistant summarises them in the
user's language. The demo does the same: it renders the real tool results and translates the finding
texts it knows into short English lines (numbers always come from the result, unknown texts are shown
unchanged).

    uv run --group demo python scripts/demo.py           # paced like a live session
    uv run --group demo python scripts/demo.py --fast    # no pauses (used by the tests)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SEVERITY_STYLE = {"critical": "bold red", "warn": "bold yellow", "info": "cyan", "ok": "green", "unknown": "dim"}
SEVERITY_ORDER = {"critical": 0, "warn": 1, "info": 2}
TIER_STYLE = {"read": "green", "write": "yellow", "critical": "red"}


# ------------------------------------------------------------------ simulated box


def build_demo_server() -> Any:
    """MCP server wired to a fake box: weak DSL line, a few security warnings, generic devices."""
    # never touch the real state/cache directories, never download the OUI registry
    tmp = Path(tempfile.mkdtemp(prefix="fritzos8-demo-"))
    os.environ["FRITZ_STATE_DIR"] = str(tmp / "state")
    os.environ["FRITZ_CACHE_DIR"] = str(tmp / "cache")
    os.environ["FRITZ_OUI_DOWNLOAD"] = "0"
    sys.path.insert(0, str(ROOT))

    import httpx

    from fritzos8_mcp.auth import SessionManager
    from fritzos8_mcp.landevice import LanDeviceClient
    from fritzos8_mcp.rest import RestClient
    from fritzos8_mcp.security import Gate
    from fritzos8_mcp.server import build_server
    from tests.conftest import BASE, CHALLENGE_XML, PASSWORD, FakeBox, make_service, session_xml
    from tests.test_diagnose import DSL, UI_UPDATE, secure_box
    from tests.test_doctor import LOG_BAD, doctor_fc

    box = FakeBox()
    box.devices = [
        {"UID": "landevice1", "name": "fritz.box", "friendly_name": "fritz.box", "mac": "AA:BB:CC:DD:EE:00",
         "ip": "192.0.2.1", "static_dhcp": "0", "active": "1", "online": "1", "deleteable": "0", "flags": "ownentry"},
        {"UID": "landevice1001", "name": "tv-4f2a", "friendly_name": "tv-4f2a", "mac": "AA:BB:CC:DD:EE:21",
         "ip": "192.0.2.21", "static_dhcp": "0", "active": "1", "online": "1", "deleteable": "1", "flags": ""},
        {"UID": "landevice1002", "name": "Office-Printer", "friendly_name": "Office-Printer",
         "mac": "AA:BB:CC:DD:EE:22", "ip": "192.0.2.30", "static_dhcp": "1", "active": "0", "online": "0",
         "deleteable": "1", "flags": ""},
    ]  # fmt: skip
    box.generic["dnscfg"] = {"dns_over_tls_enabled": "0", "ipv4_use_user_dns": "0", "ipv6_use_user_dns": "0"}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login_sid.lua":
            return httpx.Response(200, text=CHALLENGE_XML if request.method == "GET" else session_xml())
        return box.handle(request)

    http = httpx.Client(base_url=BASE, transport=httpx.MockTransport(handler))
    landevices = LanDeviceClient(RestClient(http, SessionManager(http, "mcp", PASSWORD)))

    # TR-064: security answers (remote access on, update available) + a noisy DSL line with resyncs
    fc = secure_box(
        guest_on=True,
        extra={
            ("X_AVM-DE_RemoteAccess1", "GetInfo"): {"NewEnabled": "1", "NewPort": 443},
            ("UserInterface1", "GetInfo"): UI_UPDATE,
        },
    )
    line = doctor_fc(
        dsl={**DSL, "NewDownstreamNoiseMargin": 25, "NewUpstreamNoiseMargin": 50},
        stats={"NewCRCErrors": 9000, "NewSeverelyErroredSecs": 5},
        log=LOG_BAD,
    )
    for key, value in line.responses.items():
        if key not in fc.responses or key[0].startswith("WAN") or key == ("DeviceInfo1", "GetDeviceLog"):
            fc.responses[key] = value
    host_names = {d["mac"]: d["name"] for d in box.devices}

    def set_host_name(NewMACAddress: str, NewHostName: str) -> dict[str, Any]:
        host_names[NewMACAddress.upper()] = NewHostName
        return {}

    fc.responses[("Hosts1", "X_AVM-DE_SetHostNameByMACAddress")] = set_host_name
    fc.responses[("Hosts1", "GetSpecificHostEntry")] = lambda NewMACAddress: {
        "NewHostName": host_names.get(NewMACAddress.upper(), "")
    }

    service = make_service(landevices, fc)  # type: ignore[arg-type]
    return build_server(service, Gate(True, True), (PASSWORD,))


# ------------------------------------------------------------------ English summaries of the German texts


def finding_en(f: dict[str, Any]) -> str:
    text, ev = f.get("finding", ""), f.get("evidence") or {}
    if "snr_db" in ev:
        direction = "Downstream" if "Downstream" in text else "Upstream"
        return f"{direction} SNR margin only {ev['snr_db']} dB"
    if "crc_errors" in ev:
        return f"{ev['crc_errors']:,} CRC errors since the last sync"
    if "Synchronisationsverluste" in text:
        return f"{ev.get('count')} line resyncs in the event log"
    if "Radar" in text:
        return f"{ev.get('count')} radar event – 5 GHz channel had to change (DFS)"
    if "DNS-Störung" in text:
        return f"{ev.get('count')} DNS failure in the event log"
    return text


CHECK_EN = {
    "fernzugriff": ("remote access", "HTTPS access from the internet is on"),
    "firmware": ("firmware", "update available ({version})"),
    "dns_over_tls": ("dns over tls", "DNS queries leave the box unencrypted"),
}
GRADE_EN = {"gut": "good", "mittel": "fair", "kritisch": "critical"}


def menu_path(remediation: str) -> str:
    return remediation.split(":", 1)[0].strip()


# ------------------------------------------------------------------ rendering


class Demo:
    def __init__(self, fast: bool) -> None:
        from rich.console import Console

        self.fast = fast
        self.console = Console(highlight=False)

    def pause(self, seconds: float) -> None:
        if not self.fast:
            time.sleep(seconds)

    def ask(self, question: str) -> None:
        c = self.console
        c.print()
        c.print("[bold magenta]›[/] ", end="")
        for ch in question:
            c.print(f"[bold]{ch}[/]", end="")
            self.pause(0.035)
        c.print()
        self.pause(0.5)

    def call(self, tool: str, args: str, tier: str) -> None:
        self.console.print(f"  [dim]→[/] [bold blue]{tool}[/]([dim]{args}[/])  [{TIER_STYLE[tier]}]\\[{tier}][/]")
        self.pause(0.9)

    def clear(self) -> None:
        if not self.fast:
            self.console.clear()

    def line(self, text: str = "", delay: float = 0.25) -> None:
        self.console.print(text)
        self.pause(delay)


def sev(level: str, width: int = 8) -> str:
    return f"[{SEVERITY_STYLE.get(level, '')}]{level.upper():<{width}}[/]"


async def run(fast: bool) -> dict[str, Any]:
    from mcp import Client

    server = build_demo_server()
    d = Demo(fast)
    results: dict[str, Any] = {}

    d.line("[bold]fritzos8-mcp[/] [dim]· simulated FRITZ!Box from the test fakes · invented data[/]", 0.8)

    async with Client(server) as client:

        async def call(name: str, args: dict[str, Any]) -> dict[str, Any]:
            result = await client.call_tool(name, args)
            data: dict[str, Any] = result.structured_content or {}
            results[name] = data
            return data

        # 1 · network doctor
        d.ask("Why is my internet slow tonight?")
        d.call("network_doctor", 'symptom="slow tonight"', "read")
        doc = await call("network_doctor", {"symptom": "slow tonight"})
        s = doc["summary"]
        d.line(
            f"  [green]✓[/] {sum(s.values())} findings: "
            f"[bold red]{s.get('critical', 0)} critical[/] · [bold yellow]{s.get('warn', 0)} warn[/] · "
            f"[cyan]{s.get('info', 0)} info[/]"
        )
        findings = sorted(doc["findings"], key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
        for f in findings[:5]:
            d.line(f"    {sev(f['severity'])} [dim]{f['area']:<5}[/] {finding_en(f)}")
        top = findings[0]
        if "störanfällige Leitung" in top.get("likely_cause", ""):
            d.line("    [dim]likely cause:[/] noisy line – in-house wiring or an aggressive line profile")
        menu = re.search(r"unter (.+?) auf mehr Stabilität", top.get("recommendation", ""))
        if menu:
            d.line(f"    [dim]fix:[/] {menu.group(1)} [dim]→ more stability[/]")
        d.pause(1.6)

        # 2 · security check
        d.ask("How secure is my FRITZ!Box?")
        d.call("security_check", "", "read")
        sec = await call("security_check", {})
        cnt = sec["counts"]
        d.line(
            f"  [green]✓[/] score [bold]{sec['score']}/100[/] ({GRADE_EN.get(sec['grade'], sec['grade'])}) · "
            f"[green]{cnt.get('ok', 0)} ok[/] · [bold yellow]{cnt.get('warn', 0)} warn[/] · "
            f"[dim]{cnt.get('unknown', 0)} not assessable[/]"
        )
        for check in (c for c in sec["checks"] if c["status"] == "warn"):
            label, summary = CHECK_EN.get(check["check"], (check["check"], check["summary"]))
            summary = summary.format(version=(check.get("details") or {}).get("available_version", "?"))
            d.line(f"    {sev('warn', 5)} [bold]{label:<13}[/] {summary}")
            d.line(f"          [dim]menu:[/] {menu_path(check['remediation'])}", 0.35)
        d.pause(4.0)
        d.clear()

        # 3 · write with read-back
        d.ask("Rename tv-4f2a to Living-Room-TV.")
        d.call("rename_host", 'mac="AA:BB:CC:DD:EE:21", name="Living-Room-TV"', "write")
        ren = await call("rename_host", {"mac": "AA:BB:CC:DD:EE:21", "name": "Living-Room-TV"})
        for key, label in (("host_name", "TR-064 host name"), ("friendly_name", "web UI name")):
            ok = ren[key].get("verified")
            mark = "[green]✓ read back[/]" if ok else "[red]✗ not confirmed[/]"
            d.line(f"    {label:<17} → {ren['name']}  {mark}")
        verified = "[bold green]true[/]" if ren["verified"] else "[bold red]false[/]"
        d.line(f"  [green]✓[/] verified: {verified}", 1.4)

        # 4 · critical: plan → token → execute
        d.ask("Restart the box.")
        d.call("reboot_plan", "", "critical")
        plan = await call("reboot_plan", {})
        d.line("  [bold yellow]![/] only a plan – [bold]nothing has changed yet[/]")
        consequence = plan["consequence"]
        if "startet neu" in consequence:
            consequence = "internet, Wi-Fi, phone and smart home down for ~2–4 min"
        d.line(f"    [dim]consequence:[/] {consequence}")
        d.line(f"    [dim]token:[/] [bold]{plan['token']}[/] [dim](one-time, valid {plan['token_valid_s']} s)[/]")
        d.line(f"    [dim]next:[/] [bold blue]{plan['execute_with']['tool']}[/](token) – only after you say yes")
        d.line()
        d.line("[dim]read-only by default · writes need FRITZ_ALLOW_WRITE=1 · critical: plan → token → execute[/]", 2.5)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--fast", action="store_true", help="no pauses")
    logging.disable(logging.WARNING)  # the server logs every fake HTTP request – not part of the show
    asyncio.run(run(parser.parse_args().fast))


if __name__ == "__main__":
    main()
