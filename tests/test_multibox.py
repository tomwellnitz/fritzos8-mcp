from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fritzconnection.core.exceptions import FritzConnectionException
from mcp.server.mcpserver.exceptions import ToolError

from fritzos8_mcp.config import load_all
from fritzos8_mcp.errors import ConfigError
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.multibox import compare, overview
from fritzos8_mcp.security import Gate
from fritzos8_mcp.server import build_server

from .conftest import PASSWORD, FakeFC, make_service
from .test_diagnose import secure_box

REPO = Path(__file__).resolve().parent.parent


# ------------------------------------------------------------------ config


def test_single_box_config_stays_default() -> None:
    cfgs = load_all({"FRITZ_HOST": "192.0.2.1", "FRITZ_USER": "mcp", "FRITZ_PASSWORD": "x-pass"})
    assert len(cfgs) == 1 and cfgs[0].name == "default" and cfgs[0].host == "192.0.2.1"


def test_multi_box_config(tmp_path: Path) -> None:
    pw = tmp_path / "pw"
    pw.write_text("datei-pass\n")
    env = {
        "FRITZ_BOXES": "heim, Zweit-Box",
        "FRITZ_HEIM_HOST": "192.0.2.1",
        "FRITZ_HEIM_USER": "a",
        "FRITZ_HEIM_PASSWORD": "pass-a",
        "FRITZ_ZWEIT_BOX_HOST": "198.51.100.1",
        "FRITZ_ZWEIT_BOX_USER": "b",
        "FRITZ_ZWEIT_BOX_PASSWORD_FILE": str(pw),
        "FRITZ_ZWEIT_BOX_TIMEOUT": "5",
        "FRITZ_ALLOW_WRITE": "1",
        # global single-box values must not leak into the boxes
        "FRITZ_HOST": "203.0.113.9",
        "FRITZ_PASSWORD": "global-pass",
    }
    heim, zweit = load_all(env)
    assert (heim.name, heim.host, heim.user, heim.password) == ("heim", "192.0.2.1", "a", "pass-a")
    assert (zweit.name, zweit.host, zweit.password, zweit.timeout) == ("zweit-box", "198.51.100.1", "datei-pass", 5.0)
    assert heim.allow_write and zweit.allow_write


@pytest.mark.parametrize(
    "env,msg",
    [
        ({"FRITZ_BOXES": "a,a"}, "doppelt"),
        ({"FRITZ_BOXES": "Bad Name!"}, "Ungültiger Boxname"),
        ({"FRITZ_BOXES": "a", "FRITZ_A_USER": "u", "FRITZ_A_PASSWORD": "p"}, "FRITZ_A_HOST"),
        ({"FRITZ_BOXES": "a", "FRITZ_A_HOST": "h", "FRITZ_A_USER": "u"}, "Box 'a'"),
        ({"FRITZ_BOXES": " , "}, "leer"),
    ],
)
def test_multi_box_config_errors(env: dict[str, str], msg: str) -> None:
    with pytest.raises(ConfigError) as ei:
        load_all(env)
    assert msg in str(ei.value)


def test_multi_start_script_never_passes_password_as_argument() -> None:
    script = REPO / "scripts" / "fritzos8-mcp-multi-start.sh"
    assert script.stat().st_mode & 0o111
    text = script.read_text()
    exec_line = next(line for line in text.splitlines() if line.startswith("exec "))
    assert "PASSWORT" not in exec_line and "PASSWORD" not in exec_line
    assert "unset PASSWORT" in text
    assert '"$PROGRAMM"' in exec_line and "PROGRAMM=fritzos8-collector" in text  # --collector: same credentials path
    zsh = shutil.which("zsh")
    if zsh:  # syntax check where zsh exists (CI: ubuntu without zsh → skipped)
        assert subprocess.run([zsh, "-n", str(script)], capture_output=True).returncode == 0  # noqa: S603


# ------------------------------------------------------------------ server routing


async def test_box_parameter_routes_to_service() -> None:
    a, b = MagicMock(), MagicMock()
    a.system_info.return_value = {"model": "A"}
    b.system_info.return_value = {"model": "B"}
    server = build_server({"heim": a, "zweit": b}, Gate(False, False))
    assert (await server.call_tool("system_info", {})).structured_content["model"] == "A"
    assert (await server.call_tool("system_info", {"box": "zweit"})).structured_content["model"] == "B"
    assert (await server.call_tool("system_info", {"box": "ZWEIT"})).structured_content["model"] == "B"
    with pytest.raises(ToolError) as ei:
        await server.call_tool("system_info", {"box": "nachbar"})
    assert "heim, zweit" in str(ei.value)
    status = (await server.call_tool("server_status", {})).structured_content
    assert status["boxes"] == ["heim", "zweit"] and status["default_box"] == "heim"


async def test_every_box_tool_has_optional_box_parameter() -> None:
    tools = await build_server(MagicMock(), Gate(True, True)).list_tools()
    without = {"server_status", "boxes_overview", "compare_boxes", "family_admin_report"}
    for t in tools:
        props = t.input_schema.get("properties", {})
        if t.name in without:
            assert "box" not in props, t.name
        else:
            assert "box" in props and "box" not in t.input_schema.get("required", []), t.name


async def test_write_tool_with_box_routes() -> None:
    a, b = MagicMock(), MagicMock()
    b.rename_host.return_value = {"verified": True}
    server = build_server({"heim": a, "zweit": b}, Gate(True, False))
    await server.call_tool("rename_host", {"mac": "AA:BB:CC:DD:EE:01", "name": "x", "box": "zweit"})
    b.rename_host.assert_called_once_with("AA:BB:CC:DD:EE:01", "x", None)
    a.rename_host.assert_not_called()


# ------------------------------------------------------------------ overview / compare


def two_boxes(landevices: LanDeviceClient) -> dict:
    fc_a = secure_box()
    fc_a.responses[("DeviceInfo1", "GetInfo")] = {"NewModelName": "FRITZ!Box 7583", "NewSoftwareVersion": "164.08.26"}
    fc_b = secure_box()
    fc_b.responses[("DeviceInfo1", "GetInfo")] = {
        "NewModelName": "FRITZ!Box 6660 Cable",
        "NewSoftwareVersion": "164.08.25",
    }
    return {"heim": make_service(landevices, fc_a), "zweit": make_service(landevices, fc_b)}


def test_overview(landevices: LanDeviceClient) -> None:
    r = overview(two_boxes(landevices))
    boxes = {b["box"]: b for b in r["boxes"]}
    assert boxes["heim"]["model"] == "FRITZ!Box 7583" and boxes["zweit"]["firmware"] == "164.08.25"
    assert boxes["heim"]["online"] is True and boxes["heim"]["update_available"] is False
    assert "overall" in boxes["heim"]["security"]


def test_overview_tolerates_unreachable_box(landevices: LanDeviceClient) -> None:
    services = two_boxes(landevices)
    down = FakeFC({("DeviceInfo1", "GetInfo"): FritzConnectionException("timeout")})
    services["kaputt"] = make_service(landevices, down)
    boxes = {b["box"]: b for b in overview(services)["boxes"]}
    assert boxes["kaputt"]["reachable"] is False and "system" in boxes["kaputt"]["errors"]
    assert boxes["heim"]["reachable"] is True


def test_compare_firmware(landevices: LanDeviceClient) -> None:
    r = compare(two_boxes(landevices), "system")
    assert r["differences"]["model"] == {"heim": "FRITZ!Box 7583", "zweit": "FRITZ!Box 6660 Cable"}
    assert r["identical"] is False
    w = compare(two_boxes(landevices), "wlan")
    assert w["differences"] == {} and w["identical"] is True


async def test_compare_rejects_unknown_aspect() -> None:
    service = MagicMock()
    with pytest.raises(ToolError):
        await build_server(service, Gate(False, False)).call_tool("compare_boxes", {"aspect": "passwords"})


# ------------------------------------------------------------------ prompts & resources


async def test_prompts_listed_and_rendered() -> None:
    server = build_server(MagicMock(), Gate(False, False))
    names = {p.name for p in await server.list_prompts()}
    assert names == {"netz_doktor", "geraete_aufraeumen", "sicherheits_check"}
    r = await server.get_prompt("netz_doktor", {"symptom": "WLAN langsam", "box": "zweit"})
    text = r.messages[0].content.text
    assert "WLAN langsam" in text and 'box="zweit"' in text and "network_doctor" in text
    r = await server.get_prompt("geraete_aufraeumen", {})
    assert "devices_cleanup_report" in r.messages[0].content.text


async def test_resources_are_read_only_and_redacted(landevices: LanDeviceClient) -> None:
    svc = MagicMock()
    svc.list_landevices.return_value = {"count": 1, "landevices": [{"name": f"x {PASSWORD}"}]}
    svc.snapshots.latest.return_value = None
    server = build_server({"heim": svc}, Gate(False, False), (PASSWORD,))
    templates = {t.uri_template for t in await server.list_resource_templates()}
    assert templates == {"fritz://{box}/landevices", "fritz://{box}/snapshot/latest"}
    contents = list(await server.read_resource("fritz://heim/landevices"))
    assert PASSWORD not in contents[0].content and '"count": 1' in contents[0].content
    snap = list(await server.read_resource("fritz://heim/snapshot/latest"))
    assert "snapshot_create" in snap[0].content
    unknown = list(await server.read_resource("fritz://nachbar/landevices"))
    assert json.loads(unknown[0].content)["error"]["type"] == "invalid_parameter"


async def test_snapshot_resource_returns_latest(landevices: LanDeviceClient) -> None:
    svc = make_service(landevices, secure_box())
    created = svc.snapshot_create("r")
    server = build_server(svc, Gate(False, False))
    data = json.loads(next(iter(await server.read_resource("fritz://default/snapshot/latest"))).content)
    assert data["id"] == created["id"] and data["label"] == "r"
