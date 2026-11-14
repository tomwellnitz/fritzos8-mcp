"""Stage 8.7 – family admin report across several boxes."""

from __future__ import annotations

from fritzconnection.core.exceptions import FritzConnectionException

from fritzos8_mcp.family import family_report
from fritzos8_mcp.landevice import LanDeviceClient

from .conftest import FakeFC, make_service
from .test_multibox import two_boxes


def test_report_two_boxes_and_markdown(landevices: LanDeviceClient) -> None:
    services = two_boxes(landevices)
    services["zweit"].tr064.fc.responses[("UserInterface1", "GetInfo")] = {  # type: ignore[attr-defined]
        "NewUpgradeAvailable": "1",
        "NewX_AVM-DE_Version": "164.08.30",
    }
    r = family_report(services)
    boxes = {b["box"]: b for b in r["boxes"]}
    assert boxes["zweit"]["light"] == "yellow" and any("Update" in x for x in boxes["zweit"]["reasons"])
    assert boxes["zweit"]["updates"] and "164.08.30" in boxes["zweit"]["updates"][0]
    assert r["overall"] in ("yellow", "red")
    md = r["markdown"]
    assert "| heim |" in md and "| zweit |" in md and "## zweit" in md and "164.08.30" in md


def test_unreachable_box_is_red_and_does_not_break(landevices: LanDeviceClient) -> None:
    services = two_boxes(landevices)
    dead = FakeFC({("DeviceInfo1", "GetInfo"): FritzConnectionException("Read timed out")})
    services["weg"] = make_service(landevices, dead)
    r = family_report(services)
    boxes = {b["box"]: b for b in r["boxes"]}
    assert boxes["weg"]["light"] == "red" and boxes["weg"]["reasons"] == ["Box nicht erreichbar"]
    assert r["overall"] == "red" and boxes["heim"]["reachable"] is True


def test_alarms_from_state_or_fresh_check(landevices: LanDeviceClient) -> None:
    services = two_boxes(landevices)
    r = family_report(services)
    assert all(b["alarms"] == [] for b in r["boxes"])
    r = family_report(services, check_alarms=True)
    assert all("alarms" in b for b in r["boxes"])
