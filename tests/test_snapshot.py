from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from fritzos8_mcp.errors import InvalidParameterError, NotFoundError
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.snapshot import SnapshotStore, diff

from .conftest import PASSWORD, FakeBox, make_service
from .test_diagnose import UI_CURRENT, secure_box
from .test_wlan import KEY

DNSCFG = {
    "ipv4_use_user_dns": "1",
    "ipv4_user_firstdns": "192.0.2.53",
    "ipv4_user_seconddns": "",
    "ipv6_use_user_dns": "1",
    "ipv6_user_firstdns": "2001:db8::53",
    "ipv6_user_seconddns": "",
    "ipv4_dhcpserver_lan_dns": "",
    "dns_over_tls_enabled": "1",
    "public_dns_servers_use_as_fallback": "0",
}

MAPPING = {
    "NewExternalPort": 8443,
    "NewProtocol": "TCP",
    "NewInternalClient": "192.0.2.20",
    "NewInternalPort": 443,
    "NewEnabled": True,
    "NewPortMappingDescription": "NAS",
}


def snap_service(landevices: LanDeviceClient, fake_box: FakeBox, mappings: list[dict[str, Any]] | None = None):
    fake_box.generic["dnscfg"] = dict(DNSCFG)
    fake_box.generic["ipv6"] = {"lan_dns6_server": "", "radv_advdns": "1"}
    fc = secure_box(mappings=mappings)
    fc.responses[("DeviceInfo1", "GetInfo")] = {
        "NewModelName": "FRITZ!Box 7583",
        "NewSoftwareVersion": "164.08.26",
        "NewUpTime": 1000,
    }
    fc.responses[("UserInterface1", "GetInfo")] = UI_CURRENT
    svc = make_service(landevices, fc)
    return svc, fc


def state_files(tmp_path: Path) -> list[Path]:
    return sorted((tmp_path / "state").rglob("*.json"))


def test_create_writes_private_redacted_file(landevices: LanDeviceClient, fake_box: FakeBox, tmp_path: Path) -> None:
    fake_box.devices[0]["friendly_name"] = f"PC {PASSWORD}"  # a secret that must never land on disk
    svc, _ = snap_service(landevices, fake_box)
    r = svc.snapshot_create("vor Update")
    files = state_files(tmp_path)
    assert len(files) == 1 and files[0].stem == r["id"]
    assert files[0].parent == tmp_path / "state" / "fritz.test" / "snapshots"
    assert files[0].stat().st_mode & 0o777 == 0o600
    for d in (files[0].parent, files[0].parent.parent, tmp_path / "state"):
        assert d.stat().st_mode & 0o777 == 0o700
    text = files[0].read_text()
    assert PASSWORD not in text and KEY not in text and "12345670" not in text and "admin" not in text
    data = json.loads(text)
    assert data["label"] == "vor Update" and data["box"] == "fritz.test"
    sec = data["sections"]
    assert sec["system"]["model"] == "FRITZ!Box 7583" and "uptime_s" not in sec["system"]
    assert sec["dns"]["web_settings"]["internet_ipv6"]["dns1"] == "2001:db8::53"
    assert sec["wlan"]["WLANConfiguration3"]["guest"] is True
    assert "clients" not in sec["wlan"]["WLANConfiguration1"] and "channel" not in sec["wlan"]["WLANConfiguration1"]
    assert sec["static_ips"]["AA:BB:CC:DD:EE:02"]["ip"] == "192.0.2.30"
    assert sec["security"]["fernzugriff"]["status"] == "ok"
    assert "smarthome" in r["sections_failed"]  # no AHA client configured → section error, not abort
    assert "landevices" in r["sections_ok"]


def test_retention(landevices: LanDeviceClient, fake_box: FakeBox, tmp_path: Path) -> None:
    svc, _ = snap_service(landevices, fake_box)
    svc._snapshot_keep = 2
    ids = [svc.snapshot_create(str(i))["id"] for i in range(3)]
    listing = svc.snapshot_list()
    assert listing["count"] == 2 and [s["id"] for s in listing["snapshots"]] == [ids[2], ids[1]]
    assert len(set(ids)) == 3  # same second → suffixed ids


def test_diff_requires_snapshot(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    svc, _ = snap_service(landevices, fake_box)
    with pytest.raises(NotFoundError):
        svc.snapshot_diff()


@pytest.mark.parametrize("bad", ["../../etc/passwd", "x", "20261114T120000Z/../a"])
def test_invalid_snapshot_id(landevices: LanDeviceClient, fake_box: FakeBox, bad: str) -> None:
    svc, _ = snap_service(landevices, fake_box)
    with pytest.raises(InvalidParameterError):
        svc.snapshot_diff(bad)


def test_unknown_snapshot_id(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    svc, _ = snap_service(landevices, fake_box)
    with pytest.raises(NotFoundError):
        svc.snapshot_diff("20200101T000000Z")


def test_diff_live_detects_changes_and_ignores_counters(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    mappings = [dict(MAPPING)]
    svc, fc = snap_service(landevices, fake_box, mappings)
    svc.snapshot_create()
    unchanged = svc.snapshot_diff()
    assert unchanged["change_count"] == 0, unchanged["summary"]
    assert unchanged["b"]["id"] == "live"

    # counters/measurements change → still no change
    fc.responses[("DeviceInfo1", "GetInfo")] = {**fc.responses[("DeviceInfo1", "GetInfo")], "NewUpTime": 99999}
    fake_box.devices[0]["online"] = "0"
    assert svc.snapshot_diff()["change_count"] == 0

    # real changes
    mappings.append({**MAPPING, "NewExternalPort": 22, "NewInternalPort": 22, "NewPortMappingDescription": "ssh"})
    fc.responses[("WANIPConn1", "GetPortMappingNumberOfEntries")] = {"NewPortMappingNumberOfEntries": 2}
    fake_box.generic["dnscfg"]["ipv6_user_firstdns"] = "2001:db8::99"
    fake_box.devices.append({"UID": "landevice3001", "name": "fremd", "mac": "00:1A:2B:00:00:99", "ip": ""})
    fake_box.devices[1]["static_dhcp"] = "0"
    fc.responses[("X_AVM-DE_RemoteAccess1", "GetInfo")] = {"NewEnabled": "1", "NewPort": 443}
    r = svc.snapshot_diff()
    text = "\n".join(r["summary"])
    assert "neue Portfreigabe TCP/22 → 192.0.2.20:22" in text
    assert "DNSv6 geändert" in text and "2001:db8::99" in text
    assert "unbekanntes/neues Gerät fremd (00:1A:2B:00:00:99)" in text
    assert "feste IP aufgehoben" in text
    assert "Sicherheit fernzugriff" in text
    assert "TCP/22" in r["added"]["port_forwards"]
    assert "00:1A:2B:00:00:99" in r["added"]["landevices"]


def test_diff_between_two_snapshots(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    svc, _ = snap_service(landevices, fake_box)
    first = svc.snapshot_create("a")["id"]
    fake_box.devices = [d for d in fake_box.devices if d["UID"] != "landevice1002"]
    second = svc.snapshot_create("b")["id"]
    r = svc.snapshot_diff(first, second)
    assert r["a"]["label"] == "a" and r["b"]["label"] == "b"
    assert any("alter-drucker" in line and "nicht mehr" in line for line in r["summary"])
    assert any("feste IP aufgehoben" in line for line in r["summary"])


def test_diff_marks_failed_sections_not_comparable() -> None:
    a = {"sections": {"dns": {"_error": {"type": "x"}}, "system": {"model": "A"}}}
    b = {"sections": {"dns": {"lan_dhcp_dns": ["192.0.2.1"]}, "system": {"model": "A"}}}
    r = diff(a, b)
    assert r["not_comparable"] == ["dns"] and r["change_count"] == 0


def test_diff_summary_is_capped() -> None:
    a = {"sections": {"landevices": {}}}
    b = {"sections": {"landevices": {f"00:1A:2B:00:{i // 256:02X}:{i % 256:02X}": {"name": "x"} for i in range(80)}}}
    r = diff(a, b)
    assert r["change_count"] == 80 and len(r["summary"]) == 61 and "weitere" in r["summary"][-1]


def test_store_ignores_foreign_files(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path, "../evil host", keep=5)
    assert store.dir == tmp_path / "_evil_host" / "snapshots"
    store.dir.mkdir(parents=True)
    (store.dir / "notes.json").write_text("{}")
    assert store.ids() == []
