from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from fritzos8_mcp.cleanup import (
    ProtectionContext,
    analyze,
    is_generic_name,
    last_seen,
    make_unique,
    mesh_node_macs,
    normalize_name,
)
from fritzos8_mcp.errors import InvalidParameterError, PlanError, TierDisabledError
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.oui import (
    OUI_URL,
    OuiDb,
    avm_mac_kind,
    is_locally_administered,
    parse_oui_csv,
    short_vendor,
    universal_variant,
)

from .conftest import FakeBox, FakeFC, make_service
from .test_service import HostNames, fc_with_names

OUI_CSV = (
    "Registry,Assignment,Organization Name,Organization Address\n"
    'MA-L,001A2B,"Example Networks, Inc.",Musterweg 1 Musterstadt DE\n'
    "MA-L,3C1234,Apple Inc.,1 Example Park Cupertino US\n"
    "MA-L,C0FFEE,AVM Audiovisuelles Marketing und Computersysteme GmbH,Berlin DE\n"
)
NOW = 1_800_000_000.0
DAY = 86400


def dev(uid: str, mac: str, name: str, **kw: Any) -> dict[str, Any]:
    base = {
        "UID": uid,
        "name": name,
        "friendly_name": name,
        "mac": mac,
        "ip": "",
        "static_dhcp": "0",
        "active": "0",
        "online": "0",
        "deleteable": "1",
        "flags": "",
    }
    base.update(kw)
    return base


DEVICES = [
    dev(
        "landevice1",
        "C0:FF:EE:00:00:01",
        "fritz.box",
        ip="192.0.2.1",
        active="1",
        online="1",
        deleteable="0",
        flags="ownentry",
    ),
    dev("landevice10", "3C:12:34:00:00:10", "iPhone von Kim", ip="192.0.2.10", active="1", online="1"),
    dev("landevice11", "DA:A1:19:00:00:11", "iPhone", ip="192.0.2.11", static_dhcp="1"),  # random, static
    dev("landevice12", "00:1A:2B:00:00:12", "PC-192-0-2-12", ip="192.0.2.12"),  # generic name
    dev("landevice13", "", "ohne-mac"),
    dev("landevice14", "00:1A:2B:00:00:14", "Drucker", ip="192.0.2.14"),
    dev("landevice15", "00:1A:2B:00:00:15", "Drucker", ip="192.0.2.15", static_dhcp="1"),
    dev("landevice16", "DA:A1:19:00:00:16", "Gast-Handy", ip="192.0.2.16", online="1"),  # random but online
    dev("landevice17", "00:1A:2B:00:00:17", "Küche Radio", ip="192.0.2.17"),
    dev("landevice18", "00:1A:2B:00:00:18", "Alt-Scanner", ip="192.0.2.18", last_seen=str(int(NOW - 200 * DAY))),
]


def oui_db(tmp_path: Path, text: str = OUI_CSV, *, fail: bool = False) -> OuiDb:
    def fetch() -> str:
        if fail:
            raise httpx.ConnectError("offline")
        return text

    return OuiDb(tmp_path / "oui.csv", fetch=fetch, download=True, now=lambda: NOW)


# ------------------------------------------------------------------ OUI


def test_parse_and_short_vendor() -> None:
    m = parse_oui_csv(OUI_CSV)
    assert m["001A2B"] == "Example Networks, Inc."
    assert short_vendor("Apple Inc.") == "Apple"
    assert short_vendor(m["C0FFEE"]) == "AVM"
    assert short_vendor("Example Networks, Inc.") == "Example"
    assert short_vendor(None) is None


def test_locally_administered() -> None:
    assert is_locally_administered("DA:A1:19:00:00:11")
    assert is_locally_administered("02:00:00:00:00:01")
    assert not is_locally_administered("00:1A:2B:00:00:12")
    assert not is_locally_administered("")


def test_oui_downloads_once_and_caches_private(tmp_path: Path) -> None:
    calls = []
    db = OuiDb(tmp_path / "c" / "oui.csv", fetch=lambda: calls.append(1) or OUI_CSV, download=True, now=lambda: NOW)
    assert db.vendor("3c-12-34-aa-bb-cc") == "Apple"
    assert db.vendor("00:1A:2B:00:00:01") == "Example"
    assert db.source == "download" and len(calls) == 1
    assert (tmp_path / "c" / "oui.csv").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "c").stat().st_mode & 0o777 == 0o700
    # second instance: fresh cache, no download
    db2 = OuiDb(
        tmp_path / "c" / "oui.csv", fetch=lambda: pytest.fail("no download"), download=True, now=lambda: time.time()
    )
    assert db2.vendor("3C:12:34:00:00:01") == "Apple" and db2.source == "cache"


def test_oui_random_mac_has_no_vendor(tmp_path: Path) -> None:
    assert oui_db(tmp_path).vendor("DA:A1:19:00:00:11") is None


def test_oui_offline_without_cache(tmp_path: Path) -> None:
    db = oui_db(tmp_path, fail=True)
    assert db.vendor("3C:12:34:00:00:01") is None and db.source == "none"


def test_oui_stale_cache_used_when_offline(tmp_path: Path) -> None:
    path = tmp_path / "oui.csv"
    path.write_text(OUI_CSV)
    old = NOW - 40 * DAY
    os.utime(path, (old, old))
    db = oui_db(tmp_path, fail=True)
    assert db.vendor("3C:12:34:00:00:01") == "Apple" and db.source == "stale-cache"


def test_oui_expired_cache_is_refreshed(tmp_path: Path) -> None:
    path = tmp_path / "oui.csv"
    path.write_text("Registry,Assignment,Organization Name\nMA-L,3C1234,Old Name\n")
    old = NOW - 31 * DAY
    os.utime(path, (old, old))
    db = oui_db(tmp_path)
    assert db.vendor("3C:12:34:00:00:01") == "Apple" and db.source == "download"


def test_oui_default_fetch_uses_ieee_url(respx_mock: Any, tmp_path: Path) -> None:
    route = respx_mock.get(OUI_URL).mock(return_value=httpx.Response(200, text=OUI_CSV))
    db = OuiDb(tmp_path / "oui.csv", download=True)
    assert db.vendor("3C:12:34:00:00:01") == "Apple" and route.called


def test_oui_download_disabled_by_env(tmp_path: Path) -> None:
    db = OuiDb(tmp_path / "oui.csv", fetch=lambda: pytest.fail("must not download"))
    assert db.vendor("3C:12:34:00:00:01") is None  # FRITZ_OUI_DOWNLOAD=0 from conftest


# ------------------------------------------------------------------ names


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Küche Radio", "Kueche-Radio"),
        ("Straßen_Lampe.1", "Strassen-Lampe-1"),
        ("  --Café  (alt)-- ", "Cafe-alt"),
        ("ÄÖÜ", "AeOeUe"),
        ("x" * 80, "x" * 63),
    ],
)
def test_normalize_name(raw: str, expected: str) -> None:
    assert normalize_name(raw) == expected


def test_make_unique() -> None:
    taken = {"Drucker", "drucker-2"}
    assert make_unique("Drucker", taken) == "Drucker-3"
    assert make_unique("Neu", taken) == "Neu"
    assert make_unique("neu", taken) == "neu-2"


def test_generic_names() -> None:
    assert is_generic_name("PC-192-0-2-12")
    assert is_generic_name("android-1a2b3c4d")
    assert is_generic_name("001a2b000012", "00:1A:2B:00:00:12")
    assert not is_generic_name("Drucker-Buero")


def test_last_seen_detection() -> None:
    assert last_seen({"last_seen": str(int(NOW - 5 * DAY))}, NOW) == (NOW - 5 * DAY, "last_seen")
    assert last_seen({"x_lastconnect": NOW - DAY}, NOW) == (NOW - DAY, "x_lastconnect")
    assert last_seen({"lastused": "0", "uptime": "12"}, NOW) == (None, None)
    assert last_seen({"last_seen": str(NOW + 10 * DAY)}, NOW) == (None, None)


# ------------------------------------------------------------------ analysis


def _report(tmp_path: Path, devices: list[dict[str, Any]] | None = None, **kw: Any) -> dict[str, Any]:
    return analyze(devices or DEVICES, [], oui_db(tmp_path), box_ips={"192.0.2.1"}, now=NOW, **kw)


def by_uid(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {i["uid"]: i for i in items}


VPN_CHECKED = ProtectionContext(vpn_checked=True)


def test_report_delete_candidates(tmp_path: Path) -> None:
    r = _report(tmp_path, context=VPN_CHECKED)
    cands = by_uid(r["delete_candidates"])
    assert "zufällige" in cands["landevice11"]["reasons"][0]
    assert any("verwaiste feste IP" in x for x in cands["landevice11"]["reasons"])
    assert "ohne gültige MAC" in cands["landevice13"]["reasons"][0]
    # duplicate name 'Drucker' with vendor MACs: info only, nothing proposed
    assert "landevice14" not in cands and "landevice15" not in cands
    dup = next(d for d in r["duplicates"] if d["by"] == "name" and d["value"] == "drucker")
    assert dup["keep"] == "landevice15" and dup["severity"] == "info"
    # long offline vendor MAC with a known age is proposed
    assert "seit 200 Tagen" in cands["landevice18"]["reasons"][0]
    # never: box, online devices (even with random MAC)
    assert not {"landevice1", "landevice10", "landevice16"} & set(cands)
    skipped = by_uid(r["not_proposed"])
    assert skipped["landevice16"]["not_proposed_because"] == "aktiv/online"
    assert r["last_seen_field"] == "last_seen"
    # plain offline devices without age are only listed
    assert "landevice12" in by_uid(r["offline_age_unknown"])


def test_report_entry_without_mac_needs_vpn_check(tmp_path: Path) -> None:
    skipped = by_uid(_report(tmp_path)["not_proposed"])
    assert "VPN-Liste nicht lesbar" in skipped["landevice13"]["not_proposed_because"]


# Live finding 14.11.2026: the report proposed a WireGuard peer (no MAC, IP in remote_networks, seen today) and a
# FRITZ!Powerline adapter with the locally administered variant of an AVM OUI for deletion.
def test_report_never_proposes_vpn_peers(tmp_path: Path) -> None:
    devices = [
        dev("landevice60", "", "wg-peer", ip="192.0.2.200", last_seen=str(int(NOW))),
        dev("landevice61", "", "wg-peer-alt", ip="198.51.100.7"),
        dev("landevice62", "", "ohne-mac-heute", ip="192.0.2.62", last_seen=str(int(NOW - 3600))),
        dev("landevice63", "", "ohne-mac-alt", ip="192.0.2.63", last_seen=str(int(NOW - 30 * DAY))),
    ]
    ctx = ProtectionContext(
        vpn_checked=True, vpn_networks=[("Büro", "192.0.2.200/32"), ("Büro", "198.51.100.0/24")], vpn_names={"büro"}
    )
    r = _report(tmp_path, devices, context=ctx)
    skipped = by_uid(r["not_proposed"])
    assert "VPN-Gegenstelle" in skipped["landevice60"]["not_proposed_because"]
    assert "VPN-Gegenstelle" in skipped["landevice61"]["not_proposed_because"]
    assert "heute noch gesehen" in skipped["landevice62"]["not_proposed_because"]
    assert set(by_uid(r["delete_candidates"])) == {"landevice63"}
    assert r["protection"]["vpn_list_checked"] is True


def test_avm_mac_detection() -> None:
    assert universal_variant("76:42:7F:00:00:01") == "74:42:7F:00:00:01"
    assert avm_mac_kind("74:42:7F:00:00:01") == "avm"
    assert avm_mac_kind("76:42:7F:00:00:01") == "avm_local"
    assert avm_mac_kind("7A:42:7F:00:00:01") == "avm_local"  # live: Powerline adapter, AVM block 74:42:7F
    assert avm_mac_kind("7A:42:7E:00:00:01") is None
    assert avm_mac_kind("DA:A1:19:00:00:11") is None and avm_mac_kind("") is None


def test_report_never_deletes_or_renames_avm_devices(tmp_path: Path) -> None:
    devices = [
        # locally administered address derived from the AVM block 74:42:7F (as seen live on a Powerline adapter)
        dev(
            "landevice70",
            "7A:42:7F:00:00:70",
            "FRITZ!Powerline 510E",
            ip="192.0.2.70",
            last_seen=str(int(NOW - 200 * DAY)),
        ),
        dev(
            "landevice71",
            "C0:FF:EE:00:00:71",
            "FRITZ!Repeater 1200 AX",
            ip="192.0.2.71",
            last_seen=str(int(NOW - 200 * DAY)),
        ),  # AVM per OUI db
        dev("landevice72", "DA:A1:19:00:00:72", "FRITZ!DECT 500", last_seen=str(int(NOW - 200 * DAY))),  # name
        dev("landevice73", "DA:A1:19:00:00:73", "Mesh-Knoten", last_seen=str(int(NOW - 200 * DAY))),  # mesh list
        dev("landevice74", "DA:A1:19:00:00:74", "Handy", ip="192.0.2.74"),  # real random MAC
    ]
    ctx = ProtectionContext(vpn_checked=True, mesh_macs={"DA:A1:19:00:00:73"}, mesh_checked=True)
    r = _report(tmp_path, devices, context=ctx)
    assert set(by_uid(r["delete_candidates"])) == {"landevice74"}
    skipped = by_uid(r["not_proposed"])
    assert "lokal administrierte Variante einer AVM-MAC" in skipped["landevice70"]["not_proposed_because"]
    assert not any("zufällige" in x for x in skipped["landevice70"]["reasons"])  # not a "random MAC"
    assert "AVM-Gerät" in skipped["landevice71"]["not_proposed_because"]
    assert "FRITZ!" in skipped["landevice72"]["not_proposed_because"]
    assert "Mesh-Liste" in skipped["landevice73"]["not_proposed_because"]
    assert not {"landevice70", "landevice71", "landevice72", "landevice73"} & set(by_uid(r["rename_suggestions"]))


def test_mesh_node_macs() -> None:
    doc = {
        "nodes": [
            {"device_mac_address": "AA:BB:CC:00:00:01", "mesh_role": "master", "node_interfaces": []},
            {
                "device_mac_address": "AA:BB:CC:00:00:02",
                "device_model": "FRITZ!Powerline 510E",
                "node_interfaces": [{"mac_address": "AA:BB:CC:00:00:03"}],
            },
            {"device_mac_address": "AA:BB:CC:00:00:09", "mesh_role": "unknown", "device_model": "Phone"},
        ]
    }
    assert mesh_node_macs(doc) == {"AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02", "AA:BB:CC:00:00:03"}


def test_report_long_offline_with_last_seen(tmp_path: Path) -> None:
    devices = [
        dev("landevice20", "00:1A:2B:00:00:20", "Alt-Tablet", last_seen=str(int(NOW - 200 * DAY))),
        dev("landevice21", "00:1A:2B:00:00:21", "Neu-Tablet", last_seen=str(int(NOW - 3 * DAY))),
    ]
    r = _report(tmp_path, devices, offline_days=90)
    cands = by_uid(r["delete_candidates"])
    assert set(cands) == {"landevice20"} and cands["landevice20"]["last_seen_days"] == 200
    assert r["last_seen_field"] == "last_seen"


def test_report_active_per_tr064_is_protected(tmp_path: Path) -> None:
    devices = [dev("landevice30", "DA:A1:19:00:00:30", "x")]
    hosts = [{"mac": "DA:A1:19:00:00:30", "active": True}]
    r = analyze(devices, hosts, oui_db(tmp_path), now=NOW)
    assert r["delete_candidates"] == [] and r["not_proposed"][0]["not_proposed_because"] == "aktiv/online"


def test_report_rename_suggestions(tmp_path: Path) -> None:
    r = _report(tmp_path)
    ren = by_uid(r["rename_suggestions"])
    assert ren["landevice12"]["suggested"] == "Example-Geraet" and ren["landevice12"]["vendor"] == "Example"
    assert ren["landevice17"]["suggested"] == "Kueche-Radio"
    assert "iPhone von Kim" in ren["landevice10"]["current"] and ren["landevice10"]["suggested"] == "iPhone-von-Kim"
    assert "landevice1" not in ren  # protected box entry
    assert r["vendor_source"] == "download"


def test_report_rename_unique_and_unknown_vendor(tmp_path: Path) -> None:
    devices = [
        dev("landevice40", "00:99:99:00:00:40", "android-aa11"),
        dev("landevice41", "00:99:99:00:00:41", "android-bb22"),
        dev("landevice42", "00:99:99:00:00:42", "Unbekannt-Geraet"),
    ]
    r = _report(tmp_path, devices)
    assert r["last_seen_field"] is None and "kein 'zuletzt online'" in r["note"]
    ren = by_uid(r["rename_suggestions"])
    assert ren["landevice40"]["vendor"] == "unknown"
    assert {ren["landevice40"]["suggested"], ren["landevice41"]["suggested"]} == {
        "Unbekannt-Geraet-2",
        "Unbekannt-Geraet-3",
    }


def test_plan_rejects_vpn_peer_and_avm(landevices: LanDeviceClient, fake_box: FakeBox, tmp_path: Path) -> None:
    fake_box.devices = [
        dev("landevice80", "00:1A:2B:00:00:80", "wg-peer", ip="192.0.2.200"),
        dev("landevice81", "7A:42:7F:00:00:81", "FRITZ!Powerline 510E", ip="192.0.2.81"),
    ]
    fake_box.generic["vpn"] = {
        "connection": [{"name": "Büro", "state": "ready", "wg_endpoint": "x", "display_remote_net": "192.0.2.200/32"}]
    }
    svc = make_service(landevices, FakeFC())
    svc.oui = oui_db(tmp_path)
    p = svc.devices_cleanup_plan(
        [
            {"action": "delete", "mac": "00:1A:2B:00:00:80"},
            {"action": "delete", "mac": "7A:42:7F:00:00:81"},
            {"action": "rename", "mac": "7A:42:7F:00:00:81", "name": "FRITZPowerline-510E"},
        ]
    )
    assert p["accepted"] == [] and "token" not in p
    reasons = [x["rejected"] for x in p["rejected"]]
    assert "VPN-Gegenstelle" in reasons[0] and "Löschen abgelehnt" in reasons[0]
    assert "AVM-Gerät" in reasons[1] and "nicht umbenannt" in reasons[2]


def test_report_works_offline(tmp_path: Path) -> None:
    r = analyze(DEVICES, [], oui_db(tmp_path, fail=True), now=NOW)
    assert r["vendor_source"] == "none"
    assert by_uid(r["rename_suggestions"])["landevice12"]["suggested"] == "Unbekannt-Geraet"


# ------------------------------------------------------------------ service: report / plan / execute


def cleanup_service(landevices: LanDeviceClient, fake_box: FakeBox, tmp_path: Path, names: HostNames | None = None):
    fake_box.devices = [dict(d) for d in DEVICES]
    svc = make_service(landevices, fc_with_names(names or HostNames()))
    svc.oui = oui_db(tmp_path)
    return svc


def test_service_report(landevices: LanDeviceClient, fake_box: FakeBox, tmp_path: Path) -> None:
    r = cleanup_service(landevices, fake_box, tmp_path).devices_cleanup_report()
    assert "landevice11" in by_uid(r["delete_candidates"])
    assert "hosts_note" not in r


def test_service_report_validates_days(landevices: LanDeviceClient, fake_box: FakeBox, tmp_path: Path) -> None:
    with pytest.raises(InvalidParameterError):
        cleanup_service(landevices, fake_box, tmp_path).devices_cleanup_report(0)


def test_plan_needs_write(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    svc = make_service(landevices, FakeFC(), write=False, critical=False)
    with pytest.raises(TierDisabledError):
        svc.devices_cleanup_plan([{"action": "delete", "mac": "DA:A1:19:00:00:11"}])
    with pytest.raises(TierDisabledError):
        svc.devices_cleanup_execute("x")
    assert fake_box.requests == []


def test_plan_rejects_unsafe_actions(landevices: LanDeviceClient, fake_box: FakeBox, tmp_path: Path) -> None:
    fake_box.devices = [dict(d) for d in DEVICES] + [
        dev("landevice50", "00:1A:2B:00:00:50", "a"),
        dev("landevice51", "00:1A:2B:00:00:50", "b"),
    ]
    svc = make_service(landevices, FakeFC())
    p = svc.devices_cleanup_plan(
        [
            {"action": "delete", "mac": "3C:12:34:00:00:10"},  # online
            {"action": "delete", "mac": "C0:FF:EE:00:00:01"},  # box
            {"action": "delete", "mac": "00:1A:2B:00:00:50"},  # ambiguous
            {"action": "rename", "mac": "00:1A:2B:00:00:12", "name": "Drucker"},  # name taken
            {"action": "rename", "mac": "00:1A:2B:00:00:17", "name": "!!!"},  # nothing left
            {"action": "delete", "mac": "kaputt"},
            {"action": "format", "mac": "00:1A:2B:00:00:12"},
        ]
    )
    assert p["accepted"] == [] and "token" not in p and len(p["rejected"]) == 7
    reasons = " ".join(x["rejected"] for x in p["rejected"])
    assert "aktiv/online" in reasons and "geschützt" in reasons and "mehrere Einträge" in reasons
    assert "schon vergeben" in reasons and "Ungültige MAC" in reasons and "Unbekannte Aktion" in reasons
    assert all(r.method == "GET" for r in fake_box.requests)


def test_plan_and_execute(landevices: LanDeviceClient, fake_box: FakeBox, tmp_path: Path) -> None:
    names = HostNames()
    svc = cleanup_service(landevices, fake_box, tmp_path, names)
    p = svc.devices_cleanup_plan(
        [
            {"action": "delete", "mac": "da-a1-19-00-00-11"},
            {"action": "rename", "mac": "00:1A:2B:00:00:17", "name": "Küche Radio"},
            {"action": "delete", "mac": "da-a1-19-00-00-11"},  # duplicate in plan
        ]
    )
    assert len(p["accepted"]) == 2 and p["accepted"][1]["name"] == "Kueche-Radio"
    assert p["accepted"][1]["normalized_from"] == "Küche Radio"
    assert "Mehrere Aktionen" in p["rejected"][0]["rejected"]
    assert all(r.method == "GET" for r in fake_box.requests)

    r = svc.devices_cleanup_execute(p["token"])
    assert r["done"] == 2 and r["verified"] == 2, r
    assert not any(d["UID"] == "landevice11" for d in fake_box.devices)
    renamed = next(d for d in fake_box.devices if d["UID"] == "landevice17")
    assert renamed["friendly_name"] == "Kueche-Radio" and names.names["00:1A:2B:00:00:17"] == "Kueche-Radio"
    with pytest.raises(PlanError):
        svc.devices_cleanup_execute(p["token"])  # one-time


def test_execute_rechecks_and_continues(landevices: LanDeviceClient, fake_box: FakeBox, tmp_path: Path) -> None:
    svc = cleanup_service(landevices, fake_box, tmp_path)
    p = svc.devices_cleanup_plan(
        [{"action": "delete", "mac": "DA:A1:19:00:00:11"}, {"action": "delete", "mac": "00:1A:2B:00:00:18"}]
    )
    # device 11 comes online between plan and execute → skipped, the other one still runs
    next(d for d in fake_box.devices if d["UID"] == "landevice11")["online"] = "1"
    r = svc.devices_cleanup_execute(p["token"])
    res = {x["uid"]: x for x in r["results"]}
    assert res["landevice11"]["ok"] is False and "aktiv/online" in res["landevice11"]["skipped"]
    assert res["landevice18"]["verified"] is True and r["failed_or_skipped"] == 1


def test_execute_reports_silent_discard(landevices: LanDeviceClient, fake_box: FakeBox, tmp_path: Path) -> None:
    svc = cleanup_service(landevices, fake_box, tmp_path)
    p = svc.devices_cleanup_plan([{"action": "delete", "mac": "00:1A:2B:00:00:18"}])
    fake_box.discard_writes = True
    r = svc.devices_cleanup_execute(p["token"])
    assert r["results"][0]["verified"] is False and "note" in r["results"][0]


# ------------------------------------------------------------------ live findings 14.11.2026 (box with 98 devices)


def test_same_ip_is_never_a_delete_reason(tmp_path: Path) -> None:
    devices = [
        dev("landevice90", "00:1A:2B:00:00:90", "Zisterne", ip="192.0.2.90"),  # offline, former IP reused
        dev("landevice91", "3C:12:34:00:00:91", "Laptop", ip="192.0.2.90", online="1", active="1"),
        dev("landevice92", "00:1A:2B:00:00:92", "Sauger", ip="192.0.2.92", last_seen=str(int(NOW - 10 * DAY))),
        dev("landevice93", "DA:A1:19:00:00:93", "Handy-alt", ip="192.0.2.92"),
    ]
    r = _report(tmp_path, devices, context=VPN_CHECKED)
    cands = by_uid(r["delete_candidates"])
    assert "landevice90" not in cands and "landevice92" not in cands
    assert not any("Duplikat" in x for c in cands.values() for x in c["reasons"])
    ip_dups = [d for d in r["duplicates"] if d["by"] == "ip"]
    assert {d["value"] for d in ip_dups} == {"192.0.2.90", "192.0.2.92"}
    assert all(d["severity"] == "info" and "keep" not in d for d in ip_dups)
    assert "landevice90" in by_uid(r["offline_age_unknown"])


def test_name_duplicate_only_for_random_macs_keeps_newest(tmp_path: Path) -> None:
    devices = [
        dev("landevice94", "DA:A1:19:00:00:94", "Tablet", last_seen=str(int(NOW - 40 * DAY))),
        dev("landevice95", "DA:A1:19:00:00:95", "Tablet", last_seen=str(int(NOW - 2 * DAY))),  # seen last
        dev("landevice96", "00:1A:2B:00:00:96", "Tablet", last_seen=str(int(NOW - 30 * DAY))),  # vendor MAC
    ]
    r = _report(tmp_path, devices, context=VPN_CHECKED)
    cands = by_uid(r["delete_candidates"])
    assert set(cands) == {"landevice94"}
    assert any("Duplikat" in x and "landevice95" in x for x in cands["landevice94"]["reasons"])
    skipped = by_uid(r["not_proposed"])
    assert "wird behalten" in skipped["landevice95"]["not_proposed_because"]
    dup = next(d for d in r["duplicates"] if d["by"] == "name")
    assert dup["keep"] == "landevice95" and dup["severity"] == "delete_candidates"


def test_online_entry_is_kept_in_name_duplicates(tmp_path: Path) -> None:
    devices = [
        dev("landevice97", "DA:A1:19:00:00:97", "Watch", online="1"),
        dev("landevice98", "DA:A1:19:00:00:98", "Watch", last_seen=str(int(NOW - DAY))),
    ]
    r = _report(tmp_path, devices, context=VPN_CHECKED)
    assert set(by_uid(r["delete_candidates"])) == {"landevice98"}
    assert next(d for d in r["duplicates"] if d["by"] == "name")["keep"] == "landevice97"


def test_vendor_mac_needs_known_old_last_seen(tmp_path: Path) -> None:
    devices = [
        # vendor MAC + fixed IP, last seen unknown: the orphaned-IP rule must not propose it
        dev("landevice100", "00:1A:2B:00:00:C0", "ESP-Steuerung", ip="192.0.2.100", static_dhcp="1"),
        dev(
            "landevice101",
            "00:1A:2B:00:00:C1",
            "PC-Alt",
            ip="192.0.2.101",
            static_dhcp="1",
            kisi_profile="filtprof3",
            last_seen=str(int(NOW - 120 * DAY)),
        ),
    ]
    r = _report(tmp_path, devices, context=VPN_CHECKED)
    cands = by_uid(r["delete_candidates"])
    assert set(cands) == {"landevice101"}
    warn = cands["landevice101"]["reasons"][-1]
    assert "feste IP-Zuweisung (192.0.2.101)" in warn and "Kindersicherungsprofil (kisi_profile=filtprof3)" in warn
    assert "landevice100" in by_uid(r["offline_age_unknown"])


def test_orphaned_static_ip_reason_only_offline(tmp_path: Path) -> None:
    devices = [dev("landevice102", "DA:A1:19:00:00:C2", "Handy", ip="192.0.2.102", static_dhcp="1", online="1")]
    r = _report(tmp_path, devices, context=VPN_CHECKED)
    skipped = by_uid(r["not_proposed"])["landevice102"]
    assert skipped["not_proposed_because"] == "aktiv/online"
    assert not any("verwaiste feste IP" in x for x in skipped["reasons"])


def test_rename_lost_umlaut_and_place_vendor(tmp_path: Path) -> None:
    csv = OUI_CSV + "MA-L,080B0C,China,Somewhere CN\nMA-L,000B0D,Shenzhen Bilian Electronic Co.,Ltd,CN\n"
    devices = [
        dev("landevice103", "00:1A:2B:00:00:C3", "K--chen-Wand"),
        dev("landevice104", "08:0B:0C:00:00:C4", "esp-0a0b0c"),
        dev("landevice105", "00:0B:0D:00:00:C5", "esp-000b0d"),
        dev("landevice106", "00:1A:2B:00:00:C6", "Bad Lüfter"),
    ]
    db = oui_db(tmp_path, csv)
    r = analyze(devices, [], db, now=NOW, context=VPN_CHECKED)
    ren = by_uid(r["rename_suggestions"])
    skipped = by_uid(r["rename_not_proposed"])
    assert "landevice103" not in ren and "Umlaut nicht rekonstruierbar" in skipped["landevice103"]["reason"]
    assert "landevice104" not in ren and "nicht verwertbar" in skipped["landevice104"]["reason"]
    assert ren["landevice105"]["suggested"] == "Bilian-Geraet"
    assert ren["landevice106"]["suggested"] == "Bad-Luefter"


def test_short_vendor_drops_places_and_legal_forms() -> None:
    assert short_vendor("China") is None
    assert short_vendor("Private") is None
    assert short_vendor("IEEE Registration Authority") is None
    assert short_vendor("Shenzhen Example Technology Co., Ltd") == "Example"
    assert short_vendor("Hangzhou Example Holding Co.,Ltd.") == "Example"
    assert short_vendor("Hon Hai Precision Ind. Co.,Ltd.") == "Hon Hai"


def test_plan_enforces_vendor_mac_and_duplicate_rules(
    landevices: LanDeviceClient, fake_box: FakeBox, tmp_path: Path
) -> None:
    fake_box.devices = [
        dev("landevice110", "00:1A:2B:00:00:D0", "Zisterne", ip="192.0.2.110"),  # age unknown
        dev("landevice111", "00:1A:2B:00:00:D1", "PC", ip="192.0.2.111", last_seen=str(int(time.time() - 5 * DAY))),
        dev("landevice112", "DA:A1:19:00:00:D2", "Tablet", last_seen=str(int(time.time() - DAY))),  # newest dup
        dev("landevice113", "DA:A1:19:00:00:D3", "Tablet", last_seen=str(int(time.time() - 50 * DAY))),
        dev(
            "landevice114",
            "00:1A:2B:00:00:D4",
            "Alt-PC",
            ip="192.0.2.114",
            static_dhcp="1",
            last_seen=str(int(time.time() - 40 * DAY)),
        ),
    ]
    svc = make_service(landevices, FakeFC())
    svc.oui = oui_db(tmp_path)
    p = svc.devices_cleanup_plan(
        [
            {"action": "delete", "mac": "00:1A:2B:00:00:D0"},
            {"action": "delete", "mac": "00:1A:2B:00:00:D1"},
            {"action": "delete", "mac": "DA:A1:19:00:00:D2"},
            {"action": "delete", "mac": "DA:A1:19:00:00:D3"},
            {"action": "delete", "mac": "00:1A:2B:00:00:D4"},
        ],
        offline_days=30,
    )
    rejected = {x["uid"]: x["rejected"] for x in p["rejected"]}
    assert "'zuletzt online' unbekannt" in rejected["landevice110"]
    assert "vor 5 Tagen" in rejected["landevice111"]
    assert "wird behalten" in rejected["landevice112"]
    accepted = by_uid(p["accepted"])
    assert set(accepted) == {"landevice113", "landevice114"}
    assert "feste IP-Zuweisung (192.0.2.114)" in accepted["landevice114"]["warning"]
    assert "offline_days" not in accepted["landevice114"] and "identity" not in accepted["landevice114"]
    # execute re-checks with the planned threshold
    r = svc.devices_cleanup_execute(p["token"])
    assert r["verified"] == 2, r


def test_execute_rechecks_vendor_mac_age(landevices: LanDeviceClient, fake_box: FakeBox, tmp_path: Path) -> None:
    svc = cleanup_service(landevices, fake_box, tmp_path)
    p = svc.devices_cleanup_plan([{"action": "delete", "mac": "00:1A:2B:00:00:18"}])
    # the device showed up again between plan and execute
    next(d for d in fake_box.devices if d["UID"] == "landevice18")["last_seen"] = str(int(time.time()))
    r = svc.devices_cleanup_execute(p["token"])
    assert r["results"][0]["ok"] is False and "noch kein Löschgrund" in r["results"][0]["skipped"]


def test_access_profile_ignores_kisi_display_flags() -> None:
    from fritzos8_mcp.cleanup import access_profile

    assert access_profile({"kisi_state_hide": "2", "name": "x"}) is None
    assert access_profile({"kisi_profile": "filtprof3"}) == ("kisi_profile", "filtprof3")
