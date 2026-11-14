"""Stage 8.6 – FRITZ as Code: spec parsing, drift, plan/execute (mock box only)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from fritzos8_mcp.errors import InvalidParameterError, PlanError, TierDisabledError
from fritzos8_mcp.fritzcode import load_spec
from fritzos8_mcp.landevice import LanDeviceClient

from .test_access_ports import Box, service

SPEC = """
version: 1
internet_access:
  "aa-bb-cc-dd-ee-02": false
static_ip:
  "AA:BB:CC:DD:EE:01": true
tam: {0: false}
dns_dhcp: ["192.0.2.53"]
port_forwards:
  - {protocol: TCP, external_port: 8443, internal_port: 443, ip: 192.0.2.20}
  - {protocol: UDP, external_port: 51820, internal_port: 51820, ip: 192.0.2.50}
"""


def make(landevices: LanDeviceClient, *, critical: bool = True) -> tuple[Any, Any, dict[str, Any]]:
    box = Box()
    svc, fc = service(landevices, box, critical=critical)
    tam = {"enabled": True}
    svc.tam_list = lambda: {"machines": [{"index": 0, "name": "AB", "enabled": tam["enabled"]}]}  # type: ignore[method-assign]

    def set_tam(index: int, enabled: bool) -> dict[str, Any]:
        tam["enabled"] = enabled
        return {"index": index, "enabled": enabled, "changed": True, "verified": True}

    svc.set_tam_enabled = set_tam  # type: ignore[method-assign]
    fc.responses[("LANHostConfigManagement1", "GetDNSServer")] = {"NewDNSServers": "192.0.2.1"}
    return svc, box, tam


@pytest.mark.parametrize(
    "spec,name,msg",
    [
        (None, None, "Genau eins"),
        ("a: [", None, "kein gültiges YAML"),
        ("- 1", None, "YAML-Objekt"),
        ("wlan_password: x", None, "Unbekannte Schlüssel"),
        ("version: 2", None, "version: 1"),
        (None, "../etc/passwd", "kein Pfad"),
        (None, "fehlt.yaml", "nicht lesbar"),
    ],
)
def test_load_spec_errors(spec: str | None, name: str | None, msg: str, tmp_path: Path) -> None:
    with pytest.raises(InvalidParameterError) as ei:
        load_spec(spec, name, tmp_path)
    assert msg in str(ei.value) + (ei.value.hint or "")


def test_load_spec_from_file(tmp_path: Path) -> None:
    (tmp_path / "heim.yaml").write_text("version: 1\nguest_wifi: false\n", encoding="utf-8")
    assert load_spec(None, "heim.yaml", tmp_path) == {"version": 1, "guest_wifi": False}


def test_drift(landevices: LanDeviceClient) -> None:
    svc, _, _ = make(landevices)
    d = svc.code.drift(SPEC)
    kinds = sorted(a["kind"] for a in d["applicable"])
    assert kinds == ["internet_access", "static_ip", "tam"]
    dns = next(a for a in d["not_applicable"] if a["kind"] == "dns_dhcp")
    assert dns["current"] == ["192.0.2.1"] and dns["desired"] == ["192.0.2.53"] and "7.2" in dns["reason"]
    assert any(a["kind"] == "port_forward" and a["current"] == "fehlt" for a in d["not_applicable"])
    assert any(a["kind"] == "dns_dhcp" for a in d["not_applicable"]) and d["errors"] == {}
    ports = [a for a in d["not_applicable"] if a["kind"] == "port_forward"]
    assert len(ports) == 1 and "51820" in ports[0]["target"]  # the existing 8443 forward matches


def test_plan_execute_idempotent(landevices: LanDeviceClient) -> None:
    svc, box, tam = make(landevices)
    plan = svc.code.plan(SPEC)
    assert len(plan["actions"]) == 3 and "gesperrt" in " ".join(plan["warnings"])
    r = svc.code.execute(plan["token"])
    assert r["applied"] == 3 and r["verified"] == 3 and r["failed"] == []
    assert box.blocked["192.0.2.30"] is True and tam["enabled"] is False
    assert svc.code.drift(SPEC)["applicable"] == []  # now in sync
    with pytest.raises(PlanError):
        svc.code.execute(plan["token"])
    assert "Nichts anzuwenden" in svc.code.plan(SPEC)["note"]


def test_execute_reports_failures_without_stopping(landevices: LanDeviceClient) -> None:
    svc, box, _ = make(landevices)
    plan = svc.code.plan("version: 1\ninternet_access: {'AA:BB:CC:DD:EE:02': false}\ntam: {0: false}")
    box.discard = True  # box silently drops the host filter change
    r = svc.code.execute(plan["token"])
    assert r["applied"] == 2 and r["verified"] == 1 and len(r["failed"]) == 1


def test_apply_needs_critical(landevices: LanDeviceClient) -> None:
    svc, _, _ = make(landevices, critical=False)
    with pytest.raises(TierDisabledError):
        svc.code.plan(SPEC)
    assert svc.code.drift(SPEC)["checked"] > 0  # drift stays read-only


def test_export_round_trip(landevices: LanDeviceClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FRITZ_CODE_DIR", str(tmp_path / "code"))
    svc, _, _ = make(landevices)
    r = svc.code.export(save_as="heim.yaml")
    assert "static_ip" in r["yaml"] and "tam" in r["yaml"]
    assert Path(r["saved_to"]).stat().st_mode & 0o777 == 0o600
    d = svc.code.drift(name="heim.yaml")
    assert d["applicable"] == []  # exported state is in sync with the box
    with pytest.raises(InvalidParameterError):
        svc.code.export(save_as="../x.yaml")


def test_tam_label_ohne_doppelung() -> None:
    from fritzos8_mcp.fritzcode import _tam_label

    assert _tam_label("Anrufbeantworter", 0) == "Anrufbeantworter"
    assert _tam_label("Büro", 1) == "Anrufbeantworter Büro"
    assert _tam_label(None, 2) == "Anrufbeantworter 2"
