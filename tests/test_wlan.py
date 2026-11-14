from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from fritzconnection.core.exceptions import FritzActionError, FritzConnectionException

from fritzos8_mcp.errors import (
    ConfirmationRequiredError,
    InvalidParameterError,
    NotFoundError,
    PlanError,
    TierDisabledError,
)
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.wlan import band_from, normalize_band

from .conftest import FakeFC, make_service

KEY = "SuperGeheimerWLANKey123"


class Radios:
    """In-memory WLANConfiguration1..3 of a dual-band box (3 = guest)."""

    def __init__(self, *, ap_type: bool = True, discard: bool = False, guest_open: bool = False) -> None:
        self.discard = discard
        self.ap_type = ap_type
        self.state: dict[int, dict[str, Any]] = {
            1: {"NewEnable": True, "NewSSID": "Heim", "NewChannel": 6, "NewStandard": "ax", "NewBeaconType": "11i"},
            2: {"NewEnable": True, "NewSSID": "Heim", "NewChannel": 36, "NewStandard": "ax", "NewBeaconType": "11i"},
            3: {
                "NewEnable": False,
                "NewSSID": "Gast",
                "NewChannel": 6,
                "NewStandard": "n",
                "NewBeaconType": "None" if guest_open else "WPAand11i",
            },
        }
        self.clients = {1: 4, 2: 7, 3: 0}

    def responses(self) -> dict[tuple[str, str], Any]:
        out: dict[tuple[str, str], Any] = {}
        for i in self.state:
            svc = f"WLANConfiguration{i}"
            out[(svc, "GetInfo")] = lambda i=i: {
                **self.state[i],
                "NewStatus": "Up" if self.state[i]["NewEnable"] else "Disabled",
                "NewBSSID": f"AA:BB:CC:00:00:0{i}",
                # A secret that must never leak, even if the box sent it here.
                "NewKeyPassphrase": KEY,
            }
            out[(svc, "GetTotalAssociations")] = lambda i=i: {"NewTotalAssociations": self.clients[i]}
            if self.ap_type:
                out[(svc, "X_AVM-DE_GetWLANExtInfo")] = lambda i=i: {
                    "NewX_AVM-DE_APType": "guest" if i == 3 else "normal",
                    "NewX_AVM-DE_TimeoutActive": "1",
                    "NewX_AVM-DE_Timeout": 360,
                    "NewX_AVM-DE_TimeRemain": 120,
                    "NewX_AVM-DE_UserIsolation": "1",
                }
            else:
                out[(svc, "X_AVM-DE_GetWLANExtInfo")] = FritzActionError("unknown action")
            out[(svc, "SetEnable")] = lambda NewEnable, i=i: self._set(i, NewEnable)
        return out

    def _set(self, i: int, value: int) -> dict[str, Any]:
        if not self.discard:
            self.state[i]["NewEnable"] = bool(value)
        return {}


def wlan_fc(radios: Radios) -> FakeFC:
    fc = FakeFC(radios.responses())
    for i in (2, 3):
        fc.services[f"WLANConfiguration{i}"] = SimpleNamespace(actions={}, state_variables={})
    return fc


# ------------------------------------------------------------------ helpers


@pytest.mark.parametrize("raw,band", [("2.4", "2.4"), ("2,4 GHz", "2.4"), ("24", "2.4"), ("5ghz", "5"), ("6", "6")])
def test_normalize_band(raw: str, band: str) -> None:
    assert normalize_band(raw) == band


def test_normalize_band_rejects() -> None:
    with pytest.raises(InvalidParameterError):
        normalize_band("60")


def test_band_prefers_explicit_field() -> None:
    assert band_from({"NewChannel": 37, "NewX_AVM-DE_FrequencyBand": "6000"}, None) == ("6", "field")
    assert band_from({"NewChannel": 11}, None) == ("2.4", "channel")
    assert band_from({"NewChannel": 0}, None) == (None, "unknown")


# ------------------------------------------------------------------ read


def test_wlan_status_lists_bands_without_keys(landevices: LanDeviceClient) -> None:
    r = make_service(landevices, wlan_fc(Radios())).wlan_status()
    assert r["count"] == 3
    nets = {n["service"]: n for n in r["networks"]}
    assert nets["WLANConfiguration1"]["band_ghz"] == "2.4"
    assert nets["WLANConfiguration2"]["band_ghz"] == "5"
    assert nets["WLANConfiguration2"]["clients"] == 7
    assert nets["WLANConfiguration3"]["guest"] is True
    assert nets["WLANConfiguration3"]["guest_detection"] == "ap_type"
    assert nets["WLANConfiguration3"]["guest_extra"]["time_remaining_min"] == 120
    assert nets["WLANConfiguration3"]["guest_extra"]["user_isolation"] is True
    assert KEY not in json.dumps(r)  # whitelist: key never even copied


def test_guest_extra_field_names_after_avm_doc(landevices: LanDeviceClient) -> None:
    """AVM doc: NewX_AVM-DE_UserIsolation / NewX_AVM-DE_NoForcedOff; old '…Enabled' spelling = fallback;
    a missing field is None (unknown), never False."""
    fc = wlan_fc(Radios())
    fc.responses[("WLANConfiguration3", "X_AVM-DE_GetWLANExtInfo")] = {
        "NewX_AVM-DE_APType": "guest",
        "NewX_AVM-DE_NoForcedOff": "1",
    }
    extra = make_service(landevices, fc).guest_wifi_status()["guest_extra"]
    assert extra["user_isolation"] is None and extra["no_forced_off"] is True
    fc.responses[("WLANConfiguration3", "X_AVM-DE_GetWLANExtInfo")] = {
        "NewX_AVM-DE_APType": "guest",
        "NewX_AVM-DE_UserIsolationEnabled": "0",
    }
    extra = make_service(landevices, fc).guest_wifi_status()["guest_extra"]
    assert extra["user_isolation"] is False and extra["no_forced_off"] is None


def test_guest_falls_back_to_highest_service(landevices: LanDeviceClient) -> None:
    g = make_service(landevices, wlan_fc(Radios(ap_type=False))).guest_wifi_status()
    assert g["service"] == "WLANConfiguration3" and g["guest_detection"] == "position"


def test_guest_missing(landevices: LanDeviceClient) -> None:
    fc = FakeFC({("WLANConfiguration1", "GetInfo"): {"NewEnable": True, "NewChannel": 6}})
    with pytest.raises(NotFoundError, match="Gast"):
        make_service(landevices, fc).guest_wifi_status()


# ------------------------------------------------------------------ set_guest_wifi


def test_set_guest_wifi_needs_write(landevices: LanDeviceClient) -> None:
    fc = wlan_fc(Radios())
    with pytest.raises(TierDisabledError):
        make_service(landevices, fc, write=False, critical=False).set_guest_wifi(True)
    assert fc.calls == []


def test_set_guest_wifi_verified(landevices: LanDeviceClient) -> None:
    radios = Radios()
    fc = wlan_fc(radios)
    r = make_service(landevices, fc).set_guest_wifi(True)
    assert r["verified"] is True and r["changed"] is True and r["ssid"] == "Gast"
    assert ("WLANConfiguration3", "SetEnable", {"NewEnable": 1}) in fc.calls
    assert radios.state[3]["NewEnable"] is True
    assert radios.state[1]["NewEnable"] is True  # other radios untouched


def test_set_guest_wifi_unchanged(landevices: LanDeviceClient) -> None:
    fc = wlan_fc(Radios())
    r = make_service(landevices, fc).set_guest_wifi(False)
    assert r == {
        "service": "WLANConfiguration3",
        "enabled": False,
        "ssid": "Gast",
        "guest_detection": "ap_type",
        "changed": False,
        "verified": True,
    }
    assert not [c for c in fc.calls if c[1] == "SetEnable"]


def test_set_guest_wifi_silently_discarded(landevices: LanDeviceClient) -> None:
    r = make_service(landevices, wlan_fc(Radios(discard=True))).set_guest_wifi(True)
    assert r["verified"] is False and r["read_back"] is False
    assert "nicht übernommen" in r["note"]


def test_set_guest_wifi_two_factor(landevices: LanDeviceClient) -> None:
    radios = Radios()
    fc = wlan_fc(radios)
    fc.responses[("WLANConfiguration3", "SetEnable")] = FritzConnectionException("errorCode: 866")
    with pytest.raises(ConfirmationRequiredError):
        make_service(landevices, fc).set_guest_wifi(True)


# ------------------------------------------------------------------ set_wlan_enabled (critical)


def test_set_wlan_enabled_needs_critical(landevices: LanDeviceClient) -> None:
    svc = make_service(landevices, wlan_fc(Radios()), write=True, critical=False)
    with pytest.raises(TierDisabledError):
        svc.set_wlan_enabled_plan("5", False)
    with pytest.raises(TierDisabledError):
        svc.set_wlan_enabled_execute("t", "5", False)


def test_set_wlan_enabled_plan_execute(landevices: LanDeviceClient) -> None:
    radios = Radios()
    fc = wlan_fc(radios)
    svc = make_service(landevices, fc)
    plan = svc.set_wlan_enabled_plan("5 GHz", False)
    assert plan["target"]["service"] == "WLANConfiguration2"
    assert "sperrt man sich aus" in plan["consequence"] and "alle 7" in plan["consequence"]
    assert not [c for c in fc.calls if c[1] == "SetEnable"]  # planning changes nothing
    r = svc.set_wlan_enabled_execute(plan["token"], "5", False)
    assert r["verified"] is True and r["band_ghz"] == "5"
    assert radios.state[2]["NewEnable"] is False and radios.state[1]["NewEnable"] is True
    with pytest.raises(PlanError):
        svc.set_wlan_enabled_execute(plan["token"], "5", False)


def test_set_wlan_enabled_token_bound_to_params(landevices: LanDeviceClient) -> None:
    radios = Radios()
    svc = make_service(landevices, wlan_fc(radios))
    plan = svc.set_wlan_enabled_plan("5", False)
    with pytest.raises(PlanError, match="passt nicht"):
        svc.set_wlan_enabled_execute(plan["token"], "2.4", False)
    assert radios.state[1]["NewEnable"] is True


def test_set_wlan_enabled_target_changed(landevices: LanDeviceClient) -> None:
    radios = Radios()
    svc = make_service(landevices, wlan_fc(radios))
    plan = svc.set_wlan_enabled_plan("5", False)
    radios.state[2]["NewSSID"] = "Anders"
    with pytest.raises(PlanError, match="geändert"):
        svc.set_wlan_enabled_execute(plan["token"], "5", False)


def test_set_wlan_enabled_already_in_state(landevices: LanDeviceClient) -> None:
    plan = make_service(landevices, wlan_fc(Radios())).set_wlan_enabled_plan("2.4", True)
    assert plan["changed"] is False and "token" not in plan


def test_set_wlan_enabled_unknown_band(landevices: LanDeviceClient) -> None:
    with pytest.raises(NotFoundError):
        make_service(landevices, wlan_fc(Radios())).set_wlan_enabled_plan("6", True)


def test_broken_service_does_not_hide_others(landevices: LanDeviceClient) -> None:
    radios = Radios()
    fc = wlan_fc(radios)
    fc.responses[("WLANConfiguration2", "GetInfo")] = FritzActionError("unknown action")
    r = make_service(landevices, fc).wlan_status()
    nets = {n["service"]: n for n in r["networks"]}
    assert nets["WLANConfiguration2"]["error"]["type"] == "not_found"
    assert nets["WLANConfiguration1"]["enabled"] is True and nets["WLANConfiguration3"]["guest"] is True
