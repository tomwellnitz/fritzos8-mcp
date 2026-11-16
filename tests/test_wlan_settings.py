"""Stage 7.4 – WLAN settings: channel/auto channel, night control, SetChannel with read-back."""

from __future__ import annotations

from typing import Any

import pytest

from fritzos8_mcp.errors import InvalidParameterError, TierDisabledError
from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.wlan import parse_channels, parse_night_control, wlan_light_hints

from .conftest import FakeBox, make_service
from .test_wlan import KEY, Radios, wlan_fc

NIGHT_XML = (
    "<NightControl><Enabled>1</Enabled><Timer><Start>23:00</Start><End>06:00</End></Timer>"
    "<Timer><Start>00:00</Start><End>07:00</End></Timer></NightControl>"
)


class ChannelRadios(Radios):
    """Radios with GetChannelInfo/SetChannel per AVM doc (argument name spelled as in the doc)."""

    def __init__(
        self, *, discard_channel: bool = False, auto_off_only: bool = False, auto_field: bool = True, **kw: Any
    ) -> None:
        super().__init__(**kw)
        self.discard_channel = discard_channel
        self.auto_off_only = auto_off_only
        self.auto_field = auto_field
        self.auto = {1: False, 2: True, 3: False}
        self.possible = {1: "1,2,3,4,5,6,7,8,9,10,11,12,13", 2: "36,40,44,48,52,56,60,64,100,104", 3: "1,6,11"}
        self.freq = {1: "2400", 2: "5000", 3: "2400"}

    def responses(self) -> dict[tuple[str, str], Any]:
        out = super().responses()
        for i in self.state:
            svc = f"WLANConfiguration{i}"

            def info(i: int = i) -> dict[str, Any]:
                r = {
                    "NewChannel": self.state[i]["NewChannel"],
                    "NewPossibleChannels": self.possible[i],
                    "NewX_AVM-DE_FrequencyBand": self.freq[i],
                }
                if self.auto_field:
                    r["NewX_AVM-DEAuto_ChannelEnabled"] = "1" if self.auto[i] else "0"
                return r

            out[(svc, "GetChannelInfo")] = info
            out[(svc, "SetChannel")] = lambda NewChannel, i=i: self._set_channel(i, NewChannel)
        out[("WLANConfiguration1", "X_AVM-DE_GetNightControl")] = {
            "NewNightControl": NIGHT_XML,
            "NewNightTimeControlNoForcedOff": "1",
        }
        base_info = out[("WLANConfiguration1", "GetInfo")]
        out[("WLANConfiguration1", "GetInfo")] = lambda: {**base_info(), "NewX_AVM-DE_WLANGlobalEnable": "1"}
        return out

    def _set_channel(self, i: int, channel: int) -> dict[str, Any]:
        if self.auto_off_only:  # live 6660/8.25: fixed channel only switches auto off, channel stays
            self.auto[i] = channel == 0
            return {}
        if not self.discard_channel:
            if channel == 0:
                self.auto[i] = True
            else:
                self.auto[i] = False
                self.state[i]["NewChannel"] = channel
        return {}


def test_parse_helpers() -> None:
    assert parse_channels("36, 40;44 x 48") == [36, 40, 44, 48]
    flat = parse_night_control(NIGHT_XML)
    assert flat["NightControl/Enabled"] == "1"
    assert flat["NightControl/Timer/Start"] == ["23:00", "00:00"]


def test_wlan_settings_reads_channels_auto_and_night_control(landevices: LanDeviceClient) -> None:
    r = make_service(landevices, wlan_fc(ChannelRadios())).wlan_settings()
    radios = {x["band_ghz"]: x for x in r["radios"]}
    assert set(radios) == {"2.4", "5"}  # guest network is not a radio of its own
    assert radios["2.4"]["channel"] == 6 and radios["2.4"]["auto_channel"] is False
    assert radios["5"]["auto_channel"] is True
    assert radios["5"]["possible_channels"][:2] == [36, 40]
    assert radios["5"]["channel_width_mhz"] is None
    assert r["wlan_global_enabled"] is True
    assert r["night_control"]["no_forced_off"] is True
    assert r["night_control"]["settings"]["NightControl/Timer/End"] == ["06:00", "07:00"]
    assert r["band_steering"]["status"] == "unknown"
    assert KEY not in repr(r)


def test_wlan_settings_without_night_control_action(landevices: LanDeviceClient) -> None:
    radios = ChannelRadios()
    fc = wlan_fc(radios)
    from fritzconnection.core.exceptions import FritzActionError

    fc.responses[("WLANConfiguration1", "X_AVM-DE_GetNightControl")] = FritzActionError("unknown action")
    r = make_service(landevices, fc).wlan_settings()
    assert r["night_control"]["available"] is False


def test_set_channel_verified(landevices: LanDeviceClient) -> None:
    radios = ChannelRadios()
    fc = wlan_fc(radios)
    r = make_service(landevices, fc).set_wlan_channel("2.4", 11)
    assert r["verified"] is True and r["changed"] is True
    assert r["before"]["channel"] == 6 and r["after"]["channel"] == 11
    assert ("WLANConfiguration1", "SetChannel", {"NewChannel": 11}) in fc.calls


def test_set_channel_auto(landevices: LanDeviceClient) -> None:
    radios = ChannelRadios()
    r = make_service(landevices, wlan_fc(radios)).set_wlan_channel("2.4", 0)
    assert r["verified"] is True and r["after"]["auto_channel"] is True


def test_set_channel_auto_unverifiable_without_flag(landevices: LanDeviceClient) -> None:
    radios = ChannelRadios(auto_field=False)
    r = make_service(landevices, wlan_fc(radios)).set_wlan_channel("2.4", 0)
    assert r["verified"] is False
    assert "Autokanal-Status" in r["note"]


def test_set_channel_unchanged(landevices: LanDeviceClient) -> None:
    radios = ChannelRadios()
    fc = wlan_fc(radios)
    r = make_service(landevices, fc).set_wlan_channel("2.4", 6)
    assert r["changed"] is False and r["verified"] is True
    assert not any(c[1] == "SetChannel" for c in fc.calls)


def test_set_channel_rejects_impossible_channel(landevices: LanDeviceClient) -> None:
    with pytest.raises(InvalidParameterError, match="nicht erlaubt"):
        make_service(landevices, wlan_fc(ChannelRadios())).set_wlan_channel("5", 165)


def test_set_channel_dfs_warning_and_discarded(landevices: LanDeviceClient) -> None:
    radios = ChannelRadios(discard_channel=True)
    r = make_service(landevices, wlan_fc(radios)).set_wlan_channel("5", 100)
    assert r["verified"] is False and r["changed"] is False
    assert any("DFS" in w for w in r["warnings"])
    assert "nicht" in r["note"]


def test_set_channel_partial_write_restores_auto_channel(landevices: LanDeviceClient) -> None:
    # Regression (live 6660/8.25): fixed channel not applied, but auto channel switched off → was "changed: false"
    radios = ChannelRadios(auto_off_only=True)
    fc = wlan_fc(radios)
    r = make_service(landevices, fc).set_wlan_channel("5", 44)
    assert r["verified"] is False
    assert r["restored"]["ok"] is True and r["after"]["auto_channel"] is True
    assert r["changed"] is False  # back to the state before
    assert any("wiederhergestellt" in w for w in r["warnings"])
    assert ("WLANConfiguration2", "SetChannel", {"NewChannel": 0}) in fc.calls
    assert radios.auto[2] is True


def test_set_channel_partial_write_without_restore_reports_change(landevices: LanDeviceClient) -> None:
    radios = ChannelRadios(auto_off_only=True)
    radios.auto[1] = False  # auto already off: a fixed channel is just not applied → no change, no restore
    r = make_service(landevices, wlan_fc(radios)).set_wlan_channel("2.4", 11)
    assert r["verified"] is False and r["changed"] is False and "restored" not in r


def test_set_channel_needs_write(landevices: LanDeviceClient) -> None:
    with pytest.raises(TierDisabledError):
        make_service(landevices, wlan_fc(ChannelRadios()), write=False, critical=False).set_wlan_channel("5", 36)


def test_wlan_light_hints_drop_secrets() -> None:
    data = {
        "ap": [
            {"channel": "36", "bandwidth": "80", "band_steering": "1", "wpa_key": "x", "psk_mode": "y"},
        ],
        "nightTimer": {"active": "1", "start": "23:00"},
        "ssid": "Heim",
    }
    hints = wlan_light_hints(data)
    assert hints["ap[0].channel"] == "36"
    assert hints["ap[0].band_steering"] == "1"
    assert hints["nightTimer.active"] == "1"
    assert not any("key" in k or "psk" in k for k in hints)
    assert "ssid" not in hints


def test_wlan_settings_web_ui_hints(landevices: LanDeviceClient, fake_box: FakeBox) -> None:
    fake_box.generic["wlan_light"] = {"radio": [{"autochannel": "1", "wpa_key": "nein"}]}
    r = make_service(landevices, wlan_fc(ChannelRadios())).wlan_settings(include_web_ui=True)
    assert r["web_ui_hints"]["fields"] == {"radio[0].autochannel": "1"}
    assert r["web_ui_hints"]["verified_structure"] is False


def test_wlan_settings_web_ui_missing(landevices: LanDeviceClient) -> None:
    r = make_service(landevices, wlan_fc(ChannelRadios())).wlan_settings(include_web_ui=True)
    assert r["web_ui_hints"]["error"]["type"] in {"unsupported_firmware", "not_found"}
