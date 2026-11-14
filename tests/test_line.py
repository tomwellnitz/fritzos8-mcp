"""Stage 8.9 – line diagnostics per access type (fixtures after the AVM TR-064 documents, invented values)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fritzconnection.core.exceptions import FritzActionError, FritzServiceError

from fritzos8_mcp.landevice import LanDeviceClient
from fritzos8_mcp.line import classify_access, parse_cell_list, rsrp_rating

from .conftest import FakeFC, make_service

NO_FIBER = {("X_AVM-DE_WANFiber1", "GetInfo"): FritzServiceError("x")}
NO_MOBILE = {("X_AVM-DE_WANMobileConnection1", "GetInfo"): FritzServiceError("x")}

DSL = {
    ("WANCommonInterfaceConfig1", "GetCommonLinkProperties"): {"NewWANAccessType": "DSL"},
    ("WANDSLInterfaceConfig1", "GetInfo"): {
        "NewEnable": "1",
        "NewStatus": "Up",
        "NewDownstreamCurrRate": 116790,
        "NewUpstreamCurrRate": 46720,
        "NewDownstreamNoiseMargin": 90,
        "NewUpstreamNoiseMargin": 80,
    },
    ("WANDSLInterfaceConfig1", "X_AVM-DE_GetDSLInfo"): {
        "NewLinkStatus": "Up",
        "NewModulationType": "VDSL",
        "NewCurrentProfile": "17a",
        "NewSNRGds": 8,
        "NewSNRpsds": ",".join(["3"] * 30 + ["20"] * 70),
        "NewSNRpsus": "10,12,14",
    },
    ("WANDSLInterfaceConfig1", "X_AVM-DE_GetDSLDiagnoseInfo"): {
        "NewX_AVM-DE_DSLDigagnoseState": "DONE_CABLE_NOK",  # AVM spelling
        "NewX_AVM-DE_CableNokDistance": 37,
        "NewX_AVM-DE_DSLSignalLossTime": 400,
        "NewX_AVM-DE_DSLActive": 1,
        "NewX_AVM-DE_DSLSync": 0,
    },
    **NO_FIBER,
    **NO_MOBILE,
}

FIBER = {
    ("WANCommonInterfaceConfig1", "GetCommonLinkProperties"): {"NewWANAccessType": "X_AVM-DE_Fiber"},
    ("WANDSLInterfaceConfig1", "GetInfo"): FritzServiceError("x"),
    ("X_AVM-DE_WANFiber1", "GetInfo"): {
        "NewOpticalSignalLevel": -27000,
        "NewLowerOpticalThreshold": -28000,
        "NewUpperOpticalThreshold": -8000,
        "NewTransmitOpticalLevel": 2500,
        "NewLowerTransmitPowerThreshold": 500,
        "NewUpperTransmitPowerThreshold": 5000,
        "NewSFPVendor": "Beispiel",
        "NewSFPSerialNumber": "SFP-SERIAL-123",
        "NewFiberMode": "GPON",
    },
    ("X_AVM-DE_WANFiber1", "GetInfoGPON"): {"NewGponSerial": "GPON-SERIAL-9", "NewPONId": "P1", "NewONUId": 3},
    ("X_AVM-DE_WANFiber1", "GetStatistics"): {"NewResyncs": 2, "NewMinutesInShowtime": 600},
    **NO_MOBILE,
}

CELLS = (
    "<CellList><Cell><Index>1</Index><Connected>primary</Connected><CellType>lte</CellType><PLMN>26202</PLMN>"
    "<Provider>Beispielnetz</Provider><TAC>C0FC</TAC><PhysicalId>323</PhysicalId><Distance>1200</Distance>"
    "<RSSI>70</RSSI><RSRQ>-12</RSRQ><RSRP>-104</RSRP><Cellid>03584-03</Cellid></Cell></CellList>"
)
MOBILE = {
    ("WANCommonInterfaceConfig1", "GetCommonLinkProperties"): {"NewWANAccessType": "X_AVM-DE_UMTS"},
    ("WANDSLInterfaceConfig1", "GetInfo"): FritzServiceError("x"),
    ("X_AVM-DE_WANMobileConnection1", "GetInfo"): {"NewEnable": 1, "NewStatus": "PIN successful"},
    ("X_AVM-DE_WANMobileConnection1", "GetInfoEx"): {
        "NewIMSI": "262011234567890",
        "NewPPPUsername": "mobil-user",
        "NewSerialNumber": "SN-1",
        "NewCurrentAccessTechnology": "LTE",
        "NewSignalRSRP0": -104,
        "NewSignalRSRP1": -108,
        "NewCellList": CELLS,
    },
    ("X_AVM-DE_WANMobileConnection1", "GetEnabledBandCapabilities"): {"NewBandCapabilitiesLTE": "1,3,7,20"},
    **NO_FIBER,
}


def run(landevices: LanDeviceClient, responses: dict[tuple[str, str], Any], **kw: Any) -> dict[str, Any]:
    return make_service(landevices, FakeFC(responses)).line.diagnose(**kw)


@pytest.mark.parametrize(
    "raw,kind",
    [
        ("DSL", "dsl"),
        ("X_AVM-DE_Fiber", "fiber"),
        ("X_AVM-DE_UMTS", "mobile"),
        ("Ethernet", "ethernet"),
        ("X_AVM-DE_Cable", "cable"),
        ("", "unknown"),
    ],
)
def test_classify_access(raw: str, kind: str) -> None:
    assert classify_access(raw) == kind


def test_dsl_cable_test_spectrum_and_finding(landevices: LanDeviceClient) -> None:
    r = run(landevices, DSL)
    dsl = r["dsl"]
    assert r["access"]["kind"] == "dsl" and dsl["profile"] == "17a" and dsl["modulation"] == "VDSL"
    assert dsl["cable_test"]["state"] == "DONE_CABLE_NOK" and dsl["cable_test"]["fault_distance_m"] == 37
    assert "37 m" in dsl["cable_test"]["meaning"]
    down = dsl["snr_spectrum"]["down"]
    assert down["groups"] == 100 and down["low_share_pct"] == 30.0 and "values" not in down
    sev = {f["severity"] for f in r["findings"]}
    assert "critical" in sev and any("37 m" in f["finding"] for f in r["findings"])
    assert "fiber" not in r and "mobile_backup" not in r


def test_dsl_spectrum_values_on_request(landevices: LanDeviceClient) -> None:
    r = run(landevices, DSL, include_spectrum=True)
    assert len(r["dsl"]["snr_spectrum"]["down"]["values"]) == 100


def test_fiber_levels_near_threshold_and_no_serials(landevices: LanDeviceClient) -> None:
    r = run(landevices, FIBER)
    f = r["fiber"]
    assert f["rx_dbm"] == -27.0 and f["rx_rating"] == "warn" and f["tx_rating"] == "ok"
    assert f["gpon"]["pon_id"] == "P1" and f["statistics"]["resyncs"] == 2
    assert "SERIAL" not in str(r)
    assert any(x["area"] == "fiber" and x["severity"] == "warn" for x in r["findings"])


def test_mobile_rating_cells_without_location_or_identity(landevices: LanDeviceClient) -> None:
    r = run(landevices, MOBILE)
    m = r["mobile"]
    assert m["technology"] == "LTE" and m["rsrp_rating"] == "schwach"
    assert m["cells"][0]["provider"] == "Beispielnetz" and m["enabled_bands"]["lte"] == "1,3,7,20"
    text = str(r)
    for secret in ("262011234567890", "mobil-user", "SN-1", "03584-03", "C0FC", "1200"):
        assert secret not in text
    assert any(x["area"] == "mobile" for x in r["findings"])


def test_cable_is_unknown(landevices: LanDeviceClient) -> None:
    responses = {
        ("WANCommonInterfaceConfig1", "GetCommonLinkProperties"): {"NewWANAccessType": "X_AVM-DE_Cable"},
        **NO_FIBER,
        **NO_MOBILE,
    }
    r = run(landevices, responses)
    assert r["cable"]["status"] == "unknown" and "dsl" not in r


def test_mobile_backup_reported_next_to_dsl(landevices: LanDeviceClient) -> None:
    responses = {**MOBILE, **{k: v for k, v in DSL.items() if k[0] != "X_AVM-DE_WANMobileConnection1"}}
    responses[("WANCommonInterfaceConfig1", "GetCommonLinkProperties")] = {"NewWANAccessType": "DSL"}
    r = run(landevices, responses)
    assert r["mobile_backup"]["technology"] == "LTE"


def test_sim_locked_finding() -> None:
    from fritzos8_mcp.line import LineDiagnostics

    f = LineDiagnostics.findings({"mobile": {"sim_status": "enter PUK"}})
    assert f[0]["severity"] == "critical" and "PIN/PUK setzt dieser Server nie" in f[0]["recommendation"]


def test_parse_cell_list_bad_xml_and_rating() -> None:
    assert parse_cell_list("<kaputt") == [] and parse_cell_list("") == []
    assert rsrp_rating(-85) == "gut" and rsrp_rating(-95) == "mittel" and rsrp_rating(-115) == "sehr schwach"
    assert rsrp_rating(0) == "unknown"


def test_network_doctor_includes_line_findings(landevices: LanDeviceClient) -> None:
    svc = make_service(landevices, FakeFC(DSL))
    r = svc.network_doctor()
    assert r["sources"]["line"] == "ok"
    assert any("Kabeltest" in f["finding"] for f in r["findings"])


def test_line_metrics_feed_history(landevices: LanDeviceClient, tmp_path: Path) -> None:
    svc = make_service(landevices, FakeFC(FIBER))
    assert svc.line.metrics() == {"fiber.rx_dbm": -27.0, "fiber.resyncs": 2.0}
    r = svc.history.collect()
    assert r["metrics"]["fiber.rx_dbm"] == -27.0
    svc2 = make_service(landevices, FakeFC(MOBILE))
    assert svc2.line.metrics() == {"mobile.rsrp_dbm": -104.0}


def test_dsl_info_missing_gives_unavailable(landevices: LanDeviceClient) -> None:
    responses = {
        ("WANCommonInterfaceConfig1", "GetCommonLinkProperties"): {"NewWANAccessType": "DSL"},
        ("WANDSLInterfaceConfig1", "GetInfo"): FritzActionError("x"),
        **NO_MOBILE,
    }
    r = run(landevices, responses)
    assert r["dsl"]["available"] is False
