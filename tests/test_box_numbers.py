"""Oversized numbers in box answers (found by fuzzing, fuzz/fuzz_box_xml.py + fuzz/fuzz_mesh.py).

Python ints are unbounded, but float arithmetic is not: a 400-digit value in an AHA or mesh answer raised
``OverflowError`` ("int too large to convert to float") instead of being treated as an unusable value.
"""

from __future__ import annotations

import copy

import pytest

from fritzos8_mcp.diagnose import _tenth_db
from fritzos8_mcp.netinfo import parse_mesh, percent_to_dbm, rcpi_to_dbm
from fritzos8_mcp.smarthome import parse_device_list, parse_stats
from fritzos8_mcp.util import MAX_BOX_INT, box_int

from .test_netinfo import MESH

HUGE = "9" * 400


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("42", 42), (" -7 ", -7), (17, 17), (str(MAX_BOX_INT - 1), MAX_BOX_INT - 1), (str(MAX_BOX_INT), None),
     (HUGE, None), ("-" + HUGE, None), ("1.5", None), ("", None), (None, None), ("abc", None)],
)  # fmt: skip
def test_box_int(raw: object, expected: int | None) -> None:
    assert box_int(raw) == expected


def test_stats_with_oversized_value() -> None:
    xml = f'<devicestats><power><stats count="2" grid="10">{HUGE},150000</stats></power></devicestats>'
    series = parse_stats(xml)["power"]["series"][0]
    assert series["values"] == [None, 1500.0]


def test_device_with_oversized_values() -> None:
    xml = (
        f'<devicelist><device identifier="12345 0000001" functionbitmask="{HUGE}"><name>X</name>'
        f"<powermeter><power>{HUGE}</power><voltage>230000</voltage></powermeter>"
        f"<temperature><celsius>{HUGE}</celsius></temperature><hkr><tist>{HUGE}</tist><tsoll>{HUGE}</tsoll></hkr>"
        "</device></devicelist>"
    )
    dev = parse_device_list(xml)[0]
    assert dev["power"]["power_w"] is None and dev["power"]["voltage_v"] == 230.0
    assert dev["temperature_c"] is None and dev["thermostat"]["current_c"] is None


def test_mesh_with_oversized_rates() -> None:
    doc = copy.deepcopy(MESH)
    for node in doc["nodes"]:
        for iface in node.get("node_interfaces") or []:
            for link in iface.get("node_links") or []:
                link.update(cur_data_rate_rx=HUGE, max_data_rate_tx=int(HUGE), rx_rcpi=HUGE)
    result = parse_mesh(doc)
    assert all(c["rate_down_mbit"] is None for c in result["clients"] + result["backbone"])


def test_signal_and_db_helpers_with_oversized_values() -> None:
    assert rcpi_to_dbm(HUGE) is None and percent_to_dbm(HUGE) is None
    assert _tenth_db(HUGE) is None and _tenth_db("123") == 12.3
