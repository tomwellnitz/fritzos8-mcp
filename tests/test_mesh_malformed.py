"""Mesh documents with an unexpected structure (found by fuzzing, fuzz/fuzz_mesh.py).

The box guarantees nothing below the top-level object: ``nodes``, ``node_interfaces`` and ``node_links`` can be
missing, ``null``, a string, a number or a list with non-object entries. Every consumer must treat that as empty
instead of raising ``AttributeError``/``TypeError``.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from fritzos8_mcp.cleanup import mesh_node_macs
from fritzos8_mcp.netinfo import parse_mesh
from fritzos8_mcp.quality import mesh_clients
from fritzos8_mcp.util import json_objects

from .test_netinfo import MESH

ODD = [None, "x", 5, 1.5, True, {"a": 1}, ["x", 3, None]]


@pytest.mark.parametrize("value", ODD)
def test_odd_nodes(value: Any) -> None:
    doc = {"nodes": value}
    assert parse_mesh(doc)["nodes"] == []
    assert mesh_clients(doc) == []
    assert mesh_node_macs(doc) == set()


@pytest.mark.parametrize("value", ODD)
def test_odd_interfaces_and_links(value: Any) -> None:
    doc = copy.deepcopy(MESH)
    doc["nodes"][0]["node_interfaces"] = value
    doc["nodes"][1]["node_interfaces"][0]["node_links"] = value
    doc["nodes"].append({"uid": "n-odd", "mesh_role": "slave", "node_interfaces": [value, {"node_links": value}]})
    result = parse_mesh(doc)
    assert len(result["nodes"]) == 3
    mesh_clients(doc)
    mesh_node_macs(doc)


def test_json_objects() -> None:
    assert json_objects([{"a": 1}, "x", None, {"b": 2}]) == [{"a": 1}, {"b": 2}]
    assert json_objects({"a": 1}) == [] and json_objects("ab") == [] and json_objects(None) == []
