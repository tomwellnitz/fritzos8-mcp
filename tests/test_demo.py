"""The README demo (scripts/demo.py) keeps working against the current tool output."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("rich")

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "demo.py"


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("fritzos8_demo", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def test_demo_runs_against_the_fake_box(capsys: pytest.CaptureFixture[str]) -> None:
    results = await _load().run(fast=True)
    doctor = results["network_doctor"]
    assert doctor["summary"]["critical"] >= 1
    assert doctor["findings"][0]["evidence"]["snr_db"] == 2.5
    assert results["security_check"]["counts"]["warn"] == 3
    assert results["rename_host"]["verified"] is True
    assert results["reboot_plan"]["execute_with"]["tool"] == "reboot_execute"
    out = capsys.readouterr().out
    # every finding was translated – no German finding text leaks into the English demo
    assert "Störabstand" not in out and "Synchronisationsverluste" not in out
    assert "verified: true" in out and "nothing has changed yet" in out
