"""Stage 7.6 – critical actions ask the human via MCP elicitation (fake clients), token stays the fallback."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp import types
from mcp.client import Client

from fritzos8_mcp.confirm import plan_summary
from fritzos8_mcp.security import Gate, PlanStore
from fritzos8_mcp.server import build_server

MODES = ["legacy", "auto"]  # legacy = elicitation/create request; auto = 2026-07-28 InputRequiredResult round trip


def make_service() -> tuple[MagicMock, PlanStore, list[str]]:
    plans = PlanStore()
    executed: list[str] = []
    service = MagicMock()
    service.plans = plans

    def reboot_plan() -> dict[str, Any]:
        token = plans.issue("reboot", {})
        return {
            "action": "reboot",
            "consequence": "Die FRITZ!Box startet neu.",
            "warnings": ["Telefonate brechen ab."],
            "token": token,
        }

    def reboot_execute(token: str) -> dict[str, Any]:
        plans.redeem(token, "reboot", {})
        executed.append(token)
        return {"action": "reboot", "accepted": True, "verified": False}

    service.reboot_plan.side_effect = reboot_plan
    service.reboot_execute.side_effect = reboot_execute
    return service, plans, executed


class Recorder:
    def __init__(self, action: str, confirm: bool | None = True) -> None:
        self.action = action
        self.confirm = confirm
        self.messages: list[str] = []

    async def __call__(self, context: Any, params: Any) -> types.ElicitResult:
        self.messages.append(params.message)
        content = {"confirm": self.confirm} if self.action == "accept" else None
        return types.ElicitResult(action=self.action, content=content)  # type: ignore[arg-type]


async def _plan_and_execute(client: Client) -> Any:
    plan = await client.call_tool("reboot_plan", {})
    token = plan.structured_content["token"]
    return token, await client.call_tool("reboot_execute", {"token": token})


@pytest.mark.parametrize("mode", MODES)
async def test_accepted_elicitation_executes(mode: str) -> None:
    service, _, executed = make_service()
    cb = Recorder("accept", True)
    async with Client(build_server(service, Gate(True, True)), mode=mode, elicitation_callback=cb) as client:
        token, result = await _plan_and_execute(client)
    assert not result.is_error
    assert result.structured_content["confirmed_via"] == "elicitation"
    assert executed == [token]
    assert len(cb.messages) == 1
    assert "Die FRITZ!Box startet neu." in cb.messages[0] and "Telefonate brechen ab." in cb.messages[0]
    assert "reboot" in cb.messages[0]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("action,confirm", [("decline", None), ("cancel", None), ("accept", False)])
async def test_declined_elicitation_changes_nothing_and_burns_token(mode: str, action: str, confirm: bool) -> None:
    service, plans, executed = make_service()
    cb = Recorder(action, confirm)
    async with Client(build_server(service, Gate(True, True)), mode=mode, elicitation_callback=cb) as client:
        token, result = await _plan_and_execute(client)
    assert result.is_error
    text = result.content[0].text
    assert json.loads(text[text.index("{") :])["error"]["type"] == "declined"
    assert executed == []
    assert plans.peek(token) is None  # token discarded


@pytest.mark.parametrize("mode", MODES)
async def test_client_without_elicitation_falls_back_to_token(mode: str) -> None:
    service, _, executed = make_service()
    async with Client(build_server(service, Gate(True, True)), mode=mode) as client:
        token, result = await _plan_and_execute(client)
    assert not result.is_error
    assert result.structured_content["confirmed_via"] == "token"
    assert executed == [token]


async def test_invalid_token_is_not_asked_and_fails() -> None:
    service, _, executed = make_service()
    cb = Recorder("accept", True)
    async with Client(build_server(service, Gate(True, True)), mode="legacy", elicitation_callback=cb) as client:
        result = await client.call_tool("reboot_execute", {"token": "nope"})
    assert result.is_error
    assert cb.messages == []
    assert executed == []


async def test_confirmation_is_not_part_of_the_input_schema() -> None:
    service, _, _ = make_service()
    tools = {t.name: t for t in await build_server(service, Gate(True, True)).list_tools()}
    for name, tool in tools.items():
        assert "confirmation" not in tool.input_schema.get("properties", {}), name
    assert set(tools["reboot_execute"].input_schema["required"]) == {"token"}


def test_plan_summary() -> None:
    assert plan_summary({"consequence": "A", "warnings": ["x", "y"]}) == "A\nWarnungen: x; y"
    assert plan_summary({"action": "reboot"}) == "Aktion reboot"
    assert plan_summary(None) == ""
