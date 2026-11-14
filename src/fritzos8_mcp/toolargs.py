"""Shared tool argument types and annotations for the stage-8 modules (one place instead of a copy per module)."""

from __future__ import annotations

from typing import Annotated

from mcp.types import ToolAnnotations
from pydantic import Field

READ = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)
WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False)
DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False)

BoxArg = Annotated[
    str | None, Field(description="Name der FRITZ!Box bei Mehrbox-Betrieb (Standard: erste Box, siehe server_status)")
]
MacArg = Annotated[str, Field(description="MAC-Adresse, z. B. AA:BB:CC:DD:EE:FF")]
TokenArg = Annotated[str, Field(description="Freigabe-Token aus dem zugehörigen *_plan-Aufruf")]
AinArg = Annotated[str, Field(description='AIN bzw. UID des Smart-Home-Geräts, z. B. "08761 0000434"')]
