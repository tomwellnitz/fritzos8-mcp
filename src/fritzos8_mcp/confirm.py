"""Stage 7.6 – confirmation of critical actions via MCP elicitation, plan/execute token as fallback.

Every critical action stays two-step (``*_plan`` → token → ``*_execute``). In addition, when the client
declares form elicitation, the ``*_execute`` tool asks the HUMAN directly in the client – with the plan's
consequence/warnings – before anything is sent to the box:

* accepted with ``confirm = true`` → executed, result carries ``confirmed_via: "elicitation"``;
* declined, cancelled or ``confirm = false`` → nothing is executed, the token is discarded,
  error ``declined``;
* client without (form) elicitation, or an invalid/expired token → no question, the token alone decides
  as before (``confirmed_via: "token"``; an invalid token still fails in ``redeem``).

Uses the SDK's resolver mechanism (``Annotated[..., Resolve(fn)]``), so it works on both protocol
generations: a standalone ``elicitation/create`` request up to 2025-11-25 and an ``InputRequiredResult``
round trip from 2026-07-28 on. The confirmation parameter is injected by the framework and never part of
the tool's input schema – an agent cannot pre-fill it.
"""

from __future__ import annotations

import functools
import inspect
import json
import typing
from collections.abc import Callable
from typing import Annotated, Any

from mcp.server.elicitation import AcceptedElicitation, ElicitationResult
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.mcpserver.resolve import Elicit, Resolve
from pydantic import BaseModel, Field

from .errors import DeclinedError
from .security import PlanStore


class ConfirmExecution(BaseModel):
    confirm: bool = Field(description="Ja – diese Aktion jetzt an der FRITZ!Box ausführen")


class NoElicitation(BaseModel):
    """Resolver outcome when no question is asked (fallback to the token)."""

    reason: str


def supports_form_elicitation(ctx: Context[Any, Any]) -> bool:
    caps = ctx.client_capabilities
    el = caps.elicitation if caps is not None else None
    # A bare ``elicitation: {}`` (before modes existed) means form; url-only does not.
    return el is not None and (el.form is not None or el.url is None)


def plan_summary(result: Any) -> str:
    if not isinstance(result, dict):
        return ""
    parts = [str(result.get("consequence") or f"Aktion {result.get('action') or '?'}")]
    warnings = result.get("warnings")
    if warnings:
        parts.append("Warnungen: " + "; ".join(str(w) for w in warnings))
    return "\n".join(parts)


def with_plan_summary(fn: Callable[..., Any], plans_for: Callable[[str | None], PlanStore]) -> Callable[..., Any]:
    """Wrap a ``*_plan`` tool: remember consequence/warnings with the issued token."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        result = fn(*args, **kwargs)
        if isinstance(result, dict) and result.get("token"):
            plans_for(kwargs.get("box")).annotate(str(result["token"]), plan_summary(result))
        return result

    return wrapper


def with_confirmation(
    fn: Callable[..., Any],
    original: Callable[..., Any],
    plans_for: Callable[[str | None], PlanStore],
    box_label: Callable[[str | None], str],
) -> Callable[..., Any]:
    """Wrap a ``*_execute`` tool (``fn`` = already error-wrapped tool, ``original`` = the plain function whose
    signature is published) with the elicitation question."""

    def resolver(ctx: Context[Any, Any], token: str, box: str | None = None) -> Any:
        if not supports_form_elicitation(ctx):
            return NoElicitation(reason="client_without_elicitation")
        peeked = plans_for(box).peek(token)
        if peeked is None:
            return NoElicitation(reason="token_unknown")  # redeem() reports the invalid token
        action, summary = peeked
        message = (
            f"FRITZ!Box „{box_label(box)}“ – kritische Aktion „{action}“:\n\n"
            f"{summary or 'Keine Zusammenfassung vorhanden.'}\n\nJetzt ausführen?"
        )
        return Elicit(message, ConfirmExecution)

    confirmation_type = Annotated[ElicitationResult[ConfirmExecution], Resolve(resolver)]

    async def wrapper(*, confirmation: Any = None, **kwargs: Any) -> Any:
        via = "token"
        if isinstance(confirmation, AcceptedElicitation) and isinstance(confirmation.data, ConfirmExecution):
            if not confirmation.data.confirm:
                confirmation = None  # accepted the form, but answered "no"
            else:
                via = "elicitation"
        if not (isinstance(confirmation, AcceptedElicitation)):
            plans_for(kwargs.get("box")).discard(str(kwargs.get("token") or ""))
            err = DeclinedError("Ausführung im Client nicht bestätigt (abgelehnt/abgebrochen).")
            raise ToolError(json.dumps({"ok": False, "error": err.to_dict()}, ensure_ascii=False))
        result = fn(**kwargs)
        if isinstance(result, dict):
            result = {**result, "confirmed_via": via}
        return result

    hints = typing.get_type_hints(original, include_extras=True)
    sig = inspect.signature(original, eval_str=True)
    params = [*sig.parameters.values()]
    params.append(
        inspect.Parameter("confirmation", inspect.Parameter.KEYWORD_ONLY, default=None, annotation=confirmation_type)
    )
    wrapper.__signature__ = sig.replace(parameters=params)  # type: ignore[attr-defined]
    wrapper.__annotations__ = {**hints, "confirmation": confirmation_type}
    wrapper.__name__ = original.__name__
    wrapper.__qualname__ = original.__qualname__
    wrapper.__doc__ = original.__doc__
    return wrapper
