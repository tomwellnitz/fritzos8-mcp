"""Stage 8.7 – family admin report: every configured box at a glance (reachable, online, FRITZ!OS + updates of all AVM
devices, security score, active alarms, NAS as backup target) with a traffic light per box and a Markdown summary.

Read only. Alarms come from the local alarm state of the last ``alarms_check`` unless ``check_alarms`` is set (then a
check runs, without notifications). One unreachable box never breaks the report.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from . import multibox
from .errors import FritzError
from .nasremote import ToolDecorator
from .security import Tier
from .toolargs import READ

if TYPE_CHECKING:
    from .service import FritzService

LIGHTS = {"green": "grün", "yellow": "gelb", "red": "rot"}


def _try(fn: Callable[[], Any]) -> tuple[Any, dict[str, Any] | None]:
    try:
        return fn(), None
    except FritzError as exc:
        return None, exc.to_dict()


def box_report(name: str, svc: FritzService, base: dict[str, Any], check_alarms: bool) -> dict[str, Any]:
    entry: dict[str, Any] = {**base}
    if not base.get("reachable"):
        entry["light"] = "red"
        entry["reasons"] = ["Box nicht erreichbar"]
        return entry
    updates, err = _try(svc.devices.updates_overview)
    entry["updates"] = updates["summary"]["updates_available"] if updates else None
    if err:
        entry.setdefault("errors", {})["updates"] = err
    if check_alarms:
        result, err = _try(lambda: svc.alarms.check(notify=False))
        alarms = result["alarms"] if result else []
    else:
        alarms, err = _try(svc.alarms.active)
        alarms = alarms or []
    entry["alarms"] = [{"severity": a.get("severity"), "message": a.get("message")} for a in alarms]
    if err:
        entry.setdefault("errors", {})["alarms"] = err
    backup, err = _try(svc.nasremote.backup_target_check)
    entry["backup_target"] = backup.get("overall") if backup else "unknown"

    reasons_red: list[str] = []
    reasons_yellow: list[str] = []
    if base.get("online") is False:
        reasons_red.append("Internet getrennt")
    if any(a.get("severity") == "critical" for a in entry["alarms"]):
        reasons_red.append("kritischer Alarm")
    score = (base.get("security") or {}).get("score")
    if isinstance(score, int) and score < 60:
        reasons_red.append(f"Sicherheits-Score {score}")
    elif isinstance(score, int) and score < 85:
        reasons_yellow.append(f"Sicherheits-Score {score}")
    if entry["updates"]:
        reasons_yellow.append(f"{len(entry['updates'])} Update(s) verfügbar")
    if any(a.get("severity") == "warn" for a in entry["alarms"]):
        reasons_yellow.append("Warnung(en)")
    if entry["backup_target"] in ("warn", "fail"):
        reasons_yellow.append(f"Backup-Ziel: {entry['backup_target']}")
    entry["light"] = "red" if reasons_red else "yellow" if reasons_yellow else "green"
    entry["reasons"] = reasons_red + reasons_yellow
    return entry


def markdown(boxes: list[dict[str, Any]]) -> str:
    lines = [f"# FRITZ!Box-Familienbericht – {time.strftime('%d.%m.%Y %H:%M')}", ""]
    lines += ["| Box | Status | Modell | FRITZ!OS | Internet | Score | Hinweise |", "|---|---|---|---|---|---|---|"]
    for b in boxes:
        online = {True: "verbunden", False: "getrennt", None: "?"}[b.get("online")]
        score = (b.get("security") or {}).get("score")
        lines.append(
            f"| {b['box']} | {LIGHTS[b['light']]} | {b.get('model') or '?'} | {b.get('firmware') or '?'} | {online} | "
            f"{score if score is not None else '?'} | {', '.join(b.get('reasons') or []) or '–'} |"
        )
    for b in boxes:
        details = [f"- Update: {u}" for u in b.get("updates") or []]
        details += [f"- Alarm ({a['severity']}): {a['message']}" for a in b.get("alarms") or []]
        if details:
            lines += ["", f"## {b['box']}", "", *details]
    lines += [
        "",
        "Ampel: rot = nicht erreichbar/offline/kritisch · gelb = Updates, Warnungen, Score < 85 · "
        "grün = alles in Ordnung.",
    ]
    return "\n".join(lines)


def family_report(services: Mapping[str, FritzService], check_alarms: bool = False) -> dict[str, Any]:
    base = {b["box"]: b for b in multibox.overview(services)["boxes"]}
    boxes = [box_report(name, svc, base[name], check_alarms) for name, svc in services.items()]
    lights = [b["light"] for b in boxes]
    return {
        "count": len(boxes),
        "overall": "red" if "red" in lights else "yellow" if "yellow" in lights else "green",
        "boxes": boxes,
        "markdown": markdown(boxes),
        "note": "Alarme aus dem letzten alarms_check (check_alarms=true prüft neu, ohne Benachrichtigung).",
    }


def register_family_tools(tool: ToolDecorator, services: Callable[[], Mapping[str, FritzService]]) -> None:
    @tool(Tier.READ, READ)
    def family_admin_report(
        check_alarms: Annotated[
            bool, Field(description="Alarme jetzt neu prüfen statt den letzten Stand zu zeigen")
        ] = False,
    ) -> dict[str, Any]:
        """Familien-Admin-Bericht über ALLE Boxen: Ampel je Box mit Gründen, erreichbar, Internet, Modell, FRITZ!OS,
        Updates aller AVM-Geräte, Sicherheits-Score, aktive Alarme, NAS als Backup-Ziel – strukturiert und als
        Markdown. Nur lesend; eine nicht erreichbare Box bricht den Bericht nicht ab."""
        return family_report(services(), check_alarms)
