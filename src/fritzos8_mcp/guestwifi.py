"""Stage 8.4 – guest WLAN with a time limit, guest WLAN QR code (opt-in tier ``secrets``) and the WPS button.

After the AVM document "TR-064 Support – WLANConfiguration" (2026-03-10):

* The box's own guest timeout (``X_AVM-DE_TimeoutActive``/``Timeout``/``TimeRemain``) is only readable
  (``X_AVM-DE_GetWLANExtInfo``) – there is no TR-064 action to set it. ``guest_wifi_session_start`` therefore switches
  the guest WLAN on (``SetEnable`` + read-back) and keeps the end time in ``<state dir>/<box>/guest_session.json``;
  it is enforced by a timer in the running server process and by ``fritzos8-collector`` on every run
  (``enforce_expiry``). Reliable box-side alternative: "Gastzugang automatisch deaktivieren" in the web UI.
* QR code: ``GetSecurityKeys`` (denied for ``tr064_call``) is read ONLY here, ONLY with ``FRITZ_ALLOW_SECRETS=1``; the
  key goes into a QR image file (SVG, 0600) and never into the tool result, logs or errors. Needs the optional
  dependency ``segno`` (``pip install fritzos8-mcp[qr]``).
* WPS: ``X_AVM-DE_GetWPSInfo`` (mode, status off/inactive/active/success/…), ``X_AVM-DE_SetWPSConfig`` with mode ``pbc``
  (push button, the box stops it after about 2 minutes) or ``stop``. WPS must already be enabled in the box – this
  server never switches WPS on permanently (``X_AVM-DE_SetWPSEnable`` is not used).
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import Field

from .errors import FritzError, InvalidParameterError, NotFoundError
from .nasremote import ToolDecorator
from .paths import ensure_private_dir, safe_component, state_dir, write_private
from .security import Tier
from .toolargs import READ, WRITE, BoxArg

if TYPE_CHECKING:
    from .service import FritzService

log = logging.getLogger(__name__)

MIN_SESSION_MIN = 15
MAX_SESSION_MIN = 24 * 60


def wifi_qr_payload(ssid: str, key: str, security: str = "WPA") -> str:
    """WIFI:T:<sec>;S:<ssid>;P:<key>;; with the special characters escaped (ZXing convention)."""

    def esc(value: str) -> str:
        out = value
        for ch in ("\\", ";", ",", ":", '"'):
            out = out.replace(ch, "\\" + ch)
        return out

    return f"WIFI:T:{security};S:{esc(ssid)};P:{esc(key)};;"


class GuestWifi:
    def __init__(
        self,
        service: FritzService,
        *,
        now: Callable[[], float] = time.time,
        state_root: Path | None = None,
        start_timer: bool = True,
    ) -> None:
        self.svc = service
        self.now = now
        self._state_root = state_root
        self._start_timer = start_timer
        self._timer: threading.Timer | None = None

    # ------------------------------------------------------------ session state

    @property
    def _state_path(self) -> Path:
        base = ensure_private_dir((self._state_root or state_dir()) / safe_component(self.svc.box_host))
        return base / "guest_session.json"

    def _load(self) -> dict[str, Any] | None:
        try:
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except (OSError, ValueError):
            return None

    def _clear(self) -> None:
        path = self._state_path
        if path.exists():
            path.unlink()

    def box_timeout(self) -> dict[str, Any]:
        guest = self.svc.wlan.guest()
        extra = guest.get("guest_extra") or {}
        return {
            "active": extra.get("timeout_active"),
            "timeout": extra.get("timeout_min"),
            "remaining": extra.get("time_remaining_min"),
            "unit_note": "Einheit laut AVM-Doku nicht angegeben (vermutlich Minuten, live prüfen – V-11).",
        }

    def session_start(self, minutes: int) -> dict[str, Any]:
        self.svc.gate.require(Tier.WRITE)
        if not MIN_SESSION_MIN <= minutes <= MAX_SESSION_MIN:
            raise InvalidParameterError(f"minutes muss {MIN_SESSION_MIN}–{MAX_SESSION_MIN} sein.")
        result = self.svc.set_guest_wifi(True)
        if not result.get("verified"):
            return {**result, "session": None, "note": "Gast-WLAN nicht verifiziert eingeschaltet – keine Sitzung."}
        until = self.now() + minutes * 60
        write_private(self._state_path, json.dumps({"until": until, "ssid": result.get("ssid")}).encode("utf-8"))
        self._arm(until)
        return {
            **result,
            "session": {"until": _iso(until), "minutes": minutes},
            "box_timeout": self._safe(self.box_timeout),
            "warning": "Die FRITZ!Box kann die Zeitbegrenzung per TR-064 nicht selbst übernehmen. Abgeschaltet wird "
            "durch diesen Server (solange er läuft) bzw. fritzos8-collector. Zuverlässig: in der Web-UI unter WLAN > "
            "Gastzugang 'automatisch deaktivieren' einstellen.",
        }

    def session_stop(self) -> dict[str, Any]:
        self.svc.gate.require(Tier.WRITE)
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        self._clear()
        return {**self.svc.set_guest_wifi(False), "session": None}

    def session_status(self) -> dict[str, Any]:
        st = self._load()
        guest = self.svc.wlan.guest()
        remaining = None if st is None else max(0, int(st["until"] - self.now()))
        return {
            "enabled": guest.get("enabled"),
            "ssid": guest.get("ssid"),
            "session": None if st is None else {"until": _iso(st["until"]), "remaining_s": remaining},
            "box_timeout": self.box_timeout(),
        }

    def enforce_expiry(self) -> dict[str, Any] | None:
        """Switch the guest WLAN off if a session has expired (called by the timer and by the collector)."""
        st = self._load()
        if st is None or self.now() < float(st.get("until") or 0):
            return None
        try:
            result = self.svc.wlan.set_enable(self.svc.wlan.guest()["service"], False)
        except FritzError as exc:
            log.warning("Gast-WLAN-Sitzung abgelaufen, Abschalten fehlgeschlagen: %s", exc)
            return {"ok": False, "error": exc.to_dict()}
        if result.get("verified"):
            self._clear()
        return result

    def _arm(self, until: float) -> None:
        if not self._start_timer:
            return
        if self._timer is not None:
            self._timer.cancel()
        self._timer = threading.Timer(max(1.0, until - self.now()), self.enforce_expiry)
        self._timer.daemon = True
        self._timer.start()

    @staticmethod
    def _safe(fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        try:
            return fn()
        except FritzError as exc:
            return {"status": "unknown", "error": exc.to_dict()}

    # ------------------------------------------------------------ QR code (secrets tier)

    def qr_code(self) -> dict[str, Any]:
        self.svc.gate.require(Tier.SECRETS)
        try:
            import segno
        except ImportError:
            raise NotFoundError(
                "QR-Erzeugung nicht installiert.",
                hint="Optionale Abhängigkeit: pip install 'fritzos8-mcp[qr]' (segno).",
            ) from None
        guest = self.svc.wlan.guest()
        ssid = str(guest.get("ssid") or "")
        if not ssid:
            raise NotFoundError("Gast-WLAN hat keine SSID.")
        try:
            keys = self.svc.tr064.call(guest["service"], "GetSecurityKeys")
        except FritzError as exc:
            raise FritzError(f"Schlüssel des Gast-WLANs nicht lesbar ({exc.code}).") from None
        key = str(keys.get("NewKeyPassphrase") or "")
        security = "nopass" if not key or not guest.get("encrypted") else "WPA"
        payload = wifi_qr_payload(ssid, key, security) if security != "nopass" else f"WIFI:T:nopass;S:{ssid};;"
        path = self._state_path.parent / "qr" / "guest-wifi.svg"
        ensure_private_dir(path.parent)
        try:
            qr = segno.make(payload, error="m")
            from io import BytesIO

            buf = BytesIO()
            qr.save(buf, kind="svg", scale=8, border=4)
        except Exception as exc:  # never let a library error carry the payload
            raise FritzError(f"QR-Code konnte nicht erzeugt werden ({type(exc).__name__}).") from None
        finally:
            key = ""
            payload = ""
        write_private(path, buf.getvalue())
        return {
            "ssid": ssid,
            "encrypted": security != "nopass",
            "qr_file": str(path),
            "format": "SVG",
            "key_in_output": False,
            "note": "Der WLAN-Schlüssel steckt NUR im QR-Bild (Datei 0600), nicht in dieser Antwort. Datei nach dem "
            "Teilen löschen; wer das Bild hat, hat den Schlüssel.",
        }

    # ------------------------------------------------------------ WPS

    def _wps_service(self, guest: bool) -> str:
        nets = [n for n in self.svc.wlan.networks() if not n.get("error")]
        if guest:
            return str(self.svc.wlan.guest()["service"])
        main = [n for n in nets if not n.get("guest") and n.get("enabled")]
        if not main:
            raise NotFoundError("Kein eingeschaltetes WLAN für WPS gefunden.")
        return str(main[0]["service"])

    def wps_info(self, service: str) -> dict[str, Any]:
        r = self.svc.tr064.call(service, "X_AVM-DE_GetWPSInfo")
        return {"mode": r.get("NewX_AVM-DE_WPSMode"), "status": r.get("NewX_AVM-DE_WPSStatus")}

    def wps(self, action: str, guest: bool = False) -> dict[str, Any]:
        self.svc.gate.require(Tier.WRITE)
        if action not in ("start", "stop"):
            raise InvalidParameterError("action: start oder stop.")
        service = self._wps_service(guest)
        before = self.wps_info(service)
        if action == "start" and str(before.get("status") or "").lower() == "off":
            raise InvalidParameterError(
                "WPS ist in der Box ausgeschaltet – dieser Server schaltet WPS nicht dauerhaft ein.",
                hint="Web-UI: WLAN > Sicherheit > WPS-Schnellverbindung (Push-Button) aktivieren, dann erneut.",
            )
        r = self.svc.tr064.call(
            service, "X_AVM-DE_SetWPSConfig", **{"NewX_AVM-DE_WPSMode": "pbc" if action == "start" else "stop"}
        )
        after = self.wps_info(service)
        status = str(after.get("status") or r.get("NewX_AVM-DE_WPSStatus") or "").lower()
        verified = status == "active" if action == "start" else status in ("inactive", "off", "success", "")
        out = {
            "service": service,
            "action": action,
            "before": before,
            "status": after.get("status") or r.get("NewX_AVM-DE_WPSStatus"),
            "changed": True,
            "verified": verified,
        }
        if action == "start":
            out["warning"] = (
                "WPS ist jetzt ca. 2 Minuten offen: jedes Gerät, das in dieser Zeit WPS drückt, kommt ins WLAN. "
                "Mit action=stop vorzeitig beenden."
            )
        return out


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts))


def register_guest_tools(tool: ToolDecorator, svc: Callable[[str | None], GuestWifi]) -> None:
    @tool(Tier.READ, READ)
    def guest_wifi_session(box: BoxArg = None) -> dict[str, Any]:
        """Gast-WLAN-Sitzung: an/aus, SSID, laufende Zeitbegrenzung dieses Servers (bis/Restzeit) und die eigene
        Zeitbegrenzung der Box (nur lesbar). Ohne Schlüssel."""
        return svc(box).session_status()

    @tool(Tier.WRITE, WRITE)
    def guest_wifi_session_start(
        minutes: Annotated[int, Field(description="Dauer in Minuten (15–1440)", ge=15, le=1440)],
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Schaltet das Gast-WLAN für eine begrenzte Zeit ein (SetEnable + Rücklesen) und danach automatisch aus –
        abgeschaltet wird durch diesen Server bzw. fritzos8-collector (die Box kann die Zeit per TR-064 nicht selbst
        übernehmen; Hinweis im Ergebnis)."""
        return svc(box).session_start(minutes)

    @tool(Tier.WRITE, WRITE)
    def guest_wifi_session_stop(box: BoxArg = None) -> dict[str, Any]:
        """Beendet die Gast-WLAN-Sitzung sofort (Gast-WLAN aus, Rücklesen)."""
        return svc(box).session_stop()

    @tool(Tier.SECRETS, READ)
    def guest_wifi_qr(box: BoxArg = None) -> dict[str, Any]:
        """QR-Code zum Verbinden mit dem Gast-WLAN als SVG-Datei (lokal, 0600). Der Schlüssel steht NUR im Bild,
        nie in der Antwort. Nur mit FRITZ_ALLOW_SECRETS=1 verfügbar."""
        return svc(box).qr_code()

    @tool(Tier.WRITE, WRITE)
    def wps_button(
        action: Annotated[Literal["start", "stop"], Field(description="start = WPS-Taste (ca. 2 min), stop = beenden")],
        guest: Annotated[bool, Field(description="WPS für das Gast-WLAN statt des Heim-WLANs")] = False,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Drückt die WPS-Taste per Tool (X_AVM-DE_SetWPSConfig pbc, die Box beendet nach ca. 2 min) bzw. beendet WPS;
        liest den WPS-Status zurück. Nur wenn WPS in der Box aktiviert ist – öffnet das WLAN kurz für jedes Gerät."""
        return svc(box).wps(action, guest)
