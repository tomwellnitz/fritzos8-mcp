"""Web login via login_sid.lua?version=2 (PBKDF2, MD5 only if the box demands it) + SID cache.

Implemented after AVM's technical note "Session-IDs im FRITZ!OS mit PBKDF2"
(challenge format ``2$<iter1>$<salt1>$<iter2>$<salt2>``).
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
from defusedxml import ElementTree as ET

from .errors import AuthError, FritzConnectionError, FritzError

log = logging.getLogger(__name__)

LOGIN_PATH = "/login_sid.lua?version=2"
INVALID_SID = "0000000000000000"


def pbkdf2_response(challenge: str, password: str) -> str:
    """Answer a version-2 challenge ``2$iter1$salt1$iter2$salt2`` → ``salt2$hash2``."""
    parts = challenge.split("$")
    if len(parts) != 5 or parts[0] != "2":
        raise AuthError("Unbekanntes PBKDF2-Challenge-Format der FRITZ!Box.")
    try:
        iter1, salt1, iter2, salt2 = int(parts[1]), bytes.fromhex(parts[2]), int(parts[3]), bytes.fromhex(parts[4])
    except ValueError:
        raise AuthError("Ungültige PBKDF2-Challenge der FRITZ!Box.") from None
    hash1 = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt1, iter1)
    hash2 = hashlib.pbkdf2_hmac("sha256", hash1, salt2, iter2)
    return f"{parts[4]}${hash2.hex()}"


def md5_response(challenge: str, password: str) -> str:
    """Legacy answer: ``challenge-md5(utf16le(challenge-password))``.

    AVM: characters > U+00FF are replaced by '.' before hashing.
    """
    cleaned = "".join(c if ord(c) <= 0xFF else "." for c in password)
    digest = hashlib.md5(f"{challenge}-{cleaned}".encode("utf-16le")).hexdigest()  # noqa: S324 - AVM protocol
    return f"{challenge}-{digest}"


def login_response(challenge: str, password: str) -> str:
    if challenge.startswith("2$"):
        return pbkdf2_response(challenge, password)
    return md5_response(challenge, password)


@dataclass
class SessionInfo:
    sid: str
    challenge: str
    block_time: int
    rights: dict[str, int] = field(default_factory=dict)

    @property
    def valid(self) -> bool:
        return bool(self.sid) and self.sid != INVALID_SID and set(self.sid) != {"0"}


def parse_session_info(xml_text: str) -> SessionInfo:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        raise FritzConnectionError("Antwort von login_sid.lua ist kein gültiges XML.") from None
    rights: dict[str, int] = {}
    rights_node = root.find("Rights")
    if rights_node is not None:
        names = [n.text or "" for n in rights_node.findall("Name")]
        access = [a.text or "0" for a in rights_node.findall("Access")]
        for n, a in zip(names, access, strict=False):
            try:
                rights[n] = int(a)
            except ValueError:
                rights[n] = 0
    try:
        block = int(root.findtext("BlockTime") or "0")
    except ValueError:
        block = 0
    return SessionInfo(
        sid=(root.findtext("SID") or "").strip(),
        challenge=(root.findtext("Challenge") or "").strip(),
        block_time=block,
        rights=rights,
    )


def _check_login_status(status: int, step: str) -> None:
    """login_sid.lua answers 200 with XML – even for a wrong password (invalid SID in the XML). Any other status
    (e.g. 503 while the box is busy or restarting) is a connection problem, not a bad password."""
    if not 200 <= status < 300:
        raise FritzConnectionError(f"login_sid.lua ({step}): HTTP {status} – FRITZ!Box antwortet nicht regulär.")


class SessionManager:
    """Thread-safe SID cache with explicit re-login."""

    def __init__(self, http: httpx.Client, user: str, password: str) -> None:
        self._http = http
        self._user = user
        self._password = password
        self._sid: str | None = None
        self._rights: dict[str, int] = {}
        self._lock = threading.Lock()
        # health counters for server_status (no secrets: no SID, no user name)
        self.logins = 0
        self.relogins = 0
        self.session_started: float | None = None
        self.last_login_error: dict[str, Any] | None = None

    @property
    def rights(self) -> dict[str, int]:
        return dict(self._rights)

    def get_sid(self) -> str:
        with self._lock:
            if self._sid is None:
                self._sid = self._tracked_login()
            return self._sid

    def relogin(self) -> str:
        with self._lock:
            self.relogins += 1
            self._sid = self._tracked_login()
            return self._sid

    def stats(self, now: float | None = None) -> dict[str, Any]:
        """Login counters and session age – for server_status, never the SID."""
        t = time.time() if now is None else now
        with self._lock:
            started = self.session_started
            active = self._sid is not None
        return {
            "logged_in": active,
            "logins": self.logins,
            "relogins_since_start": self.relogins,
            "session_age_s": int(t - started) if active and started is not None else None,
            "last_login_error": dict(self.last_login_error) if self.last_login_error else None,
        }

    def _tracked_login(self) -> str:
        try:
            sid = self._login()
        except FritzError as exc:
            self.last_login_error = {
                "type": exc.code,
                "message": " ".join(str(exc).split())[:160],
                "at": datetime.fromtimestamp(time.time(), UTC).isoformat(timespec="seconds"),
            }
            raise
        self.logins += 1
        self.session_started = time.time()
        return sid

    def invalidate(self) -> None:
        with self._lock:
            self._sid = None
            self.session_started = None

    def logout(self) -> None:
        with self._lock:
            sid, self._sid = self._sid, None
        if not sid:
            return
        try:
            self._http.post(LOGIN_PATH, data={"logout": "1", "sid": sid})
        except httpx.HTTPError:
            log.debug("Logout fehlgeschlagen (ignoriert)")

    def _login(self) -> str:
        try:
            first = self._http.get(LOGIN_PATH)
            _check_login_status(first.status_code, "Challenge")
            info = parse_session_info(first.text)
            if info.block_time > 0:
                raise AuthError(
                    f"Login gesperrt: die FRITZ!Box blockiert Anmeldungen noch {info.block_time} s "
                    "(zu viele Fehlversuche)."
                )
            if not info.challenge:
                raise AuthError("login_sid.lua lieferte keine Challenge.")
            response = login_response(info.challenge, self._password)
            second = self._http.post(LOGIN_PATH, data={"username": self._user, "response": response})
            _check_login_status(second.status_code, "Anmeldung")
        except httpx.HTTPError as exc:
            raise FritzConnectionError(f"FRITZ!Box nicht erreichbar (Login): {type(exc).__name__}") from None
        result = parse_session_info(second.text)
        if not result.valid:
            extra = f" Nächster Versuch frühestens in {result.block_time} s." if result.block_time else ""
            raise AuthError(f"Anmeldung an der FRITZ!Box fehlgeschlagen.{extra}")
        self._rights = result.rights
        method = "PBKDF2" if info.challenge.startswith("2$") else "MD5"
        log.info("Web-Login erfolgreich (%s)", method)
        return result.sid
