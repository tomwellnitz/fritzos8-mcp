"""Central redaction of secrets in text, structured results and log records.

The text redaction (`redact`) is adapted from Schimmilab/fritzbox-mcp-server
(src/fritzbox_mcp/redact.py, MIT License, Copyright (c) 2026 Schimmilab).
Extended here with structured redaction (`redact_obj`), secret field names and a
logging filter.
"""

from __future__ import annotations

import html
import logging
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import quote, quote_plus

# Session id in all spellings. 'ssid=' must NOT match (no letter/digit in front).
_SID_QUERY = re.compile(r"(?<![A-Za-z0-9])(sid=)[0-9a-f]+", re.I)
_SID_XML = re.compile(r"(<sid>)[0-9a-f]+(</sid>)", re.I)
_SID_JSON = re.compile(r"""(["']sid["']\s*:\s*["'])[0-9a-f]+(["'])""", re.I)
_SID_HEADER = re.compile(r"(AVM-SID\s+)[0-9a-f]+", re.I)
# scheme://user:pass@host — a port (':49000/') is not a password.
_URL_CRED = re.compile(r"(\w+://)[^\s/@:]+:(?!\d+(?:/|\s|$))\S*@")
# PBKDF2/MD5 login responses ("<salt>$<hex>" / "<challenge>-<md5>") in form bodies.
_LOGIN_RESPONSE = re.compile(r"(response=)[^&\s]+", re.I)
# Secrets inside XML documents carried in a single TR-064 field (e.g. a VoIP client list with
# <ClientPassword>…</ClientPassword>): the field name alone does not reveal them.
_XML_SECRET = re.compile(
    r"(<([A-Za-z_:\-]*(?:password|passwort|passphrase|secret|presharedkey|urlparameters)[A-Za-z_:\-]*)>)[^<]*(</\2>)",
    re.I,
)

# Download token of a NAS shared link (/nas/filelink.lua?id=<hex>): whoever has it can download.
_FILELINK_ID = re.compile(r"(filelink\.lua\?id=)[0-9A-Za-z]+", re.I)

# Login token of a mesh repeater (Hosts X_AVM-DE_URLParameters = "token=<hex>", AVM doc "Hosts" 4.1).
_URL_TOKEN = re.compile(r"(?<![A-Za-z0-9_])(token=)[^&\s\"'<]+", re.I)

# WireGuard/IPSec configuration lines ("PrivateKey = …", "PresharedKey = …") in any text.
_WG_CONF_KEY = re.compile(r"((?:PrivateKey|PresharedKey|PreSharedKey)\s*=\s*)\S+", re.I)

# Shorter values would mangle normal text (e.g. 'box' inside 'fritz.box').
MIN_SECRET_LEN = 4

MASK = "***"

# Field names whose values are always masked in structured results.
# WLAN: NewKeyPassphrase, NewPreSharedKey, NewWEPKey0..3, NewX_AVM-DE_PresharedKey;
# WPS: NewX_AVM-DE_WPSAPPIN, NewX_AVM-DE_WPSClientPIN, …; 'Mapping'/'Ping' must NOT match.
SECRET_FIELD = re.compile(
    r"(password|passwort|passwd|passphrase|secret|psk|keypassphrase|wepkey|preshared|securitykey|"
    r"(^|_)sid$|urlsid|credential|privatekey|private_key|privkey|wg_?key|ipsec\w*key|vpn\w*key|ikesecret|"
    r"pin$|pin[_-]?code|wps\w*pin|(^|[_-])pin[_-]|"
    # DynDNS update URL: often carries account name/password as query parameters (stage 5).
    r"updateurl|"
    # Mesh repeater login token (Hosts X_AVM-DE_URLParameters), TR-064 token fields (NewToken …) – but not the
    # MCP plan token ("token"), which the caller needs.
    r"urlparameters|^new\w*token$)",
    re.I,
)


def _variants(secret: str) -> set[str]:
    return {
        secret,
        quote(secret, safe=""),
        quote_plus(secret),
        html.escape(secret),
        html.escape(secret, quote=False),
    }


def redact(text: str, secrets: Iterable[str] = ()) -> str:
    """Mask known secrets (incl. URL/HTML encodings), SIDs and URL credentials in text."""
    out = text
    variants = {v for s in secrets if s and len(s) >= MIN_SECRET_LEN for v in _variants(s)}
    # Longest first: a short secret that is part of a long one must not leave a remainder.
    for v in sorted(variants, key=len, reverse=True):
        out = out.replace(v, MASK)
    out = _SID_QUERY.sub(rf"\1{MASK}", out)
    out = _SID_XML.sub(rf"\1{MASK}\2", out)
    out = _SID_JSON.sub(rf"\1{MASK}\2", out)
    out = _SID_HEADER.sub(rf"\1{MASK}", out)
    out = _LOGIN_RESPONSE.sub(rf"\1{MASK}", out)
    out = _XML_SECRET.sub(rf"\1{MASK}\3", out)
    out = _FILELINK_ID.sub(rf"\1{MASK}", out)
    out = _WG_CONF_KEY.sub(rf"\1{MASK}", out)
    out = _URL_TOKEN.sub(rf"\1{MASK}", out)
    return _URL_CRED.sub(rf"\1{MASK}@", out)


def is_secret_field(name: str) -> bool:
    return bool(SECRET_FIELD.search(name))


def redact_obj(obj: Any, secrets: Iterable[str] = ()) -> Any:
    """Recursively redact a JSON-like structure: secret field names and secret values."""
    secret_list = list(secrets)
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            if isinstance(k, str) and is_secret_field(k) and v not in (None, "", False):
                out[k] = MASK
            else:
                out[k] = redact_obj(v, secret_list)
        return out
    if isinstance(obj, list | tuple):
        return [redact_obj(v, secret_list) for v in obj]
    if isinstance(obj, str):
        return redact(obj, secret_list)
    return obj


# ------------------------------------------------------------------ /api/v0 (web UI REST)

# Stage 6: the undocumented /api/v0 answers carry secrets in plain text – live seen on FRITZ!OS 8.26:
# generic/vpn returns wg_preshared_key, wg_slave_config/wg_master_config/wg_mastered_slave_config
# (complete WireGuard configurations), access_psk, xauth_password and the IPSec user names. These field
# name patterns are masked in EVERY /api/v0 answer before any other code sees it (RestClient), in
# addition to SECRET_FIELD. Deliberately broad: a false positive only hides a value, a miss leaks a key.
API_SECRET_FIELD = re.compile(
    r"(psk|preshared|passw|secret|private|privkey|token|credential|"
    r"username|user_name|"
    r"security_?id|(^|_)dpw$|"  # Powerline device password (security ID)
    r"(^|_)key$|_key_|wg_\w*key|"  # wg_preshared_key, wg_public_key, *_key
    r"wg_\w*config|device_config|_config$|"  # wg_slave_config, wg_master_config, wg_device_config, …
    # stage 8.5a (Smart-Home-REST, AVM doc 8.2/8.5): location for the sun position and geofencing, push-mail
    # recipient, pairing/install/reset codes of Zigbee/DECT-ULE devices
    r"^(latitude|longitude)$|geofenc|^recipient$|install_?code|reset_?code|pairing_?code)",
    re.I,
)
# Smart-Home-REST objects that may carry URLs with credentials, headers with tokens or bodies (template action
# "httpRequest"): masked as a whole, only the HTTP method stays readable.
API_SECRET_OBJECTS = frozenset({"httpRequest", "httpRequestInterface", "geofence", "geofencing", "location"})
# Values that are configuration documents with keys, whatever the field is called.
_CONFIG_DOCUMENT = re.compile(
    r"(\[Interface\]|\[Peer\]|PrivateKey\s*=|PresharedKey\s*=|-----BEGIN [A-Z ]*PRIVATE KEY-----)", re.I
)


def is_api_secret_field(name: str) -> bool:
    return is_secret_field(name) or bool(API_SECRET_FIELD.search(name))


def _empty(value: Any) -> bool:
    return value is None or value == "" or value is False or value == [] or value == {}


def redact_api(obj: Any) -> Any:
    """Redact a parsed /api/v0 answer: secret field names (incl. nested lists/objects under them) and
    string values that are WireGuard/IPSec/PEM configuration documents are replaced by MASK."""
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            if isinstance(k, str) and k in API_SECRET_OBJECTS and isinstance(v, dict):
                out[k] = {kk: (vv if kk == "method" else MASK) for kk, vv in v.items() if not _empty(vv)}
            elif isinstance(k, str) and is_api_secret_field(k) and not _empty(v):
                out[k] = MASK
            else:
                out[k] = redact_api(v)
        return out
    if isinstance(obj, list | tuple):
        return [redact_api(v) for v in obj]
    if isinstance(obj, str):
        return MASK if _CONFIG_DOCUMENT.search(obj) else redact(obj)
    return obj


# Stage 9.9: serial numbers/hardware identifiers are no credentials, but identify a device (warranty, provider
# records). Masked only on request: FRITZ_REDACT_SERIALS=1.
SERIAL_FIELD = re.compile(r"(serial|seriennummer|imei|iccid|(^|_)udn$|uuid)", re.I)


def redact_serials(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            k: (MASK if isinstance(k, str) and SERIAL_FIELD.search(k) and not _empty(v) else redact_serials(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list | tuple):
        return [redact_serials(v) for v in obj]
    return obj


class RedactingFilter(logging.Filter):
    """Logging filter that masks secrets in every record (message + args)."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        super().__init__()
        self._secrets = [s for s in secrets if s]

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - malformed record, let logging handle it
            return True
        record.msg = redact(message, self._secrets)
        record.args = None
        if record.exc_text:
            record.exc_text = redact(record.exc_text, self._secrets)
        return True
