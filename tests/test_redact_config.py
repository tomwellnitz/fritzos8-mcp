from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from fritzos8_mcp.config import load
from fritzos8_mcp.errors import ConfigError
from fritzos8_mcp.redact import MASK, RedactingFilter, is_secret_field, redact, redact_obj

SECRET = "S3cr3t&pass/word"


# ------------------------------------------------------------------ redact


def test_redact_plain_and_encoded_variants() -> None:
    text = f"a {SECRET} b S3cr3t%26pass%2Fword c S3cr3t&amp;pass/word"
    out = redact(text, [SECRET])
    assert "S3cr3t" not in out
    assert out.count(MASK) == 3


@pytest.mark.parametrize(
    "text,expected",
    [
        ("GET /x.lua?sid=0123abcd4567ef89&x=1", "GET /x.lua?sid=***&x=1"),
        ("<SID>0123abcd4567ef89</SID>", "<SID>***</SID>"),
        ('{"sid": "0123abcd4567ef89"}', '{"sid": "***"}'),
        ("AUTHORIZATION: AVM-SID 0123abcd4567ef89", "AUTHORIZATION: AVM-SID ***"),
        ("username=mcp&response=5A1722$abcdef", "username=mcp&response=***"),
        ("http://user:pw@fritz.box/", "http://***@fritz.box/"),
    ],
)
def test_redact_patterns(text: str, expected: str) -> None:
    assert redact(text) == expected


def test_redact_keeps_ssid_and_ports() -> None:
    assert redact("ssid=MeinWLAN") == "ssid=MeinWLAN"
    assert redact("http://fritz.box:49000/tr64desc.xml") == "http://fritz.box:49000/tr64desc.xml"


def test_short_secret_ignored() -> None:
    assert redact("fritz.box", ["box"]) == "fritz.box"


def test_redact_obj_masks_secret_fields_and_values() -> None:
    data = {
        "NewKeyPassphrase": "wlan-key-123",
        "NewSSID": "Heimnetz",
        "nested": [{"NewPassword": "x"}, {"note": f"pw is {SECRET}"}],
        "NewX_AVM-DE_UrlSID": "sid=1234567890abcdef",
        "empty_password": "",
    }
    out = redact_obj(data, [SECRET])
    assert out["NewKeyPassphrase"] == MASK
    assert out["NewSSID"] == "Heimnetz"
    assert out["nested"][0]["NewPassword"] == MASK
    assert SECRET not in out["nested"][1]["note"]
    assert out["NewX_AVM-DE_UrlSID"] == MASK
    assert out["empty_password"] == ""


@pytest.mark.parametrize(
    "field",
    [
        "NewKeyPassphrase",
        "NewPreSharedKey",
        "NewX_AVM-DE_PresharedKey",
        "NewWEPKey0",
        "NewWEPKey3",
        "NewX_AVM-DE_WPSAPPIN",
        "NewX_AVM-DE_WPSClientPIN",
        "NewX_AVM-DE_WPSPinCode",
        "NewPIN",
        "NewX_AVM-DE_PIN_Code",
        "NewSecurityKey",
    ],
)
def test_wlan_and_wps_secrets_are_secret_fields(field: str) -> None:
    assert is_secret_field(field)


@pytest.mark.parametrize(
    "field",
    ["NewPortMappingIndex", "NewPortMappingDescription", "NewSSID", "NewX_AVM-DE_WPSMode", "NewBeaconType", "ping"],
)
def test_normal_fields_are_not_secret(field: str) -> None:
    assert not is_secret_field(field)


def test_logging_filter_redacts(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("test.redact")
    handler_filter = RedactingFilter([SECRET])
    logger.addFilter(handler_filter)
    try:
        with caplog.at_level(logging.INFO, logger="test.redact"):
            logger.info("login with %s and sid=%s", SECRET, "0123abcd4567ef89")
    finally:
        logger.removeFilter(handler_filter)
    assert SECRET not in caplog.text
    assert "0123abcd4567ef89" not in caplog.text


@pytest.mark.parametrize(
    ("msg", "args"),
    [
        ("login failed: %d", (SECRET,)),  # wrong conversion
        ("no placeholder", (SECRET,)),  # surplus argument
        ("%(user)s %(pw)d", {"user": "mcp", "pw": SECRET}),  # mapping with wrong conversion
        ("%s %s", ([SECRET, "x"],)),  # too few arguments, secret inside a container
    ],
)
def test_logging_filter_redacts_unformattable_records(msg: str, args: object) -> None:
    """Found by fuzzing (fuzz/fuzz_redact.py): a record whose format string does not match its arguments was passed
    on unchanged, and logging's handleError() then printed the raw arguments – incl. the secret – to stderr."""
    record = logging.LogRecord("test.redact", logging.INFO, __file__, 1, msg, args, None)  # type: ignore[arg-type]
    assert RedactingFilter([SECRET]).filter(record)
    assert record.args is None
    shown = record.getMessage()
    assert SECRET not in shown
    assert MASK in shown and shown.startswith(msg.split("%")[0])  # still useful for diagnosis


# ------------------------------------------------------------------ config


def test_config_minimal_defaults() -> None:
    cfg = load({"FRITZ_USER": "mcp", "FRITZ_PASSWORD": SECRET})
    assert cfg.host == "fritz.box"
    assert not cfg.allow_write and not cfg.allow_critical
    assert SECRET not in repr(cfg)


def test_config_password_file(tmp_path: Path) -> None:
    f = tmp_path / "pw"
    f.write_text(" lead and trail \n", encoding="utf-8")
    cfg = load({"FRITZ_USER": "mcp", "FRITZ_PASSWORD_FILE": str(f)})
    assert cfg.password == " lead and trail "


def test_config_password_file_missing(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="nicht lesbar"):
        load({"FRITZ_USER": "mcp", "FRITZ_PASSWORD_FILE": str(tmp_path / "nope")})


def test_config_both_password_sources_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load({"FRITZ_USER": "mcp", "FRITZ_PASSWORD": "x", "FRITZ_PASSWORD_FILE": str(tmp_path)})


@pytest.mark.parametrize("env", [{}, {"FRITZ_USER": "mcp"}, {"FRITZ_PASSWORD": "x"}])
def test_config_required(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        load(env)


def test_critical_requires_write() -> None:
    base = {"FRITZ_USER": "mcp", "FRITZ_PASSWORD": "x"}
    assert not load({**base, "FRITZ_ALLOW_CRITICAL": "1"}).allow_critical
    cfg = load({**base, "FRITZ_ALLOW_WRITE": "1", "FRITZ_ALLOW_CRITICAL": "1", "FRITZ_HOST": "192.0.2.1"})
    assert cfg.allow_write and cfg.allow_critical and cfg.host == "192.0.2.1"


def test_xml_secrets_inside_a_field_are_masked() -> None:
    xml = "<List><Item><ClientUsername>620</ClientUsername><ClientPassword>sip-geheim-1</ClientPassword></Item></List>"
    out = redact_obj({"NewX_AVM-DE_ClientList": xml})
    assert (
        "sip-geheim-1" not in json.dumps(out)
        and "<ClientUsername>620</ClientUsername>" in out["NewX_AVM-DE_ClientList"]
    )


def test_voip_and_call_list_urls_redacted() -> None:
    out = redact("http://192.0.2.1:49000/calllist.lua?sid=0123456789abcdef&days=7")
    assert "0123456789abcdef" not in out and "days=7" in out
