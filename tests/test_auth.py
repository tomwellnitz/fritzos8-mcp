from __future__ import annotations

import httpx
import pytest

from fritzos8_mcp.auth import (
    SessionManager,
    login_response,
    md5_response,
    parse_session_info,
    pbkdf2_response,
)
from fritzos8_mcp.errors import AuthError, FritzConnectionError

from .conftest import BASE, CHALLENGE_XML, PASSWORD, SID, session_xml

LOGIN = f"{BASE}/login_sid.lua?version=2"


# Test vectors from AVM's technical notes on login_sid.lua
def test_pbkdf2_avm_test_vector() -> None:
    assert (
        pbkdf2_response("2$10000$5A1711$2000$5A1722", "1example!")
        == "5A1722$1798a1672bca7c6463d6b245f82b53703b0f50813401b03e4045a5861e689adb"
    )


def test_md5_avm_test_vector() -> None:
    assert md5_response("1234567z", "äbc") == "1234567z-9e224a41eeefa284df7bb0f26c2913e2"


def test_md5_replaces_chars_above_latin1() -> None:
    assert md5_response("abc", "€x") == md5_response("abc", ".x")


def test_login_response_dispatch() -> None:
    assert login_response("2$10000$5A1711$2000$5A1722", "1example!").startswith("5A1722$")
    assert login_response("1234567z", "äbc").startswith("1234567z-")


@pytest.mark.parametrize("bad", ["2$abc$5A$2000$5A", "2$1$2", "2$10$zz$10$aa"])
def test_pbkdf2_rejects_malformed_challenge(bad: str) -> None:
    with pytest.raises(AuthError):
        pbkdf2_response(bad, "x")


def test_parse_session_info_rights() -> None:
    info = parse_session_info(session_xml())
    assert info.valid and info.sid == SID
    assert info.rights == {"BoxAdmin": 2, "Dial": 2}


def test_login_posts_pbkdf2_response_and_caches_sid(respx_mock) -> None:
    respx_mock.get(LOGIN).mock(return_value=httpx.Response(200, text=CHALLENGE_XML))
    post = respx_mock.post(LOGIN).mock(return_value=httpx.Response(200, text=session_xml()))
    sm = SessionManager(httpx.Client(base_url=BASE), "mcp", "1example!")

    assert sm.get_sid() == SID
    assert sm.get_sid() == SID  # cached
    assert post.call_count == 1
    body = post.calls[0].request.content.decode()
    assert "username=mcp" in body
    assert "response=5A1722%241798a1672bca7c6463d6b245f82b53703b0f50813401b03e4045a5861e689adb" in body
    assert sm.rights["BoxAdmin"] == 2


def test_relogin_fetches_new_sid(respx_mock) -> None:
    respx_mock.get(LOGIN).mock(return_value=httpx.Response(200, text=CHALLENGE_XML))
    post = respx_mock.post(LOGIN).mock(
        side_effect=[httpx.Response(200, text=session_xml()), httpx.Response(200, text=session_xml("ffffeeeeddddcccc"))]
    )
    sm = SessionManager(httpx.Client(base_url=BASE), "mcp", PASSWORD)
    assert sm.get_sid() == SID
    assert sm.relogin() == "ffffeeeeddddcccc"
    assert sm.get_sid() == "ffffeeeeddddcccc"
    assert post.call_count == 2


def test_wrong_password_raises_auth_error_without_secret(respx_mock) -> None:
    respx_mock.get(LOGIN).mock(return_value=httpx.Response(200, text=CHALLENGE_XML))
    respx_mock.post(LOGIN).mock(return_value=httpx.Response(200, text=session_xml("0000000000000000", block=8)))
    sm = SessionManager(httpx.Client(base_url=BASE), "mcp", PASSWORD)
    with pytest.raises(AuthError) as ei:
        sm.get_sid()
    assert "8 s" in str(ei.value)
    assert PASSWORD not in str(ei.value)


def test_blocked_before_login(respx_mock) -> None:
    respx_mock.get(LOGIN).mock(return_value=httpx.Response(200, text=session_xml("0000000000000000", block=30)))
    post = respx_mock.post(LOGIN)
    sm = SessionManager(httpx.Client(base_url=BASE), "mcp", PASSWORD)
    with pytest.raises(AuthError, match="30 s"):
        sm.get_sid()
    assert not post.called


def test_md5_fallback_only_when_box_demands_it(respx_mock) -> None:
    legacy = (
        "<SessionInfo><SID>0000000000000000</SID><Challenge>1234567z</Challenge><BlockTime>0</BlockTime></SessionInfo>"
    )
    respx_mock.get(LOGIN).mock(return_value=httpx.Response(200, text=legacy))
    post = respx_mock.post(LOGIN).mock(return_value=httpx.Response(200, text=session_xml()))
    sm = SessionManager(httpx.Client(base_url=BASE), "mcp", "äbc")
    sm.get_sid()
    assert "response=1234567z-9e224a41eeefa284df7bb0f26c2913e2" in post.calls[0].request.content.decode()


def test_unreachable_box(respx_mock) -> None:
    respx_mock.get(LOGIN).mock(side_effect=httpx.ConnectError("boom"))
    sm = SessionManager(httpx.Client(base_url=BASE), "mcp", PASSWORD)
    with pytest.raises(FritzConnectionError):
        sm.get_sid()


def test_logout_posts_sid(respx_mock) -> None:
    respx_mock.get(LOGIN).mock(return_value=httpx.Response(200, text=CHALLENGE_XML))
    post = respx_mock.post(LOGIN).mock(return_value=httpx.Response(200, text=session_xml()))
    sm = SessionManager(httpx.Client(base_url=BASE), "mcp", PASSWORD)
    sm.get_sid()
    sm.logout()
    assert f"sid={SID}" in post.calls[-1].request.content.decode()


def test_login_non_200_is_connection_error(respx_mock) -> None:
    """login_sid.lua answers 200 even for wrong passwords; 503 (box busy) must not look like a bad password."""
    respx_mock.get(LOGIN).mock(return_value=httpx.Response(503, text="<html>busy</html>"))
    sm = SessionManager(httpx.Client(base_url=BASE), "mcp", PASSWORD)
    with pytest.raises(FritzConnectionError, match="HTTP 503"):
        sm.get_sid()
