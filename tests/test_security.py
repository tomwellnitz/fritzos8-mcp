from __future__ import annotations

import pytest

from fritzos8_mcp.errors import ActionDeniedError, PlanError, TierDisabledError
from fritzos8_mcp.security import DENYLIST, Gate, PlanStore, Tier, check_generic_action, is_read_only_action


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


# ------------------------------------------------------------------ gate


@pytest.mark.parametrize(
    "write,critical,expected",
    [
        (False, False, {Tier.READ: True, Tier.WRITE: False, Tier.CRITICAL: False}),
        (True, False, {Tier.READ: True, Tier.WRITE: True, Tier.CRITICAL: False}),
        (False, True, {Tier.READ: True, Tier.WRITE: False, Tier.CRITICAL: False}),  # critical needs write
        (True, True, {Tier.READ: True, Tier.WRITE: True, Tier.CRITICAL: True}),
    ],
)
def test_gate_tiers(write: bool, critical: bool, expected: dict[Tier, bool]) -> None:
    gate = Gate(write, critical)
    assert {t: gate.enabled(t) for t in Tier} == {**expected, Tier.SECRETS: False}


def test_secrets_tier_is_independent_opt_in() -> None:
    assert Gate(False, False, allow_secrets=True).enabled(Tier.SECRETS) is True
    assert Gate(True, True).enabled(Tier.SECRETS) is False
    with pytest.raises(TierDisabledError) as ei:
        Gate(True, True).require(Tier.SECRETS)
    assert "FRITZ_ALLOW_SECRETS" in (ei.value.hint or "")


def test_gate_require_messages() -> None:
    with pytest.raises(TierDisabledError) as ei:
        Gate(False, False).require(Tier.WRITE)
    assert "FRITZ_ALLOW_WRITE" in (ei.value.hint or "")
    with pytest.raises(TierDisabledError) as ei:
        Gate(True, False).require(Tier.CRITICAL)
    assert "FRITZ_ALLOW_CRITICAL" in (ei.value.hint or "")
    Gate(False, False).require(Tier.READ)


# ------------------------------------------------------------------ plan store


def test_token_roundtrip_once() -> None:
    store = PlanStore()
    token = store.issue("reboot", {})
    store.redeem(token, "reboot", {})
    with pytest.raises(PlanError, match="ungültig oder schon benutzt"):
        store.redeem(token, "reboot", {})


def test_token_expires_after_ttl() -> None:
    clock = Clock()
    store = PlanStore(ttl=300, now=clock)
    token = store.issue("reboot", {})
    clock.t += 301
    with pytest.raises(PlanError, match="abgelaufen"):
        store.redeem(token, "reboot", {})


def test_token_bound_to_action_and_params() -> None:
    store = PlanStore()
    t1 = store.issue("delete_host_force", {"mac": "AA:BB:CC:DD:EE:01", "uid": "landevice1"})
    with pytest.raises(PlanError, match="passt nicht"):
        store.redeem(t1, "delete_host_force", {"mac": "AA:BB:CC:DD:EE:02", "uid": "landevice1"})
    t2 = store.issue("reboot", {})
    with pytest.raises(PlanError, match="passt nicht"):
        store.redeem(t2, "reconnect_wan", {})


def test_token_identity_must_match() -> None:
    store = PlanStore()
    token = store.issue("delete_host_force", {"uid": "x"}, identity="x|AA")
    with pytest.raises(PlanError, match="geändert"):
        store.redeem(token, "delete_host_force", {"uid": "x"}, identity=lambda: "x|BB")


def test_tokens_unique_and_expired_cleaned() -> None:
    clock = Clock()
    store = PlanStore(ttl=10, now=clock)
    tokens = {store.issue("reboot", {}) for _ in range(50)}
    assert len(tokens) == 50
    clock.t += 11
    store.issue("reboot", {})
    assert len(store._plans) == 1


# ------------------------------------------------------------------ deny / read-only


@pytest.mark.parametrize(
    "action", ["GetInfo", "X_AVM-DE_GetHostListPath", "X_AVM_DE_GetExternalIPv6Address", "GetSpecificHostEntry"]
)
def test_read_only_actions_allowed(action: str) -> None:
    assert is_read_only_action(action)
    check_generic_action("Hosts1", action)


@pytest.mark.parametrize("action", ["SetEnable", "X_AVM-DE_SetHostNameByMACAddress", "Getaway", "AddPortMapping"])
def test_non_read_actions_denied(action: str) -> None:
    with pytest.raises(ActionDeniedError, match="nicht lesend"):
        check_generic_action("X1", action)


@pytest.mark.parametrize(
    "action",
    [
        "Reboot",
        "FactoryReset",
        "ForceTermination",
        "RequestConnection",
        "X_AVM-DE_SetConfigFile",
        "X_AVM-DE_GetConfigFile",
        "GetSecurityKeys",
        "X_AVM-DE_GetWLANHybridMode",
        "X_AVM-DE_GetDDNSInfo",
    ],
)
def test_denylist(action: str) -> None:
    assert action in DENYLIST
    with pytest.raises(ActionDeniedError, match="gesperrt"):
        check_generic_action("DeviceConfig1", action)


@pytest.mark.parametrize(
    "action", ["X_AVM-DE_GetClient", "X_AVM-DE_GetClient3", "X_AVM-DE_GetClients", "X_AVM-DE_GetVoIPAccount"]
)
def test_voip_credential_actions_denied(action: str) -> None:
    with pytest.raises(ActionDeniedError, match="gesperrt"):
        check_generic_action("X_VoIP1", action)


# ------------------------------------------------------------------ AVM-Doku-Abgleich (docs/COVERAGE.md)


@pytest.mark.parametrize(
    "service,action",
    [
        ("X_VoIP1", "X_AVM-DE_GetVoIPAccounts"),  # SIP user names of all accounts (XML list)
        ("X_AVM-DE_AppSetup1", "GetAppRemoteInfo"),  # documented spelling
        ("X_AVM-DE_RemoteAccess1", "GetDDNSInfo"),  # documented spelling
        ("WANPPPConnection1", "GetUserName"),  # PPP login name
        ("UserInterface1", "X_AVM-DE_DoPrepareCGI"),  # session ID for firmwarecfg
        ("X_AVM-DE_Dect1", "DectDoUpdate"),
        ("X_AVM-DE_Homeplug1", "DeviceDoUpdate"),
        ("X_AVM-DE_WANMobileConnection1", "SetPIN"),
        ("WLANConfiguration1", "X_AVM-DE_SetWLANGlobalEnable"),
        ("UserInterface1", "X_AVM-DE_SetInternationalConfig"),
        ("X_VoIP1", "X_AVM-DE_DialNumber"),
        ("LANEthernetInterfaceConfig1", "SetEnable"),
    ],
)
def test_doc_review_actions_denied(service: str, action: str) -> None:
    from fritzos8_mcp.security import is_denied

    assert is_denied(action, service)
    with pytest.raises(ActionDeniedError, match="gesperrt"):
        check_generic_action(service, action)


def test_set_enable_still_only_blocked_as_write_elsewhere() -> None:
    """The service-bound LAN entry must not turn every SetEnable into a denylist hit."""
    from fritzos8_mcp.security import is_denied

    assert not is_denied("SetEnable", "WLANConfiguration1")


@pytest.mark.parametrize(
    "service,action,field",
    [
        ("WANPPPConnection1", "GetInfo", "NewUserName"),
        ("ManagementServer1", "GetInfo", "NewUsername"),
        ("ManagementServer1", "GetInfo", "NewConnectionRequestUsername"),
        ("X_AVM-DE_WANMobileConnection1", "GetInfoEx", "NewIMSI"),
        ("X_AVM-DE_WANMobileConnection1", "GetInfoEx", "NewPPPUsername"),
        ("X_AVM-DE_OnTel1", "GetInfoByIndex", "NewUsername"),
    ],
)
def test_doc_review_fields_masked(service: str, action: str, field: str) -> None:
    from fritzos8_mcp.security import mask_service_fields

    out = mask_service_fields(service, action, {field: "geheim-wert", "NewEnable": "1"})
    assert out == {field: "***", "NewEnable": "1"}


def test_mesh_repeater_token_redacted() -> None:
    """Hosts X_AVM-DE_GetSpecificHostEntryByIP: X_AVM-DE_URLParameters = 'token=<hex>' (repeater login)."""
    from fritzos8_mcp.redact import redact, redact_obj

    out = redact_obj({"NewX_AVM-DE_URLParameters": "token=3f35907c05b3e5b9", "NewX_AVM-DE_URL": "http://192.0.2.20"})
    assert out == {"NewX_AVM-DE_URLParameters": "***", "NewX_AVM-DE_URL": "http://192.0.2.20"}
    assert redact("http://192.0.2.20/?token=3f35907c05b3e5b9") == "http://192.0.2.20/?token=***"
    xml = "<Item><X_AVM-DE_URLParameters>token=3f35907c05b3e5b9</X_AVM-DE_URLParameters></Item>"
    assert "3f35907c05b3e5b9" not in redact(xml)
    assert redact_obj({"NewToken": "a1b2-c3"}) == {"NewToken": "***"}
    assert redact_obj({"token": "plan-token"}) == {"token": "plan-token"}  # MCP plan token stays usable
