"""Stage 7.7 – structured outputs: pydantic models published as ``outputSchema`` for the main tools.

Rules: the models describe the fields the tools already return – nothing is renamed or removed.
Every model allows extra fields (``extra="allow"``), so conditional or later fields pass through
unchanged; values the box delivers raw (numbers that may arrive as strings) are typed leniently.
Field names here are the stable contract (README "Strukturierte Ausgaben").

If a live answer ever does not fit a model, the tool still answers (see ``server._with_output``):
the result is passed on unvalidated and a warning is logged – a schema must never cost a result.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

Raw = int | str | None  # box values that may come as number or string


class _Out(BaseModel):
    model_config = ConfigDict(extra="allow")


# ------------------------------------------------------------------ system_info


class SystemInfoOut(_Out):
    model: str | None = Field(description="Modellname, z. B. FRITZ!Box 7583")
    description: str | None = None
    software_version: str | None = Field(description="FRITZ!OS-Version")
    hardware_version: str | None = None
    uptime_s: Raw = Field(description="Laufzeit seit Neustart in Sekunden")
    manufacturer: str | None = None


# ------------------------------------------------------------------ wan_status


class WanConnectionOut(_Out):
    service: str = Field(description="WANIPConnection1, WANPPPConnection1 (TR-064) oder WANIPConn1 (IGD)")
    source: str | None = Field(default=None, description="tr064 oder igd (UPnP)")
    status: str | None = Field(description="z. B. Connected")
    uptime_s: Raw = None
    last_error: str | None = None


class WanLinkOut(_Out):
    access_type: str | None = None
    physical_status: str | None = None
    max_down_bps: Raw = None
    max_up_bps: Raw = None


class WanStatusOut(_Out):
    connection: WanConnectionOut
    link: WanLinkOut | None = None
    external_ipv4: str | None = None
    external_ipv6: str | None = None
    ipv4_note: str | None = Field(default=None, description="Erklärung bei fehlender öffentlicher IPv4 (DS-Lite)")


# ------------------------------------------------------------------ list_landevices


class LanDeviceOut(_Out):
    uid: str = Field(description="landeviceNNNN")
    name: str = Field(description="TR-064-Hostname")
    friendly_name: str = Field(description="Anzeigename der Web-UI")
    mac: str
    ip: str
    static_dhcp: bool
    active: bool
    online: bool
    deleteable: bool


class LanDevicesOut(_Out):
    count: int
    landevices: list[LanDeviceOut]


# ------------------------------------------------------------------ lan_ports


class LanPortOut(_Out):
    label: str | None = Field(description='z. B. "LAN:1"')
    uid: str | None = None
    ifname: str | None = None
    function: str | None = Field(default=None, description="lan, guest oder wan")
    connected: bool
    speed_mbit: int | None = None
    max_speed_mbit: int | None = None
    supported_speeds_mbit: list[int] | None = None
    below_max_speed: bool = False
    power_mode: str | None = None
    eee_supported: bool = False
    eee_mode: str | None = Field(default=None, description="auto oder off")
    eee_active: bool = False
    raw: dict[str, Any] | None = None


class LanPortsOut(_Out):
    count: int
    ports: list[LanPortOut]
    eee_enabled_ports: list[Any] = []
    eee_uniform: bool | None = None
    notes: list[str] = []
    value_mapping: dict[str, Any] | None = None
    source: str | None = None


# ------------------------------------------------------------------ wlan_status


class WlanNetworkOut(_Out):
    service: str = Field(description="WLANConfigurationN")
    enabled: bool | None = None
    status: str | None = None
    ssid: str | None = None
    bssid: str | None = None
    channel: Raw = None
    standard: str | None = None
    band_ghz: str | None = Field(default=None, description="2.4, 5 oder 6")
    band_source: str | None = None
    security: str | None = Field(default=None, description="BeaconType, z. B. 11i")
    encrypted: bool | None = None
    guest: bool = False
    guest_detection: str | None = None
    clients: int | None = None
    guest_extra: dict[str, Any] | None = None
    error: dict[str, Any] | None = None


class WlanStatusOut(_Out):
    count: int
    networks: list[WlanNetworkOut]
    note: str | None = None


# ------------------------------------------------------------------ security_check


class SecurityCheckItemOut(_Out):
    check: str
    status: str = Field(description="ok, warn oder unknown")
    summary: str | None = None
    details: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    weight: int = 0
    remediation: str | None = Field(default=None, description="Menüpfad in der Web-UI")


class SecurityCheckOut(_Out):
    overall: str = Field(description="ok, warn oder unknown")
    score: int = Field(description="0–100")
    grade: str | None = None
    score_basis: str | None = None
    counts: dict[str, int] | None = None
    checks: list[SecurityCheckItemOut]
    menu_note: str | None = None
    not_covered: list[str] = []


# ------------------------------------------------------------------ network_doctor


class DoctorFindingOut(_Out):
    severity: str = Field(description="critical, warn oder info")
    area: str
    finding: str
    likely_cause: str | None = None
    recommendation: str | None = None
    evidence: dict[str, Any] = {}


class NetworkDoctorOut(_Out):
    symptom: str | None = None
    summary: dict[str, int] = Field(description="Anzahl Befunde je Schweregrad")
    findings: list[DoctorFindingOut]
    verdict: str
    sources: dict[str, Any] = {}
    thresholds: dict[str, Any] = {}
    note: str | None = None


# ------------------------------------------------------------------ vpn_connections


class VpnConnectionOut(_Out):
    name: str | None = None
    uid: str | None = None
    type: str = Field(description="WireGuard oder IPSec")
    state: str | None = None
    state_label: str | None = None
    activated: bool = False
    connected_since: str | None = Field(default=None, description="ISO-Zeit")
    remote: str | None = None
    remote_ip: str | None = None
    local_networks: list[str] = []
    remote_networks: list[str] = []
    wireguard_type: str | None = None
    error: dict[str, Any] | None = Field(default=None, description="aktiver Fehler (nur wenn nicht verbunden)")
    last_error: dict[str, Any] | None = Field(
        default=None, description="zuletzt gespeicherter Fehler einer jetzt verbundenen Verbindung (historisch)"
    )


class VpnConnectionsOut(_Out):
    available: bool
    count: int
    connections: list[VpnConnectionOut]
    active: int = 0
    wireguard_listen_port: int | None = None
    source: str | None = None
    note: str | None = None


OUTPUT_MODELS: dict[str, type[BaseModel]] = {
    "system_info": SystemInfoOut,
    "wan_status": WanStatusOut,
    "list_landevices": LanDevicesOut,
    "lan_ports": LanPortsOut,
    "wlan_status": WlanStatusOut,
    "security_check": SecurityCheckOut,
    "network_doctor": NetworkDoctorOut,
    "vpn_connections": VpnConnectionsOut,
}
