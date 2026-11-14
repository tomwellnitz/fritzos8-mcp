"""Stage 6 – LAN ports, VPN/Powerline, speed test and connection quality: service logic and MCP tool
registration.

Kept in its own module like stage 5: ``FritzService`` holds one ``ConnectivityService``
(``service.connectivity``) and ``build_server`` calls ``register_connectivity_tools`` once.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated, Any, Literal

from mcp.types import ToolAnnotations
from pydantic import Field

from . import clienttest
from .errors import AuthError, ConfirmationRequiredError, FritzError, NotFoundError
from .lanports import LanPortClient
from .nasremote import ToolDecorator
from .netinfo import PERCENT_SCALE_NOTE, band_of_channel, merge_station, percent_to_dbm
from .quality import RATING_ORDER, assoc_info, mesh_clients, rate_device
from .rest import RestClient
from .security import Gate, Tier
from .speedtest import Sender, SpeedtestClient, send_tcp
from .tr064 import Tr064Client
from .util import normalize_mac, safe_mac
from .vpnplc import VpnPlcClient

if TYPE_CHECKING:
    from .access import HostResolver
    from .netinfo import NetInfoClient
    from .wlan import WlanClient

_READ = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)
_WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False)
_MEASURE = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=True)


class Probes:
    """Network primitives of test_my_device / box_speedtest_run – replaced by fakes in tests."""

    def __init__(
        self,
        connect: clienttest.Connect = clienttest.tcp_connect,
        exchange: clienttest.UdpExchange = clienttest.udp_exchange,
        download: Callable[..., dict[str, Any]] = clienttest.http_download,
        sender: Sender = send_tcp,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        import time

        self.connect = connect
        self.exchange = exchange
        self.download = download
        self.sender = sender
        self.sleep = sleep or time.sleep


class ConnectivityService:
    def __init__(
        self,
        tr064: Tr064Client,
        rest: RestClient,
        gate: Gate,
        *,
        netinfo: NetInfoClient | None = None,
        wlan: WlanClient | None = None,
        resolver: HostResolver | None = None,
        box_host: Callable[[], str] = lambda: "fritz.box",
        local_ips: Callable[[], set[str]] = set,
        probes: Probes | None = None,
    ) -> None:
        self.tr064 = tr064
        self.rest = rest
        self.gate = gate
        self.lan = LanPortClient(rest)
        self.vpnplc = VpnPlcClient(rest)
        self.netinfo = netinfo
        self.wlan = wlan
        self.resolver = resolver
        self.box_host = box_host
        self.local_ips = local_ips
        self.probes = probes or Probes()
        self.speedtest = SpeedtestClient(tr064, box_host, lambda h, p, s: self.probes.sender(h, p, s))

    # ================================================================ LAN ports

    def lan_ports(self) -> dict[str, Any]:
        return self.lan.status()

    def set_lan_eee(self, port: str, mode: str) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        return self.lan.set_eee(port, mode)

    # ================================================================ VPN & Powerline

    def vpn_connections(self) -> dict[str, Any]:
        return self.vpnplc.vpn_connections()

    def powerline_status(self) -> dict[str, Any]:
        return self.vpnplc.powerline()

    # ================================================================ speed test (box server)

    def box_speedtest_info(self) -> dict[str, Any]:
        return self.speedtest.info()

    def box_speedtest_run(self, seconds: float = 10.0) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        return self.speedtest.run(seconds)

    # ================================================================ connection quality

    def _section(self, fn: Callable[[], Any]) -> tuple[Any, dict[str, Any] | None]:
        try:
            return fn(), None
        except (AuthError, ConfirmationRequiredError):
            raise
        except FritzError as exc:
            return None, exc.to_dict()

    def _wlan_services(self) -> list[tuple[str, str | None]]:
        if self.wlan is None:
            return []
        out = []
        for name in self.wlan.service_names():
            band = None
            info = self.tr064.try_call(name, "X_AVM-DE_GetWLANExtInfo") or {}
            raw = str(info.get("NewX_AVM-DE_FrequencyBand") or "")
            band = {"2400": "2.4", "5000": "5", "6000": "6"}.get(raw)
            out.append((name, band))
        return out

    def _assoc(self, mac: str) -> dict[str, Any] | None:
        for service, band in self._wlan_services():
            r = self.tr064.try_call(service, "GetSpecificAssociatedDeviceInfo", NewAssociatedDeviceMACAddress=mac)
            if r:
                info = assoc_info(r)
                if band and "band_ghz" not in info:
                    info["band_ghz"] = band
                return {"service": service, **info}
        return None

    def _service_for_connection(
        self, info: dict[str, Any], raw: dict[str, Any], services: list[tuple[str, str | None]]
    ) -> tuple[str | None, str]:
        mac = safe_mac(raw.get("NewAssociatedDeviceMACAddress"))
        if mac:
            assoc = self._assoc(mac)
            if assoc:
                return assoc["service"], "GetSpecificAssociatedDeviceInfo"
        band = info.get("band_ghz") or band_of_channel(info.get("channel"))
        candidates = [name for name, b in services if band and b == band]
        if len(candidates) == 1:
            return candidates[0], "band"
        if candidates:
            return candidates[0], "band (mehrdeutig, z. B. Gastnetz im selben Band)"
        return None, "unbekannt"

    def device_connection_quality(self, mac: str | None = None) -> dict[str, Any]:
        sources: dict[str, Any] = {}
        doc, err = self._section(lambda: self.netinfo.mesh_document() if self.netinfo else {})
        sources["mesh"] = err or "ok"
        devices = mesh_clients(doc) if isinstance(doc, dict) else []
        stations: dict[str, dict[str, Any]] = {}
        if self.netinfo is not None and not mac:
            # one list request for ALL stations (X_AVM-DE_GetWLANDeviceListPath), cached by the guard
            result, err = self._section(self.netinfo.wlan_stations_with_source)
            if result:
                stations, sources["tr064_wlan_stations"] = result[0], result[1]
            else:
                sources["tr064_wlan_stations"] = err or "keine Daten"
        devices = [
            merge_station(d, stations.get(d.get("mac") or "")) if d.get("connection") == "wlan" else d for d in devices
        ]
        ports, err = self._section(self.lan.ports)
        sources["lan_ports"] = err or "ok"
        by_label = {p["label"]: p for p in ports or []}

        wanted = normalize_mac(mac) if mac else None
        if wanted:
            devices = [d for d in devices if d["mac"] == wanted]
            assoc = self._assoc(wanted)
            sources["tr064_wlan_assoc"] = "ok" if assoc else "kein WLAN-Eintrag"
            if not devices and assoc:
                devices = [{"name": None, "mac": wanted, "connection": "wlan", "band_ghz": assoc.get("band_ghz")}]
            if devices and assoc:
                devices[0] = {
                    **devices[0],
                    "tr064": assoc,
                    "speed_mbit": assoc.get("speed_mbit"),
                    "signal_percent": assoc.get("signal_percent"),
                    "signal_dbm_estimated": percent_to_dbm(assoc.get("signal_percent"))
                    if devices[0].get("signal_dbm") is None
                    else None,
                    "channel_width_mhz": assoc.get("channel_width_mhz"),
                    "ip": assoc.get("ip"),
                }
            if not devices:
                raise NotFoundError(
                    f"Gerät {wanted} ist weder in der Mesh-Übersicht noch als WLAN-Client verbunden "
                    "(offline oder unbekannt)."
                )
        for d in devices:
            port = by_label.get(d.get("lan_port") or "")
            if port:
                d["port_speed_mbit"] = port["speed_mbit"]
                d["port_max_speed_mbit"] = port["max_speed_mbit"]
                d["port_eee_mode"] = port["eee_mode"]
                d["port_eee_active"] = port["eee_active"]
        rated = sorted((rate_device(d) for d in devices), key=lambda d: RATING_ORDER.get(d["rating"], 3))
        summary: dict[str, int] = {}
        for d in rated:
            summary[d["rating"]] = summary.get(d["rating"], 0) + 1
        return {
            "count": len(rated),
            "devices": rated,
            "summary": summary,
            "sources": sources,
            "thresholds": {
                "signal_dbm": {"gut": "≥ −60", "ok": "≥ −70", "schwach": "≥ −78", "sehr schwach": "< −78"},
                "signal_percent": {"gut": "≥ 80", "ok": "≥ 60", "schwach": "≥ 44", "sehr schwach": "< 44"},
            },
            "units": "Raten Mbit/s; signal_dbm gemessen (Mesh-Liste); " + PERCENT_SCALE_NOTE,
        }

    # ================================================================ test_my_device

    def test_my_device(
        self,
        count: int = 10,
        dns_name: str = clienttest.DEFAULT_DNS_NAME,
        public_dns: str = clienttest.DEFAULT_PUBLIC_DNS,
        download: bool = True,
        download_url: str | None = None,
        download_bytes: int = clienttest.DEFAULT_DOWNLOAD_BYTES,
    ) -> dict[str, Any]:
        from .errors import InvalidParameterError

        if not 1 <= count <= 50:
            raise InvalidParameterError("count muss 1–50 sein.")
        if not 100_000 <= download_bytes <= clienttest.MAX_DOWNLOAD_BYTES:
            raise InvalidParameterError(f"download_bytes muss 100000–{clienttest.MAX_DOWNLOAD_BYTES} sein.")
        host = self.box_host()
        p = self.probes
        latency = {
            str(port): clienttest.tcp_ping(host, port, count, connect=p.connect, sleep=p.sleep) for port in (80, 49000)
        }
        best = min(
            latency.values(), key=lambda r: (r["loss_pct"] or 0, r["avg_ms"] if r["avg_ms"] is not None else 1e9)
        )

        box_dns_servers: list[str] = []
        try:
            box_dns_servers = list(self.tr064.get_lan_dns().get("dns_servers") or [])
        except (AuthError, ConfirmationRequiredError):
            raise
        except FritzError:
            box_dns_servers = []
        if not box_dns_servers:
            box_dns_servers = [host]
        dns = {
            "box_dns": [clienttest.dns_time(s, dns_name, exchange=p.exchange) for s in box_dns_servers[:2] if s],
            "public": clienttest.dns_time(public_dns, dns_name, exchange=p.exchange) if public_dns else None,
            "note": "box_dns = von der FRITZ!Box per DHCP verteilte DNS-Server.",
        }

        dl: dict[str, Any] | None = None
        if download:
            url = download_url or clienttest.download_url_default(download_bytes)
            if not url.lower().startswith(("http://", "https://")):
                raise InvalidParameterError("download_url muss mit http:// oder https:// beginnen.")
            dl = p.download(url, download_bytes)

        box_view = self._box_view()
        findings = clienttest.assess(best, dns)
        return {
            "box_host": host,
            "latency_to_box": latency,
            "latency_summary": best,
            "dns": dns,
            "download": dl if dl is not None else {"skipped": True},
            "box_view": box_view,
            "findings": findings,
            "thresholds": clienttest.THRESHOLDS,
            "method": "TCP-Connect-Zeit auf Port 80/49000 (kein ICMP, kein Root), DNS-A-Abfrage per UDP, "
            "HTTP-Download mit Byte-Limit. Messwerte gelten für DIESEN Rechner und diesen Moment.",
            "for_network_doctor": {"latency": best, "dns": dns},
        }

    def _box_view(self) -> dict[str, Any]:
        """What the box knows about this machine: own IP → host entry → WLAN details / connection quality."""
        out: dict[str, Any] = {}
        ips = sorted(self.local_ips())
        out["local_ips"] = ips
        # X_AVM-DE_GetWLANConnectionInfo answers for the REQUESTING device – i.e. this machine – and gives the
        # same answer on every WLANConfiguration service. The service that answered first is therefore NOT the one
        # the device is associated with: match by band (answer vs. service), else by GetSpecificAssociatedDeviceInfo.
        services = self._wlan_services()
        for service, _band in services:
            r = self.tr064.try_call(service, "X_AVM-DE_GetWLANConnectionInfo")
            if r:
                info = assoc_info(r)
                assoc_service, how = self._service_for_connection(info, r, services)
                if "band_ghz" not in info:
                    band_of = dict(services).get(assoc_service or "")
                    if band_of:
                        info["band_ghz"] = band_of
                out["wlan_connection"] = {
                    "service": assoc_service,
                    "service_match": how,
                    **({"answered_by": service} if service != assoc_service else {}),
                    **info,
                }
                break
        host = None
        if self.resolver is not None and ips:
            try:
                host = next((h for h in self.resolver.hosts() if h.ip in ips), None)
            except (AuthError, ConfirmationRequiredError):
                raise
            except FritzError as exc:
                out["hosts_error"] = exc.to_dict()
        if host is None:
            out["note"] = "Dieser Rechner wurde in der Geräteliste der Box nicht gefunden (anderes Netz, VPN?)."
            out.setdefault("connection", "wlan" if "wlan_connection" in out else "unbekannt")
            return out
        out["host"] = host.as_dict()
        mac = safe_mac(host.mac)
        if mac:
            try:
                q = self.device_connection_quality(mac)
                out["quality"] = q["devices"][0] if q["devices"] else None
            except NotFoundError:
                out["quality"] = None
        quality = out.get("quality") or {}
        out["connection"] = quality.get("connection") or ("wlan" if "wlan_connection" in out else "unbekannt")
        return out


BoxArg = Annotated[
    str | None, Field(description="Name der FRITZ!Box bei Mehrbox-Betrieb (Standard: erste Box, siehe server_status)")
]
PortArg = Annotated[
    str, Field(description='LAN-Port, z. B. "LAN:1" (auch "1", "eth0" oder die UID) – oder "all" für alle Ports')
]


def register_connectivity_tools(tool: ToolDecorator, svc: Callable[[str | None], ConnectivityService]) -> None:
    """Register the stage-6 tools with the tier-aware ``tool`` decorator of ``build_server``."""

    @tool(Tier.READ, _READ)
    def lan_ports(box: BoxArg = None) -> dict[str, Any]:
        """LAN-Ports der Box (/api/v0/generic/eth_ports): Bezeichnung, Funktion (lan/guest/wan), verbunden,
        Geschwindigkeit vs. Maximalrate, Power-/Green-Mode, EEE-Modus (auto/off) und ob EEE gerade
        ausgehandelt ist. Hinweis: EEE wirkt auf manchen Modellen box-weit."""
        return svc(box).lan_ports()

    @tool(Tier.WRITE, _WRITE)
    def set_lan_eee(
        port: PortArg,
        mode: Annotated[Literal["auto", "off"], Field(description="auto = EEE automatisch, off = EEE aus")],
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Schaltet Energy Efficient Ethernet (EEE) eines LAN-Ports bzw. aller Ports (PUT
        /api/v0/generic/eth_ports/eth/<UID> mit nur eee_mode). Liest danach ALLE Ports zurück: verified je
        Port und other_ports_changed, falls die Box die Einstellung box-weit anwendet. 'off' hilft bei
        Link-Flapping (z. B. Raspberry Pi 5). Ports handeln den Link kurz neu aus."""
        return svc(box).set_lan_eee(port, mode)

    @tool(Tier.READ, _READ)
    def vpn_connections(box: BoxArg = None) -> dict[str, Any]:
        """VPN-Verbindungen der Box (/api/v0/generic/vpn): Name, Typ WireGuard/IPSec, Zustand, aktiviert,
        verbunden seit (ISO), Gegenstelle, lokale/entfernte Netze, aktiver Fehler bzw. bei verbundener Verbindung
        letzter (historischer) Fehler – Codes roh, undokumentiert –, WireGuard-Port. Gibt NIE
        Schlüssel, Pre-Shared-Keys, Konfigurationen oder Zugangsdaten aus."""
        return svc(box).vpn_connections()

    @tool(Tier.READ, _READ)
    def powerline_status(box: BoxArg = None) -> dict[str, Any]:
        """Powerline-Adapter (/api/v0/generic/plc): Modell, Status, Kopplung, Firmware/Update, PHY-Raten
        (Einheit unverifiziert), Green-Mode, LED, Gegenstellen + Hinweise bei niedriger Rate."""
        return svc(box).powerline_status()

    @tool(Tier.READ, _READ)
    def box_speedtest_info(box: BoxArg = None) -> dict[str, Any]:
        """Speedtest-SERVER der Box (TR-064 X_AVM-DE_Speedtest: GetInfo/GetStatistics): TCP/UDP im Heimnetz
        bzw. aus dem Internet aktiv, Ports, letzte Messung (Mbit/s). Kein Internet-Speedtest (gibt es per
        TR-064 nicht); warnt, wenn der Server aus dem Internet erreichbar ist."""
        return svc(box).box_speedtest_info()

    @tool(Tier.WRITE, _WRITE)
    def box_speedtest_run(
        seconds: Annotated[float, Field(description="Messdauer in Sekunden (1–30)", ge=1, le=30)] = 10,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Misst den Durchsatz dieses Rechners ZUR Box (Heimnetz-Upload): setzt die Speedtest-Statistik zurück
        (ResetStatistics), sendet TCP-Daten an den Speedtest-Port und liest die Box-Zählung. Erzeugt Last;
        schaltet den Speedtest-Server nie ein (muss bereits aktiv sein)."""
        return svc(box).box_speedtest_run(seconds)

    @tool(Tier.READ, _READ)
    def device_connection_quality(
        mac: Annotated[str | None, Field(description="Optional: nur dieses Gerät (MAC); sonst alle")] = None,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Verbindungsqualität je Gerät: WLAN (Signal dBm/%, Band, Kanal, Kanalbreite, aktuelle/max. Rate,
        Zugangspunkt) bzw. LAN (Port, Speed vs. Maximalrate, EEE) – mit Bewertung gut/ok/schwach und
        konkreten Tipps. Quellen: Mesh-Liste, TR-064 WLANConfiguration, /api/v0 eth_ports. Schlechteste zuerst."""
        return svc(box).device_connection_quality(mac)

    @tool(Tier.READ, _MEASURE)
    def test_my_device(
        count: Annotated[int, Field(description="Anzahl Latenz-Messungen je Port (1–50)", ge=1, le=50)] = 10,
        dns_name: Annotated[str, Field(description="Name für die DNS-Abfrage")] = clienttest.DEFAULT_DNS_NAME,
        public_dns: Annotated[
            str, Field(description="Öffentlicher DNS-Server zum Vergleich ('' = keiner)")
        ] = clienttest.DEFAULT_PUBLIC_DNS,
        download: Annotated[bool, Field(description="HTTP-Download-Durchsatz messen")] = True,
        download_url: Annotated[
            str | None,
            Field(description="Download-URL (Standard: FRITZ_TEST_DOWNLOAD_URL oder speed.cloudflare.com)"),
        ] = None,
        download_bytes: Annotated[
            int, Field(description="Höchstens so viele Bytes laden", ge=100_000, le=clienttest.MAX_DOWNLOAD_BYTES)
        ] = clienttest.DEFAULT_DOWNLOAD_BYTES,
        box: BoxArg = None,
    ) -> dict[str, Any]:
        """Testet DIESEN Rechner (auf dem der MCP läuft): Latenz/Jitter/Verlust zur Box (TCP-Connect 80/49000,
        kein Root), DNS-Antwortzeit gegen den von der Box verteilten und einen öffentlichen DNS, HTTP-Download-
        Durchsatz (kleine Datenmenge) – und vergleicht mit der Sicht der Box (eigene IP → Gerät → WLAN-Signal/
        Band/Rate bzw. LAN-Port). Ergebnis 'for_network_doctor' kann an network_doctor übergeben werden."""
        return svc(box).test_my_device(count, dns_name, public_dns, download, download_url, download_bytes)
