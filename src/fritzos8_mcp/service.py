"""Business logic of the curated tools. Independent of MCP so it can be unit-tested."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import cleanup, snapshot
from .access import Host, HostFilterClient, HostResolver
from .alerts import AlarmService
from .anomaly import AnomalyDetector
from .connectivity import ConnectivityService, Probes
from .devices import DeviceUpdateClient
from .diagnose import DiagnoseClient
from .dns import DnsClient
from .errors import (
    AuthError,
    ConfirmationRequiredError,
    FritzError,
    InvalidParameterError,
    NotFoundError,
    UnsupportedFirmwareError,
)
from .fritzcode import FritzCode
from .guestwifi import GuestWifi
from .history import HistoryService, HistoryStore, Sampler
from .ispreport import IspReport
from .landevice import LanDevice, LanDeviceClient
from .line import LineDiagnostics
from .nasremote import NasRemoteService
from .netinfo import NetInfoClient
from .optimizer import NetworkOptimizer
from .oui import OuiDb
from .parental import ParentalClient, ParentalService
from .phone import PhoneClient
from .phonewrite import PhoneWriter
from .portforward import (
    SENSITIVE_PORTS,
    PortForwardClient,
    normalize_protocol,
    require_absent,
    require_present,
    validate_description,
    validate_port,
)
from .security import Gate, PlanStore, Tier
from .smarthome import AhaClient
from .smarthome_config import SmartHomeConfig
from .smarthome_rest import SmartHomeControl
from .syswrite import SystemWriter
from .telephony import TelephonyClient
from .tr064 import Tr064Client
from .transparency import SystemTransparency
from .util import normalize_mac, validate_hostname
from .wlan import WlanClient, WlanSettings, normalize_band, wlan_light_hints

MAX_CLEANUP_ACTIONS = 50
_HIDDEN_PLAN_KEYS = {"identity", "offline_days"}  # internal plan fields, re-checked in *_execute


def _step_error(exc: FritzError) -> dict[str, Any]:
    return {"ok": False, "verified": False, "error": exc.to_dict()}


class FritzService:
    def __init__(
        self,
        tr064: Tr064Client,
        landevices: LanDeviceClient,
        gate: Gate,
        plans: PlanStore,
        *,
        smarthome: AhaClient | None = None,
        local_ips: Callable[[], set[str]] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        reconnect_wait: float = 60.0,
        reconnect_poll: float = 5.0,
        oui: OuiDb | None = None,
        box_host: str | None = None,
        secrets: tuple[str, ...] = (),
        snapshot_keep: int = snapshot.DEFAULT_KEEP,
        state_root: Path | None = None,
        probes: Probes | None = None,
    ) -> None:
        self.tr064 = tr064
        self.landevices = landevices
        self.gate = gate
        self.plans = plans
        self._sleep = sleep
        self._reconnect_wait = reconnect_wait
        self._reconnect_poll = reconnect_poll
        self.wlan = WlanClient(tr064, sleep=sleep)
        self.wlan_cfg = WlanSettings(self.wlan)  # stage 7.4
        self.diag = DiagnoseClient(tr064, self.wlan)
        self._smarthome = smarthome
        self.telephony = TelephonyClient(tr064)
        self.resolver = HostResolver(tr064, local_ips)
        self.hostfilter = HostFilterClient(tr064, self.resolver)
        self.parental = ParentalService(  # stage 7.5: access profiles + tickets
            ParentalClient(tr064, self.resolver, sleep=sleep), gate, plans
        )
        self.ports = PortForwardClient(tr064, self.diag, self.resolver)
        self.dns = DnsClient(tr064, landevices.rest)
        self.netinfo = NetInfoClient(tr064)
        self.nasremote = NasRemoteService(tr064, gate, plans, sleep=sleep)  # stage 5: NAS & remote access
        self.connectivity = ConnectivityService(  # stage 6: LAN ports, VPN/Powerline, quality
            tr064,
            landevices.rest,
            gate,
            netinfo=self.netinfo,
            wlan=self.wlan,
            resolver=self.resolver,
            box_host=lambda: self.box_host,
            local_ips=local_ips or (lambda: set()),
            probes=probes,
        )
        self.devices = DeviceUpdateClient(
            tr064, self.diag, mesh=self.netinfo.mesh_document
        )  # stage 8.11: device & update overview
        self.oui = oui or OuiDb()  # lazy: downloads only on the first lookup
        self._box_host = box_host
        self._secrets = secrets or tr064.secrets
        self._snapshot_keep = snapshot_keep
        self._state_root = state_root
        self.history = HistoryService(  # stage 8.1: local measurement series
            lambda: Sampler(self, HistoryStore.for_box(self.box_host, self._state_root), extra=self.history_extra)
        )
        self.line = LineDiagnostics(tr064, self.diag)  # stage 8.9: line diagnostics per access type
        self.anomalies = AnomalyDetector(  # stage 10.1: creeping degradation in the measurement series
            lambda: HistoryStore.for_box(self.box_host, self._state_root)
        )
        self.history_extra: list[Callable[[], dict[str, float]]] = [self.line.metrics]
        self.isp = IspReport(self)  # stage 8.2: Störungsprotokoll
        self.alarms = AlarmService(self, state_root=state_root)  # stage 8.3: alarms + notifications
        self.transparency = SystemTransparency(tr064, self.diag)  # stage 8.12
        self.phone = PhoneClient(tr064)  # stage 8.10: telephony read
        self.phone_write = PhoneWriter(tr064, gate, plans)  # stage 8.8: telephony write
        self.smarthome_rest = SmartHomeControl(  # stage 8.5: Smart-Home-REST (AHA as fallback for writes)
            landevices.rest, gate, sleep=sleep, aha=lambda: self.smarthome
        )
        self.smarthome_config = SmartHomeConfig(  # stage 10.6b: Smart-Home configuration, pairing, TR-064
            landevices.rest, gate, plans, tr064, aha=lambda: self.smarthome
        )
        self.code = FritzCode(self)  # stage 8.6: FRITZ as Code
        self.guest = GuestWifi(self, state_root=state_root)  # stage 8.4: guest WLAN session, QR, WPS
        self.optimizer = NetworkOptimizer(self, state_root=state_root)  # stage 10.2: network optimizer
        self.system_write = SystemWriter(  # stage 10.6: firmware update, static routes, IPv6 pinholes, 2FA
            tr064, gate, plans, box_host=lambda: self.box_host, state_root=state_root
        )
        self.alarms.extra_checks.append(("telephony", self.phone.registration_alarms))

    @property
    def box_host(self) -> str:
        if self._box_host is None:
            self._box_host = urlparse(self.tr064.fc.address).hostname or "box"
        return self._box_host

    @property
    def snapshots(self) -> snapshot.SnapshotStore:
        from .paths import state_dir

        return snapshot.SnapshotStore(self._state_root or state_dir(), self.box_host, self._snapshot_keep)

    @property
    def smarthome(self) -> AhaClient:
        if self._smarthome is None:
            raise NotFoundError("Smart-Home-Client ist nicht konfiguriert.")
        return self._smarthome

    # ================================================================ read

    def system_info(self) -> dict[str, Any]:
        return self.tr064.system_info()

    def wan_status(self) -> dict[str, Any]:
        return self.tr064.wan_status()

    def list_hosts(self, only_active: bool = False) -> dict[str, Any]:
        hosts = self.tr064.list_hosts()
        if only_active:
            hosts = [h for h in hosts if h.get("active")]
        return {"count": len(hosts), "hosts": hosts}

    def list_landevices(self, only_active: bool = False) -> dict[str, Any]:
        devices = self.landevices.list()
        if only_active:
            devices = [d for d in devices if d.active or d.online]
        return {"count": len(devices), "landevices": [d.model_dump() for d in devices]}

    def get_lan_dns(self) -> dict[str, Any]:
        return self.tr064.get_lan_dns()

    def tr064_list_services(self) -> dict[str, Any]:
        services = self.tr064.list_services()
        return {"count": len(services), "services": services}

    def tr064_describe_action(self, service: str, action: str) -> dict[str, Any]:
        return self.tr064.describe_action(service, action)

    def tr064_call(self, service: str, action: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.tr064.generic_call(service, action, arguments)

    # ---------------------------------------------------------------- WLAN

    def wlan_status(self) -> dict[str, Any]:
        networks = self.wlan.networks()
        return {"count": len(networks), "networks": networks, "note": "WLAN-Schlüssel werden nie ausgegeben."}

    def guest_wifi_status(self) -> dict[str, Any]:
        return self.wlan.guest()

    def wlan_settings(self, include_web_ui: bool = False) -> dict[str, Any]:
        """Stage 7.4: channel/auto channel per radio, global WLAN switch, night control; optional
        /api/v0 wlan_light hints (unverified, whitelisted)."""
        result: dict[str, Any] = {
            "radios": self.wlan_cfg.radios(),
            "wlan_global_enabled": self.wlan_cfg.global_enable(),
            "night_control": self.wlan_cfg.night_control(),
            "band_steering": {
                "status": "unknown",
                "note": "Bandsteuerung ist per TR-064 nicht lesbar (laut AVM-Doku kein Parameter).",
            },
            "channel_width": {
                "status": "unknown",
                "note": "Die Kanalbandbreite eines Zugangspunkts ist per TR-064 nicht lesbar – nur je verbundenem "
                "Gerät (device_connection_quality, channel_width_mhz).",
            },
            "source": "TR-064 WLANConfiguration (GetInfo, GetChannelInfo, X_AVM-DE_GetNightControl) nach AVM-Doku",
        }
        if include_web_ui:
            try:
                data = self.landevices.rest.request("GET", "/api/v0/generic/wlan_light", missing="firmware")
                result["web_ui_hints"] = {
                    "fields": wlan_light_hints(data),
                    "verified_structure": False,
                    "note": "Auszug aus /api/v0/generic/wlan_light (Struktur nicht belegt, nur Kanal-/Band-/"
                    "Zeitplan-artige Felder, Schlüssel entfernt). Nur als Hinweis lesen.",
                }
            except (AuthError, ConfirmationRequiredError):
                raise
            except FritzError as exc:
                result["web_ui_hints"] = {"error": exc.to_dict()}
        return result

    # ---------------------------------------------------------------- Smart Home

    def smarthome_list_devices(self) -> dict[str, Any]:
        devices = self.smarthome.list_devices()
        result: dict[str, Any] = {"count": len(devices), "devices": devices}
        if not devices:
            result["note"] = "Keine Smart-Home-Geräte an dieser FRITZ!Box angemeldet."
        return result

    def smarthome_device_stats(self, ain: str) -> dict[str, Any]:
        return self.smarthome.device_stats(ain)

    # ---------------------------------------------------------------- Diagnose

    def system_log(self, count: int = 50, text_filter: str | None = None) -> dict[str, Any]:
        return self.diag.system_log(count, text_filter)

    def dsl_info(self) -> dict[str, Any]:
        return self.diag.dsl_info()

    def firmware_status(self) -> dict[str, Any]:
        return self.diag.firmware_status()

    def security_check(self) -> dict[str, Any]:
        def dot() -> bool | None:
            web = self.dns.settings().get("web_settings") or {}
            value = web.get("dns_over_tls") if web.get("available") else None
            return value if isinstance(value, bool) else None

        def static_count() -> int:
            return sum(1 for d in self.landevices.list() if d.static_dhcp)

        return self.diag.security_check(
            dns_over_tls=dot,
            static_ip_count=static_count,
            extra_checks=[("provider_fernwartung", self.transparency.security_item)],
        )

    def network_doctor(
        self,
        symptom: str | None = None,
        flap_check_seconds: int = 0,
        client_measurement: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        from .doctor import NetworkDoctor

        return NetworkDoctor(self).run((symptom or "").strip()[:200] or None, flap_check_seconds, client_measurement)

    # ---------------------------------------------------------------- Telefonie

    def call_list(
        self, days: int | None = None, max_entries: int = 50, call_type: str = "all", resolve_names: bool = False
    ) -> dict[str, Any]:
        result = self.telephony.call_list(days, max_entries, call_type)
        return self.phone.enrich_call_list(result) if resolve_names else result

    def tam_list(self) -> dict[str, Any]:
        return self.telephony.tam_list()

    def phonebook_list(self, with_counts: bool = False) -> dict[str, Any]:
        return self.telephony.phonebook_list(with_counts)

    # ---------------------------------------------------------------- Kindersicherung, Ports, DNS

    def internet_access_status(self, mac: str | None = None, ip: str | None = None) -> dict[str, Any]:
        return self.hostfilter.status(mac, ip)

    def list_port_forwards(self, include_web_ui_lists: bool = False) -> dict[str, Any]:
        result = self.ports.list_all()
        if include_web_ui_lists:
            # stage 6: /api/v0 forwardrules + ipv6firewall – structure unknown, raw + redacted
            result["web_ui_lists"] = self.connectivity.vpnplc.web_firewall_lists()
        return result

    def get_dns_settings(self) -> dict[str, Any]:
        return self.dns.settings()

    # ---------------------------------------------------------------- device clean-up

    def _box_ips_safe(self) -> set[str]:
        try:
            return self.resolver.box_ips()
        except FritzError:
            return set()

    def _cleanup_context(self) -> tuple[cleanup.ProtectionContext, list[str]]:
        """VPN peers and AVM mesh nodes the clean-up must never touch. Unreadable sources are noted – without the
        VPN list, entries without a MAC are never proposed."""
        ctx = cleanup.ProtectionContext()
        notes: list[str] = []
        try:
            ctx.vpn_networks, ctx.vpn_names = cleanup.vpn_context(self.connectivity.vpn_connections())
            ctx.vpn_checked = True
        except (AuthError, ConfirmationRequiredError):
            raise
        except FritzError as exc:
            notes.append(f"VPN-Liste nicht lesbar ({exc.code}) – Einträge ohne MAC werden nicht vorgeschlagen.")
        try:
            ctx.mesh_macs = cleanup.mesh_node_macs(self.netinfo.mesh_document())
            ctx.mesh_checked = True
        except (AuthError, ConfirmationRequiredError):
            raise
        except FritzError as exc:
            notes.append(f"Mesh-Liste nicht lesbar ({exc.code}) – AVM-Geräte nur über MAC/Name erkannt.")
        return ctx, notes

    def devices_cleanup_report(self, offline_days: int = cleanup.DEFAULT_OFFLINE_DAYS) -> dict[str, Any]:
        if not 1 <= offline_days <= 3650:
            raise InvalidParameterError("offline_days muss 1–3650 sein.")
        raw = self.landevices.raw_list()
        try:
            hosts = self.tr064.list_hosts()
            hosts_note = None
        except FritzError as exc:
            hosts, hosts_note = [], f"TR-064-Hostliste nicht lesbar ({exc.code}) – nur /api/v0 ausgewertet."
        ctx, notes = self._cleanup_context()
        report = cleanup.analyze(
            raw, hosts, self.oui, box_ips=self._box_ips_safe(), offline_days=offline_days, context=ctx
        )
        if hosts_note:
            report["hosts_note"] = hosts_note
        if notes:
            report["protection"]["notes"] = notes
        return report

    # ---------------------------------------------------------------- mesh, online monitor, VPN

    def mesh_overview(self) -> dict[str, Any]:
        return self.netinfo.mesh()

    def online_monitor(self) -> dict[str, Any]:
        return self.netinfo.online_monitor()

    def vpn_status(self) -> dict[str, Any]:
        out = self.netinfo.vpn_status()
        # stage 6: WireGuard/IPSec connections from /api/v0/generic/vpn (whitelisted, no keys)
        section = out.get("vpn_connections") or {}
        try:
            vpn = self.connectivity.vpn_connections()
        except (AuthError, ConfirmationRequiredError):
            raise
        except FritzError as exc:
            section["api_v0_error"] = exc.to_dict()
        else:
            section.update(vpn)
            section["status"] = "known"
            section.pop("note", None)
        out["vpn_connections"] = section
        return out

    # ---------------------------------------------------------------- snapshots (write only locally)

    def snapshot_create(self, label: str | None = None) -> dict[str, Any]:
        snap = snapshot.build(self, label, self._secrets)
        store = self.snapshots
        snap_id = store.save(snap)
        sections = snap["sections"]
        return {
            "id": snap_id,
            "created": snap["created"],
            "label": snap["label"],
            "path": str(store.dir / f"{snap_id}.json"),
            "sections_ok": sorted(k for k, v in sections.items() if not (isinstance(v, dict) and "_error" in v)),
            "sections_failed": {k: v["_error"] for k, v in sections.items() if isinstance(v, dict) and "_error" in v},
            "kept": store.keep,
            "note": "Lokal gespeichert (Verzeichnis 0700, Datei 0600), ohne Schlüssel/Passwörter und ohne Messwerte.",
        }

    def snapshot_list(self) -> dict[str, Any]:
        store = self.snapshots
        items = store.listing()
        return {"box": self.box_host, "count": len(items), "keep": store.keep, "snapshots": items}

    def _snapshot_or_live(self, ref: str) -> tuple[dict[str, Any], str]:
        if ref == "live":
            return snapshot.build(self, None, self._secrets), "live"
        return self.snapshots.load(ref), ref

    def snapshot_diff(self, a: str | None = None, b: str | None = None) -> dict[str, Any]:
        store = self.snapshots
        a_ref = (a or "").strip() or store.latest()
        if a_ref is None:
            raise NotFoundError("Noch kein Schnappschuss vorhanden.", hint="Erst snapshot_create aufrufen.")
        b_ref = (b or "").strip() or "live"
        snap_a, a_id = self._snapshot_or_live(a_ref)
        snap_b, b_id = self._snapshot_or_live(b_ref)
        result = snapshot.diff(snap_a, snap_b)
        return {
            "a": {"id": a_id, "created": snap_a.get("created"), "label": snap_a.get("label")},
            "b": {"id": b_id, "created": snap_b.get("created"), "label": snap_b.get("label")},
            **result,
        }

    # ================================================================ write

    def _cleanup_devices(self) -> tuple[list[LanDevice], dict[str, dict[str, Any]], dict[str, int | None], set[str]]:
        """Current device list with raw entries, 'last seen' age in days and the online UIDs."""
        raws = self.landevices.raw_list()
        now = time.time()
        devices = [LanDevice.from_raw(r) for r in raws]
        raw_by_uid = {d.uid: r for d, r in zip(devices, raws, strict=True)}
        ages = {d.uid: cleanup.offline_days_of(r, now) for d, r in zip(devices, raws, strict=True)}
        online = {d.uid for d in devices if d.active or d.online}
        return devices, raw_by_uid, ages, online

    def _cleanup_check(
        self,
        item: dict[str, Any],
        devices: list[LanDevice],
        ctx: cleanup.ProtectionContext | None = None,
        *,
        raw_by_uid: dict[str, dict[str, Any]] | None = None,
        ages: dict[str, int | None] | None = None,
        online: set[str] | None = None,
        offline_days: int = cleanup.DEFAULT_OFFLINE_DAYS,
    ) -> tuple[dict[str, Any], str | None]:
        """Validate one clean-up action against the CURRENT device list. Returns (normalized, reason).
        ``ctx``: VPN peers / AVM mesh nodes; ``ages``/``offline_days``: 'last seen' rule for vendor MACs; same rules
        as devices_cleanup_report (unknown age = not deletable for a globally unique MAC)."""
        ctx = ctx or cleanup.ProtectionContext()
        ages = ages or {}
        action = str(item.get("action") or "").strip().lower()
        raw_mac = str(item.get("mac") or "")
        uid = str(item.get("uid") or "") or None
        out: dict[str, Any] = {"action": action, "mac": raw_mac, "uid": uid}
        if action not in {"delete", "rename"}:
            return out, f'Unbekannte Aktion "{action}" – erlaubt: delete, rename.'
        try:
            mac = normalize_mac(raw_mac)
        except InvalidParameterError as exc:
            return out, str(exc)
        out["mac"] = mac
        matches = [d for d in devices if d.mac == mac and (uid is None or d.uid == uid)]
        if not matches:
            return out, "Kein Geräteeintrag mit dieser MAC" + (f" und UID {uid}" if uid else "") + "."
        if len(matches) > 1:
            return out, f"MAC passt auf mehrere Einträge ({', '.join(d.uid for d in matches)}) – uid angeben."
        d = matches[0]
        out.update(uid=d.uid, current_name=d.display_name, ip=d.ip or None)
        if not d.deleteable:
            return out, "Von der FRITZ!Box als geschützt/nicht löschbar markiert (z. B. die Box selbst)."
        avm = cleanup.avm_device(d, ctx, self.oui)
        if action == "rename" and avm:
            return out, f"{avm} – AVM-Geräte werden vom Aufräum-Assistenten nicht umbenannt."
        if action == "delete":
            if d.active or d.online:
                return out, "Gerät ist aktiv/online – Löschen abgelehnt."
            protected = (
                cleanup.protection_reason(d, ctx, self.oui)
                or cleanup.age_block(d, ages.get(d.uid), offline_days)
                or cleanup.duplicate_keeper_block(
                    d, devices, ages, online if online is not None else {x.uid for x in devices if x.active or x.online}
                )
            )
            if protected:
                return out, f"{protected} – Löschen abgelehnt."
            note = cleanup.loss_note(d, (raw_by_uid or {}).get(d.uid))
            if note:
                out["warning"] = note
            out["offline_days"] = offline_days
            out["identity"] = f"{d.uid}|{d.mac}|offline"
            return out, None
        new = cleanup.normalize_name(str(item.get("name") or ""))
        if not new:
            return out, "Neuer Name fehlt oder enthält keine erlaubten Zeichen (A–Z a–z 0–9 -)."
        if new.lower() in {x.display_name.lower() for x in devices if x.uid != d.uid}:
            return out, f'Name "{new}" ist schon vergeben – eindeutigen Namen wählen.'
        out["name"] = new
        if new != str(item.get("name") or "").strip():
            out["normalized_from"] = str(item.get("name") or "")
        out["identity"] = f"{d.uid}|{d.mac}"
        return out, None

    def devices_cleanup_plan(
        self, actions: list[dict[str, Any]], offline_days: int = cleanup.DEFAULT_OFFLINE_DAYS
    ) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        if not actions:
            raise InvalidParameterError("Keine Aktionen angegeben.")
        if len(actions) > MAX_CLEANUP_ACTIONS:
            raise InvalidParameterError(f"Höchstens {MAX_CLEANUP_ACTIONS} Aktionen pro Plan.")
        if not 1 <= offline_days <= 3650:
            raise InvalidParameterError("offline_days muss 1–3650 sein.")
        devices, raw_by_uid, ages, online = self._cleanup_devices()
        ctx, _ = self._cleanup_context()
        accepted: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        seen: set[str] = set()
        names: set[str] = set()
        for item in actions:
            norm, reason = self._cleanup_check(
                dict(item), devices, ctx, raw_by_uid=raw_by_uid, ages=ages, online=online, offline_days=offline_days
            )
            key = f"{norm.get('uid')}"
            if reason is None and key in seen:
                reason = "Mehrere Aktionen für denselben Eintrag – nur eine pro Gerät."
            if reason is None and norm["action"] == "rename" and norm["name"].lower() in names:
                reason = f'Name "{norm["name"]}" kommt im Plan mehrfach vor.'
            if reason is not None:
                rejected.append({**{k: v for k, v in norm.items() if k not in _HIDDEN_PLAN_KEYS}, "rejected": reason})
                continue
            seen.add(key)
            if norm["action"] == "rename":
                names.add(norm["name"].lower())
            accepted.append(norm)
        result: dict[str, Any] = {
            "action": "devices_cleanup",
            "accepted": [{k: v for k, v in a.items() if k not in _HIDDEN_PLAN_KEYS} for a in accepted],
            "rejected": rejected,
        }
        if not accepted:
            result["note"] = "Keine ausführbare Aktion – kein Token ausgestellt."
            return result
        n_del = sum(1 for a in accepted if a["action"] == "delete")
        n_ren = len(accepted) - n_del
        token = self.plans.issue("devices_cleanup", {"n": len(accepted)}, payload=accepted)
        result.update(
            consequence=f"{n_del} Geräteeintrag/-einträge werden gelöscht (Name, feste IP und Einstellungen gehen "
            f"verloren, nicht umkehrbar) und {n_ren} umbenannt (TR-064-Hostname und Anzeigename).",
            token=token,
            token_valid_s=int(self.plans.ttl),
            execute_with={"tool": "devices_cleanup_execute", "token": token},
        )
        return result

    def devices_cleanup_execute(self, token: str) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        planned = self.plans.redeem_payload(token, "devices_cleanup")
        ctx, _ = self._cleanup_context()
        results: list[dict[str, Any]] = []
        for item in planned or []:
            base = {k: item.get(k) for k in ("action", "mac", "uid", "current_name", "name") if item.get(k)}
            try:
                devices, raw_by_uid, ages, online = self._cleanup_devices()
                norm, reason = self._cleanup_check(
                    item,
                    devices,
                    ctx,
                    raw_by_uid=raw_by_uid,
                    ages=ages,
                    online=online,
                    offline_days=int(item.get("offline_days") or cleanup.DEFAULT_OFFLINE_DAYS),
                )
                if reason is None and norm.get("identity") != item.get("identity"):
                    reason = "Eintrag hat sich seit dem Plan geändert."
                if reason is not None:
                    results.append({**base, "ok": False, "verified": False, "skipped": reason})
                    continue
                if item["action"] == "delete":
                    device = next(d for d in devices if d.uid == item["uid"])
                    r = self.landevices.delete(device)
                    results.append(
                        {**base, "ok": True, "verified": r["verified"], **({"note": r["note"]} if "note" in r else {})}
                    )
                else:
                    r = self.rename_host(item["mac"], item["name"], item["uid"])
                    results.append(
                        {
                            **base,
                            "ok": True,
                            "verified": r["verified"],
                            "host_name": r["host_name"],
                            "friendly_name": r["friendly_name"],
                        }
                    )
            except FritzError as exc:
                results.append({**base, **_step_error(exc)})
        return {
            "action": "devices_cleanup",
            "results": results,
            "done": sum(1 for r in results if r.get("ok")),
            "verified": sum(1 for r in results if r.get("verified")),
            "failed_or_skipped": sum(1 for r in results if not r.get("verified")),
        }

    # ================================================================ write (single)

    def wake_on_lan(self, mac: str) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        mac_n = normalize_mac(mac)
        host: Host | None = None
        try:
            host = next((h for h in self.resolver.hosts() if h.mac == mac_n), None)
        except FritzError:
            host = None
        self.tr064.call("Hosts1", "X_AVM-DE_WakeOnLANByMACAddress", NewMACAddress=mac_n)
        result: dict[str, Any] = {
            "mac": mac_n,
            "name": host.name if host else None,
            "known_to_box": host is not None,
            "sent": True,
            "verified": False,
            "note": "Magic Packet über die FRITZ!Box gesendet. Ob das Gerät aufwacht, ist nicht rücklesbar – "
            "nach 1–2 min mit list_hosts (active) prüfen.",
        }
        if host is None:
            result["warning"] = "Die MAC ist der Box nicht bekannt – Wake-on-LAN erreicht ggf. kein Gerät."
        elif host.active:
            result["warning"] = "Das Gerät ist laut Box bereits aktiv."
        return result

    def set_tam_enabled(self, index: int, enabled: bool) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        return self.telephony.set_tam_enabled(index, enabled)

    def set_internet_access(self, mac: str, allowed: bool) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        return self.hostfilter.set_allowed(mac, allowed)

    def set_wlan_channel(self, band: str, channel: int) -> dict[str, Any]:
        """Stage 7.4: TR-064 SetChannel for the (non-guest) radio of one band, 0 = auto, read back."""
        self.gate.require(Tier.WRITE)
        if not 0 <= channel <= 233:
            raise InvalidParameterError("channel muss 0 (automatisch) oder ein WLAN-Kanal (1–233) sein.")
        return self.wlan_cfg.set_channel(self._wlan_by_band(band), channel)

    def set_guest_wifi(self, enabled: bool) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        guest = self.wlan.guest()
        base = {"ssid": guest["ssid"], "guest_detection": guest["guest_detection"]}
        if guest["enabled"] == enabled:
            return {"service": guest["service"], "enabled": enabled, **base, "changed": False, "verified": True}
        return {**self.wlan.set_enable(guest["service"], enabled), **base}

    def smarthome_set_switch(self, ain: str, on: bool) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        return self.smarthome.set_switch(ain, on)

    def smarthome_set_thermostat(
        self, ain: str, target_c: float | None = None, mode: str | None = None
    ) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        return self.smarthome.set_thermostat(ain, target_c, mode)

    def rename_host(self, mac: str, name: str, uid: str | None = None) -> dict[str, Any]:
        """Set BOTH names: TR-064 host name and the web-UI friendly_name. Each step is read back."""
        self.gate.require(Tier.WRITE)
        mac_n = normalize_mac(mac)
        new_name = validate_hostname(name)

        # Resolve the LAN device first so ambiguous MACs are rejected BEFORE any write.
        device: LanDevice | None = None
        rest_note: str | None = None
        try:
            device = self.landevices.find(mac_n, uid)
        except UnsupportedFirmwareError as exc:
            rest_note = str(exc)

        host_step: dict[str, Any]
        try:
            self.tr064.set_host_name(mac_n, new_name)
            after = self.tr064.host_name_by_mac(mac_n)
            host_step = {
                "ok": True,
                "verified": after == new_name,
                "read_back": after,
            }
        except FritzError as exc:
            host_step = _step_error(exc)

        friendly_step: dict[str, Any]
        if device is None:
            friendly_step = {
                "ok": False,
                "verified": False,
                "error": {"type": "unsupported_firmware", "message": rest_note or "REST nicht verfügbar"},
            }
        else:
            try:
                r = self.landevices.set_friendly_name(mac_n, new_name, device.uid)
                friendly_step = {"ok": True, **r}
            except FritzError as exc:
                friendly_step = _step_error(exc)

        return {
            "mac": mac_n,
            "uid": device.uid if device else uid,
            "name": new_name,
            "host_name": host_step,
            "friendly_name": friendly_step,
            "verified": bool(host_step.get("verified")) and bool(friendly_step.get("verified")),
        }

    def set_static_ip(self, mac: str, uid: str | None = None, enabled: bool = True) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        return self.landevices.set_static_dhcp(normalize_mac(mac), enabled, uid)

    def _deletable(self, mac: str, uid: str | None, *, allow_active: bool) -> LanDevice:
        device = self.landevices.find(normalize_mac(mac), uid)
        if not device.deleteable:
            raise InvalidParameterError(
                f"{device.display_name} ({device.uid}) ist von der FRITZ!Box als nicht löschbar markiert."
            )
        if (device.active or device.online) and not allow_active:
            raise InvalidParameterError(
                f"{device.display_name} ({device.uid}) ist aktiv/online – Löschen abgelehnt.",
                hint="Erzwingen nur über delete_host_force_plan/_execute (Stufe critical).",
            )
        return device

    def delete_host(self, mac: str, uid: str | None = None) -> dict[str, Any]:
        self.gate.require(Tier.WRITE)
        device = self._deletable(mac, uid, allow_active=False)
        return self.landevices.delete(device)

    # ================================================================ critical (plan/execute)

    @staticmethod
    def _identity(device: LanDevice) -> str:
        return f"{device.uid}|{device.mac}"

    def delete_host_force_plan(self, mac: str, uid: str | None = None) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        device = self._deletable(mac, uid, allow_active=True)
        params = {"mac": device.mac, "uid": device.uid}
        token = self.plans.issue("delete_host_force", params, self._identity(device))
        return {
            "action": "delete_host_force",
            "target": device.model_dump(),
            "consequence": "Der Geräteeintrag wird gelöscht, auch wenn das Gerät gerade aktiv ist "
            "(Name, feste IP-Zuweisung und Einstellungen gehen verloren). Nicht umkehrbar.",
            "token": token,
            "token_valid_s": int(self.plans.ttl),
            "execute_with": {"tool": "delete_host_force_execute", "mac": device.mac, "uid": device.uid},
        }

    def delete_host_force_execute(self, token: str, mac: str, uid: str) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        params = {"mac": normalize_mac(mac), "uid": uid}

        def identity() -> str:
            try:
                return self._identity(self._deletable(mac, uid, allow_active=True))
            except FritzError:
                return ""  # target vanished or became protected -> mismatch

        self.plans.redeem(token, "delete_host_force", params, identity)
        device = self.landevices.find(params["mac"], uid)
        return self.landevices.delete(device)

    def _wlan_by_band(self, band: str) -> dict[str, Any]:
        b = normalize_band(band)
        matches = [n for n in self.wlan.networks() if not n["guest"] and n["band_ghz"] == b]
        if not matches:
            raise NotFoundError(f"Kein (Nicht-Gast-)WLAN im {b}-GHz-Band gefunden – siehe wlan_status.")
        if len(matches) > 1:
            services = ", ".join(n["service"] for n in matches)
            raise InvalidParameterError(f"Mehrere WLANs im {b}-GHz-Band ({services}) – nicht eindeutig.")
        return matches[0]

    @staticmethod
    def _wlan_identity(net: dict[str, Any]) -> str:
        return f"{net['service']}|{net['ssid']}|{net['enabled']}"

    def set_wlan_enabled_plan(self, band: str, enabled: bool) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        net = self._wlan_by_band(band)
        b = net["band_ghz"]
        if net["enabled"] == enabled:
            return {"action": "set_wlan_enabled", "target": net, "changed": False, "note": "Bereits in diesem Zustand."}
        params = {"band": b, "enabled": enabled}
        token = self.plans.issue("set_wlan_enabled", params, self._wlan_identity(net))
        if enabled:
            consequence = f"Das WLAN im {b}-GHz-Band ({net['ssid']}) wird eingeschaltet."
        else:
            consequence = (
                f"Das WLAN im {b}-GHz-Band ({net['ssid']}) wird AUSGESCHALTET: alle {net.get('clients') or 0} "
                "verbundenen Geräte in diesem Band verlieren die Verbindung. Läuft dieser Server/Client selbst "
                "über dieses WLAN, sperrt man sich aus – Wiedereinschalten dann nur per LAN, WLAN-Taste oder "
                "anderem Band."
            )
        return {
            "action": "set_wlan_enabled",
            "target": net,
            "consequence": consequence,
            "token": token,
            "token_valid_s": int(self.plans.ttl),
            "execute_with": {"tool": "set_wlan_enabled_execute", "band": b, "enabled": enabled},
        }

    def set_wlan_enabled_execute(self, token: str, band: str, enabled: bool) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        params = {"band": normalize_band(band), "enabled": enabled}
        found: dict[str, Any] = {}

        def identity() -> str:
            try:
                found["net"] = self._wlan_by_band(band)
                return self._wlan_identity(found["net"])
            except FritzError:
                return ""

        self.plans.redeem(token, "set_wlan_enabled", params, identity)
        net = found["net"]
        return {**self.wlan.set_enable(net["service"], enabled), "band_ghz": net["band_ghz"], "ssid": net["ssid"]}

    # ---------------------------------------------------------------- port forwards

    def _port_forward_args(
        self, protocol: str, external_port: int, internal_port: int | None, description: str | None = None
    ) -> tuple[str, int, int | None, str | None]:
        proto = normalize_protocol(protocol)
        ext = validate_port(external_port, "external_port")
        internal = validate_port(internal_port, "internal_port") if internal_port is not None else None
        desc = validate_description(description) if description is not None else None
        return proto, ext, internal, desc

    @staticmethod
    def _pf_params(proto: str, ext: int, internal: int | None, ip: str, desc: str | None) -> dict[str, Any]:
        return {"protocol": proto, "external_port": ext, "internal_port": internal, "ip": ip, "description": desc}

    def _port_target(self, mac: str | None, ip: str | None) -> Host:
        host = self.resolver.resolve(mac, ip)
        if host.ip in self.resolver.box_ips():
            raise InvalidParameterError("Portfreigabe auf die FRITZ!Box selbst ist nicht erlaubt.")
        if host.ip not in self.resolver.server_ips():
            # V-8 (AVM doc WANIPConnection/WANPPPConnection, AddPortMapping): a TR-064 client may only create
            # port mappings for ITSELF – not for other LAN devices, not in the guest network. Refuse early
            # instead of letting the box answer with an unexplained 606.
            raise InvalidParameterError(
                f"Per TR-064 darf dieser Server Portfreigaben nur für sein eigenes Gerät anlegen, nicht für "
                f"{host.name or host.ip} ({host.ip}).",
                hint="Laut AVM-Doku (AddPortMapping) erlaubt die Box selbstständige Portfreigaben nur für den "
                "anfragenden Rechner. Freigaben für andere Geräte: Web-Oberfläche Internet > Freigaben > "
                "Portfreigaben (ein /api/v0-Weg ist als Stufe 7.3 geplant, wartet auf einen Mitschnitt).",
            )
        return host

    # Live (7583/8.26): AddPortMapping makes the box pin the target's IPv4 ("always same IP"), and deleting the
    # forward leaves it pinned. Pins set that way are remembered per box and undone by delete_port_forward_execute.
    AUTO_STATIC_NOTE = (
        "Die FRITZ!Box weist dem Zielgerät beim Anlegen einer Portfreigabe dauerhaft eine feste IPv4 zu "
        "(„Diesem Netzwerkgerät immer die gleiche IPv4-Adresse zuweisen“). delete_port_forward_execute hebt sie "
        "wieder auf, wenn sie erst durch die Freigabe entstanden ist."
    )

    def _auto_static_path(self) -> Path:
        from .paths import ensure_private_dir, safe_component, state_dir

        base = ensure_private_dir((self._state_root or state_dir()) / safe_component(self.box_host))
        return base / "port_forward_static_ip.json"

    def _auto_static_load(self) -> dict[str, str]:
        try:
            data = json.loads(self._auto_static_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}

    def _auto_static_save(self, data: dict[str, str]) -> None:
        from .paths import write_private

        path = self._auto_static_path()
        if data:
            write_private(path, json.dumps(data, sort_keys=True).encode("utf-8"))
        elif path.exists():
            path.unlink()

    def _static_of(self, mac: str) -> bool | None:
        try:
            return self.landevices.find(mac).static_dhcp
        except FritzError:
            return None

    def add_port_forward_plan(
        self,
        protocol: str,
        external_port: int,
        internal_port: int,
        description: str,
        mac: str | None = None,
        ip: str | None = None,
    ) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        proto, ext, internal, desc = self._port_forward_args(protocol, external_port, internal_port, description)
        host = self._port_target(mac, ip)
        service = self.ports.service()
        require_absent(self.ports.find(proto, ext), proto, ext)
        wan = self.tr064.wan_status()
        public_ip = wan.get("external_ipv4")
        warnings: list[str] = []
        if internal in SENSITIVE_PORTS or ext in SENSITIVE_PORTS:
            port = internal if internal in SENSITIVE_PORTS else ext
            warnings.append(
                f"Port {port} ({SENSITIVE_PORTS[port or 0]}) ist ein häufiges Angriffsziel – nur mit starker "
                "Authentifizierung/aktueller Software freigeben."
            )
        if not public_ip:
            warnings.append(
                "Die Box hat keine eigene öffentliche IPv4 (z. B. DS-Lite) – eine IPv4-Freigabe ist von außen "
                "voraussichtlich NICHT erreichbar."
            )
        if not host.active:
            warnings.append("Das Zielgerät ist gerade nicht aktiv.")
        if host.mac and self._static_of(host.mac) is False:
            warnings.append(self.AUTO_STATIC_NOTE)
        params = {
            "protocol": proto,
            "external_port": ext,
            "internal_port": internal,
            "ip": host.ip,
            "description": desc,
        }
        token = self.plans.issue("add_port_forward", params, f"{service}|{host.ip}|{host.mac}|absent")
        reach = f"{public_ip or '<öffentliche IPv4>'}:{ext}/{proto}"
        return {
            "action": "add_port_forward",
            "target": host.as_dict(),
            "mapping": {"service": service, **params},
            "consequence": f"Aus dem INTERNET wird {reach} erreichbar und an {host.name or host.ip} "
            f"({host.ip}) Port {internal}/{proto} weitergeleitet. Jeder im Internet kann diesen Dienst "
            "ansprechen – er muss selbst abgesichert sein.",
            "warnings": warnings,
            "token": token,
            "token_valid_s": int(self.plans.ttl),
            "execute_with": {
                "tool": "add_port_forward_execute",
                "protocol": proto,
                "external_port": ext,
                "internal_port": internal,
                "description": desc,
                "ip": host.ip,
            },
        }

    def add_port_forward_execute(
        self,
        token: str,
        protocol: str,
        external_port: int,
        internal_port: int,
        description: str,
        mac: str | None = None,
        ip: str | None = None,
    ) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        proto, ext, internal, desc = self._port_forward_args(protocol, external_port, internal_port, description)
        found: dict[str, Any] = {}

        def identity() -> str:
            try:
                host = self._port_target(mac, ip)
                service = self.ports.service()
                found.update(host=host, service=service)
                state = "absent" if self.ports.find(proto, ext) is None else "present"
                return f"{service}|{host.ip}|{host.mac}|{state}"
            except FritzError:
                return ""

        # params need the resolved IP; resolve once up front (the identity check re-resolves).
        target_ip = self._port_target(mac, ip).ip
        params = {
            "protocol": proto,
            "external_port": ext,
            "internal_port": internal,
            "ip": target_ip,
            "description": desc,
        }
        self.plans.redeem(token, "add_port_forward", params, identity)
        host = found["host"]
        static_before = self._static_of(host.mac) if host.mac else None
        result = self.ports.add(found["service"], host, proto, ext, internal or ext, desc or "")
        static_after = self._static_of(host.mac) if host.mac else None
        if static_before is False and static_after is True:
            record = self._auto_static_load()
            record[host.mac] = host.ip
            self._auto_static_save(record)
            result["static_ip"] = {"before": False, "after": True, "set_by_box": True, "note": self.AUTO_STATIC_NOTE}
        return result

    def delete_port_forward_plan(self, protocol: str, external_port: int) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        proto, ext, _, _ = self._port_forward_args(protocol, external_port, None)
        service = self.ports.service()
        entry = require_present(self.ports.find(proto, ext), proto, ext)
        params = {"protocol": proto, "external_port": ext}
        token = self.plans.issue("delete_port_forward", params, f"{service}|{sorted(entry.items())}")
        consequence = (
            f"Die Portfreigabe {ext}/{proto} → {entry.get('internal_client')}:{entry.get('internal_port')} wird "
            "gelöscht; der Dienst ist danach aus dem Internet nicht mehr über diese Freigabe erreichbar."
        )
        if str(entry.get("internal_client") or "") in self._auto_static_load().values():
            consequence += (
                " Die feste IP, die die Box beim Anlegen gesetzt hat, wird aufgehoben, falls keine weitere "
                "Freigabe auf das Gerät zeigt."
            )
        return {
            "action": "delete_port_forward",
            "target": {"service": service, **entry},
            "consequence": consequence,
            "token": token,
            "token_valid_s": int(self.plans.ttl),
            "execute_with": {"tool": "delete_port_forward_execute", "protocol": proto, "external_port": ext},
        }

    def delete_port_forward_execute(self, token: str, protocol: str, external_port: int) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        proto, ext, _, _ = self._port_forward_args(protocol, external_port, None)
        found: dict[str, Any] = {}

        def identity() -> str:
            try:
                service = self.ports.service()
                entry = self.ports.find(proto, ext)
                if entry is None:
                    return ""
                found.update(service=service, entry=entry)
                return f"{service}|{sorted(entry.items())}"
            except FritzError:
                return ""

        self.plans.redeem(token, "delete_port_forward", {"protocol": proto, "external_port": ext}, identity)
        result = self.ports.delete(found["service"], found["entry"], proto, ext)
        if result.get("verified"):
            restored = self._undo_auto_static(str(found["entry"].get("internal_client") or ""))
            if restored is not None:
                result["static_ip_restored"] = restored
        return result

    def _undo_auto_static(self, ip: str) -> dict[str, Any] | None:
        """Unpin a fixed IP that only exists because of a port forward created here – once no forward to that
        IP is left. Pins the user set themselves are never in the record and stay untouched."""
        record = self._auto_static_load()
        mac = next((m for m, i in record.items() if i == ip), None)
        if mac is None:
            return None
        remaining = [m for m in self.ports.list_all()["port_forwards"] if m.get("internal_client") == ip]
        if remaining:
            return {"mac": mac, "kept": True, "note": f"Weitere Portfreigaben zeigen noch auf {ip} – feste IP bleibt."}
        try:
            r = self.landevices.set_static_dhcp(mac, False)
        except FritzError as exc:
            return {"mac": mac, "ok": False, "error": exc.to_dict()}
        if r.get("verified"):
            record.pop(mac, None)
            self._auto_static_save(record)
        return {"mac": mac, "ok": True, "static_dhcp": r.get("static_dhcp"), "verified": r.get("verified")}

    def reboot_plan(self) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        uptime = self.tr064.uptime()
        token = self.plans.issue("reboot", {})
        return {
            "action": "reboot",
            "current": {"uptime_s": uptime},
            "consequence": "Die FRITZ!Box startet neu: Internet, WLAN, Telefonie und Smart Home sind ca. "
            "2–4 min weg, laufende Telefonate brechen ab. Nicht abbrechbar, sobald ausgelöst.",
            "token": token,
            "token_valid_s": int(self.plans.ttl),
            "execute_with": {"tool": "reboot_execute"},
        }

    def reboot_execute(self, token: str) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        self.plans.redeem(token, "reboot", {})
        before = self.tr064.uptime()
        self.tr064.reboot()
        return {
            "action": "reboot",
            "accepted": True,
            "verified": False,
            "uptime_before_s": before,
            "note": "Neustart ausgelöst. Die Box ist jetzt einige Minuten nicht erreichbar; Erfolg "
            "anschließend mit system_info prüfen (uptime_s muss klein sein).",
        }

    def reconnect_wan_plan(self) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        status = self.tr064.wan_connection_status()
        token = self.plans.issue("reconnect_wan", {})
        return {
            "action": "reconnect_wan",
            "current": status,
            "consequence": "Die Internetverbindung wird getrennt und neu aufgebaut: meist neue öffentliche "
            "IP, laufende Verbindungen, VPNs und Telefonate brechen ab.",
            "token": token,
            "token_valid_s": int(self.plans.ttl),
            "execute_with": {"tool": "reconnect_wan_execute"},
        }

    def reconnect_wan_execute(self, token: str) -> dict[str, Any]:
        self.gate.require(Tier.CRITICAL)
        self.plans.redeem(token, "reconnect_wan", {})
        before = self.tr064.wan_connection_status()
        self.tr064.force_termination(before["service"])

        waited = 0.0
        after: dict[str, Any] | None = None
        while waited < self._reconnect_wait:
            self._sleep(self._reconnect_poll)
            waited += self._reconnect_poll
            try:
                after = self.tr064.wan_connection_status()
            except FritzError:
                continue
            uptime_before = before.get("uptime_s") or 0
            uptime_after = after.get("uptime_s")
            if (
                after.get("status") == "Connected"
                and uptime_after is not None
                and int(uptime_after) < int(uptime_before)
            ):
                return {"action": "reconnect_wan", "verified": True, "before": before, "after": after}
        return {
            "action": "reconnect_wan",
            "verified": False,
            "before": before,
            "after": after,
            "note": f"Nach {int(waited)} s keine neu aufgebaute Verbindung erkennbar – wan_status später prüfen.",
        }
