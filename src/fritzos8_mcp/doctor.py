"""Network doctor: combines WAN/DSL values, event log, WLAN, mesh and online monitor into findings
with severity, likely cause and recommendation (read-only).

The thresholds below are rules of thumb, deliberately conservative; findings are phrased as
"deutet auf …", never as a diagnosis. Log patterns match German FRITZ!OS messages and are not
exhaustive. Each data source fails independently (reported under ``sources``).
"""

from __future__ import annotations

import ipaddress
import itertools
import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from . import clienttest
from .errors import AuthError, ConfirmationRequiredError, FritzError
from .netinfo import parse_mesh
from .quality import EEE_BUG_LINKS, is_raspberry_pi, mesh_clients

if TYPE_CHECKING:
    from .service import FritzService

# Documented thresholds (also returned with every report).
THRESHOLDS: dict[str, Any] = {
    "dsl_snr_margin_warn_db": 6.0,
    "dsl_snr_margin_critical_db": 3.0,
    "dsl_attenuation_info_db": 45.0,
    "dsl_crc_errors_warn": 5000,
    "dsl_severely_errored_secs_warn": 100,
    "log_resyncs_warn": 3,
    "log_resyncs_critical": 10,
    "log_disconnects_warn": 3,
    "log_dns_warn": 3,
    "wlan_clients_per_band_info": 30,
    "wlan_24ghz_non_overlapping_channels": [1, 6, 11, 13],
    "mesh_backbone_rate_warn_mbit": 100,
    "signal_weak_dbm": -75,
    "throughput_busy_ratio": 0.9,
    "log_lines_scanned": 500,
    # stage 6
    "log_lan_link_events_warn": 6,
    "flap_sample_interval_s": 2,
    "flap_port_changes_warn": 2,
    "flap_device_changes_warn": 2,
}
MAX_FLAP_CHECK_SECONDS = 60

LOG_PATTERNS: dict[str, re.Pattern[str]] = {
    "resync": re.compile(
        r"dsl antwortet nicht|keine dsl-synchronisation|dsl-synchronisation beginnt|synchronisation verloren|"
        r"kabel-?synchronisation|ranging|t3-timeout|t4-timeout",
        re.I,
    ),
    "disconnect": re.compile(
        r"internetverbindung wurde getrennt|zwangstrennung|pppoe-fehler|verbindung.{0,30}abgebrochen|"
        r"zeitüberschreitung bei der ppp",
        re.I,
    ),
    "dns": re.compile(r"dns-störung|dns.{0,40}(nicht erreichbar|fehlgeschlagen|antwortet nicht|störung)", re.I),
    "radar": re.compile(r"radar|\bdfs\b", re.I),
    # stage 6, unverified wording: "LAN-Anschluss 1 getrennt", "LAN 2: Verbindung hergestellt (1000 Mbit/s)" …
    "lan_link": re.compile(
        r"\blan\b[\s-]*(?:-?anschluss|-?port)?\s*:?\s*(\d)?.{0,60}?"
        r"(getrennt|unterbrochen|verbunden|hergestellt|link (?:up|down))",
        re.I,
    ),
}

SYMPTOM_AREAS: dict[str, tuple[str, ...]] = {
    r"langsam|slow|speed|geschwindigkeit|ruckel|lag|puffer": ("throughput", "dsl", "wlan", "mesh"),
    r"abbr|weg|trenn|disconnect|instabil|ausfall|offline": ("dsl", "log", "wan"),
    r"wlan|wifi|funk|empfang|signal|repeater|mesh": ("wlan", "mesh", "log"),
    r"dns|seite|website|namensaufl|internet geht nicht": ("log", "wan", "dns", "client"),
    r"abbr|bricht|instabil|verlust|aussetz|flatter|flapp|kabel|lan|ethernet|pi\b|raspberry": ("lan", "client"),
    r"langsam|abbr|instabil|schlechter|nachts|immer öfter|zunehm|seit tagen|seit wochen": ("trend",),
}

SEVERITY_ORDER = {"critical": 0, "warn": 1, "info": 2}


def _areas_for(symptom: str | None) -> set[str]:
    if not symptom:
        return set()
    out: set[str] = set()
    for pattern, areas in SYMPTOM_AREAS.items():
        if re.search(pattern, symptom, re.I):
            out.update(areas)
    return out


class NetworkDoctor:
    def __init__(self, svc: FritzService) -> None:
        self.svc = svc

    def run(
        self,
        symptom: str | None = None,
        flap_check_seconds: int = 0,
        client_measurement: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        sources: dict[str, Any] = {}
        findings: list[dict[str, Any]] = []

        def load(name: str, fn: Callable[[], Any]) -> Any:
            try:
                value = fn()
                sources[name] = "ok"
                return value
            except (AuthError, ConfirmationRequiredError):
                raise
            except FritzError as exc:
                sources[name] = exc.to_dict()
                return None

        def add(severity: str, area: str, finding: str, cause: str, recommendation: str, **evidence: Any) -> None:
            findings.append(
                {
                    "severity": severity,
                    "area": area,
                    "finding": finding,
                    "likely_cause": cause,
                    "recommendation": recommendation,
                    "evidence": evidence,
                }
            )

        wan = load("wan", self.svc.tr064.wan_status)
        dsl = load("dsl", self.svc.diag.dsl_info)
        log = load("log", lambda: self.svc.diag.system_log(THRESHOLDS["log_lines_scanned"]))
        wlan = load("wlan", self.svc.wlan.networks)
        mesh_doc = load("mesh", self.svc.netinfo.mesh_document)
        # TR-064 station list (signal %) – the mesh list often carries no signal (live 7583/6660, 8.25/8.26)
        stations = load("wlan_stations", self.svc.netinfo.wlan_stations) if isinstance(mesh_doc, dict) else None
        mesh = parse_mesh(mesh_doc, stations or None) if isinstance(mesh_doc, dict) else None
        monitor = load("throughput", self.svc.netinfo.online_monitor)

        # --- WAN
        if wan:
            status = wan.get("connection", {}).get("status")
            if status != "Connected":
                add(
                    "critical",
                    "wan",
                    f"Internetverbindung nicht aufgebaut (Status {status}).",
                    "deutet auf eine Störung beim Anschluss/Provider oder fehlende Synchronisation hin",
                    "wan_status/dsl_info erneut prüfen; bei anhaltendem Ausfall Störung beim Provider melden.",
                    status=status,
                    last_error=wan.get("connection", {}).get("last_error"),
                )

        # --- DSL line
        if dsl and dsl.get("available"):
            for direction, key in (("Downstream", "snr_down_db"), ("Upstream", "snr_up_db")):
                snr = dsl.get(key)
                if snr is None or snr <= 0:
                    continue
                if snr < THRESHOLDS["dsl_snr_margin_critical_db"]:
                    sev = "critical"
                elif snr < THRESHOLDS["dsl_snr_margin_warn_db"]:
                    sev = "warn"
                else:
                    continue
                add(
                    sev,
                    "dsl",
                    f"Geringe Störabstandsmarge im {direction} ({snr} dB).",
                    "deutet auf eine störanfällige Leitung hin (Einkopplungen, schlechte Hausverkabelung, "
                    "zu aggressive Profileinstellung)",
                    "TAE-/Hausverkabelung prüfen (kurzes, direktes Kabel); in der Web-UI unter Internet > "
                    "DSL-Informationen > Störsicherheit auf mehr Stabilität stellen; bei Bedarf Provider informieren.",
                    snr_db=snr,
                )
            att = dsl.get("attenuation_down_db")
            if att and att > THRESHOLDS["dsl_attenuation_info_db"]:
                add(
                    "info",
                    "dsl",
                    f"Hohe Leitungsdämpfung im Downstream ({att} dB).",
                    "deutet auf eine lange Leitung zum Verteiler hin – begrenzt die erreichbare Rate",
                    "Kein Fehler an sich; bei niedrigen Raten Verkabelung im Haus kurz halten.",
                    attenuation_db=att,
                )
            errors = dsl.get("errors_total") or {}
            crc = errors.get("CRCErrors")
            ses = errors.get("SeverelyErroredSecs")
            if (isinstance(crc, int | float) and crc > THRESHOLDS["dsl_crc_errors_warn"]) or (
                isinstance(ses, int | float) and ses > THRESHOLDS["dsl_severely_errored_secs_warn"]
            ):
                add(
                    "warn",
                    "dsl",
                    "Viele Übertragungsfehler auf der DSL-Leitung seit der letzten Synchronisation.",
                    "deutet auf Störungen auf der Leitung hin (kann Abbrüche und Paketverluste erklären)",
                    "Verlauf beobachten; bei steigenden Werten Leitung vom Provider messen lassen.",
                    crc_errors=crc,
                    severely_errored_secs=ses,
                )

        # --- event log
        if log:
            counts = {k: 0 for k in LOG_PATTERNS}
            samples: dict[str, list[str]] = {k: [] for k in LOG_PATTERNS}
            for entry in log.get("entries", []):
                msg = str(entry.get("message") or "")
                for key, pattern in LOG_PATTERNS.items():
                    if pattern.search(msg):
                        counts[key] += 1
                        if len(samples[key]) < 3:
                            samples[key].append(f"{entry.get('date') or ''} {entry.get('time') or ''} {msg}".strip())
            n = counts["resync"]
            if n >= THRESHOLDS["log_resyncs_warn"]:
                add(
                    "critical" if n >= THRESHOLDS["log_resyncs_critical"] else "warn",
                    "log",
                    f"{n} Synchronisationsverluste/-neustarts im Ereignisprotokoll.",
                    "deutet auf eine instabile Leitung (DSL/Kabel) hin",
                    "Zeitpunkte notieren (Protokoll) und mit dsl_info-Werten dem Provider als Störung melden.",
                    count=n,
                    examples=samples["resync"],
                )
            n = counts["disconnect"]
            if n >= THRESHOLDS["log_disconnects_warn"]:
                add(
                    "warn",
                    "log",
                    f"{n} Verbindungsabbrüche im Ereignisprotokoll.",
                    "deutet auf Abbrüche der Internetverbindung hin (Leitung, Provider oder Zwangstrennung)",
                    "Mit den Synchronisationswerten vergleichen; tägliche Zwangstrennung ist normal.",
                    count=n,
                    examples=samples["disconnect"],
                )
            n = counts["dns"]
            if n:
                add(
                    "warn" if n >= THRESHOLDS["log_dns_warn"] else "info",
                    "log",
                    f"{n} DNS-Störung(en) im Ereignisprotokoll.",
                    "deutet auf nicht erreichbare DNS-Server hin (Provider oder eigene DNS-Einstellung)",
                    "get_dns_settings prüfen; ggf. öffentliche DNS-Server als Fallback erlauben.",
                    count=n,
                    examples=samples["dns"],
                )
            n = counts["radar"]
            if n:
                add(
                    "info",
                    "wlan",
                    f"{n} Radar-Ereignis(se) – 5-GHz-Kanalwechsel.",
                    "deutet auf Radarsignale (DFS) hin; die Box muss den Kanal dann kurz räumen",
                    "Bei häufigen Unterbrechungen einen 5-GHz-Kanal ohne DFS (36–48) wählen.",
                    count=n,
                    examples=samples["radar"],
                )

        # --- WLAN
        if wlan:
            for net in wlan:
                if net.get("error") or net.get("guest"):
                    continue
                band = net.get("band_ghz")
                if not net.get("enabled"):
                    add(
                        "info",
                        "wlan",
                        f"WLAN {band or '?'} GHz ({net.get('ssid')}) ist ausgeschaltet.",
                        "Band bewusst deaktiviert oder Zeitschaltung aktiv",
                        "Falls unbeabsichtigt: in der Web-UI unter WLAN > Funknetz einschalten.",
                        service=net.get("service"),
                    )
                    continue
                channel = net.get("channel")
                try:
                    ch = int(channel) if channel is not None else None
                except (TypeError, ValueError):
                    ch = None
                if band == "2.4" and ch and ch not in THRESHOLDS["wlan_24ghz_non_overlapping_channels"]:
                    add(
                        "info",
                        "wlan",
                        f"2,4-GHz-WLAN auf Kanal {ch} (überlappend).",
                        "deutet auf mögliche Störungen mit Nachbar-WLANs hin",
                        "Kanalwahl auf automatisch lassen oder 1/6/11 nutzen (WLAN > Funkkanal).",
                        channel=ch,
                    )
                clients = net.get("clients") or 0
                if clients > THRESHOLDS["wlan_clients_per_band_info"]:
                    add(
                        "info",
                        "wlan",
                        f"{clients} Geräte im {band}-GHz-WLAN.",
                        "viele gleichzeitige Geräte teilen sich die Funkzeit",
                        "Geräte mit Kabel anbinden oder auf 5 GHz verteilen.",
                        clients=clients,
                    )

        # --- mesh
        if mesh:
            for link in mesh.get("backbone", []):
                rate = link.get("rate_down_mbit")
                signal = link.get("signal_dbm")
                weak_rate = rate is not None and rate < THRESHOLDS["mesh_backbone_rate_warn_mbit"]
                weak_signal = signal is not None and signal < THRESHOLDS["signal_weak_dbm"]
                if weak_rate or weak_signal:
                    add(
                        "warn",
                        "mesh",
                        f"Schwache Mesh-Anbindung {link.get('from')} ↔ {link.get('to')} "
                        f"({rate if rate is not None else '?'} Mbit/s, {signal if signal is not None else '?'} dBm).",
                        "deutet auf zu große Entfernung oder Hindernisse zwischen Box und Repeater hin",
                        "Repeater näher an die Box setzen oder per LAN/Powerline anbinden.",
                        link=link,
                    )
            weak = mesh.get("summary", {}).get("weak_signal_clients") or []
            if weak:
                add(
                    "info",
                    "mesh",
                    f"{len(weak)} Gerät(e) mit schwachem WLAN-Signal (< {THRESHOLDS['signal_weak_dbm']} dBm, gemessen "
                    "oder aus Signal-% geschätzt).",
                    "deutet auf große Entfernung zum nächsten Zugangspunkt hin",
                    "Standort von Gerät/Repeater prüfen.",
                    devices=weak[:10],
                )

        # --- throughput
        if monitor:
            t = monitor.get("throughput") or {}
            down = (t.get("down") or {}).get("current_mbit_s")
            maxd = t.get("max_down_mbit_s")
            if t.get("available") and down and maxd and down >= THRESHOLDS["throughput_busy_ratio"] * maxd:
                add(
                    "info",
                    "throughput",
                    f"Leitung im Downstream gerade ausgelastet ({down} von {maxd} Mbit/s).",
                    "deutet darauf hin, dass ein Gerät die Leitung gerade voll nutzt (Download/Streaming/Backup)",
                    "online_monitor erneut prüfen; ggf. Priorisierung (Internet > Filter > Priorisierung).",
                    down_mbit_s=down,
                    max_down_mbit_s=maxd,
                )

        # --- stage 6: LAN links, EEE + Raspberry Pi, DNS single point of failure, client measurement
        ports = load("lan_ports", self.svc.connectivity.lan.ports)
        self._lan_log(log, add)
        if flap_check_seconds:
            sources["flap_check"] = self._flap_check(flap_check_seconds, add)
        self._eee_raspberry(ports, mesh_doc, add)
        lan_dns = load("lan_dns", self.svc.tr064.get_lan_dns)
        dns_cfg = load("dns_settings", self.svc.dns.settings)
        self._dns_spof(lan_dns, dns_cfg, add)
        if client_measurement:
            self._client(client_measurement, add)
            sources["client_measurement"] = "übergeben"

        # --- stage 8.9: line diagnostics per access type (cable test, optical levels, mobile signal)
        line = load("line", self.svc.line.diagnose)
        if isinstance(line, dict):
            findings.extend(f for f in line.get("findings") or [] if isinstance(f, dict))
        # --- stage 8.12: clock offset, DS-Lite, IPv6 status
        system = load("system", self.svc.transparency.doctor_findings)
        if isinstance(system, list):
            findings.extend(f for f in system if isinstance(f, dict))

        # --- stage 10.1: creeping degradation in the local measurement series (no box access)
        trend = load("anomalies", self.svc.anomalies.findings)
        if isinstance(trend, list):
            findings.extend(f for f in trend if isinstance(f, dict))

        relevant = _areas_for(symptom)
        for f in findings:
            f["relevant_to_symptom"] = bool(relevant) and f["area"] in relevant
        findings.sort(key=lambda f: (not f["relevant_to_symptom"], SEVERITY_ORDER[f["severity"]]))
        counts_by_sev = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
        return {
            "symptom": symptom or None,
            "summary": counts_by_sev,
            "findings": findings,
            "verdict": "keine Auffälligkeiten in den verfügbaren Daten"
            if not findings
            else f"{counts_by_sev['critical']} kritisch, {counts_by_sev['warn']} Warnung(en), "
            f"{counts_by_sev['info']} Hinweis(e)",
            "sources": sources,
            "thresholds": THRESHOLDS,
            "note": "Faustregeln, konservativ formuliert – Befunde sind Hinweise, keine Diagnose. "
            "Nicht verfügbare Quellen stehen unter sources.",
        }

    # ================================================================ stage 6 checks

    @staticmethod
    def _lan_log(log: dict[str, Any] | None, add: Callable[..., None]) -> None:
        if not log:
            return
        per_port: dict[str, int] = {}
        examples: list[str] = []
        for entry in log.get("entries", []):
            msg = str(entry.get("message") or "")
            m = LOG_PATTERNS["lan_link"].search(msg)
            if not m:
                continue
            port = f"LAN:{m.group(1)}" if m.group(1) else "LAN:?"
            per_port[port] = per_port.get(port, 0) + 1
            if len(examples) < 4:
                examples.append(f"{entry.get('date') or ''} {entry.get('time') or ''} {msg}".strip())
        for port, n in sorted(per_port.items()):
            if n >= THRESHOLDS["log_lan_link_events_warn"]:
                add(
                    "warn",
                    "lan",
                    f"{n} Link-Wechsel (getrennt/verbunden) an {port} im Ereignisprotokoll.",
                    "deutet auf Link-Flapping hin (Kabel/Stecker, Energiesparfunktion EEE, Netzteil des Geräts)",
                    "Kabel tauschen, anderen Port testen, EEE abschalten (set_lan_eee mode=off) und mit "
                    "network_doctor(flap_check_seconds=30) gegenprüfen.",
                    count=n,
                    port=port,
                    examples=examples,
                    pattern_verified=False,
                )

    def _flap_check(self, seconds: int, add: Callable[..., None]) -> dict[str, Any]:
        seconds = max(0, min(int(seconds), MAX_FLAP_CHECK_SECONDS))
        interval = THRESHOLDS["flap_sample_interval_s"]
        rounds = max(2, seconds // interval + 1)
        port_states: dict[str, list[tuple[bool, Any]]] = {}
        dev_states: dict[str, list[bool]] = {}
        names: dict[str, str] = {}
        errors = 0
        for i in range(rounds):
            try:
                for p in self.svc.connectivity.lan.ports():
                    port_states.setdefault(str(p["label"]), []).append((p["connected"], p["speed_mbit"]))
            except (AuthError, ConfirmationRequiredError):
                raise
            except FritzError:
                errors += 1
            try:
                for d in self.svc.landevices.list():
                    if d.mac:
                        dev_states.setdefault(d.mac, []).append(d.active or d.online)
                        names[d.mac] = d.display_name
            except (AuthError, ConfirmationRequiredError):
                raise
            except FritzError:
                errors += 1
            if i < rounds - 1:
                self.svc._sleep(interval)

        def changes(seq: list[Any]) -> int:
            return sum(1 for a, b in itertools.pairwise(seq) if a != b)

        flapping_ports = {k: changes(v) for k, v in port_states.items() if changes(v)}
        flapping_devs = {k: changes(v) for k, v in dev_states.items() if changes(v)}
        for port, n in flapping_ports.items():
            if n >= THRESHOLDS["flap_port_changes_warn"]:
                add(
                    "critical" if n >= 4 else "warn",
                    "lan",
                    f"Link-Flapping an {port}: {n} Zustandswechsel in {seconds} s.",
                    "deutet auf instabilen Ethernet-Link hin – typisch EEE-Probleme (z. B. Raspberry Pi 5), "
                    "defektes Kabel oder Port",
                    "EEE an diesem Port/der Box abschalten (set_lan_eee mode=off), Kabel und Port tauschen.",
                    changes=n,
                    samples=[{"connected": c, "speed_mbit": s} for c, s in port_states[port]],
                )
        for mac, n in flapping_devs.items():
            if n >= THRESHOLDS["flap_device_changes_warn"]:
                add(
                    "warn",
                    "lan",
                    f"Gerät {names.get(mac, mac)} wechselt ständig zwischen online/offline ({n}× in {seconds} s).",
                    "deutet auf instabile Verbindung des Geräts hin (Link-Flapping, WLAN-Abbrüche, Energiesparen)",
                    "device_connection_quality für dieses Gerät prüfen; bei LAN EEE/Kabel, bei WLAN Signal.",
                    mac=mac,
                    changes=n,
                )
        return {"seconds": seconds, "rounds": rounds, "read_errors": errors}

    @staticmethod
    def _eee_raspberry(ports: list[dict[str, Any]] | None, mesh_doc: Any, add: Callable[..., None]) -> None:
        if not ports:
            return
        by_label = {p["label"]: p for p in ports}
        clients = mesh_clients(mesh_doc) if isinstance(mesh_doc, dict) else []
        pis = [c for c in clients if c.get("connection") == "lan" and is_raspberry_pi(c.get("mac"))]
        reported = False
        for c in pis:
            port = by_label.get(c.get("lan_port") or "")
            if port and port["eee_supported"] and (port["eee_active"] or port["eee_mode"] == "auto"):
                reported = True
                add(
                    "warn",
                    "lan",
                    f"Raspberry Pi {c.get('name') or c.get('mac')} an {port['label']} mit EEE "
                    f"({'aktiv ausgehandelt' if port['eee_active'] else 'automatisch'}).",
                    "bekannter Fehler: Raspberry Pi (v. a. Pi 5, neuere Kernel) mit EEE → Link-Flapping und "
                    "Paketverlust, z. B. DNS-Ausfälle, wenn der Pi DNS-Server ist",
                    "EEE abschalten: set_lan_eee port=" + str(port["label"]) + " mode=off (wirkt ggf. box-weit) "
                    "oder am Pi (ethtool --set-eee eth0 eee off).",
                    mac=c.get("mac"),
                    port=port["label"],
                    links=list(EEE_BUG_LINKS),
                )
        if pis and not reported and any(p["eee_mode"] == "auto" for p in ports):
            add(
                "info",
                "lan",
                f"{len(pis)} Raspberry Pi per LAN und EEE an der Box aktiv (Port-Zuordnung unklar).",
                "bekannter EEE-Fehler bei Raspberry Pi möglich",
                "Bei Aussetzern EEE abschalten (set_lan_eee mode=off).",
                links=list(EEE_BUG_LINKS),
            )

    def _box_ips(self) -> set[str]:
        ips = {self.svc.box_host}
        try:
            for raw in self.svc.landevices.raw_list():
                if "ownentry" in str(raw.get("flags") or "") and raw.get("ip"):
                    ips.add(str(raw["ip"]))
        except (AuthError, ConfirmationRequiredError):
            raise
        except FritzError:
            pass
        return ips

    def _dns_spof(self, lan_dns: dict[str, Any] | None, cfg: dict[str, Any] | None, add: Callable[..., None]) -> None:
        servers = list((lan_dns or {}).get("dns_servers") or [])
        web = (cfg or {}).get("web_settings") or {}
        v6 = web.get("home_ipv6_dns") if web.get("available") else None
        if not servers:
            return
        box = self._box_ips()

        def home_device(ip: str) -> bool:
            try:
                return ipaddress.ip_address(ip).is_private and ip not in box
            except ValueError:
                return False

        if len(servers) == 1 and home_device(servers[0]):
            add(
                "warn",
                "dns",
                f"Alle Geräte bekommen nur EINEN DNS-Server: {servers[0]} (ein Gerät im Heimnetz).",
                "Single Point of Failure: fällt dieses Gerät aus oder hat es Aussetzer (z. B. Link-Flapping), "
                "lädt im ganzen Netz keine Webseite mehr",
                "In der Box (Heimnetz > Netzwerk > IPv4-Einstellungen bzw. DNS) einen zweiten DNS-Server oder "
                "die Box selbst als Ausweich-DNS eintragen; DNS-Gerät per Kabel ohne EEE betreiben.",
                dns_servers=servers,
                home_ipv6_dns=v6,
            )
        elif v6 and home_device(str(v6)) and all(not home_device(s) for s in servers):
            add(
                "info",
                "dns",
                f"IPv6-DNS zeigt auf ein Heimnetzgerät ({v6}), IPv4 nicht.",
                "uneinheitliche DNS-Verteilung – fällt das Gerät aus, scheitert die Namensauflösung nur teilweise",
                "get_dns_settings prüfen und IPv4/IPv6 einheitlich konfigurieren.",
                home_ipv6_dns=v6,
            )

    @staticmethod
    def _client(m: dict[str, Any], add: Callable[..., None]) -> None:
        inner = m.get("for_network_doctor")
        data: dict[str, Any] = inner if isinstance(inner, dict) else m
        latency = data.get("latency") or data.get("latency_summary")
        dns = data.get("dns")
        for f in clienttest.assess(
            latency if isinstance(latency, dict) else None, dns if isinstance(dns, dict) else None
        ):
            add(
                f["severity"],
                "client",
                f["finding"],
                f["likely_cause"],
                f["recommendation"],
                source="test_my_device",
            )
