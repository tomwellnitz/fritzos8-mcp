"""Measurements from the machine this MCP server runs on (``test_my_device``): latency/jitter/loss to the
box (TCP connect, no ICMP → no root needed), DNS answer time against the box-distributed DNS server and a
public one (raw UDP query, stdlib only), and an HTTP download throughput sample (httpx, size-limited).

All network primitives are injectable so the logic is testable without any network.
"""

from __future__ import annotations

import itertools
import os
import secrets
import socket
import statistics
import struct
import time
from collections.abc import Callable
from typing import Any

import httpx

DEFAULT_PUBLIC_DNS = "9.9.9.9"
DEFAULT_DNS_NAME = "example.com"
DEFAULT_DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes={bytes}"
DEFAULT_DOWNLOAD_BYTES = 5_000_000
MAX_DOWNLOAD_BYTES = 50_000_000

# Documented thresholds (returned with every result).
THRESHOLDS: dict[str, Any] = {
    "box_latency_avg_warn_ms": 15.0,  # LAN ~1 ms, WLAN typically 2–10 ms
    "box_latency_avg_critical_ms": 50.0,
    "box_jitter_warn_ms": 10.0,
    "loss_warn_pct": 2.0,
    "loss_critical_pct": 10.0,
    "dns_slow_ms": 150.0,
    "dns_box_slower_than_public_ms": 100.0,
}

Connect = Callable[[str, int, float], None]
UdpExchange = Callable[[str, bytes, float], bytes]


def tcp_connect(host: str, port: int, timeout: float) -> None:
    with socket.create_connection((host, port), timeout=timeout):
        pass


def udp_exchange(server: str, packet: bytes, timeout: float) -> bytes:
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (server, 53))
        data, _ = s.recvfrom(4096)
        return data


# ------------------------------------------------------------------ latency


def summarize(samples: list[float | None]) -> dict[str, Any]:
    ok = [s for s in samples if s is not None]
    sent = len(samples)
    loss = round((sent - len(ok)) / sent * 100, 1) if sent else None
    if not ok:
        return {"sent": sent, "received": 0, "loss_pct": loss, "min_ms": None, "avg_ms": None, "max_ms": None}
    jitter = statistics.fmean(abs(a - b) for a, b in itertools.pairwise(ok)) if len(ok) > 1 else 0.0
    return {
        "sent": sent,
        "received": len(ok),
        "loss_pct": loss,
        "min_ms": round(min(ok), 2),
        "avg_ms": round(statistics.fmean(ok), 2),
        "max_ms": round(max(ok), 2),
        "jitter_ms": round(jitter, 2),
    }


def tcp_ping(
    host: str,
    port: int,
    count: int = 10,
    *,
    timeout: float = 1.0,
    interval: float = 0.2,
    connect: Connect = tcp_connect,
    clock: Callable[[], float] = time.perf_counter,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    samples: list[float | None] = []
    errors: dict[str, int] = {}
    for i in range(count):
        start = clock()
        try:
            connect(host, port, timeout)
            samples.append((clock() - start) * 1000)
        except OSError as exc:
            samples.append(None)
            errors[type(exc).__name__] = errors.get(type(exc).__name__, 0) + 1
        if i < count - 1:
            sleep(interval)
    return {"target": f"{host}:{port}", **summarize(samples), "errors": errors}


# ------------------------------------------------------------------ DNS


def build_query(name: str, qid: int) -> bytes:
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # recursion desired, one question
    qname = b"".join(bytes([len(p)]) + p.encode("idna") for p in name.strip(".").split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", 1, 1)  # A, IN


def parse_response(data: bytes, qid: int) -> dict[str, Any]:
    if len(data) < 12:
        return {"ok": False, "error": "kurze Antwort"}
    rid, flags, _qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if rid != qid:
        return {"ok": False, "error": "falsche Antwort-ID"}
    rcode = flags & 0x000F
    names = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
    return {"ok": rcode == 0, "rcode": names.get(rcode, str(rcode)), "answers": an}


def dns_time(
    server: str,
    name: str = DEFAULT_DNS_NAME,
    count: int = 3,
    *,
    timeout: float = 2.0,
    exchange: UdpExchange = udp_exchange,
    clock: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    samples: list[float | None] = []
    last: dict[str, Any] = {}
    for _ in range(count):
        qid = secrets.randbelow(0xFFFF)
        start = clock()
        try:
            data = exchange(server, build_query(name, qid), timeout)
            ms = (clock() - start) * 1000
            last = parse_response(data, qid)
            samples.append(ms if last.get("ok") else None)
        except OSError as exc:
            last = {"ok": False, "error": type(exc).__name__}
            samples.append(None)
    s = summarize(samples)
    return {
        "server": server,
        "name": name,
        "answered": s["received"],
        "queries": s["sent"],
        "avg_ms": s["avg_ms"],
        "min_ms": s["min_ms"],
        "max_ms": s["max_ms"],
        "last_result": last,
    }


# ------------------------------------------------------------------ HTTP download


def download_url_default(max_bytes: int) -> str:
    template = os.environ.get("FRITZ_TEST_DOWNLOAD_URL") or DEFAULT_DOWNLOAD_URL
    return template.replace("{bytes}", str(max_bytes))


def http_download(
    url: str,
    max_bytes: int = DEFAULT_DOWNLOAD_BYTES,
    *,
    timeout: float = 15.0,
    client: httpx.Client | None = None,
    clock: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    own = client is None
    http = client or httpx.Client(timeout=timeout, follow_redirects=True)
    received = 0
    start = clock()
    error = None
    status = None
    try:
        with http.stream("GET", url) as response:
            status = response.status_code
            if response.status_code >= 400:
                error = f"HTTP {response.status_code}"
            else:
                for chunk in response.iter_bytes():
                    received += len(chunk)
                    if received >= max_bytes or clock() - start > timeout:
                        break
    except httpx.HTTPError as exc:
        error = type(exc).__name__
    finally:
        if own:
            http.close()
    duration = clock() - start
    return {
        "url_host": httpx.URL(url).host,
        "status": status,
        "bytes": received,
        "duration_s": round(duration, 2),
        "mbit_s": round(received * 8 / duration / 1e6, 2) if duration > 0 and received else None,
        "error": error,
    }


# ------------------------------------------------------------------ assessment


def assess(latency: dict[str, Any] | None, dns: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Findings from a test_my_device result (also used by the network doctor)."""
    out: list[dict[str, Any]] = []
    t = THRESHOLDS
    if latency:
        loss = latency.get("loss_pct")
        if isinstance(loss, int | float) and loss >= t["loss_warn_pct"]:
            out.append(
                {
                    "severity": "critical" if loss >= t["loss_critical_pct"] else "warn",
                    "finding": f"{loss:g} % Verbindungsverlust zwischen diesem Rechner und der Box.",
                    "likely_cause": "deutet auf instabilen Link hin (WLAN-Störung, defektes Kabel, Link-Flapping, "
                    "z. B. durch EEE)",
                    "recommendation": "lan_ports (verbunden/EEE) und device_connection_quality prüfen; per Kabel "
                    "gegentesten.",
                }
            )
        avg = latency.get("avg_ms")
        if isinstance(avg, int | float) and avg >= t["box_latency_avg_warn_ms"]:
            out.append(
                {
                    "severity": "warn" if avg >= t["box_latency_avg_critical_ms"] else "info",
                    "finding": f"Hohe Latenz zur Box (Ø {avg:g} ms).",
                    "likely_cause": "deutet auf ausgelastetes WLAN, schwaches Signal oder Energiesparmodus des "
                    "Geräts hin",
                    "recommendation": "Näher an Box/Repeater testen oder per LAN vergleichen.",
                }
            )
        jitter = latency.get("jitter_ms")
        if isinstance(jitter, int | float) and jitter >= t["box_jitter_warn_ms"]:
            out.append(
                {
                    "severity": "info",
                    "finding": f"Schwankende Latenz zur Box (Jitter {jitter:g} ms).",
                    "likely_cause": "deutet auf WLAN-Störungen oder Funkzeit-Konkurrenz hin",
                    "recommendation": "Für Telefonie/Gaming LAN nutzen oder 5-GHz-Kanal prüfen.",
                }
            )
    if dns:
        local, public = dns.get("box_dns") or [], dns.get("public")
        for entry in local:
            if not entry.get("answered"):
                out.append(
                    {
                        "severity": "critical",
                        "finding": f"Der im Heimnetz verteilte DNS-Server {entry.get('server')} antwortet nicht.",
                        "likely_cause": "deutet auf ausgefallenen DNS-Server hin (z. B. Pi-hole/AdGuard-Gerät "
                        "offline) – Webseiten laden dann nicht",
                        "recommendation": "DNS-Gerät prüfen; in der Box einen zweiten DNS bzw. Fallback eintragen.",
                    }
                )
                continue
            avg = entry.get("avg_ms")
            pub_avg = (public or {}).get("avg_ms")
            if isinstance(avg, int | float) and (
                avg >= t["dns_slow_ms"]
                or (isinstance(pub_avg, int | float) and avg - pub_avg >= t["dns_box_slower_than_public_ms"])
            ):
                out.append(
                    {
                        "severity": "info",
                        "finding": f"DNS-Antworten von {entry.get('server')} langsam (Ø {avg:g} ms).",
                        "likely_cause": "deutet auf überlasteten oder schlecht angebundenen DNS-Server hin",
                        "recommendation": "Upstream des DNS-Servers und dessen Netzanbindung prüfen.",
                    }
                )
    return out
