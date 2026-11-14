"""Box speed test via TR-064 ``X_AVM-DE_Speedtest1`` (AVM document "TR-064 Support – Speedtest", v3,
2025-08-08).

Important: this service is NOT an internet speed test. It configures the box's built-in speed-test
SERVER (TCP/UDP endpoints in the box, optionally reachable from the internet) and counts the bytes a
client sends to it:

- ``GetInfo`` → ``NewEnableTcp``, ``NewEnableUdp``, ``NewEnableUdpBidirect``, ``NewWANEnableTcp``,
  ``NewWANEnableUdp``, ``NewPortTcp``, ``NewPortUdp``, ``NewPortUdpBidirect``
- ``GetStatistics`` → ``NewByteCount``, ``NewKbitsCurrent``, ``NewKbitsAvg`` (kbit/s), ``NewPacketCount``,
  ``NewPPSCurrent``, ``NewPPSAvg`` – "only incoming packets to the FRITZ!Box on the specific speedtest
  ports are counted"
- ``ResetStatistics``; ``SetConfig`` (enable flags) – deliberately NOT used: we never switch the server
  on (and never the internet-facing variant).

``run`` therefore measures client → box throughput (this machine's LAN/WLAN upload to the box): reset the
counters, send TCP data to ``NewPortTcp`` for a few seconds, read the box statistics. Only possible when
the TCP speed-test server is already enabled. There is no TR-064 action that starts an internet speed
test on the box.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Callable
from typing import Any

from .errors import FritzError, InvalidParameterError, NotFoundError
from .tr064 import Tr064Client
from .util import truthy

SERVICE = "X_AVM-DE_Speedtest1"
MAX_SECONDS = 30
CHUNK = 64 * 1024

Sender = Callable[[str, int, float], dict[str, Any]]


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _mbit(kbit: Any) -> float | None:
    v = _int(kbit)
    return None if v is None else round(v / 1000, 2)


def send_tcp(host: str, port: int, seconds: float) -> dict[str, Any]:
    """Send zero bytes to host:port for `seconds` (no root, stdlib only)."""
    payload = bytes(CHUNK)
    sent = 0
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            s.settimeout(5)
            while time.perf_counter() - start < seconds:
                s.sendall(payload)
                sent += len(payload)
    except OSError as exc:
        return {
            "bytes_sent": sent,
            "duration_s": round(time.perf_counter() - start, 2),
            "error": type(exc).__name__,
        }
    return {"bytes_sent": sent, "duration_s": round(time.perf_counter() - start, 2), "error": None}


def parse_info(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "lan_tcp_enabled": truthy(r.get("NewEnableTcp")),
        "lan_udp_enabled": truthy(r.get("NewEnableUdp")),
        "lan_udp_bidirect_enabled": truthy(r.get("NewEnableUdpBidirect")),
        "internet_tcp_enabled": truthy(r.get("NewWANEnableTcp")),
        "internet_udp_enabled": truthy(r.get("NewWANEnableUdp")),
        "port_tcp": _int(r.get("NewPortTcp")),
        "port_udp": _int(r.get("NewPortUdp")),
        "port_udp_bidirect": _int(r.get("NewPortUdpBidirect")),
    }


def parse_statistics(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "bytes": _int(r.get("NewByteCount")),
        "current_mbit_s": _mbit(r.get("NewKbitsCurrent")),
        "avg_mbit_s": _mbit(r.get("NewKbitsAvg")),
        "packets": _int(r.get("NewPacketCount")),
        "pps_current": _int(r.get("NewPPSCurrent")),
        "pps_avg": _int(r.get("NewPPSAvg")),
    }


class SpeedtestClient:
    def __init__(self, tr064: Tr064Client, host: Callable[[], str], sender: Sender = send_tcp) -> None:
        self.tr064 = tr064
        self._host = host
        self._sender = sender

    def info(self) -> dict[str, Any]:
        r = self.tr064.try_call(SERVICE, "GetInfo")
        if r is None:
            raise NotFoundError("Speedtest-Service (X_AVM-DE_Speedtest) gibt es auf dieser Box nicht.")
        info = parse_info(r)
        stats = self.tr064.try_call(SERVICE, "GetStatistics")
        warnings = []
        if info["internet_tcp_enabled"] or info["internet_udp_enabled"]:
            warnings.append(
                "Der Speedtest-Server der Box ist aus dem INTERNET erreichbar – wenn nicht bewusst genutzt, "
                "in der Web-UI abschalten (Diagnose bzw. Internet > Freigaben, je nach FRITZ!OS)."
            )
        return {
            **info,
            "statistics": parse_statistics(stats) if stats is not None else None,
            "statistics_available": stats is not None,
            "warnings": warnings,
            "what_this_is": "Speedtest-SERVER der Box für Messungen aus dem Heimnetz (zählt nur bei der Box "
            "eingehende Daten). Kein Internet-Speedtest – den bietet TR-064 nicht.",
            "source": "TR-064 X_AVM-DE_Speedtest1 (AVM-Doku v3, 2025-08-08); live noch nicht geprüft",
        }

    def run(self, seconds: float = 10.0) -> dict[str, Any]:
        if not 1 <= seconds <= MAX_SECONDS:
            raise InvalidParameterError(f"seconds muss 1–{MAX_SECONDS} sein.")
        info = self.info()
        port = info["port_tcp"]
        if not info["lan_tcp_enabled"] or not port:
            raise FritzError(
                "Der TCP-Speedtest-Server der Box ist aus – es wird nichts gemessen und nichts umgestellt.",
                hint="Erst in der Web-UI den Speedtest (TCP, nur Heimnetz) einschalten, dann erneut ausführen.",
            )
        self.tr064.call(SERVICE, "ResetStatistics")
        client = self._sender(self._host(), int(port), float(seconds))
        stats_raw = self.tr064.try_call(SERVICE, "GetStatistics")
        stats = parse_statistics(stats_raw) if stats_raw is not None else None
        duration = client.get("duration_s") or 0
        client_mbit = round(client["bytes_sent"] * 8 / duration / 1e6, 2) if duration else None
        box_bytes = (stats or {}).get("bytes")
        verified = bool(box_bytes) and not client.get("error")
        return {
            "direction": "dieser Rechner → FRITZ!Box (Upload im Heimnetz)",
            "seconds": seconds,
            "port_tcp": port,
            "client": {**client, "mbit_s": client_mbit},
            "box": stats,
            "box_counted_mbit_s": None if not box_bytes or not duration else round(box_bytes * 8 / duration / 1e6, 2),
            "verified": verified,
            "note": "Box-Zählung = Daten, die bei der Box angekommen sind; Client-Wert = gesendete Daten. "
            "Große Abweichung deutet auf Verluste oder Puffer hin. Unverifiziert: Protokoll des Box-Servers "
            "(reines Senden auf den TCP-Port) ist nicht dokumentiert.",
        }
