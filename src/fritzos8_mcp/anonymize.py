"""Stage 10.5 – community fixtures: turn real box answers (TR-064 results, /api/v0 JSON, AHA/TR-064 XML, log text)
into anonymized test fixtures that can be shared publicly.

Replaced consistently within one run (the same real value always gets the same placeholder, so structure and
cross references stay intact):

* MAC addresses → ``AA:BB:CC:00:00:NN`` (separator/case style kept),
* IPv4 → private ``192.0.2.N`` / public ``198.51.100.N`` (documentation ranges); masks, ``0.0.0.0``, loopback,
  multicast/broadcast stay,
* IPv6 → ``2001:db8::N`` (link-local ``fe80::N``; ``::``/``::1`` stay),
* device/host/network names, SSIDs, user names, real names → ``Gerät N``, ``WLAN N``, ``benutzerN``, ``Name N``,
* serial numbers, UDNs/UUIDs, AINs → ``SERIAL000N``, ``00000000-0000-0000-0000-00000000000N``, ``12345 00000NN``,
* phone numbers (in number-like fields and in AHA/TAM/call list XML) → ``0301234NNNN``,
* e-mail addresses → ``userN@example.com``, MyFRITZ!/DynDNS host names → ``boxN.example.net``,
* coordinates/location/address fields → ``0`` / ``anonymisiert``,
* secrets (passwords, keys, PINs, SIDs, tokens) → ``***`` via the central redaction (``redact.py``).

``find_leftovers`` checks a result for anything that still looks real (MACs outside AA:BB:CC, private IPs outside
the documentation ranges, e-mail addresses, AINs, coordinates). The CLI refuses to write a fixture with leftovers
unless ``--force`` is given. The mapping real → placeholder is never written anywhere.

CLI: ``fritzos8-anonymize INPUT [-o OUTPUT] [--kind tr064|rest|aha|xml|text] [--model …] [--fritzos …]
[--name …] [--force]`` (INPUT ``-`` = stdin).
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from collections.abc import Callable
from typing import Any

from .redact import redact, redact_api, redact_obj

MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f:.-])((?:[0-9A-Fa-f]{2}([:-]))(?:[0-9A-Fa-f]{2}\2){4}[0-9A-Fa-f]{2})(?![0-9A-Fa-f:-])"
)
MAC_PLAIN_RE = re.compile(r"^[0-9A-Fa-f]{12}$")
IPV4_RE = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])")
IPV6_RE = re.compile(r"(?<![0-9A-Za-z:])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%\w+)?)(?![0-9A-Za-z:])")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
AIN_RE = re.compile(r"(?<!\d)(\d{5}) ?(\d{7})(-\d)?(?!\d)")
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
DYNDNS_RE = re.compile(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.(?:myfritz\.net|dyndns\.org|ddns\.net|duckdns\.org)\b")
PHONE_RE = re.compile(r"^\+?[\d *#/()-]{4,30}$")

_KEY_NAME = re.compile(
    r"(^|_|-)(new)?(host_?name|device_?name|friendly_?name|name|realname|displayname|nickname|"
    r"x_avm-de_friendlyname|devicename|hostname|callername|calledname|caller_name|called_name|phonename|"
    r"x_avm-de_phonename|alarmclockname|description|mesh_master|connected_to|access_point)$",
    re.I,
)
_KEY_SSID = re.compile(r"ssid$", re.I)
_KEY_USER = re.compile(r"(user_?name|username|login|account|^user$|^newuser$)", re.I)
_KEY_SERIAL = re.compile(r"(serial|seriennummer|imei|imsi|iccid|udn|^uuid$|_uuid$|deviceid$)", re.I)
_KEY_PHONE = re.compile(
    r"(number|nummer|msn|caller|called|phone|telefon|^tel$|^ziel$|deflectiontonumber|numbers?$)", re.I
)
_KEY_LOCATION = re.compile(r"(^|_)(latitude|longitude|lat|lon|lng|location|address|street|city|zip|postal)", re.I)
_KEY_KEEP = re.compile(
    r"(modelname|productname|manufacturer|softwareversion|firmware|hardwareversion|version|type|"
    r"protocol|standard|band|state|status|mode|unit|interface|service|action|category|productcategory)$",
    re.I,
)
# XML text nodes (AHA device lists, TAM/call lists, phone books, host lists) whose content is personal.
_XML_NAME_TAGS = ("name", "Name", "HostName", "realName", "DeviceName", "Caller", "Called", "CallerName", "Device")
_XML_PHONE_TAGS = ("Number", "number", "Called", "Caller", "CalledNumber", "CallerNumber", "Numbers")
_XML_SERIAL_TAGS = ("serial", "SerialNumber", "UDN", "identifier")

_KEEP_IPV4 = ("0.0.0.0", "255.255.255.255")  # noqa: S104 - values to keep, not a bind address


class Anonymizer:
    def __init__(self) -> None:
        self._maps: dict[str, dict[str, str]] = {}
        self.counts: dict[str, int] = {}

    def _get(self, kind: str, real: str, make: Callable[[int], str]) -> str:
        table = self._maps.setdefault(kind, {})
        if real not in table:
            table[real] = make(len(table) + 1)
            self.counts[kind] = len(table)
        return table[real]

    # ------------------------------------------------------------ single values

    def mac(self, real: str) -> str:
        sep = ":" if ":" in real else ("-" if "-" in real else "")
        key = re.sub(r"[^0-9a-f]", "", real.lower())
        if key in ("000000000000", "ffffffffffff") or key.startswith("aabbcc"):
            return real
        fake = self._get("mac", key, lambda n: f"AABBCC{(n >> 16) & 0xFF:02X}{(n >> 8) & 0xFF:02X}{n & 0xFF:02X}")
        parts = [fake[i : i + 2] for i in range(0, 12, 2)]
        out = sep.join(parts)
        return out.lower() if real == real.lower() and any(c.isalpha() for c in real) else out

    def ipv4(self, real: str) -> str:
        try:
            ip = ipaddress.IPv4Address(real)
        except ValueError:
            return real
        if (
            real in _KEEP_IPV4
            or ip.is_loopback
            or ip.is_multicast
            or real.startswith("255.")
            or ip in ipaddress.IPv4Network("192.0.2.0/24")
            or ip in ipaddress.IPv4Network("198.51.100.0/24")
            or ip in ipaddress.IPv4Network("203.0.113.0/24")
        ):
            return real
        if ip.is_private or ip.is_link_local or ip.is_reserved:
            return self._get("ipv4_private", real, lambda n: f"192.0.2.{min(n, 254)}")
        return self._get("ipv4_public", real, lambda n: f"198.51.100.{min(n, 254)}")

    def ipv6(self, real: str) -> str:
        addr = real.split("%", 1)[0]
        try:
            ip = ipaddress.IPv6Address(addr)
        except ValueError:
            return real
        if ip.is_unspecified or ip.is_loopback or ip in ipaddress.IPv6Network("2001:db8::/32"):
            return real
        if ip.is_link_local:
            return self._get("ipv6_ll", addr, lambda n: f"fe80::{n:x}")
        return self._get("ipv6", addr, lambda n: f"2001:db8::{n:x}")

    def name(self, real: str, kind: str = "name") -> str:
        if not real.strip():
            return real
        prefix = {"name": "Gerät", "ssid": "WLAN", "user": "benutzer", "person": "Name"}[kind]
        sep = "" if kind == "user" else " "
        return self._get(kind, real, lambda n: f"{prefix}{sep}{n}")

    def serial(self, real: str) -> str:
        if not real.strip():
            return real
        if UUID_RE.fullmatch(real.removeprefix("uuid:")):
            fake = self._get("uuid", real, lambda n: f"00000000-0000-0000-0000-{n:012d}")
            return ("uuid:" if real.startswith("uuid:") else "") + fake
        return self._get("serial", real, lambda n: f"SERIAL{n:04d}")

    def phone(self, real: str) -> str:
        digits = re.sub(r"\D", "", real)
        if len(digits) < 3 or digits in ("110", "112"):
            return real
        if len(digits) <= 3:  # internal numbers (**610) stay
            return real
        return self._get("phone", digits, lambda n: f"0301234{n:04d}")

    def ain(self, match: re.Match[str]) -> str:
        real = match.group(0)
        if match.group(1) == "12345":
            return real
        fake = self._get("ain", match.group(1) + match.group(2), lambda n: f"12345 {n:07d}")
        if " " not in real:
            fake = fake.replace(" ", "")
        return fake + (match.group(3) or "")

    # ------------------------------------------------------------ text

    def text(self, value: str) -> str:
        out = redact(value)
        out = EMAIL_RE.sub(lambda m: self._get("email", m.group(0).lower(), lambda n: f"user{n}@example.com"), out)
        out = DYNDNS_RE.sub(lambda m: self._get("dyndns", m.group(0).lower(), lambda n: f"box{n}.example.net"), out)
        out = UUID_RE.sub(lambda m: self.serial(m.group(0)), out)
        out = MAC_RE.sub(lambda m: self.mac(m.group(1)), out)
        out = IPV6_RE.sub(lambda m: self.ipv6(m.group(1)), out)
        out = IPV4_RE.sub(lambda m: self.ipv4(m.group(1)), out)
        return AIN_RE.sub(self.ain, out)

    def xml(self, value: str) -> str:
        out = value
        for tag in _XML_PHONE_TAGS:
            out = re.sub(
                rf"(<{tag}(?:\s[^>]*)?>)([^<]+)(</{tag}>)",
                lambda m: m.group(1) + (self.phone(m.group(2)) if PHONE_RE.match(m.group(2).strip()) else
                                        m.group(2)) + m.group(3),
                out,
            )  # fmt: skip
        for tag in _XML_NAME_TAGS:
            out = re.sub(
                rf"(<{tag}(?:\s[^>]*)?>)([^<]+)(</{tag}>)",
                lambda m: (
                    m.group(1)
                    + (m.group(2) if PHONE_RE.match(m.group(2).strip()) else self.name(m.group(2)))
                    + m.group(3)
                ),
                out,
            )
        for tag in _XML_SERIAL_TAGS:
            out = re.sub(
                rf"(<{tag}(?:\s[^>]*)?>)([^<]+)(</{tag}>)", lambda m: m.group(1) + self.serial(m.group(2)) + m.group(3),
                out,
            )  # fmt: skip
        out = re.sub(r'(\sname=")([^"]+)(")', lambda m: m.group(1) + self.name(m.group(2)) + m.group(3), out)
        out = re.sub(
            r'(\sidentifier=")([^"]+)(")',
            lambda m: m.group(1) + AIN_RE.sub(self.ain, m.group(2)) + m.group(3),
            out,
        )
        return self.text(out)

    # ------------------------------------------------------------ structures

    def value_for_key(self, key: str, value: Any) -> Any:
        if isinstance(value, dict | list):
            return self.obj(value)
        if not isinstance(value, str):
            if isinstance(value, int | float) and _KEY_LOCATION.search(key):
                return 0
            return value
        if value.lstrip().startswith("<") and value.rstrip().endswith(">"):
            return self.xml(value)
        if _KEY_KEEP.search(key) and not _KEY_SERIAL.search(key):
            return self.text(value)
        if _KEY_LOCATION.search(key):
            return "anonymisiert" if value.strip() else value
        if _KEY_SERIAL.search(key):
            return self.serial(value)
        if _KEY_SSID.search(key):
            return self.name(value, "ssid")
        if _KEY_USER.search(key):
            return self.name(value, "user")
        if _KEY_PHONE.search(key) and PHONE_RE.match(value.strip()) and not IPV4_RE.fullmatch(value.strip()):
            return self.phone(value)
        if "mac" in key.lower() and MAC_PLAIN_RE.match(value):
            return self.mac(value)
        if _KEY_NAME.search(key):
            if MAC_RE.fullmatch(value) or IPV4_RE.fullmatch(value):
                return self.text(value)
            return self.name(value, "person" if "real" in key.lower() else "name")
        return self.text(value)

    def replace_known_names(self, data: Any) -> Any:
        """Second pass: a real name that was replaced in a name field also appears elsewhere as a plain reference
        (mesh_overview: ``from``/``to``, dict keys of ``clients_per_node``, lists like ``weak_signal_clients``).
        Replace every string value and dict key that equals a known real name exactly – no substring matches."""
        known: dict[str, str] = {}
        for kind in ("name", "ssid", "person", "user"):
            known.update(self._maps.get(kind, {}))
        if not known:
            return data

        def walk(value: Any) -> Any:
            if isinstance(value, dict):
                return {known.get(k, k) if isinstance(k, str) else k: walk(v) for k, v in value.items()}
            if isinstance(value, list):
                return [walk(v) for v in value]
            if isinstance(value, str):
                return known.get(value, value)
            return value

        return walk(data)

    def obj(self, data: Any) -> Any:
        if isinstance(data, dict):
            return {k: self.value_for_key(str(k), v) for k, v in data.items()}
        if isinstance(data, list):
            return [self.obj(v) for v in data]
        if isinstance(data, str):
            return self.xml(data) if data.lstrip().startswith("<") else self.text(data)
        return data


def anonymize(data: Any, kind: str = "auto") -> tuple[Any, Anonymizer]:
    """Anonymize parsed JSON (dict/list) or raw text/XML; returns (result, anonymizer with counts)."""
    a = Anonymizer()
    if isinstance(data, dict | list):
        cleaned = redact_api(data) if kind == "rest" else redact_obj(data)
        return a.replace_known_names(a.obj(cleaned)), a
    text = str(data)
    if kind in ("xml", "aha") or (kind == "auto" and text.lstrip().startswith("<")):
        return a.xml(text), a
    return a.text(text), a


def find_leftovers(data: Any) -> list[str]:
    """Things in an (anonymized) result that still look real. Empty list = nothing suspicious found."""
    text = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
    found: set[str] = set()
    for m in MAC_RE.finditer(text):
        key = re.sub(r"[^0-9a-f]", "", m.group(1).lower())
        if not key.startswith("aabbcc") and key not in ("000000000000", "ffffffffffff"):
            found.add(f"MAC {m.group(1)}")
    for m in IPV4_RE.finditer(text):
        try:
            ip = ipaddress.IPv4Address(m.group(1))
        except ValueError:
            continue
        if (
            m.group(1) in _KEEP_IPV4
            or ip.is_loopback
            or ip.is_multicast
            or m.group(1).startswith("255.")
            or any(ip in ipaddress.IPv4Network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
        ):
            continue
        found.add(f"IPv4 {m.group(1)}")
    for m in IPV6_RE.finditer(text):
        try:
            ip6 = ipaddress.IPv6Address(m.group(1).split("%", 1)[0])
        except ValueError:
            continue
        if not (ip6.is_unspecified or ip6.is_loopback or ip6 in ipaddress.IPv6Network("2001:db8::/32")) and not (
            ip6.is_link_local and int(ip6) & 0xFFFFFFFFFFFFFFFF < 0x10000
        ):
            found.add(f"IPv6 {m.group(1)}")
    for m in EMAIL_RE.finditer(text):
        if not m.group(0).lower().endswith("@example.com"):
            found.add(f"E-Mail {m.group(0)}")
    for m in AIN_RE.finditer(text):
        if m.group(1) != "12345":
            found.add(f"AIN {m.group(0)}")
    for m in DYNDNS_RE.finditer(text):
        found.add(f"DynDNS {m.group(0)}")
    for m in re.finditer(r'"(latitude|longitude)"\s*:\s*(-?\d+\.\d+)', text):
        if float(m.group(2)) != 0:
            found.add(f"Koordinate {m.group(1)}")
    return sorted(found)


def build_fixture(
    data: Any, kind: str, *, model: str | None = None, fritzos: str | None = None, name: str | None = None
) -> tuple[dict[str, Any], list[str]]:
    result, a = anonymize(data, kind)
    fixture = {
        "fixture": {
            "name": name,
            "kind": kind,
            "model": model,
            "fritzos": fritzos,
            "anonymized_with": "fritzos8-anonymize",
            "replaced": dict(sorted(a.counts.items())),
        },
        "data": result,
    }
    return fixture, find_leftovers(result)


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - thin CLI wrapper, logic tested above
    import argparse
    from pathlib import Path

    p = argparse.ArgumentParser(
        prog="fritzos8-anonymize",
        description="Box-Antworten (TR-064/REST/XML/Text) anonymisieren und als Test-Fixture ausgeben.",
    )
    p.add_argument("input", help="Datei mit der Box-Antwort oder - für stdin")
    p.add_argument("-o", "--output", help="Ziel-Datei (Standard: stdout)")
    p.add_argument("--kind", default="auto", choices=["auto", "tr064", "rest", "aha", "xml", "text"])
    p.add_argument("--model", help="z. B. 'FRITZ!Box 7590' (kein Seriennummer/Standort)")
    p.add_argument("--fritzos", help="z. B. '8.20'")
    p.add_argument("--name", help="Kurzname, z. B. 'tr064-hosts-GetGenericHostEntry'")
    p.add_argument("--force", action="store_true", help="auch bei Restfunden schreiben (bitte von Hand prüfen)")
    args = p.parse_args(argv)
    raw = sys.stdin.read() if args.input == "-" else Path(args.input).read_text(encoding="utf-8")
    data: Any
    try:
        data = json.loads(raw)
        kind = "tr064" if args.kind == "auto" else args.kind
    except ValueError:
        data = raw
        kind = args.kind
    fixture, leftovers = build_fixture(data, kind, model=args.model, fritzos=args.fritzos, name=args.name)
    if leftovers and not args.force:
        print("Nicht geschrieben – noch verdächtige Werte:", file=sys.stderr)
        for item in leftovers:
            print(f"  - {item}", file=sys.stderr)
        print("Von Hand prüfen und ggf. mit --force schreiben.", file=sys.stderr)
        return 1
    text = json.dumps(fixture, ensure_ascii=False, indent=1) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Fixture geschrieben: {args.output} ({sum(fixture['fixture']['replaced'].values())} Ersetzungen)")
    else:
        sys.stdout.write(text)
    return 0


def cli() -> None:  # pragma: no cover
    raise SystemExit(main())
