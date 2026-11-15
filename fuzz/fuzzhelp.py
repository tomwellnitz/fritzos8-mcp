"""Gemeinsame Helfer der Fuzz-Targets (ClusterFuzzLite/atheris und pytest-Smoke-Tests).

Die Targets laufen auf zwei Wegen:

* unter atheris (ClusterFuzzLite, ``.clusterfuzzlite/build.sh``) mit libFuzzer-Steuerung,
* als normale pytest-Tests (``tests/test_fuzz_targets.py``) ohne atheris – damit sie nicht verrotten.

Ohne atheris liefert ``data_provider`` einen kleinen, deterministischen Ersatz für
``atheris.FuzzedDataProvider`` mit genau den Methoden, die die Targets benutzen.
"""

from __future__ import annotations

import contextlib
import json
import sys
from collections.abc import Callable, Iterator, Sequence
from typing import Any

try:  # pragma: no cover - atheris gibt es nur im ClusterFuzzLite-Build (Linux x86_64)
    import atheris
except ImportError:  # pragma: no cover
    atheris = None


class _Provider:
    """Teilmenge von ``atheris.FuzzedDataProvider`` (gleiche Methodennamen und -semantik im Groben)."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def remaining_bytes(self) -> int:
        return len(self._data) - self._pos

    def ConsumeBytes(self, count: int) -> bytes:
        out = self._data[self._pos : self._pos + max(count, 0)]
        self._pos += len(out)
        return out

    def ConsumeIntInRange(self, low: int, high: int) -> int:
        if high <= low:
            return low
        span = high - low + 1
        raw = self.ConsumeBytes((span.bit_length() + 7) // 8)
        return low + int.from_bytes(raw or b"\0", "little") % span

    def ConsumeBool(self) -> bool:
        return bool(self.ConsumeIntInRange(0, 1))

    def ConsumeUnicodeNoSurrogates(self, count: int) -> str:
        return self.ConsumeBytes(max(count, 0)).decode("utf-8", errors="replace")


_NOTHING = object()


def load_json(text: str, max_depth: int = 64) -> Any:
    """JSON wie von der Box – oder ``NOTHING`` bei ungültigem oder absurd tief verschachteltem Dokument
    (``json.loads`` selbst bricht bei ~1000 Ebenen mit RecursionError ab; echte Antworten haben < 10)."""
    depth = deepest = 0
    for ch in text:
        if ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    if deepest > max_depth:
        return _NOTHING
    try:
        return json.loads(text)
    except ValueError:
        return _NOTHING


NOTHING = _NOTHING


def pick(fdp: Any, values: Sequence[Any]) -> Any:
    """Ein Element aus ``values`` (statt ``PickValueInList``, das in atheris nur echte Listen annimmt)."""
    return values[fdp.ConsumeIntInRange(0, len(values) - 1)]


def data_provider(data: bytes) -> Any:
    """``atheris.FuzzedDataProvider`` im Fuzz-Lauf, sonst der Ersatz oben."""
    if atheris is not None:  # pragma: no cover
        return atheris.FuzzedDataProvider(data)
    return _Provider(data)


@contextlib.contextmanager
def instrumented() -> Iterator[None]:
    """Instrumentiert die im Block importierten Module für die Coverage-Steuerung (nur unter atheris)."""
    if atheris is None:
        yield
        return
    with atheris.instrument_imports():  # pragma: no cover
        yield


def run(test_one_input: Callable[[bytes], None]) -> None:  # pragma: no cover - nur im Fuzz-Lauf
    """Startet libFuzzer mit dem Target (Einstiegspunkt der Fuzz-Skripte)."""
    if atheris is None:
        raise SystemExit("atheris fehlt – Fuzz-Targets laufen über ClusterFuzzLite (CONTRIBUTING.md, Fuzzing).")
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
