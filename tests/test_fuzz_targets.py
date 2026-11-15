"""Smoke-Test der Fuzz-Targets in fuzz/ ohne atheris: Seed-Korpus + deterministische Zufallseingaben.

Hält die Targets lauffähig (Importe, Invarianten) – der eigentliche Fuzz-Lauf passiert in ClusterFuzzLite
(.clusterfuzzlite/, .github/workflows/cflite-*.yml).
"""

from __future__ import annotations

import importlib.util
import random
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType

import pytest

FUZZ = Path(__file__).resolve().parent.parent / "fuzz"
TARGETS = sorted(FUZZ.glob("fuzz_*.py"))
RANDOM_INPUTS = 300


def _load(path: Path) -> ModuleType:
    if str(FUZZ) not in sys.path:
        sys.path.insert(0, str(FUZZ))
    spec = importlib.util.spec_from_file_location(f"fuzz_target_{path.stem}", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _inputs(path: Path) -> Iterator[bytes]:
    corpus = FUZZ / "corpus" / path.stem
    seeds = sorted(corpus.iterdir()) if corpus.is_dir() else []
    yield from (seed.read_bytes() for seed in seeds)
    rng = random.Random(path.stem)  # noqa: S311 - reproducible test inputs, no cryptography
    for _ in range(RANDOM_INPUTS):
        yield rng.randbytes(rng.randint(0, 512))


def test_every_target_is_listed() -> None:
    assert {p.stem for p in TARGETS} >= {
        "fuzz_redact",
        "fuzz_redact_api",
        "fuzz_box_xml",
        "fuzz_mesh",
        "fuzz_anonymize",
        "fuzz_config",
    }


@pytest.mark.parametrize("path", TARGETS, ids=lambda p: p.stem)
def test_fuzz_target_smoke(path: Path) -> None:
    test_one_input: Callable[[bytes], None] = _load(path).TestOneInput
    for data in _inputs(path):
        test_one_input(data)


def test_clusterfuzzlite_build_covers_all_targets() -> None:
    build = (FUZZ.parent / ".clusterfuzzlite" / "build.sh").read_text(encoding="utf-8")
    assert "for fuzzer in fuzz/fuzz_*.py" in build
    assert "language: python" in (FUZZ.parent / ".clusterfuzzlite" / "project.yaml").read_text(encoding="utf-8")
