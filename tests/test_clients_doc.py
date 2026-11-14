"""docs/clients.md – every JSON/JSONC/TOML/YAML config block must parse and use the documented placeholders."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest
import yaml

CLIENTS_MD = Path(__file__).resolve().parent.parent / "docs" / "clients.md"
FENCE = re.compile(r"^```(\w+)\n(.*?)^```", re.MULTILINE | re.DOTALL)
PARSED = {"json", "jsonc", "toml", "yaml"}


def _blocks() -> list[tuple[str, str]]:
    return [(lang, body) for lang, body in FENCE.findall(CLIENTS_MD.read_text(encoding="utf-8")) if lang in PARSED]


def _strip_jsonc(text: str) -> str:
    """Remove // line comments outside of strings (VS Code and Zed accept JSON with comments)."""
    out, in_str, esc, i = [], False, False, 0
    while i < len(text):
        c = text[i]
        if in_str:
            out.append(c)
            esc = c == "\\" and not esc
            if c == '"' and not esc:
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _parse(lang: str, body: str) -> object:
    if lang == "json":
        return json.loads(body)
    if lang == "jsonc":
        return json.loads(_strip_jsonc(body))
    if lang == "toml":
        return tomllib.loads(body)
    return yaml.safe_load(body)


def test_clients_doc_has_config_blocks() -> None:
    langs = {lang for lang, _ in _blocks()}
    assert {"json", "toml", "yaml"} <= langs


@pytest.mark.parametrize(("lang", "body"), _blocks(), ids=lambda v: v if v in PARSED else None)
def test_config_block_parses(lang: str, body: str) -> None:
    assert isinstance(_parse(lang, body), dict)


def test_no_password_in_configs() -> None:
    for lang, body in _blocks():
        assert 'FRITZ_PASSWORD"' not in body and "FRITZ_PASSWORD =" not in body, (lang, body)
        if "FRITZ_USER" in body:
            assert "<user>" in body, body
