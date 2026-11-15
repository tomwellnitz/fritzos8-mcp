#!/usr/bin/env python3
"""Fuzz-Target: Konfiguration aus der Umgebung (``config.load_all`` mit ``FRITZ_*``/``FRITZ_BOXES``).

Invarianten: entweder ``ConfigError`` oder gültige Konfigurationen (Timeout endlich und > 0, Box-Schutz-Werte im
erlaubten Bereich); eine ``ConfigError``-Meldung enthält nie ein Passwort. Passwortdateien und der Schlüsselbund
werden dabei nicht angefasst (``*_PASSWORD_FILE`` fehlt, ``keyring_password`` ist ersetzt).
"""

from __future__ import annotations

import math

from fuzzhelp import data_provider, instrumented, pick, run

with instrumented():
    from fritzos8_mcp import config
    from fritzos8_mcp.errors import ConfigError

config.keyring_password = lambda *_args, **_kwargs: ""  # nie den echten Schlüsselbund befragen

GLOBAL_VARS = ("ALLOW_WRITE", "ALLOW_CRITICAL", "ALLOW_SECRETS", "SNAPSHOT_KEEP", "BOXES")
VARS = tuple(v for v in config.PER_BOX_VARS if v != "PASSWORD_FILE") + GLOBAL_VARS
BOX_NAMES = ("heim", "zweit", "a", "Box-B", "x_1")
VALUES = ("", "1", "0", "true", "nan", "inf", "-inf", "-1", "1e9", "15", " 3 ", "heim,zweit", "fritz.box", "１２")


def TestOneInput(data: bytes) -> None:
    fdp = data_provider(data)
    env: dict[str, str] = {}
    for _ in range(fdp.ConsumeIntInRange(0, 12)):
        var = pick(fdp, VARS)
        prefix = "FRITZ_"
        if var in config.PER_BOX_VARS and fdp.ConsumeBool():
            prefix = config._box_prefix(pick(fdp, BOX_NAMES))
        value = pick(fdp, VALUES) if fdp.ConsumeBool() else fdp.ConsumeUnicodeNoSurrogates(24)
        env[prefix + var] = value
    others = [v for k, v in env.items() if not k.endswith("_PASSWORD")]
    # Passwörter, die nicht zugleich als Benutzer-/Boxname o. Ä. vorkommen (die dürfen in Meldungen stehen)
    passwords = [
        v for k, v in env.items() if k.endswith("_PASSWORD") and len(v) >= 4 and not any(v in o for o in others)
    ]
    try:
        configs = config.load_all(env)
    except ConfigError as exc:
        for pw in passwords:
            assert pw not in str(exc), (pw, str(exc))
        return
    assert configs
    for cfg in configs:
        assert cfg.password and cfg.user
        assert math.isfinite(cfg.timeout) and cfg.timeout > 0, cfg.timeout
        assert 1 <= cfg.snapshot_keep <= 1000
        assert 1 <= cfg.guard.max_parallel <= 16 and 0 <= cfg.guard.rate_per_s <= 100


if __name__ == "__main__":
    run(TestOneInput)
