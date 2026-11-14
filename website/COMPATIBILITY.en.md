# Compatibility

Checked so far: **FRITZ!Box 7583** (FRITZ!OS 8.26, DSL/G.fast, PPP, DS-Lite) and **FRITZ!Box 6660 Cable** (FRITZ!OS 8.25, cable) – read tools of stages 1–10 live, write tools of stages 1–3 live, later write tools only against mocks. The German page has the per-tool matrix.

Contribute your box: run the read-only live suite (`FRITZ_LIVE_TEST=1 … uv run pytest tests/live -o addopts="" -v`) and open a "compatibility" issue with model, FRITZ!OS version, access type and the test results – no serial numbers, addresses or device names. Anonymized fixtures: see [community fixtures](fixtures.md).
