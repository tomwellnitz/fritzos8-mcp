"""Repository configuration: every label used by Dependabot and the issue forms is defined in .github/labels.yml."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
GITHUB = ROOT / ".github"


def _defined_labels() -> set[str]:
    labels = yaml.safe_load((GITHUB / "labels.yml").read_text(encoding="utf-8"))
    for label in labels:
        assert isinstance(label["color"], str) and len(label["color"]) == 6, label
    return {label["name"] for label in labels}


def test_dependabot_labels_exist() -> None:
    defined = _defined_labels()
    config = yaml.safe_load((GITHUB / "dependabot.yml").read_text(encoding="utf-8"))
    used = {label for update in config["updates"] for label in update.get("labels", [])}
    assert used <= defined, used - defined


def test_issue_form_labels_exist() -> None:
    defined = _defined_labels()
    for form in sorted((GITHUB / "ISSUE_TEMPLATE").glob("*.yml")):
        data = yaml.safe_load(form.read_text(encoding="utf-8"))
        used = set(data.get("labels", []) if isinstance(data, dict) else [])
        assert used <= defined, (form.name, used - defined)
