from __future__ import annotations

import re
from pathlib import Path

import yaml


TECHNIQUE_ID_RE = re.compile(r"^[A-Z][A-Z0-9_-]*-\d{3}$")


def test_static_rules_have_well_formed_metadata_blocks() -> None:
    rules_path = Path("src/skillscan/data/rules/default.yaml")
    data = yaml.safe_load(rules_path.read_text(encoding="utf-8"))

    static_rules = data.get("static_rules", [])
    assert static_rules, "expected static rules in default.yaml"

    for rule in static_rules:
        rid = rule.get("id", "<missing-id>")
        metadata = rule.get("metadata")
        assert isinstance(metadata, dict), f"{rid}: missing metadata block"

        for key in ("version", "status", "techniques", "tags", "applies_to", "lifecycle", "quality", "references"):
            assert key in metadata, f"{rid}: missing metadata.{key}"

        techniques = metadata.get("techniques", [])
        assert isinstance(techniques, list) and techniques, f"{rid}: metadata.techniques must be non-empty list"
        for tech in techniques:
            assert isinstance(tech, dict) and "id" in tech, f"{rid}: each technique must include id"
            assert TECHNIQUE_ID_RE.match(str(tech["id"])), f"{rid}: invalid technique id {tech['id']}"
