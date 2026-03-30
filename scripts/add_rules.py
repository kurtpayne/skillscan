#!/usr/bin/env python3
"""Safely insert new static rules into default.yaml before the capability_patterns block.

Usage:
    python3 scripts/add_rules.py <rules_yaml_file>

The <rules_yaml_file> should contain one or more YAML rule blocks starting with '- id: XXX-NNN'.
Rules are inserted at the end of the static_rules section, immediately before the
capability_patterns mapping block (which sits between static_rules and chain_rules).

This script is idempotent: if a rule ID already exists in default.yaml it is skipped.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_FILE = ROOT / "src/skillscan/data/rules/default.yaml"

# Marker: the capability_patterns block always starts with this exact line.
# It sits between the last static rule and the first chain rule.
INSERTION_MARKER = re.compile(r"^capability_patterns:", re.MULTILINE)


def load_new_rules(path: Path) -> str:
    text = path.read_text(encoding="utf-8").strip()
    if not text.startswith("- id:"):
        raise ValueError(f"{path}: expected content to start with '- id:' rule block")
    return text


def existing_rule_ids(yaml_text: str) -> set[str]:
    return set(re.findall(r"^\s*-\s+id:\s+([A-Z]{3}-\d{3})\s*$", yaml_text, flags=re.MULTILINE))


def insert_rules(yaml_text: str, new_rules_text: str) -> tuple[str, list[str]]:
    """Insert new_rules_text before capability_patterns. Returns (updated_text, inserted_ids)."""
    existing = existing_rule_ids(yaml_text)

    # Filter out rules that already exist
    blocks: list[str] = []
    inserted_ids: list[str] = []
    for block in re.split(r"\n(?=- id:)", new_rules_text):
        block = block.strip()
        if not block:
            continue
        m = re.match(r"- id:\s+([A-Z]{3}-\d{3})", block)
        if not m:
            continue
        rule_id = m.group(1)
        if rule_id in existing:
            print(f"  ⏭  {rule_id} already exists — skipping")
            continue
        blocks.append(block)
        inserted_ids.append(rule_id)

    if not blocks:
        return yaml_text, []

    new_rules_block = "\n\n".join(blocks) + "\n\n"

    match = INSERTION_MARKER.search(yaml_text)
    if not match:
        raise RuntimeError(
            "Could not find 'capability_patterns:' marker in default.yaml. "
            "The YAML structure may have changed — inspect the file manually."
        )

    insert_pos = match.start()
    updated = yaml_text[:insert_pos] + new_rules_block + yaml_text[insert_pos:]
    return updated, inserted_ids


def bump_version(yaml_text: str, new_version: str) -> str:
    return re.sub(
        r'^(version:\s*")[^"]+(")',
        lambda m: f'{m.group(1)}{new_version}{m.group(2)}',
        yaml_text,
        count=1,
        flags=re.MULTILINE,
    )


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <rules_yaml_file> [new_version]")
        return 1

    rules_path = Path(sys.argv[1])
    if not rules_path.exists():
        print(f"Error: {rules_path} does not exist")
        return 1

    new_version = sys.argv[2] if len(sys.argv) > 2 else None

    new_rules_text = load_new_rules(rules_path)
    yaml_text = RULES_FILE.read_text(encoding="utf-8")

    updated, inserted_ids = insert_rules(yaml_text, new_rules_text)

    if not inserted_ids:
        print("No new rules to insert.")
        return 0

    if new_version:
        updated = bump_version(updated, new_version)
        print(f"✓ Bumped rulepack version to {new_version}")

    RULES_FILE.write_text(updated, encoding="utf-8")
    print(f"✓ Inserted {len(inserted_ids)} rule(s) before capability_patterns: {', '.join(inserted_ids)}")

    # Validate the result parses as valid YAML
    try:
        import yaml  # type: ignore
        yaml.safe_load(updated)
        print("✓ YAML validation passed")
    except Exception as e:
        print(f"❌ YAML validation failed after insertion: {e}")
        # Restore original
        RULES_FILE.write_text(yaml_text, encoding="utf-8")
        print("  Restored original file.")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
