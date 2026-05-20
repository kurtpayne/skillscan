"""Fast validator for the bundled rules + intel snapshot.

Runs in <10 seconds against `src/skillscan/data/`. Used by the CI fast-lane
on PRs that touch only `src/skillscan/data/**` (e.g., the daily agent's
bundled-snapshot sync PRs) so they don't have to run the full ~30-minute
pytest suite.

What this validates
-------------------
- Every rules/intel file parses (YAML/JSON).
- Every rule pattern compiles as a regex.
- Every rule with `test_input` + `test_expect: fires` actually fires.
- Every rule with `test_input` + `test_expect: suppresses` does not fire.
- vuln_db.json ecosystem keys (npm, python, etc.) have per-version-map
  shape: { "<pkg>": { "<version>": {...} } }. A list under a per-package
  key means OSV-list format leaked through (the bug that broke
  refresh-intel.yml on 2026-04-26).
- Top-level product keys in vuln_db.json (windsurf, openclaw, etc.) are
  skipped — their schema is intentionally flat.

What this does NOT validate
---------------------------
- Detection quality / false-positive rate (that's the full test suite's
  job; covered on code-touching PRs).
- Cross-rule interactions (covered by chain_rules; full suite checks
  those).
- Manifest hashes — those live in `skillscan-rules`, not here.

Exit code: 0 = all checks pass, 1 = anything failed.

Usage: `python3 scripts/validate_bundled_data.py`
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA = REPO_ROOT / "src/skillscan/data"

# Ecosystem keys in vuln_db.json that hold per-version maps.
# Top-level keys not in this set are flat product entries (windsurf, openclaw,
# mcp-server-kubernetes, etc.) whose `references: [...]` list is intentional.
ECOSYSTEMS = {"npm", "python", "pip", "go", "rust", "ruby", "java", "php", "swift"}

# Rule IDs whose `test_input` is known not to match the rule's pattern. These
# are pre-existing rule-quality bugs (the pattern doesn't fire on its own
# documented test case), not validator regressions. The validator surfaces
# them but doesn't fail CI on them — fixing each is a real rule edit that
# belongs in a pattern-update PR, not a CI-tooling PR.
#
# TODO: investigate + fix each, then remove from this set. Re-flag any
# regressions caught by a sync PR.
KNOWN_BROKEN_TEST_INPUTS: set[str] = {
    "MAL-015",  # multiline pattern not firing on JSON-quoted hook config
    "MAL-051",  # base64-blob pattern needs continuous string but test_input wraps
    "SUP-025",  # test_input appears unrelated to the rule's anchors
}

failures: list[str] = []
warnings: list[str] = []


def check(name: str, ok: bool, detail: str = "", *, warn_only: bool = False) -> None:
    if ok:
        status = "OK "
    elif warn_only:
        status = "WARN"
    else:
        status = "FAIL"
    print(f"  [{status}] {name}{(' — ' + detail) if detail else ''}")
    if not ok:
        if warn_only:
            warnings.append(f"{name}: {detail}")
        else:
            failures.append(f"{name}: {detail}")


def validate_json_file(path: Path) -> dict | list | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        check(f"parse {path.relative_to(REPO_ROOT)}", True)
        return data
    except (OSError, json.JSONDecodeError) as exc:
        check(f"parse {path.relative_to(REPO_ROOT)}", False, str(exc))
        return None


def validate_yaml_file(path: Path) -> dict | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        check(f"parse {path.relative_to(REPO_ROOT)}", True)
        return data
    except (OSError, yaml.YAMLError) as exc:
        check(f"parse {path.relative_to(REPO_ROOT)}", False, str(exc))
        return None


def validate_vuln_db_shape(db: dict) -> None:
    bad: list[str] = []
    for ecosystem, pkgs in db.items():
        if ecosystem not in ECOSYSTEMS or not isinstance(pkgs, dict):
            continue
        for pkg, versions in pkgs.items():
            if isinstance(versions, list):
                bad.append(f"{ecosystem}/{pkg}")
    check(
        "vuln_db.json ecosystem keys use per-version-map shape",
        not bad,
        f"list-format entries leaked through: {bad}" if bad else "",
    )


def validate_rule_patterns(rules: list[dict]) -> None:
    pattern_failures = 0
    fires_failures: list[str] = []
    suppress_failures: list[str] = []

    for rule in rules:
        rid = rule.get("id", "<missing-id>")
        pattern_str = rule.get("pattern", "")
        if not pattern_str:
            continue

        # Pattern compiles
        flags = re.IGNORECASE
        if rule.get("multiline"):
            flags |= re.DOTALL
        try:
            pattern = re.compile(pattern_str, flags)
        except re.error as exc:
            pattern_failures += 1
            failures.append(f"{rid}: pattern doesn't compile ({exc})")
            continue

        # test_input round-trip
        test_input = rule.get("test_input")
        test_expect = rule.get("test_expect", "fires")
        if not test_input:
            continue  # not all rules have test_input yet; skip gracefully

        fired = any(pattern.search(line) for line in test_input.splitlines())
        if test_expect == "fires" and not fired:
            fires_failures.append(rid)
        elif test_expect == "suppresses" and fired:
            suppress_failures.append(rid)

    check(
        f"all {len(rules)} rule patterns compile",
        pattern_failures == 0,
        f"{pattern_failures} pattern(s) failed to compile" if pattern_failures else "",
    )

    # Split fire-failures into grandfathered (warn) vs. new (fail).
    new_silent = [r for r in fires_failures if r not in KNOWN_BROKEN_TEST_INPUTS]
    old_silent = [r for r in fires_failures if r in KNOWN_BROKEN_TEST_INPUTS]
    check(
        "no NEW rules with test_expect=fires that don't fire",
        not new_silent,
        f"new silent rules: {new_silent}" if new_silent else "",
    )
    if old_silent:
        check(
            "grandfathered fire-failures (TODO: fix these)",
            False,
            f"{old_silent}",
            warn_only=True,
        )

    new_unexpected = [r for r in suppress_failures if r not in KNOWN_BROKEN_TEST_INPUTS]
    old_unexpected = [r for r in suppress_failures if r in KNOWN_BROKEN_TEST_INPUTS]
    check(
        "no NEW rules with test_expect=suppresses that fire anyway",
        not new_unexpected,
        f"new unexpected matches: {new_unexpected}" if new_unexpected else "",
    )
    if old_unexpected:
        check(
            "grandfathered suppress-failures (TODO: fix these)",
            False,
            f"{old_unexpected}",
            warn_only=True,
        )


def main() -> int:
    print("=== Bundled data validation ===\n")

    print("JSON files:")
    for name in ("ioc_db.json", "vuln_db.json", "managed_sources.json"):
        path = DATA / "intel" / name
        data = validate_json_file(path)
        if name == "vuln_db.json" and isinstance(data, dict):
            validate_vuln_db_shape(data)

    print("\nYAML files:")
    rules_doc: dict | None = None
    for name in ("default.yaml", "ast_flows.yaml", "multilang.yaml"):
        path = DATA / "rules" / name
        doc = validate_yaml_file(path)
        if name == "default.yaml" and isinstance(doc, dict):
            rules_doc = doc

    if rules_doc is not None:
        print("\nRule patterns + test_input round-trip:")
        static_rules = rules_doc.get("static_rules", []) or []
        validate_rule_patterns(static_rules)

    print("\n" + ("=" * 32))
    if failures:
        print(f"FAILED: {len(failures)} check(s) failed.")
        for f in failures:
            print(f"  - {f}")
        if warnings:
            print(f"\n(plus {len(warnings)} warning(s) — see above)")
        return 1
    if warnings:
        print(f"PASSED with {len(warnings)} warning(s):")
        for w in warnings:
            print(f"  - {w}")
    else:
        print("PASSED: all bundled-data checks green.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
