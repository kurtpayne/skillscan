# SkillScan

SkillScan is a standalone CLI security analyzer for AI skills and tool bundles.

It scans local artifacts (code + markdown instructions), detects risky patterns, and returns deterministic verdicts:

- `allow`
- `warn`
- `block`

Default policy is `strict`.

## Features

1. Offline-first local scanning.
2. Archive-safe extraction and static analysis.
3. Malware and instruction-abuse pattern detection.
4. IOC extraction with local intel matching.
5. Dependency vulnerability and unpinned-version checks.
6. Policy profiles (`strict`, `balanced`, `permissive`) + custom policies.
7. Pretty terminal output + JSON reports.
8. Built-in examples and compromised OpenClaw-style fixtures.
9. Auto-refresh managed intel feeds (default checks every scan, 1-hour max age).

## Install

### Option A: convenience installer (curl|bash)

```bash
curl -fsSL https://raw.githubusercontent.com/your-org/skillscan/main/scripts/install.sh | bash
```

Set `SKILLSCAN_REPO_URL` first if you are using a fork/private location.

### Option B: local/dev install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

## Quick Start

```bash
skillscan scan ./examples/suspicious_skill
```

Save JSON report:

```bash
skillscan scan ./examples/suspicious_skill --format json --out report.json --fail-on never
```

Render saved report:

```bash
skillscan explain ./report.json
```

## Command Summary

- `skillscan scan <path>`
- `skillscan explain <report.json>`
- `skillscan policy show-default --profile strict|balanced|permissive`
- `skillscan policy validate <policy.yaml>`
- `skillscan intel status|list|add|remove|enable|disable|rebuild`
- `skillscan intel sync [--force]`
- `skillscan uninstall [--keep-data]`
- `skillscan version`

See full command docs: `docs/COMMANDS.md`.

## Policies

Built-ins:

1. `strict` (default)
2. `balanced`
3. `permissive`

Use a custom policy:

```bash
skillscan scan ./target --policy ./examples/policies/strict_custom.yaml
```

## Intel Management

Add a local IOC source:

```bash
skillscan intel add ./examples/intel/custom_iocs.json --type ioc --name team-iocs
```

View sources:

```bash
skillscan intel status
skillscan intel list
```

Managed intel auto-refresh runs by default on `scan`. You can tune or disable it:

```bash
skillscan scan ./target --intel-max-age-minutes 60
skillscan scan ./target --no-auto-intel
skillscan intel sync --force
```

## Example Fixtures

1. Benign sample: `examples/benign_skill`
2. Suspicious sample: `examples/suspicious_skill`
3. OpenAI-style sample: `examples/openai_style_tool`
4. Claude-style sample: `examples/claude_style_skill`
5. Comprehensive detection showcase: `examples/showcase/INDEX.md`
6. OpenClaw-compromised-style sample: `tests/fixtures/malicious/openclaw_compromised_like`

## Testing

```bash
pytest -q
ruff check src tests
mypy src
```

Or run all checks:

```bash
make check
```

## Uninstall

Remove CLI/runtime and local data:

```bash
skillscan uninstall
```

Keep local data (intel/reports/config):

```bash
skillscan uninstall --keep-data
```

Shell script uninstall is also provided at `scripts/uninstall.sh`.

## Documentation

- PRD: `docs/PRD.md`
- Architecture: `docs/ARCHITECTURE.md`
- Threat model: `docs/THREAT_MODEL.md`
- Policy guide: `docs/POLICY.md`
- Intel guide: `docs/INTEL.md`
- Testing guide: `docs/TESTING.md`
- Rules and scoring: `docs/RULES.md`
- Comprehensive examples: `docs/EXAMPLES.md`

## Security Note

SkillScan performs static analysis by default and does not execute scanned artifacts. For untrusted inputs, run in a trusted isolated environment.
