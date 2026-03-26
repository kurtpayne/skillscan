# Contributing to SkillScan

Thank you for your interest in improving SkillScan. This document describes how to contribute detection rules, corpus examples, bug reports, and code changes.

---

## Ways to contribute

### Report a false positive or false negative

The most valuable contributions are real-world scan results that expose gaps in detection accuracy.

- **False positive** (a benign skill flagged as malicious): open an issue using the [False Positive template](https://github.com/kurtpayne/skillscan-security/issues/new?template=false-positive.md)
- **False negative** (a malicious skill that was not detected): open an issue using the [False Negative template](https://github.com/kurtpayne/skillscan-security/issues/new?template=false-negative.md)

Include the full `skillscan scan --format text` output and, if possible, a minimal reproduction of the skill file (redact any sensitive content).

### Report a bug

Use the [Bug Report template](https://github.com/kurtpayne/skillscan-security/issues/new?template=bug-report.md). Include your OS, Python version, SkillScan version (`skillscan version`), and the exact command that failed.

### Suggest a feature

Use the [Feature Request template](https://github.com/kurtpayne/skillscan-security/issues/new?template=feature-request.md). Describe the use case, not just the implementation.

---

## Contributing detection rules

Rules live in `src/skillscan/data/rules/`. Each rule is a YAML file. See `docs/custom-rules-format.md` for the full schema.

Before opening a PR for a new rule:

1. The rule must have a real-world precedent — a CVE, a published threat report, or a reproducible attack technique. Include a link in the rule's `reference` field.
2. Run `skillscan rule test <rule-id>` against at least one positive and one negative example.
3. Run the full test suite: `pytest tests/ -x -q --ignore=tests/test_adversarial.py`
4. All tests must pass. PRs with broken tests will not be merged.

Rule ID assignment:

| Prefix | Category |
|---|---|
| `MAL-` | Malware / backdoor |
| `ABU-` | Capability abuse |
| `EXF-` | Data exfiltration |
| `INJ-` | Injection |
| `CHN-` | Multi-step chain |
| `CAP-` | Capability escalation |
| `PINJ-` | Prompt / pipeline injection |
| `SUP-` | Supply chain |
| `SE-` | Social engineering |

Use the next available number in the relevant prefix series. Check `src/skillscan/data/rules/` for the current highest number.

---

## Contributing IOC or vulnerability data

IOC and vulnerability data live in `src/skillscan/data/ioc_db.json` and `src/skillscan/data/vuln_db.json`. See `docs/custom-intel-format.md` for the schema.

For bulk IOC additions, open an issue with the source URL rather than editing the JSON directly. The intel update workflow will ingest it.

---

## Code contributions

### Setup

```bash
git clone https://github.com/kurtpayne/skillscan-security.git
cd skillscan-security
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### Running tests

```bash
# Fast unit tests only
pytest tests/ -x -q --ignore=tests/test_adversarial.py --ignore=tests/test_clamav.py

# Full suite (requires ClamAV installed)
pytest tests/ -x -q
```

Type checking and linting:

```bash
ruff check src tests
mypy src
```

### Scope expectations

- Keep scanner behavior deterministic.
- Add regression fixtures for new detection logic.
- Update docs and example outputs when command behavior changes.

### Code style

- Python 3.10+, type hints on all public functions
- `ruff` for linting, `black` for formatting (both run in CI)
- No new external runtime dependencies without discussion in an issue first

### PR checklist

- [ ] Tests pass (`pytest tests/ -x -q`)
- [ ] New functionality has test coverage
- [ ] `CHANGELOG.md` entry added under `[Unreleased]`
- [ ] No secrets, API keys, or corpus file paths committed

---

## Responsible disclosure

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.
