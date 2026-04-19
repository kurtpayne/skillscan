## Summary
- What changed?
- Why this is needed now?

## Pattern Update Checklist (required for rules/default.yaml edits)
- [ ] Worked on a feature branch (not `main`)
- [ ] Added/updated rule IDs in `src/skillscan/data/rules/default.yaml`
- [ ] Bumped rulepack version (`YYYY.MM.DD.N`)
- [ ] Added `test_input` and `test_expect: fires` to each new/updated rule
- [ ] Added source-backed rationale in `docs/RULE_UPDATES.md` or `PATTERN_UPDATES.md`
- [ ] Verified rule fires: `SKILLSCAN_NO_USER_RULES=1 pytest tests/test_rule_inputs.py -q`

## Validation
- [ ] `ruff check src tests`
- [ ] `pytest -q`

## Sources
- Link 1
- Link 2
