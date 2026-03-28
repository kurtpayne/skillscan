## Summary

<!-- What does this PR do? One paragraph. -->

## Type of change

- [ ] Bug fix
- [ ] New rule / pattern
- [ ] New feature
- [ ] Refactor / code quality
- [ ] Documentation
- [ ] CI / tooling
- [ ] Dependency update

## Checklist

- [ ] `ruff check` and `ruff format --check` pass locally
- [ ] `mypy src` passes with no new errors
- [ ] `pytest -q` passes (all tests green, no debug prints left in test files)
- [ ] If adding a rule: positive + negative test cases added to `tests/test_rules.py`
- [ ] If adding a rule: showcase example added to `examples/showcase/`
- [ ] If adding a rule: `sync-website-rules.py` run and TSX files committed
- [ ] If changing CLI behavior: `docs/CLI_REFERENCE.md` updated
- [ ] No hardcoded secrets, tokens, or API keys in any file
- [ ] No debug code (`print(f"DBG...`)`, inline imports, `pdb.set_trace()`) left in

## Testing

<!-- Describe how you tested this change. -->

## Related issues

<!-- Closes #xxx -->
