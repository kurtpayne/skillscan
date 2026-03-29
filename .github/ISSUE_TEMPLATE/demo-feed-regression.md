---
name: Demo Feed Regression
about: Automatically filed when the weekly demo feed scan produces unexpected verdicts
title: "[demo-feed] Unexpected verdicts detected — review required"
labels: demo-feed-regression, quality
assignees: kurtpayne
---

<!-- This template is used by the Demo Feed Update workflow. Do not file manually. -->

## Summary

The weekly demo feed scan produced **unexpected verdicts** for one or more entries.

| Entry ID | Label | Archetype | Expected | Got | Ref |
|---|---|---|---|---|---|
| _(filled by automation)_ | | | | | |

## Context

- **SkillScan version:** _(filled by automation)_
- **Total scanned:** _(filled by automation)_

## Next steps

### False Positive (benign → BLOCK)
1. Run `skillscan scan <file> --format json` locally and inspect the triggering rule
2. Check if the rule has a `confidence: low` or `confidence: medium` threshold that should be raised
3. If the skill is genuinely benign, add a suppression comment or open a rule-confidence PR
4. Update `demo_verdict_expected` in `skill-index.yaml` only if the new verdict is correct

### False Negative (malicious → ALLOW)
1. Identify which detection signal is missing
2. Add 3–5 new corpus examples to `skillscan-corpus/training_corpus/malicious/`
3. Consider adding or tightening a rule in `rules/default.yaml`
4. Re-run the demo feed scan after the fix to confirm the regression is resolved

## Resolution

Close this issue once all unexpected verdicts are resolved and the next scheduled scan produces a clean run.
