# Benchmark Guide

`skillscan benchmark` runs a labeled test manifest against the scanner and reports precision and recall. Use it to validate custom rules, tune policy thresholds, and gate releases.

---

## Quick start

```bash
# Create a manifest
cat > my-benchmark.json << 'EOF'
[
  { "path": "test-fixtures/malicious/jailbreak-01/SKILL.md", "expected": "block" },
  { "path": "test-fixtures/malicious/exfil-01/SKILL.md",     "expected": "block" },
  { "path": "test-fixtures/benign/github-actions/SKILL.md",  "expected": "allow" },
  { "path": "test-fixtures/benign/basic-skill/SKILL.md",     "expected": "allow" }
]
EOF

# Run the benchmark
skillscan benchmark my-benchmark.json

# Output:
# benchmark cases=4 precision=1.0000 recall=1.0000 tp=2 fp=0 fn=0 tn=2
```

---

## Manifest format

### Simple format (recommended)

A JSON array of objects with `path` and `expected` keys:

```json
[
  { "path": "test-fixtures/malicious/jailbreak-01/SKILL.md", "expected": "block" },
  { "path": "test-fixtures/benign/basic-skill/SKILL.md",     "expected": "allow" }
]
```

| Field | Type | Description |
|---|---|---|
| `path` | string | Path to the skill file or directory to scan |
| `expected` | string | `"block"` or `"allow"` |

**Verdict mapping:** `warn` is treated as `allow` for precision/recall calculation. If you want to distinguish `warn` from `allow`, use the `--format json` output and post-process the `results` array.

### Legacy format

The legacy format uses a `cases` wrapper and per-rule expected/forbidden ID lists:

```json
{
  "cases": [
    {
      "target": "test-fixtures/malicious/jailbreak-01/SKILL.md",
      "expected_ids": ["PINJ-009", "PINJ-001"],
      "forbidden_ids": []
    },
    {
      "target": "test-fixtures/benign/basic-skill/SKILL.md",
      "expected_ids": [],
      "forbidden_ids": ["PINJ-009"]
    }
  ]
}
```

Both formats are supported. The simple format is preferred for new manifests.

---

## Options

```
Usage: skillscan benchmark [OPTIONS] MANIFEST

Options:
  --profile TEXT          Built-in policy profile [default: strict]
  --format TEXT           Output format: text|json [default: text]
  --min-precision FLOAT   Exit non-zero if precision falls below value [default: 0.0]
  --min-recall FLOAT      Exit non-zero if recall falls below value [default: 0.0]
  --verbose               Print per-case results (pass/fail, expected/actual, rules fired)
```

---

## Verbose output

Use `--verbose` to see per-case results:

```bash
skillscan benchmark my-benchmark.json --verbose
```

```
benchmark cases=4 precision=1.0000 recall=1.0000 tp=2 fp=0 fn=0 tn=2

  PASS test-fixtures/malicious/jailbreak-01/SKILL.md  expected=block actual=block  rules=PINJ-001,PINJ-009
  PASS test-fixtures/malicious/exfil-01/SKILL.md      expected=block actual=block  rules=EXFIL-003
  PASS test-fixtures/benign/github-actions/SKILL.md   expected=allow actual=allow  rules=—
  PASS test-fixtures/benign/basic-skill/SKILL.md      expected=allow actual=allow  rules=—

Gate: PASSED
```

---

## CI gate pattern

Add a precision/recall gate to fail CI when detection quality degrades:

```bash
skillscan benchmark tests/benchmark-manifest.json \
  --profile strict \
  --min-precision 0.95 \
  --min-recall 0.90 \
  --verbose
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Benchmark passed (precision and recall above thresholds) |
| `1` | Benchmark failed (precision or recall below thresholds) |
| `2` | Invalid arguments or scan error |

### GitHub Actions example

```yaml
- name: SkillScan benchmark gate
  run: |
    skillscan benchmark tests/benchmark-manifest.json \
      --profile strict \
      --min-precision 0.95 \
      --min-recall 0.90 \
      --verbose
```

---

## JSON output

Use `--format json` for machine-readable output:

```bash
skillscan benchmark my-benchmark.json --format json
```

```json
{
  "cases": 4,
  "tp": 2,
  "fp": 0,
  "fn": 0,
  "tn": 2,
  "precision": 1.0,
  "recall": 1.0,
  "results": [
    {
      "path": "test-fixtures/malicious/jailbreak-01/SKILL.md",
      "expected": "block",
      "actual": "block",
      "outcome": "tp",
      "rules_fired": ["PINJ-001", "PINJ-009"]
    },
    {
      "path": "test-fixtures/benign/basic-skill/SKILL.md",
      "expected": "allow",
      "actual": "allow",
      "outcome": "tn",
      "rules_fired": []
    }
  ]
}
```

---

## Precision and recall definitions

For a binary malicious/benign classification:

| Term | Definition |
|---|---|
| **TP** | Expected `block`, actual `block` |
| **FP** | Expected `allow`, actual `block` |
| **FN** | Expected `block`, actual `allow` or `warn` |
| **TN** | Expected `allow`, actual `allow` or `warn` |
| **Precision** | TP / (TP + FP) — fraction of blocks that were correct |
| **Recall** | TP / (TP + FN) — fraction of malicious skills that were caught |

---

## Building a benchmark manifest

A good benchmark manifest should include:

- At least 20 malicious cases covering the categories you care about (injection, exfiltration, malware, etc.)
- At least 20 benign cases from your actual skill corpus
- Edge cases: skills that are borderline or use patterns similar to malicious ones
- Regression cases: any false positives or false negatives you have fixed in the past

The SkillScan test suite at `tests/fixtures/` contains labeled examples you can use as a starting point.
