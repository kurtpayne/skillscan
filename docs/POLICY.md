# Policy Guide

SkillScan ships with built-in profiles:

1. `strict` (default)
2. `balanced`
3. `permissive`

Custom policy files can override thresholds, rule weights, and local domain allow/block controls.
They can also tune AI-assisted blocking behavior.

Minimal custom policy example:

```yaml
name: strict-custom
description: Example
thresholds:
  warn: 40
  block: 90
weights:
  malware_pattern: 3
  instruction_abuse: 2
  exfiltration: 3
  dependency_vulnerability: 2
  threat_intel: 3
  binary_artifact: 1
hard_block_rules:
  - MAL-001
  - IOC-001
allow_domains:
  - trusted.internal.example
block_domains:
  - blocked.example
ai_block_on_critical: true
ai_block_min_confidence: 0.85
limits:
  max_files: 4000
  max_depth: 8
  max_bytes: 200000000
  timeout_seconds: 60
```

Use a custom policy:

```bash
skillscan scan ./target --policy ./my_policy.yaml
```

AI policy knobs:

1. `ai_block_on_critical`: if `true`, high-confidence `critical` AI semantic findings can force `block`.
2. `ai_block_min_confidence`: confidence floor (0.0-1.0) for the AI critical block path.
