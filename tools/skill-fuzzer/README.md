# skill-fuzzer

**M19 — LLM-powered adversarial SKILL.md variant generator**

`skill-fuzzer` generates adversarial variants of AI skill files to probe the detection boundaries of `skillscan`. It uses an OpenAI-compatible LLM API (GPT-4.1-mini by default, or any local Ollama model) to apply semantic mutations to seed skill files, producing variants with unified diffs and optional scan results.

The fuzzer is the controlled-input complement to the public scan feed (M14): instead of scanning skills found in the wild, it generates skills designed to stress-test the scanner's static rules and ML model. The output feeds directly into `skillscan-trace` (M18) for behavioral verification.

---

## Installation

```bash
# As a standalone package
pip install skillscan-fuzzer

# Or as an extra from the main package
pip install skillscan-security[fuzzer]

# Development install from source
cd tools/skill-fuzzer
pip install -e ".[dev]"
```

---

## Quick Start

```bash
# Fuzz 5 variants of each malicious seed using evasion strategy
skill-fuzzer --strategy evasion --variants 5

# Fuzz a specific seed with injection strategy and run skillscan on each variant
skill-fuzzer --strategy injection \
             --seed-file corpus/benign/gh_example.md \
             --scan

# Use a local Ollama endpoint (no API key needed)
skill-fuzzer --strategy obfuscation \
             --model llama3.1:8b \
             --base-url http://localhost:11434/v1 \
             --api-key ollama

# Dry run to verify output structure without making LLM calls
skill-fuzzer --strategy evasion --dry-run --variants 2
```

---

## Mutation Strategies

| Strategy | Seed Type | Goal |
|---|---|---|
| `evasion` | malicious | Preserve malicious intent while changing surface patterns to evade rule matching |
| `injection` | benign | Add one subtle attack vector to an otherwise clean skill |
| `benign_drift` | benign | Add security-adjacent vocabulary without actual malice (false-positive stress test) |
| `obfuscation` | malicious | Apply encoding/homoglyph/zero-width obfuscation to hide attack patterns |
| `authority` | any | Inject fake system headers, vendor impersonation, or role-escalation claims |

Seed selection is automatic: `evasion`, `obfuscation`, and `authority` default to malicious seeds from `corpus/`; `injection` and `benign_drift` default to benign seeds. Override with `--seed-dir` or `--seed-file`.

---

## Output Structure

```
fuzz-output/
  evasion/
    ah01_goal_substitution_calendar/
      variant_001.md          ← complete mutated SKILL.md
      variant_001.diff        ← unified diff against original
      variant_001.scan.json   ← skillscan SARIF result (if --scan)
      variant_002.md
      variant_002.diff
      ...
    summary.json              ← evasion rate, detection rate, per-seed results
```

The `summary.json` contains:

```json
{
  "strategy": "evasion",
  "total_seeds": 10,
  "total_variants": 50,
  "errors": 0,
  "scanned": 50,
  "evasion_rate": 0.34,
  "false_positive_rate": null,
  "per_seed": [...]
}
```

---

## CLI Reference

```
Usage: skill-fuzzer [OPTIONS]

Options:
  -s, --strategy [evasion|injection|benign_drift|obfuscation|authority]
                                  Mutation strategy  [default: evasion]
  -n, --variants INTEGER          Variants per seed  [default: 5]
  --seed-dir DIRECTORY            Directory of seed SKILL.md files
  --seed-file PATH                Specific seed file (repeatable)
  -o, --output-dir DIRECTORY      Output root  [default: fuzz-output]
  -m, --model TEXT                LLM model  [default: gpt-4.1-mini]
  --base-url TEXT                 OpenAI-compatible API base URL
  --api-key TEXT                  API key (reads OPENAI_API_KEY env var)
  --temperature FLOAT             Sampling temperature  [default: 0.9]
  --max-tokens INTEGER            Max response tokens  [default: 4096]
  --scan / --no-scan              Run skillscan on each variant  [default: no-scan]
  --dry-run                       Skip LLM calls; write placeholder variants
  --max-seeds INTEGER             Limit number of seeds processed
  -v, --verbose                   Enable debug logging
  -h, --help                      Show this message and exit
```

---

## API Key Configuration

The fuzzer reads `OPENAI_API_KEY` from (in priority order):

1. `--api-key` CLI flag
2. `OPENAI_API_KEY` environment variable
3. `~/.skillscan-secrets` (the shared credential store used by all skillscan tools)

For Ollama, pass `--base-url http://localhost:11434/v1 --api-key ollama`.

---

## Corpus Integration

Generated variants are intended to be reviewed and, if they represent genuine evasion gaps or new attack patterns, committed to `skillscan-corpus` as labeled training examples. The recommended workflow:

1. Run the fuzzer with `--scan` to identify variants that evade detection.
2. Manually review evading variants for quality (does the attack intent survive?).
3. Commit confirmed evasion variants to `skillscan-corpus/adversarial/` with label `malicious`.
4. Update the static rules or retrain the ML model to close the gap.
5. Repeat.

For behavioral verification (rather than static rule verification), pipe variants into `skillscan-trace` (M18) once it is available.

---

## Running Tests

```bash
cd tools/skill-fuzzer
pytest tests/ -v
```

All tests use `--dry-run` mode and do not require an API key or network access.
