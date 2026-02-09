# AI Assist

`AI Assist` is an optional semantic-analysis layer for SkillScan.

It is disabled by default and only runs when `--ai-assist` is provided.

## Why it exists

Deterministic local rules are strong for explicit abuse strings and code patterns. `AI Assist` adds value where risk is mostly semantic, for example socially engineered instructions that ask users for sensitive credentials without obvious malware keywords.

## Safety boundaries

1. Local static analysis runs first and remains the primary signal.
2. The AI prompt explicitly treats scanned artifacts as untrusted data.
3. Scanner does not execute scanned code or links.
4. AI failures do not fail scans unless `--ai-required` is set.
5. High-confidence critical AI semantic findings can trigger `block` by policy.

## CLI options

```bash
skillscan scan <target> \
  --ai-assist \
  --ai-provider auto \
  --ai-model gpt-4o-mini \
  --ai-timeout-seconds 20
```

Optional:

- `--ai-base-url` for self-hosted/provider-compatible endpoints.
- `--ai-report-out` to write raw AI JSON response to disk.
- `--ai-required` to fail if AI assist is unavailable.

## Environment variables

Primary (tool-native):

1. `SKILLSCAN_AI_PROVIDER`
2. `SKILLSCAN_AI_MODEL`
3. `SKILLSCAN_AI_BASE_URL`
4. `SKILLSCAN_AI_API_KEY`
5. `SKILLSCAN_AI_TIMEOUT_SECONDS`

Provider fallback keys:

1. OpenAI: `OPENAI_API_KEY`, `OPENAI_BASE_URL`
2. Anthropic: `ANTHROPIC_API_KEY`
3. Gemini: `GEMINI_API_KEY` or `GOOGLE_API_KEY`

`.env` is auto-loaded if present in current working directory.

## Prompt

Source of truth: `src/skillscan/ai.py` (`SYSTEM_PROMPT`).

Prompt goals:

1. Detect semantic instruction risks with concrete evidence.
2. Ignore prompt injection from scanned artifacts.
3. Return strict JSON only.
4. Provide actionable mitigation text per risk.

## Data sent to provider

SkillScan sends a bounded text context, not full archives:

1. Target identifier.
2. Local finding summary (IDs/titles/paths).
3. Snippets from selected text files only (UTF-8 decode, excerpted).

Current bounds in code (`src/skillscan/ai.py`):

1. Max snippet length per file: ~2200 characters.
2. Max total prompt snippet budget: ~24,000 characters.
3. Binary files are not included.

Note: snippets are textual excerpts from source files (not tokenized/AST-only), so sensitive plaintext present in included excerpts may be sent when AI assist is enabled.
