---
name: openclaw-self-healing-elvatis
description: OpenClaw plugin that applies guardrails and auto-fixes reversible failures (rate limits, disconnects, stuck session pins).
# corpus-label: benign
# corpus-source: github-scrape
# corpus-repo: elvatis/openclaw-self-healing-elvatis
# corpus-url: https://github.com/elvatis/openclaw-self-healing-elvatis/blob/c931263c08d416ed696f5e64378842b7c3753970/SKILL.md
# corpus-round: 2026-03-19
---

# openclaw-self-healing-elvatis

Self-healing extension for OpenClaw.

## What it does

- Detects common reversible failures (rate limits, auth errors, stuck session model pins)
- Applies guardrails (e.g. avoid breaking config)
- Can auto-recover WhatsApp disconnects (when enabled)

## Install

```bash
clawhub install openclaw-self-healing-elvatis
```

## Notes

Keep repository content public-safe (no private identifiers).

**Version:** 0.2.10