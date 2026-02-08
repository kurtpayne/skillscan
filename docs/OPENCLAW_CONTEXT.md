# OpenClaw Incident Context (Design Input)

This repository includes safe fixtures inspired by reported OpenClaw/ClawHub attack patterns observed in early 2026.

Patterns reflected in fixtures and rules:

1. Download-and-execute bootstrap chains (`curl|bash`, `wget|sh`).
2. IOC reuse involving suspicious IP/domain infrastructure.
3. Coercive prerequisite instructions that ask users to weaken host defenses.
4. Obfuscated staged payload workflows.

SkillScan fixtures intentionally use non-live and sanitized examples where possible to avoid distributing active malware.

Current built-in IOC seeds include public examples discussed in incident reporting:

- `91.92.242.30`
- `54.91.154.110`
- `https://glot.io/snippets/malicious-bootstrap`

These seeds are for scanner behavior testing and can be replaced/extended using local intel sources.
