# Threat Model

## Assumptions

- Input artifacts are untrusted.
- Scanner host should be considered trusted.
- Offline intel may be stale and should be updated regularly.

## In-Scope Attacks

- Prompt/instruction abuse in markdown
- Download-and-exec shell patterns
- Obfuscated command chains
- IOC reuse across campaigns
- Dependency vulnerabilities in known datasets
- Archive path traversal and unsafe extraction attempts

## Out of Scope (v1)

- Runtime memory forensics
- Public signing and transparency logs
- Multi-tenant identity and access controls

## Security posture notes

1. SkillScan does not execute scanned artifact code in default scan mode.
2. Scanning verdicts are deterministic and do not require LLMs.
3. If optional LLM analysis is added later, it should remain non-authoritative.
