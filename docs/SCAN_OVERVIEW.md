# Scan Overview

This guide explains what SkillScan checks, why each check is useful, and how safety is enforced.

## Design principles

1. Untrusted input by default.
2. Static analysis first.
3. Deterministic policy verdicting.
4. Optional AI assistance, never code execution.

## End-to-end scan stages

1. Target preparation:
- Accepts directory, file, archive, or URL target.
- Archives are extracted with traversal/symlink protections and size/count limits.
- URL mode can follow linked sources with safety controls (same-origin default, max link cap).

2. File filtering:
- Iterates text-like files only.
- Classifies non-text artifacts and raises binary findings (`BIN-*`) for executables/libraries/bytecode/blobs.

3. Instruction hardening:
- Unicode normalization (`NFKC`).
- Zero-width character stripping.
- Defanged IOC normalization (for example `hxxp` -> `http`, `[.]` -> `.`).
- Bounded base64 decoding, including split-fragment patterns.

4. Deterministic rule analysis:
- Static rule matches from YAML rulepacks.
- Action extraction and chain detection (download+execute, secret+network, privilege+disable-security).
- Python AST dataflow checks for secret-to-network and dynamic exec flows.
- Prompt-injection/jailbreak wording checks.
- Subshell/encoded execution pattern checks.
- npm lifecycle hook abuse checks.
- Bidirectional Unicode obfuscation checks (Trojan Source style).

5. IOC and dependency intelligence:
- Extracts URLs/domains/IPs.
- Correlates indicators against built-in + managed + user intel lists.
- Checks vulnerable dependency versions and unpinned requirements.

6. Capability inference:
- Identifies shell/network/filesystem-write capabilities for analyst context.

7. Optional AI semantic analysis (`--ai-assist`):
- Looks for semantic/social-engineering risk not easily captured by string patterns.
- Operates on bounded text snippets and local finding summaries.
- Adds `AI-SEM-*` findings with evidence and mitigations.

8. Scoring and verdict:
- Applies policy weights/thresholds.
- Applies hard-block rules.
- Applies optional AI critical-block policy controls.

9. Reporting:
- Pretty terminal output (`scan`, `explain`).
- JSON report output for CI and automation.
- Optional raw AI JSON output via `--ai-report-out`.

## Why this is valuable

1. Catches obvious malware patterns quickly (`curl|bash`, decode-and-exec).
2. Catches instruction-layer abuse (coercive setup, security-control bypass).
3. Catches hidden/obfuscated intent through normalization + decode pipeline.
4. Catches infra risk via IOC and vulnerability correlation.
5. Produces consistent, explainable outputs suitable for CI gates and IR triage.

## Safety model

1. SkillScan does not execute scanned artifacts.
2. Archive extraction is hardened against common abuse vectors.
3. URL fetching uses explicit safety limits and flags unreadable/skipped sources.
4. AI mode is opt-in, bounded, and prompt-hardened:
- Snippets are wrapped as untrusted input blocks.
- Output must be strict JSON schema.
- AI failures degrade gracefully unless explicitly required.

## What AI mode sends

When enabled, SkillScan sends:

1. Target identifier.
2. Local finding summary.
3. Bounded text snippets only (not full archive bytes).

Current limits (code defaults):

1. ~2200 chars per file snippet.
2. ~24,000 chars total snippet budget.

## Recommended usage

1. Default: run strict local scan first.
2. For deeper semantic review: rerun with `--ai-assist`.
3. In CI: use `--fail-on block` and store JSON artifacts.
4. For investigations: include `--ai-report-out` and keep reports with case notes.
