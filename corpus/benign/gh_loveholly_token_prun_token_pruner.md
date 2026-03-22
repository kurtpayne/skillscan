---
name: token-pruner
description: Reduce LLM context cost for structured payloads and noisy CLI output. Use when the user wants to shrink JSON, NDJSON, API responses, test logs, git output, tabular exports, or command output before sending it to Codex or Claude Code, especially with RTK, jq, TOON, qsv, or jc.
owner: b.wen
last_updated: 2026-03-20
source_of_truth: true
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: loveholly/token-pruner
# corpus-url: https://github.com/loveholly/token-pruner/blob/ca2a6731483bbf05583e04c188297dcbd42a34cf/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# Token Pruner

Use this skill when the expensive part of the context is structured data or noisy tool output, not source code.

## Quick Start

1. Resolve the skill directory from this `SKILL.md`.
2. Run a runtime check first:

```bash
python3 "<skill-dir>/scripts/token_pruner.py" doctor
```

If this is a fresh source checkout and the vendor tree is still empty, install first:

```bash
python3 "<skill-dir>/scripts/bootstrap.py" --codex-only
```

3. Probe bundled and local tooling paths when needed:

```bash
python3 "<skill-dir>/scripts/token_pruner.py" probe
```

4. Profile the payload before pruning:

```bash
python3 "<skill-dir>/scripts/token_pruner.py" profile --input "<path-to-json>"
```

5. Prune semantically first, then choose the output format:

```bash
python3 "<skill-dir>/scripts/token_pruner.py" prune \
  --input "<path-to-json>" \
  --keep-keys id,name,status,created_at \
  --head 50 \
  --format auto
```

6. Run bundled helper tools from the same entrypoint when needed:

```bash
python3 "<skill-dir>/scripts/token_pruner.py" tool rtk git status
```

7. In Claude Code projects, use the bundled hook setup in `.claude/settings.json` to rewrite common Bash calls through vendored RTK.

## System Install

- To install this bundle into Codex and Claude Code system locations on the current machine:
  The installer prefers a matching GitHub Release bundle and falls back to local bootstrap when needed.

```bash
python3 "<skill-dir>/scripts/bootstrap.py"
```

- The compatibility entrypoint `scripts/install_system.py` still works, but `bootstrap.py` is the preferred name because it also prepares missing vendor dependencies.
- Codex install target: `~/.codex/skills/token-pruner`
- Claude install target: `~/.claude/skills/token-pruner`
- The installer preserves existing Claude settings, merges the global Bash hook, and writes a managed section into `~/.claude/CLAUDE.md`.

## Workflow

### 1) Profile Before Pruning

- Start with `doctor` before substantial use. Treat its output as the source of truth for whether bundled tools actually run on the current machine.
- Start with `profile` to detect depth, row count, field uniformity, and whether TOON is likely to help.
- Treat `format` choice as the last step, not the first step.

### 2) Route by Source Type

- For supported developer commands such as `git status`, `git diff`, `git log`, `grep`, `find`, `ls`, `cargo test`, or `pytest`, prefer `rtk` first.
- Invoke bundled helpers through `python3 "<skill-dir>/scripts/token_pruner.py" tool <tool-name> ...` when you want a stable, project-local path.
- Use `python3 "<skill-dir>/scripts/token_pruner.py" rewrite-bash --command "<cmd>"` to see whether a Bash command should be routed through RTK before you wire it into a hook.
- For generic CLI text that `rtk` does not cover, normalize with `jc` when possible.
- For CSV or TSV, prune with `qsv` before converting anything to JSON.
- For JSON or NDJSON, go directly to `jq` and the built-in pruning controls.

### 3) Remove Semantic Noise First

- Prefer `jq` or the built-in `--keep-keys`, `--drop-keys`, `--head`, and `--sample` controls before changing the wire format.
- Preserve identifiers, timestamps, status fields, and enough evidence for the model to reason correctly.
- Drop blobs such as verbose markdown bodies, HTML, embeddings, base64, stack traces, and duplicated nested metadata unless the user explicitly needs them.

### 4) Pick the Rendering Format

- Default to compact JSON when the payload is nested, irregular, or already aggressively filtered.
- Prefer TOON only when the payload is mostly an array of similar objects and the bundled `toon` wrapper is available.
- Treat RTK as a command-output compressor, not as a replacement for `jq` or TOON.
- For command output that still needs structured reasoning after RTK, convert or reshape it before giving it to the model.

### 5) Report Tradeoffs Clearly

- Say what was removed, what was sampled, and which fields were preserved.
- Do not claim token savings without measurement or at least a stated estimate.
- If `toon` is available, use its `--stats` flag when the user wants a concrete before/after comparison.
- Treat RTK's savings output as useful operational telemetry, but not as exact model-token accounting for every target model.

## Guardrails

- Current prebuilt vendor bundle targets `macOS arm64`. On other platforms, including Linux-based remote agents or cloud sandboxes, do not assume the release asset or bootstrap path will succeed unchanged.
- The project bundles helper CLIs, but it still requires a working `python3` runtime. The bundled TOON wrapper also requires a working `node` runtime.
- Do not use this skill for normal source-code reading unless the source has already been turned into structured metadata.
- Do not hide critical evidence just to save tokens.
- Avoid TOON for deeply nested or semi-uniform payloads unless measured results prove it helps.
- Do not assume RTK covers every shell command. Fall back cleanly to `jc`, `jq`, or compact summaries.
- When in doubt, return compact JSON plus a short summary instead of an exotic format.

## References

- `references/implementation-strategy.md`
- `references/tooling-matrix.md`