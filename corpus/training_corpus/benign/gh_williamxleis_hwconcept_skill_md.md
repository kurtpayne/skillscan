---
name: skill.md
version: "1.0"
description: Generate hardware concept designs from requirements file or interactively.
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: WilliamxLeismer/hw-concept
# corpus-url: https://github.com/WilliamxLeismer/hw-concept/blob/HEAD/skill.md.archived
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
# /hw-concept

Generate 3 hardware concept designs with block diagrams and BOMs.

## Arguments

Parse the following from `$ARGUMENTS`:
- `--input FILE`: Requirements file (YAML or Markdown). Optional.
- `--output DIR`: Output directory. Default: `./concepts/`
- `--depth LEVEL`: Research depth (`quick`, `medium`, `thorough`). Default: `medium`

## Execution

### 1. Parse Arguments

Extract `INPUT_FILE`, `OUTPUT_DIR`, and `DEPTH` from arguments.

If `--input` provided:
- Verify file exists using Glob
- If not found, report error and exit

### 2. Invoke Agent

Use Task tool with subagent_type="hw-concept":

```
Generate hardware concepts.

Parameters:
- INPUT_FILE: [path or "interactive"]
- OUTPUT_DIR: [path]
- DEPTH: [quick|medium|thorough]

[If input file provided, include its contents here]
```

### 3. Report Results

When agent completes, report:
- Files created in OUTPUT_DIR
- Completeness score achieved
- Next step: "Review comparison-matrix.md to select concept"

## Examples

```
/hw-concept --input reqs.yaml --output ./my-project/concepts/
/hw-concept --depth thorough
/hw-concept
```