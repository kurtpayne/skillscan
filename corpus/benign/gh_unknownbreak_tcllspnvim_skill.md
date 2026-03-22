---
name: lint
version: "1.0"
description: Run linting for Lua and TCL code
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: unknownbreaker/tcl-lsp.nvim
# corpus-url: https://github.com/unknownbreaker/tcl-lsp.nvim/blob/HEAD/.claude/skills/lint/SKILL.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
Run linting tools on the codebase.

## Usage

`/lint` - Run all linters
`/lint lua` - Run only Lua linter
`/lint tcl` - Run only TCL linter

## Commands

Run all linting:
```bash
make lint
```

Run Lua linting only:
```bash
make lint-lua
```

Run TCL linting only:
```bash
make lint-tcl
```

## Tools Used

- **Lua**: luacheck
- **TCL**: nagelfar

After running linters, summarize:
1. Total warnings/errors by category
2. Files with issues
3. Suggestions for fixing critical issues