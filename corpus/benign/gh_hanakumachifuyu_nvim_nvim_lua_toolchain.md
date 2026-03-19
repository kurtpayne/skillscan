---
name: nvim-lua-toolchain
description: Set up or update local development and test toolchains for Lua projects, especially Neovim Lua plugin development. Use when Claude needs to scaffold or standardize plenary.nvim tests, luacov coverage, headless Neovim test workflows, stylua formatting, luacheck linting, lefthook git hooks, or AI code review for a Lua or Neovim plugin repository.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: HanakumaChifuyu/nvim-lua-toolchain
# corpus-url: https://github.com/HanakumaChifuyu/nvim-lua-toolchain/blob/43b27610fa1c5a258fd8d9155ea7588306fea662/SKILL.md
# corpus-round: 2026-03-19
# corpus-format: markdown_fm
---

# Nvim Lua Toolchain

Use this skill to scaffold a test-focused, quality-gated development environment for Neovim Lua plugins. The default stack is `plenary.nvim` + `luacov` + `stylua` + `luacheck` + `lefthook`.

## Installing this skill

```bash
bash path/to/nvim-lua-toolchain/install.sh
```

This copies the skill into `~/.claude/skills/nvim-lua-toolchain/`. The install location can be overridden with `CLAUDE_SKILLS_DIR`.

## Setting up a plugin repo

Run the following from the root of the target plugin repository:

```bash
bash ~/.claude/skills/nvim-lua-toolchain/scripts/install-tools.sh
```

This will:
- Copy `tests/minimal_init.lua`, `.luacov`, `.luacheckrc`, `justfile`, `stylua.toml`, `lefthook.yml`, `scripts/code-review.sh` into the repo (skips existing files)
- Install `stylua` (via cargo or GitHub binary)
- Check for `luacheck` and print install instructions if missing
- Install `luacov` into `tests/.rocks/`
- Run `lefthook install` if lefthook is available and the directory is a git repo

## Workflow

1. Identify the repository type.
   - Neovim Lua plugin → `plenary.nvim` headless tests + `luacov` (default)
   - Pure Lua library → `busted` + `luacov`
   - Mixed plugin needing fuller Busted features → `vusted` or `busted` via `nvim -l`

2. Read `references/nvim-lua-tooling.md` before selecting tools or writing config.

3. Prefer the repository's existing conventions if tools are already wired into CI.

4. Add toolchain in order: test runner → coverage → formatter/linter → git hooks.

## Available just recipes

| Recipe | Description |
|---|---|
| `just` | Run all pre-commit checks via lefthook (default) |
| `just test` | Run all specs with plenary (multi-process) |
| `just test <file...>` | Run specific spec files |
| `just coverage` | Run all specs (single-process) + generate luacov report |
| `just check-coverage` | Coverage + fail if below threshold (default 80%) |
| `just fmt` | Format Lua files with stylua |
| `just fmt-check` | Check formatting without modifying |
| `just lint` | Lint with luacheck |

Change the coverage threshold: edit `min_coverage` at the top of `justfile`.

## Git hooks (lefthook)

| Hook | Commands |
|---|---|
| `pre-commit` | `fmt` (stylua) → `lint` (luacheck) → `coverage` (check-coverage) |
| `pre-push` | `code-review` (AI review via `claude --print`) |

Skip hooks: `LEFTHOOK=0 git commit` / `LEFTHOOK_EXCLUDE=coverage git commit`

## Key implementation details

- `tests/minimal_init.lua` is loaded via `-u` in every headless nvim invocation. It finds plenary in 13+ common locations (lazy/packer/vim-plug/dein/rocks/mason/system).
- Coverage uses `plenary.busted.run()` (single-process) instead of `test_harness` (multi-process) so luacov's debug hook sees all executed lines.
- `jit.off()` must be called **before** `require("luacov")` — LuaJIT's JIT compilation bypasses `debug.sethook` line hooks.
- luacov `exclude_files` patterns are Lua patterns (not globs); `.rocks` paths require `.*%.rocks/.*`.

## Default recommendations

- Test runner: `plenary.nvim`
- Coverage: `luacov`
- Formatter: `stylua`
- Linter: `luacheck` with `globals = {"vim"}` to suppress false positives on vim API
- Git hooks: `lefthook`
- AI review: `claude --print` on pre-push
- Editor: `lua_ls` + `lazydev.nvim`

## Resources

- `references/nvim-lua-tooling.md` — tooling research and decision guide
- `template_plugin/` — complete runnable example (tools.lua + spec + justfile)
- `scripts/install-tools.sh` — sets up a target repo from the template
- `install.sh` — installs this skill into `~/.claude/skills/`