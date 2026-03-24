---
name: greencheck-setup
description: Install and configure greencheck — a GitHub Action that automatically fixes failed CI runs using Claude Code or Codex. Use this skill when a user wants automated CI failure remediation in their repository.
version: 0.1.1
author: Braedon Saunders
license: MIT
metadata:
  tags: [GitHub-Actions, CI/CD, Auto-Fix, Claude-Code, Codex, LLM, Automation]
  triggers:
    - user asks to auto-fix CI failures
    - user wants greencheck in their repo
    - user asks for automated CI remediation
    - user mentions greencheck
    - user wants an AI agent to fix broken builds
  required_commands: [git]
  optional_commands: [gh]
  repo_url: https://github.com/braedonsaunders/greencheck
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: braedonsaunders/greencheck
# corpus-url: https://github.com/braedonsaunders/greencheck/blob/cd30a9c735b911917c49f5ee26a9fba0bb0d43a7/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# greencheck Setup Skill

Install greencheck into a GitHub repository so that failed CI runs are automatically parsed, diagnosed, and fixed by an LLM coding agent (Claude Code or Codex).

## When to Use

- User wants CI failures to be auto-fixed
- User asks to install or configure greencheck
- User wants an AI agent to monitor and repair broken builds
- User mentions "greencheck", "auto-fix CI", or "automated CI remediation"

## Prerequisites

Before starting, confirm the following with the user or by inspecting the repo:

1. **The repo is on GitHub** with GitHub Actions enabled
2. **An existing CI workflow exists** in `.github/workflows/` that runs tests, lint, typecheck, or build
3. **The user has or can create** a GitHub PAT (fine-grained) with `contents: write` and `actions: read` scopes
4. **The user has** an Anthropic API key or OpenAI API key

## Step 1: Identify the CI Workflow Name

Find the CI workflow files and extract their `name:` field. This is required for the `workflow_run` trigger.

```bash
# List workflow files
ls .github/workflows/

# Extract the name: field from each workflow
grep -H '^name:' .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null
```

Note the exact name(s) — they are case-sensitive. Common examples: `CI`, `Tests`, `Lint`, `Build`, `test`, `ci`.

If the workflow has no `name:` field, the filename without extension is used (e.g., `ci.yml` → `ci`).

## Step 2: Create the greencheck Workflow

Create `.github/workflows/greencheck.yml` with the following content. Replace `"CI"` in the `workflows:` list with the actual name(s) found in Step 1.

```yaml
name: greencheck

on:
  workflow_run:
    workflows: ["CI"]  # REPLACE with actual CI workflow name(s)
    types: [completed]

permissions:
  actions: read
  contents: write
  issues: write
  pull-requests: write

jobs:
  fix:
    if: ${{ github.event.workflow_run.conclusion == 'failure' }}
    runs-on: ubuntu-latest
    concurrency:
      group: greencheck-${{ github.event.workflow_run.head_branch }}
      cancel-in-progress: true

    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
          fetch-depth: 0
          token: ${{ secrets.GREENCHECK_TOKEN }}

      - uses: braedonsaunders/greencheck@v0
        with:
          agent: claude
          agent-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
          trigger-token: ${{ secrets.GREENCHECK_TOKEN }}
```

### Agent Selection

Choose ONE of these configurations for the `uses: braedonsaunders/greencheck@v0` step:

**Claude Code with API key (recommended):**
```yaml
          agent: claude
          agent-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

**Claude Code with OAuth:**
```yaml
          agent: claude
          agent-oauth-token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
```

**Codex:**
```yaml
          agent: codex
          agent-api-key: ${{ secrets.OPENAI_API_KEY }}
```

## Step 3: Create Repository Configuration (Optional)

If the user wants fine-tuned control, create `.greencheck.yml` in the repository root:

```yaml
watch:
  workflows: [CI]
  branches: [main, develop]
  ignore-authors: [dependabot, renovate]

fix:
  agent: claude
  types: [lint, type-error, test-failure]
  max-passes: 5
  max-cost: "$3.00"
  timeout: 20m

safety:
  never-touch-files:
    - "*.lock"
    - "package-lock.json"
    - ".env*"
    - ".github/**"
  max-files-per-fix: 10
  revert-on-regression: true

report:
  pr-comment: true
  job-summary: true

merge:
  enabled: false
  max-commits: 3
  require-label: true
  protected-patterns: [main, master, release/*]
```

Adjust based on the repo's needs:
- **`watch.workflows`** — match the CI workflow name(s) from Step 1
- **`watch.branches`** — omit to watch all branches
- **`fix.types`** — set to `[lint, type-error]` for conservative mode, omit for all
- **`safety.never-touch-files`** — add project-specific sensitive files
- **`merge.enabled`** — only set `true` if user explicitly wants auto-merge

## Step 4: Commit and Push

```bash
git add .github/workflows/greencheck.yml
# If .greencheck.yml was created:
git add .greencheck.yml

git commit -m "ci: add greencheck for automated CI failure fixes

Monitors CI workflow runs and automatically fixes failures using
Claude Code. Includes safety guardrails: cost limits, timeout,
protected files, and regression detection with auto-revert."

git push origin HEAD
```

## Step 5: Tell the User to Configure Secrets

After pushing, inform the user they need to add these secrets in their GitHub repo settings (**Settings → Secrets and variables → Actions → New repository secret**):

### Required Secrets

| Secret Name | Value | How to Get It |
|-------------|-------|---------------|
| `GREENCHECK_TOKEN` | GitHub PAT (fine-grained) | github.com → Settings → Developer settings → Fine-grained tokens → Generate. Scope to this repo with `contents: write` and `actions: read`. |
| `ANTHROPIC_API_KEY` | Anthropic API key | console.anthropic.com → API Keys (only if using Claude) |
| `OPENAI_API_KEY` | OpenAI API key | platform.openai.com → API Keys (only if using Codex) |

**`GITHUB_TOKEN` is automatic** — do not ask the user to create it.

## Step 6: Verify the Setup

Tell the user how to test:

1. Make a small intentional CI-breaking change (e.g., add a TypeScript type error, remove a required import, break a lint rule)
2. Commit and push it
3. Wait for the CI workflow to fail
4. Watch the greencheck workflow trigger automatically
5. greencheck will parse the failure, invoke the agent, commit a fix, and wait for CI again

The user can monitor progress in the **Actions** tab on GitHub.

## Available Action Inputs

For customizing the workflow step, these inputs are available:

| Input | Default | Description |
|-------|---------|-------------|
| `agent` | `claude` | `claude` or `codex` |
| `agent-api-key` | — | API key for the agent |
| `agent-oauth-token` | — | Claude Code OAuth token |
| `github-token` | — | **Required.** GitHub token for API access |
| `trigger-token` | — | **Required.** PAT for push and rerun |
| `max-passes` | `5` | Max fix/verify cycles |
| `max-cost` | `$3.00` | Spend limit per run |
| `timeout` | `20m` | Runtime budget |
| `auto-merge` | `false` | Auto-merge after green CI |
| `watch-workflows` | all | Comma-separated workflow names |
| `fix-types` | `all` | `lint,type-error,test-failure,build-error,runtime-error` or `all` |
| `model` | — | Override agent model (e.g., `claude-sonnet-4-20250514`) |
| `dry-run` | `false` | Diagnose without pushing |

## Available Action Outputs

Access in subsequent steps via `${{ steps.<step-id>.outputs.<name> }}`:

| Output | Description |
|--------|-------------|
| `fixed` | `true` / `false` |
| `passes` | Number of fix cycles used |
| `failures-found` | Total failures detected |
| `failures-fixed` | Total failures resolved |
| `commits` | Comma-separated fix SHAs |
| `cost` | Estimated LLM cost |

## Supported Languages

greencheck parses CI logs for these formats out of the box:

| Tool | Detected Failures |
|------|-------------------|
| ESLint, Biome, Oxlint | Lint errors |
| TypeScript (tsc) | Type errors |
| Jest, Vitest | Test failures, snapshot failures |
| Pytest | Test failures, collection errors |
| Go (test + build) | Test failures, build errors |
| Rust (rustc + cargo) | Build errors, test panics |

## Pitfalls

1. **Workflow name mismatch** — The `workflows:` list in `greencheck.yml` must exactly match the `name:` field in the CI workflow (case-sensitive). This is the #1 setup issue.
2. **Missing `fetch-depth: 0`** — Required for greencheck to operate on git history. Do not omit.
3. **Using `GITHUB_TOKEN` as `trigger-token`** — This won't work. `GITHUB_TOKEN` cannot trigger new workflow runs. Use a PAT.
4. **Not scoping the PAT** — The `GREENCHECK_TOKEN` PAT needs `contents: write` and `actions: read` on the target repo. Missing permissions cause silent failures.
5. **Protected branches** — If the target branch has branch protection rules requiring PR reviews, greencheck's direct push will be rejected. Either relax the rules for the bot or configure greencheck to work on PR branches only.