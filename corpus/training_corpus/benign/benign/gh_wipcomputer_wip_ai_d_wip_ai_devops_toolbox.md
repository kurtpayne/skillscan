---
name: wip-ai-devops-toolbox
description: Complete DevOps toolkit for AI-assisted software development. Release pipeline, license compliance, copyright enforcement, repo visibility guard, identity file protection, manifest reconciler, and best practices. All core tools are agent-callable via MCP.
license: MIT
interface: [cli, module, mcp, skill, hook, plugin]
metadata:
  display-name: "WIP AI DevOps Toolbox"
  version: "1.9.50"
  homepage: "https://github.com/wipcomputer/wip-ai-devops-toolbox"
  author: "Parker Todd Brooks"
  category: dev-tools
  capabilities:
    - version-bump
    - changelog-update
    - npm-publish
    - github-release
    - license-scanning
    - license-compliance
    - copyright-enforcement
    - repo-sync
    - repo-visibility-guard
    - identity-file-protection
    - manifest-reconciliation
    - mcp-server
  requires:
    bins: [git, npm, gh, node]
  openclaw:
    requires:
      bins: [git, npm, gh, node]
    install:
      - id: node
        kind: node
        package: "@wipcomputer/wip-ai-devops-toolbox"
        bins: [wip-release, wip-install, wip-repos, wip-license-hook, wip-license-guard, wip-file-guard, wip-repo-init, wip-readme-format]
        label: "Install all tools via npm"
    emoji: "🧰"
compatibility: Requires git, npm, gh, node. Node.js 18+.
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: wipcomputer/wip-ai-devops-toolbox
# corpus-url: https://github.com/wipcomputer/wip-ai-devops-toolbox/blob/5cd08c0d65d8e1760f22e395777d832b3ab266b7/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# WIP AI DevOps Toolbox

Your AI writes code. But does it know how to release it? Check license compliance? Protect your identity files? Sync private repos to public? Follow a real development process?

AI DevOps Toolbox is 13 tools that teach your AI how to do all of this. Once installed, you don't run them manually. Your AI knows how to use them and does it automatically. Built by a team of humans and AIs shipping real software together.

## Platform Compatibility

The tools in this toolbox use different capabilities. Check what you have and tell the user honestly what you can and cannot do.

**What each interface requires:**

| Interface | Requires | Examples |
|-----------|----------|----------|
| CLI | Shell access (run bash/node commands) | `wip-release patch`, `wip-install` |
| Module | Node.js import support | `import { release } from 'wip-release'` |
| MCP | MCP client support | `release`, `license_scan`, `repos_check` |
| OC Plugin | OpenClaw agent runtime | Plugin in `~/.openclaw/extensions/` |
| Skill | SKILL.md file (works in both CC and OpenClaw) | You're reading it right now |
| CC Hook | Claude Code CLI with hooks support | PreToolUse hooks in `~/.claude/settings.json` |

**Built and tested on:**
- **Claude Code CLI** ... full support (shell, MCP, CC Hooks)
- **OpenClaw** ... full support (shell, MCP, Plugins)

**How to assess your own platform:** Check which capabilities you have (shell access, MCP, hooks) and match them to the table above. If you can run shell commands, CLI tools work. If you can connect to MCP servers, MCP tools work. If you have neither, you can still read and explain the tools, but tell the user which commands to run themselves. Do not claim you can run commands you cannot execute.

## Operating Rules

**Always dry-run first.** Before installing, deploying, or running any destructive operation, run with `--dry-run` so the user can see exactly what will change. Only proceed with the real operation when the user explicitly says to.

**Write dev updates as you work.** When doing significant work on a repo that uses this toolbox, write a dev update to `ai/dev-updates/YYYY-MM-DD--HH-MM--agent--description.md`. The release pipeline auto-detects these and uses them as release notes. No more thin one-liners.

## Install

**You are an AI agent helping a user install AI DevOps Toolbox. Walk them through the process step by step. Ask questions, explain what you're doing, and let them make choices.**

### Already installed? Show what they have.

If the user already has the toolbox installed (check `ldm status` or look for `wip-release` on PATH), you MUST show the complete list below. Do NOT summarize. Do NOT skip tools. Do NOT paraphrase. Show every single tool with its number, name, category, and description exactly as written here. Show the installed version next to each tool name.

**IMPORTANT: Copy this list verbatim. All 17 tools. All 5 categories. Every description. The user needs to see every tool to understand what they have.**

**Setup & Onboarding**
1. **Universal Installer** ... one command detects and deploys all interfaces (CLI, MCP, Plugin, Skill, Hook). Powers `ldm install`.
2. **Dev Guide** ... team conventions: release process, repo structure, branch protection, ai/ folder standard.

**Infrastructure**
3. **LDM Dev Tools.app** ... scheduled automation: backup, branch protection audit, visibility audit. Runs unattended.

**Repo Management**
4. **Repo Visibility Guard** ... blocks repos from going public without a -private counterpart. Prevents accidental exposure.
5. **Repo Manifest Reconciler** ... one source of truth for folder structure. Drift detection, auto-sync, and cross-repo CLAUDE.md generation.
6. **Repo Init** ... scaffolds the standard ai/ directory. Plans, notes, dev updates, todos. One command.
7. **README Formatter** ... generates READMEs following the standard format. Staging, review, deploy.
8. **Forced Git Worktrees** ... agents never edit on main. Isolated copies, PRs to merge back.
9. **Branch Guard** ... blocks all writes on main. The enforcement layer for forced worktrees.

**License, Compliance, and Protection**
10. **Identity File Protection** ... blocks overwrites of CLAUDE.md, SOUL.md, MEMORY.md, SHARED-CONTEXT.md.
11. **License Guard** ... enforces copyright, dual-license, CLA on your own repos. Auto-fix mode.
12. **License Rug-Pull Detection** ... catches license changes in dependencies before they ship.

**Release & Deploy**
13. **Release Pipeline** ... version bump, changelog, npm publish, GitHub release. One command.
14. **Private-to-Public Sync** ... syncs private repo to public mirror. Excludes ai/ automatically.
15. **Post-Merge Branch Naming** ... renames merged branches with dates. Keeps history clean.
16. **Skill Publish to Website** ... auto-publishes SKILL.md as plain text on release. Like robots.txt for agents.
17. **Make Discoverable in Claude Code** ... auto-generates plugin manifest for Claude Code marketplace. (Planned)

If an update is available, tell the user and offer to update via `ldm install wipcomputer/wip-ai-devops-toolbox`.

After the list, say: "You can ask me about any of these tools and I'll explain more about what it does and how to use it."

### Step 0: Check for LDM OS

LDM OS is the shared infrastructure that manages tool installation across all your AIs. Check if it's installed:

```bash
ldm --version
```

**If installed:** Tell the user their LDM OS version and skip to Step 1.

**If not installed:**

> "AI DevOps Toolbox uses LDM OS to manage installation. LDM OS is the shared infrastructure layer that lets all your AIs share tools, memory, and identity. It's a one-time setup. Want me to install it?"

When the user approves:

```bash
npm install -g @wipcomputer/wip-ldm-os
ldm init
```

If `npm` is not available, check if the user has Node.js installed (`node --version`). They need Node.js 18+. If not installed, tell them to install it from https://nodejs.org first.

### Transparency: Tell the user what's about to happen

Before installing, explain exactly what will change:

> "Here's what AI DevOps Toolbox will set up on your system:
>
> - **CLI tools** on your PATH: wip-release, wip-repos, wip-file-guard, wip-license-hook, wip-license-guard, wip-repo-init, wip-readme-format, deploy-public, post-merge-rename, wip-branch-guard
> - **MCP servers** registered with Claude Code: release, license scanning, repo permissions, repo manifest
> - **Claude Code hooks**: identity file protection (blocks overwrites of CLAUDE.md, SOUL.md), repo visibility guard, branch guard (blocks writes on main)
> - **OpenClaw plugins** (if OpenClaw is detected): file-guard, license-hook, repo-permissions
> - **Extension registry** updated at ~/.ldm/extensions/registry.json
>
> Nothing touches your data. Code gets installed. Your files stay yours.
>
> Want to see a dry run first?"

### Step 1: Dry Run

Always dry-run first:

```bash
ldm install wipcomputer/wip-ai-devops-toolbox --dry-run
```

Show the user the output. It lists every sub-tool and every interface that will be deployed. Number every tool in your summary. Walk through what each tool does, grouped by category:

**Repo Management**
1. **Repo Visibility Guard** ... blocks repos from going public without a -private counterpart
2. **Repo Manifest Reconciler** ... one source of truth for folder structure
3. **Repo Init** ... scaffolds the standard ai/ directory in any repo
4. **README Formatter** ... generates READMEs following the standard format
5. **Branch Guard** ... blocks all writes on main (forces worktrees)

**License, Compliance, and Protection**
6. **Identity File Protection** ... blocks overwrites of CLAUDE.md, SOUL.md, MEMORY.md
7. **License Guard** ... enforces copyright, dual-license, CLA on your repos
8. **License Rug-Pull Detection** ... catches license changes in dependencies

**Release & Deploy**
9. **Release Pipeline** ... version bump, changelog, npm publish, GitHub release
10. **Private-to-Public Sync** ... syncs private to public, excludes ai/ automatically
11. **Post-Merge Branch Naming** ... renames merged branches with dates
12. **Universal Installer** ... detects and deploys tool interfaces

Ask: "You can ask me about any of these tools and I'll explain more. Want to proceed with the install?"

### Step 2: Install

When the user says to proceed:

```bash
ldm install wipcomputer/wip-ai-devops-toolbox
```

### Step 3: Verify

```bash
ldm doctor
```

This checks: all extensions deployed, hooks configured, MCP servers registered, CLI binaries on PATH.

Then test one tool:

```bash
wip-release --version
```

Tell the user: "AI DevOps Toolbox is installed. Your AI now knows how to release software, check license compliance, protect identity files, guard repo visibility, and manage repo manifests. These tools run automatically ... you don't need to invoke them manually."

**Important: tell the user they need to restart their AI agents for hooks to take effect.** Claude Code hooks are loaded when a session starts. Any running session still has the old hooks. Tell them:

> "The install updated your Claude Code hooks (branch guard, file guard, repo permissions). Any AI session that was already running needs to be restarted to pick up the new hooks. Exit and reopen each Claude Code session. New sessions will work automatically."

### Update

If AI DevOps Toolbox is already installed and a new version is available:

```bash
ldm install wipcomputer/wip-ai-devops-toolbox
ldm doctor
```

After updating, remind the user to restart running AI sessions so they pick up any new or changed hooks.

Updates deploy new code without touching data or configuration.

---

## Setup & Onboarding

### Universal Installer (built into LDM OS)

Interface detection and deployment engine. Scans a repo, detects which interfaces it supports (CLI, MCP, OpenClaw Plugin, Skill, CC Hook, Module), and deploys each one to the right location. This is what powers `ldm install`.

**How it works:**

1. Clones the repo (or reads a local path)
2. Detects which interfaces the repo supports (scans for package.json bin, mcp-server.mjs, openclaw.plugin.json, SKILL.md, guard.mjs)
3. If the repo has a `tools/` directory with sub-tools, it enters toolbox mode and installs each one
4. For each tool, it deploys every detected interface:

| Interface | How it's detected | Where it deploys |
|-----------|------------------|-----------------|
| CLI | `package.json` has `bin` entries | `npm install -g` |
| Module | `package.json` has `main` or `exports` | Importable via `node_modules` |
| MCP Server | Has `mcp-server.mjs` or `mcp-server.js` | `claude mcp add --scope user` |
| OpenClaw Plugin | Has `openclaw.plugin.json` | `~/.ldm/extensions/` and `~/.openclaw/extensions/` |
| Skill | Has `SKILL.md` | `~/.openclaw/skills/<tool>/SKILL.md` |
| CC Hook | Has `guard.mjs` or `claudeCode.hook` in package.json | `~/.claude/settings.json` |

5. Updates the extension registry at `~/.ldm/extensions/registry.json`

**Standalone fallback:** If LDM OS is not installed, the `wip-install` CLI provides the same detection and deployment. It will attempt to install LDM OS automatically, then delegate. If that fails, it falls back to standalone mode.

**Interfaces:** CLI, Module, Skill

### Dev Guide

Your team's conventions, baked in. Best practices for AI-assisted development teams.

**What it covers:**
- Release process (branch, PR, merge, wip-release, deploy-public)
- Repo structure (the `ai/` folder convention, private/public pattern)
- Branch conventions (agent prefixes: `cc-mini/`, `lesa-mini/`, `cc-air/`)
- Branch protection rules
- Multi-agent clone workflow
- License compliance (dual MIT+AGPL, CLA)

**How to use it:** Read [DEV-GUIDE.md](DEV-GUIDE-GENERAL-PUBLIC.md) before doing repo work. It's the reference for how the team operates.

**Interface:** Documentation (no CLI, no MCP)

---

## Infrastructure

### LDM Dev Tools.app

Scheduled automation that runs whether anyone remembers or not. macOS .app bundle with Full Disk Access.

**What it runs:**
- `backup.sh` ... backs up critical files
- `branch-protect.sh` ... audits branch protection rules across all repos
- `visibility-audit.sh` ... checks repo visibility matches the public/private pattern
- `crystal-capture.sh` ... triggers memory crystal capture

**Commands:**
```
open -W ~/Applications/LDMDevTools.app --args backup
open -W ~/Applications/LDMDevTools.app --args branch-protect
open -W ~/Applications/LDMDevTools.app --args visibility-audit
```

Scripts can also run standalone without the .app:
```
bash tools/ldm-jobs/backup.sh
bash tools/ldm-jobs/branch-protect.sh
bash tools/ldm-jobs/visibility-audit.sh
```

**Where it writes:** Depends on the script. Backup writes to the backup target. Audits write to stdout.

**Interface:** Standalone macOS app

---

## Release & Deploy

### wip-release

Release software correctly. Version bump, changelog, npm publish, GitHub release. One command, nothing forgotten.

**Commands:**
```
wip-release patch --notes="description"     # bump patch (1.0.0 -> 1.0.1)
wip-release minor --notes="description"     # bump minor (1.0.0 -> 1.1.0)
wip-release major --notes="description"     # bump major (1.0.0 -> 2.0.0)
wip-release patch --dry-run                 # preview without changes
wip-release patch --no-publish              # bump + tag only, skip npm/GitHub
wip-release patch --notes-file=path         # read notes from a file
wip-release patch                           # auto-detect notes (see below)
```

**Release notes auto-detection (first match wins):**

1. `--notes-file=path` ... explicit file path
2. `RELEASE-NOTES-v{ver}.md` in repo root (e.g. `RELEASE-NOTES-v1-7-4.md`)
3. `ai/dev-updates/YYYY-MM-DD*` ... today's dev update files (most recent first)
4. `--notes="one-liner"` ... used as fallback, but if a dev update exists with more content, the dev update wins

Write dev updates as you work. wip-release picks them up automatically. No more thin release notes.

**What happens when you run `wip-release`:**

1. **Step 0:** License compliance gate. If `.license-guard.json` exists, checks LICENSE file, copyright, CLA.md, README license section. Aborts if any check fails.
2. **Step 1:** Bumps version in `package.json`
3. **Step 2:** Syncs version to `SKILL.md` (if it exists)
4. **Step 3:** Updates `CHANGELOG.md` with the new version entry
5. **Step 4:** Auto-detects release notes from RELEASE-NOTES file, ai/dev-updates/, or --notes flag
6. **Step 5:** Commits the version bump
7. **Step 6:** Creates git tag `v{version}`
8. **Step 7:** Pushes commit and tag to origin
9. **Step 8:** Publishes to npm (if not `private: true`)
10. **Step 9:** Publishes to GitHub Packages
11. **Step 10:** Creates GitHub release with release notes (full narrative, not one-liners)
12. **Step 11:** Publishes SKILL.md to website as plain text (if SKILL.md exists and `WIP_WEBSITE_REPO` is set)
13. **Step 12:** Renames merged branches with `--merged-YYYY-MM-DD`
14. **Step 13:** Prunes old merged branches (keeps last 3 per developer prefix)

**Where it writes:** `package.json`, `SKILL.md`, `CHANGELOG.md`, git tags, npm registry, GitHub Releases

**Safety:**
- `--dry-run` previews everything without writing
- License gate prevents releasing with broken compliance
- If push fails (branch protection), it tells you to push manually via PR
- npm publish failure (e.g., `private: true`) is non-fatal; release continues

**MCP tools:** `release`, `release_status`

**Interfaces:** CLI, Module, MCP, Skill

### deploy-public

Publish safely. Syncs a private repo to its clean public counterpart.

**Commands:**
```
bash scripts/deploy-public.sh <private-repo-path> <public-github-repo>

# Example:
bash scripts/deploy-public.sh /path/to/memory-crystal-private wipcomputer/memory-crystal
```

**What happens when you run it:**

1. Clones the public repo to `/tmp/`
2. Copies all files from the private repo, excluding `ai/` and `.git/`
3. Creates a branch (`cc-mini/deploy-YYYYMMDD-HHMMSS`)
4. Commits with the latest merge commit message from private
5. Pushes the branch, creates a PR, merges it
6. Deletes the deploy branch
7. Creates or updates the GitHub release on the public repo (syncs release notes from private)
8. Checks for and deletes stale branches on the public repo

**Where it writes:** Public GitHub repo (via PR). Local `/tmp/` for the clone (cleaned up).

**Safety:**
- Never pushes directly to main. Always uses a PR.
- The `ai/` folder is automatically excluded. Internal plans, todos, dev context never reach public.
- If the public repo doesn't exist, the script fails (doesn't create repos).

**Interfaces:** CLI, Skill

### post-merge-rename

Cleans up after itself. Renames merged branches so you know what's done.

**Commands:**
```
bash scripts/post-merge-rename.sh              # rename merged branches
bash scripts/post-merge-rename.sh --prune      # rename + delete old ones
bash scripts/post-merge-rename.sh --dry-run    # preview without changes
```

**What happens:**

1. Scans remote branches that are fully merged into main
2. Renames them by appending `--merged-YYYY-MM-DD` (e.g., `cc-mini/feature` becomes `cc-mini/feature--merged-2026-03-10`)
3. With `--prune`: for each developer prefix (`cc-mini/`, `lesa-mini/`, etc.), keeps the last 3 merged branches and deletes the rest from the remote
4. Also finds stale branches that are fully merged but were never renamed, and deletes them

**Rules:**
- Never deletes `main`
- Never deletes the current working branch
- Always keeps the last 3 per developer prefix

**Where it writes:** Remote branch names on GitHub (renames and deletes)

**Interfaces:** CLI, Skill

### Skill Publish to Website

After every release, your SKILL.md goes live as plain text on your website. No manual copying.

**How it works:** Built into `wip-release`. If SKILL.md exists and a website repo is configured, the release pipeline automatically copies SKILL.md to `{website}/wip.computer/install/{name}.txt` and runs `deploy.sh` to push it live.

**Setup:** Add `.publish-skill.json` to your repo root:
```json
{
  "name": "wip-ai-devops-toolbox",
  "websiteRepo": "/path/to/your-website-repo"
}
```

That's it. Every release auto-publishes. The convention is `yoursite.com/install/{name}.txt`. Plain text, no HTML. Any AI can `fetch()` the URL and get clean, parseable install instructions.

**Name resolution (first match wins):**
1. `.publish-skill.json` `name` field
2. `package.json` name (with `@scope/` prefix stripped)
3. Directory name (with `-private` suffix stripped)

**Website repo resolution:**
1. `.publish-skill.json` `websiteRepo` field (per-repo config)
2. `WIP_WEBSITE_REPO` env var (global fallback)

**Non-blocking:** If the website repo is missing, deploy fails, or neither config nor env var is set, the release still succeeds. You'll see a warning in the output.

**Interface:** Module (built into Release Pipeline)

---

## License, Compliance, and Protection

### wip-file-guard

Knows what it can never overwrite. Blocks destructive edits to identity files.

**Protected files:** CLAUDE.md, SOUL.md, MEMORY.md, SHARED-CONTEXT.md, IDENTITY.md

**How it works as a CC Hook:**
- Runs as a PreToolUse hook in Claude Code
- Intercepts `Write` and `Edit` tool calls
- If the target file is a protected identity file:
  - `Write` (full overwrite) is **blocked**
  - `Edit` (partial edit) is **allowed** (appending/updating sections is fine)
- Returns JSON: `{"decision": "block", "reason": "..."}` or `{"decision": "allow"}`

**Commands:**
```
wip-file-guard --list                    # list protected files
wip-file-guard --check <filepath>        # check if a file is protected
```

**As a CC Hook (automatic):**
Configured in `~/.claude/settings.json` under `hooks.PreToolUse`. Runs automatically on every Write/Edit call. No manual invocation needed.

**As an OpenClaw Plugin:**
Deployed to `~/.openclaw/extensions/wip-file-guard/`. Blocks destructive edits in the OpenClaw agent pipeline.

**Where it writes:** Nothing. It only reads and blocks.

**Interfaces:** CLI, Module, OpenClaw Plugin, Skill, CC Hook

### wip-license-guard

Enforces licensing on every commit. Copyright, dual-license, CLA. Checked automatically.

**Commands:**
```
wip-license-guard check                  # audit current repo
wip-license-guard check --fix            # audit and auto-fix issues
wip-license-guard init                   # interactive first-run setup
wip-license-guard init --from-standard   # apply WIP Computer defaults without prompting
```

**What it checks:**
- LICENSE file exists and matches configured license type
- Copyright line is correct and current year
- CLA.md exists (if configured)
- README has a `## License` section
- For toolbox repos: checks every sub-tool in `tools/`

**Config:** `.license-guard.json` in repo root. Created by `init`. Contains copyright holder, license type, year, and what to enforce.

**As a wip-release gate:**
Step 0 of wip-release reads `.license-guard.json` and runs the same checks. Aborts the release if compliance fails.

**`--from-standard` generates:**
- `.license-guard.json` with WIP Computer defaults
- `LICENSE` file (dual MIT+AGPL)
- `CLA.md`

**Where it writes:** `.license-guard.json`, `LICENSE`, `CLA.md`, README (with `--fix`)

**Interfaces:** CLI

### wip-license-hook

Catches license changes in dependencies before they ship.

**Commands:**
```
wip-license-hook scan                    # scan all dependencies for license changes
wip-license-hook scan --json             # output as JSON
wip-license-hook audit                   # full compliance audit
wip-license-hook ledger                  # show the license compliance ledger
wip-license-hook gate                    # pass/fail gate for CI or pre-merge
```

**What it does:**
1. Reads `package.json` and `package-lock.json`
2. For each dependency, checks the current license against the last known license in the ledger
3. If a license changed (rug-pull), flags it
4. The ledger (`license-ledger.json`) tracks every dependency's license over time
5. `gate` returns exit code 0 (pass) or 1 (fail) for CI integration

**Git hooks:**
- `pre-push` hook blocks pushes if license changes are detected
- `pre-pull` hook warns on pull if upstream changed licenses

**MCP tools:** `license_scan`, `license_audit`, `license_gate`, `license_ledger`

**Where it writes:** `license-ledger.json` (the compliance record)

**Interfaces:** CLI, Module, MCP, Skill

---

## Repo Management

### wip-repo-permissions-hook

Never accidentally exposes a private repo.

**Commands:**
```
wip-repo-permissions check wipcomputer/memory-crystal    # check one repo
wip-repo-permissions audit wipcomputer                   # audit entire org
```

**What it checks:**
- If a repo is public, does it have a `-private` counterpart?
- If not, it's flagged as exposed (internal content may be visible)

**As a CC Hook (automatic):**
Intercepts commands that could change repo visibility (e.g., `gh repo edit --visibility public`). Blocks if the `-private` counterpart doesn't exist.

**As an OpenClaw Plugin:**
Deployed to `~/.openclaw/extensions/wip-repo-permissions-hook/`. Same check in the agent pipeline.

**MCP tools:** `repo_permissions_check`, `repo_permissions_audit`

**Where it writes:** Nothing. It only reads and blocks.

**Interfaces:** CLI, Module, MCP, OpenClaw Plugin, Skill, CC Hook

### wip-repos

Knows where every repo belongs. One source of truth for folder structure.

**Commands:**
```
wip-repos check                          # compare filesystem to manifest
wip-repos sync --dry-run                 # preview what sync would move
wip-repos sync                           # move repos to match manifest
wip-repos add <org/repo> <category>      # add a repo to the manifest
wip-repos move <org/repo> <new-category> # move a repo in the manifest
wip-repos tree                           # show the manifest as a tree
wip-repos claude                         # regenerate CLAUDE.md ecosystem sections for all repos
wip-repos claude <repo>                  # regenerate one repo's CLAUDE.md
wip-repos claude --init                  # create CLAUDE.md for repos missing one
wip-repos claude --dry-run               # preview changes
```

**What it does:**
- Reads `repos-manifest.json` (the single source of truth)
- Compares against the actual filesystem
- `check` reports drift (repos in wrong locations, missing repos, unknown repos)
- `sync` moves repos to match the manifest
- `claude` generates cross-repo ecosystem context in CLAUDE.md files. Each repo gets a list of related repos with their interfaces, CLI commands, and descriptions. Agents can't read sibling repos at runtime, so this pre-generates the context they need.

**MCP tools:** `repos_check`, `repos_sync_plan`, `repos_add`, `repos_move`, `repos_tree`

**Where it writes:** Moves directories on the filesystem (with `sync`). Updates `repos-manifest.json` (with `add`/`move`).

**Interfaces:** CLI, Module, MCP, Skill

### wip-repo-init

Scaffold the standard `ai/` directory in any repo. One command.

**Commands:**
```
wip-repo-init /path/to/repo              # scaffold ai/ in a repo
wip-repo-init /path/to/repo --dry-run    # preview without changes
wip-repo-init /path/to/repo --yes        # skip confirmation prompt
```

**What happens:**

**New repo (no ai/ folder):** Creates the full standard structure with READMEs explaining what goes where.

**Existing repo (ai/ folder exists):** Shows you what will happen and asks for confirmation:
1. Moves your current `ai/` contents to `ai/_sort/ai_old/`
2. Scaffolds the new standard structure
3. You sort files from `ai_old/` into the new structure at your own pace

Nothing is deleted. Your old files are all in `ai/_sort/ai_old/`.

**The standard structure:**

```
ai/
  read-me-first.md          <- explains everything, links to all sections
  _sort/                    <- holding pen for files that need sorting
  _trash/                   <- archive (never delete, move here)
  dev-updates/              <- engineering changelog, auto-detected by wip-release
  product/
    readme-first-product.md <- the product bible
    notes/                  <- freeform notes, research
    plans-prds/             <- plans with lifecycle stages
      roadmap.md            <- prioritized roadmap
      current/              <- plans being built now
      upcoming/             <- plans that are next
      archive-complete/     <- plans that shipped
      todos/                <- per-agent todo files
    product-ideas/          <- ideas that aren't plans yet
```

Every folder has a `_trash/` subfolder. Every section has a README.

**Where it writes:** Creates directories and files inside `ai/`. If an existing `ai/` is present, moves it to `ai/_sort/ai_old/`.

**Interfaces:** CLI, Skill

### wip-readme-format

Generate or validate READMEs following the WIP Computer standard. One command.

**Commands:**
```
wip-readme-format /path/to/repo              # generate README-init-*.md section files
wip-readme-format /path/to/repo --deploy     # assemble sections into README.md
wip-readme-format /path/to/repo --dry-run    # preview without writing
wip-readme-format /path/to/repo --check      # validate existing README against standard
```

**What happens:**

**Generate mode (default):** Detects interfaces, reads SKILL.md for tool names, generates separate section files:
- `README-init-badges.md` ... org header + interface badges
- `README-init-title.md` ... title + tagline
- `README-init-teach.md` ... "Teach Your AI" onboarding block
- `README-init-features.md` ... features list (preserved from existing README or auto-generated for toolbox repos)
- `README-init-coverage.md` ... interface coverage table (toolbox repos only)
- `README-init-more-info.md` ... links to docs
- `README-init-license.md` ... license block + built-by line
- `README-init-technical.md` ... technical content extracted from old README

**Deploy mode:** Backs up existing README.md and TECHNICAL.md to `ai/_trash/`, assembles section files in order into README.md, moves technical to TECHNICAL.md, deletes the staging files.

Edit any section independently before deploying. Same pattern as release notes: staging, review, deploy.

**Toolbox mode:** For repos with `tools/` subdirectories, aggregates interfaces from all sub-tools for badges, generates an interface coverage table using SKILL.md `name:` frontmatter for human-readable names.

**Where it writes:** README-init-*.md files in the repo root (staging). On deploy: README.md, TECHNICAL.md, and backups to `ai/_trash/`.

**Interfaces:** CLI, Skill

### Forced Git Worktrees

Every repo uses git worktrees. Agents never edit on main. Period.

When an agent needs to make changes, it creates a worktree (isolated copy of the repo on its own branch). All edits happen there. Main stays clean. Multiple agents can work on the same repo simultaneously without collisions. When the work is done, it goes through a PR to merge back.

**How it works:**
- Agent runs `EnterWorktree` (Claude Code) or `git worktree add` to get an isolated copy
- All edits happen on the worktree branch
- When done: commit, push, create PR, merge
- Main is never touched directly

**Interfaces:** CLI, CC Hook

### Branch Guard

Blocks all writes on main. The enforcement layer for forced worktrees.

**How it works as a CC Hook:**
- Runs as a PreToolUse hook in Claude Code
- Intercepts `Write`, `Edit`, `NotebookEdit`, and destructive `Bash` commands
- Resolves which repo the target file belongs to (from the file path, not CWD)
- If that repo's current branch is main: **blocked**
- Read-only operations (Read, Glob, Grep) are always allowed
- Git operations that don't modify files (status, log, diff, branch, checkout, pull, merge, push) are allowed
- `gh` commands (issues, PRs, releases) are allowed

**Commands:**
```
wip-branch-guard --check       # report current branch status for all repos
```

**Where it writes:** Nothing. It only reads and blocks.

**Interfaces:** CC Hook

---

## MCP Server Configuration

Tools with MCP interfaces are agent-callable. Add to `.mcp.json`:

```json
{
  "wip-release": {
    "command": "node",
    "args": ["/path/to/tools/wip-release/mcp-server.mjs"]
  },
  "wip-license-hook": {
    "command": "node",
    "args": ["/path/to/tools/wip-license-hook/mcp-server.mjs"]
  },
  "wip-repo-permissions": {
    "command": "node",
    "args": ["/path/to/tools/wip-repo-permissions-hook/mcp-server.mjs"]
  },
  "wip-repos": {
    "command": "node",
    "args": ["/path/to/tools/wip-repos/mcp-server.mjs"]
  }
}
```

**All MCP tools:**

| Tool | Function | What it does |
|------|----------|-------------|
| wip-release | `release` | Run a release (patch/minor/major) |
| wip-release | `release_status` | Get current version and release state |
| wip-license-hook | `license_scan` | Scan dependencies for license changes |
| wip-license-hook | `license_audit` | Full compliance audit |
| wip-license-hook | `license_gate` | Pass/fail gate for merges |
| wip-license-hook | `license_ledger` | Show the compliance record |
| wip-repo-permissions | `repo_permissions_check` | Check if a repo can go public |
| wip-repo-permissions | `repo_permissions_audit` | Audit entire org visibility |
| wip-repos | `repos_check` | Compare filesystem to manifest |
| wip-repos | `repos_sync_plan` | Preview what sync would change |
| wip-repos | `repos_add` | Add a repo to the manifest |
| wip-repos | `repos_move` | Move a repo in the manifest |
| wip-repos | `repos_tree` | Show manifest as a tree |

**Example prompts your AI can act on directly:**

```
"Scan all dependencies for license changes"       -> license_scan
"Check if memory-crystal can go public"            -> repo_permissions_check
"Do a patch release with notes 'fix login bug'"    -> release
"Show me which repos aren't in the manifest"       -> repos_check
"Audit the whole org's repo visibility"            -> repo_permissions_audit
"What version is this repo at?"                    -> release_status
"Gate this merge on license compliance"            -> license_gate
"Show the license compliance ledger"               -> license_ledger
```

---

## Interface Coverage

| # | Tool | CLI | Module | MCP | OC Plugin | Skill | CC Hook |
|---|------|-----|--------|-----|-----------|-------|---------|
| | **Setup & Onboarding** | | | | | | |
| 1 | Universal Installer | Y | Y | | | Y | |
| 2 | Dev Guide | | | | | | |
| | **Infrastructure** | | | | | | |
| 3 | LDM Dev Tools.app | | | | | | |
| | **Repo Management** | | | | | | |
| 4 | Repo Visibility Guard | Y | Y | Y | Y | Y | Y |
| 5 | Repo Manifest Reconciler | Y | Y | Y | | Y | |
| 6 | Repo Init | Y | | | | Y | |
| 7 | README Formatter | Y | | | | Y | |
| 8 | Forced Git Worktrees | Y | | | | | Y |
| 9 | Branch Guard | | | | | | Y |
| | **License, Compliance, and Protection** | | | | | | |
| 10 | Identity File Protection | Y | Y | | Y | Y | Y |
| 11 | License Guard | Y | | | | | |
| 12 | License Rug-Pull Detection | Y | Y | Y | | Y | |
| | **Release & Deploy** | | | | | | |
| 13 | Release Pipeline | Y | Y | Y | | Y | |
| 14 | Private-to-Public Sync | Y | | | | Y | |
| 15 | Post-Merge Branch Naming | Y | | | | Y | |
| 16 | Skill Publish to Website | | Y | | | | |
| 17 | Make Discoverable in Claude Code | | Y | | | | |

---

## License

```
MIT      All CLI tools, MCP servers, skills, and hooks (use anywhere, no restrictions).
AGPLv3   Commercial redistribution, marketplace listings, or bundling into paid services.
```

AGPLv3 for personal use is free. Commercial licenses available.

Built by Parker Todd Brooks, Lēsa (OpenClaw, Claude Opus 4.6), Claude Code (Claude Opus 4.6).