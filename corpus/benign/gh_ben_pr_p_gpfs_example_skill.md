---
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: ben-pr-p/gpfs
# corpus-url: https://github.com/ben-pr-p/gpfs/blob/a4490bd309a8e7ce9472f59679afb6646c1f9ece/EXAMPLE_SKILL.md
# corpus-round: 2026-03-19
# corpus-format: plain_instructions
---
# gpfs

Manage GitHub Projects via local markdown files using gpfs (gh-project-file-sync).

## Creating Issues

**Create a new issue by creating a markdown file** in any tracked project directory:

```markdown
---
title: Fix the login bug
status: Todo
assignees:
  - octocat
labels:
  - bug
priority: High
---

When users try to log in with SSO, they get a 500 error.

## Steps to reproduce
1. Go to /login
2. Click "Sign in with SSO"
3. Error appears
```

Then run `gpfs push` to sync to GitHub. The file will be updated with the assigned `id` after creation.

**Required fields:** Only `title` is required. All other fields are optional.

**File naming:** Name files descriptively (e.g., `fix-login-bug.md`). The filename doesn't affect the issue title on GitHub.

## Quick Start

```sh
# 1. Attach to an existing project
gpfs attach myorg/42

# 2. Pull existing items
gpfs pull myorg/42

# 3. Create a new issue - just create a file!
echo '---
title: My new issue
status: Todo
---

Issue description here.' > ~/.gpfs/myorg/42-project-name/my-new-issue.md

# 4. Push to GitHub
gpfs push myorg/42
```

## Available Commands

### Project Management
- `gpfs attach <owner/project-number>` - Start tracking existing project
- `gpfs detach <owner/project-number>` - Stop tracking project (keeps local files)
- `gpfs list` - List all tracked projects
- `gpfs link <owner/project-number> [path]` - Create symlink to project directory
- `gpfs unlink [path]` - Remove symlink

### Sync Operations
- `gpfs pull [owner/project-number]` - Pull from GitHub (all projects if no arg)
- `gpfs push [owner/project-number]` - Push to GitHub (all projects if no arg)
- `gpfs status [owner/project-number]` - Show sync status

### Query
- `gpfs query "<sql>"` - Query items using SQL (DuckDB)

### Daemon
- `gpfs daemon start` - Start background sync
- `gpfs daemon stop` - Stop daemon

## File Format

```yaml
---
# Auto-generated after first push (leave blank for new items)
id: PVTI_xxx
project_id: PVT_xxx

# Required
title: Fix login bug

# Optional - common fields
status: In Progress
assignees:
  - octocat
  - janedoe
labels:
  - bug
  - priority-high

# Optional - custom project fields
priority: High
sprint: Sprint 3
due_date: 2025-02-01
estimate: 5
---

Issue body in markdown.
```