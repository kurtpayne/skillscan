---
name: standup-generator
description: Generate a daily standup summary from recent git commits and open issues.
allowed-tools:
  - Bash
  - Read
  - Grep
---

## Purpose

This skill generates a concise standup summary by examining recent git activity
and open GitHub issues. It is read-only and does not modify any files.

## Usage

1. Run `git log --oneline --since=yesterday` to get recent commits.
2. Use the GitHub CLI to list open issues assigned to the current user.
3. Produce a three-section standup: **Done**, **In Progress**, **Blockers**.

## Output format

```
## Daily Standup — {date}

**Done:**
- ...

**In Progress:**
- ...

**Blockers:**
- ...
```

## Notes

This skill is read-only. It does not commit, push, or modify any files.
