---
name: notify-web
version: "1.0"
description: Notify the web UI when AI creates content that needs user review.
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: vogon101/KnowledgeWork
# corpus-url: https://github.com/vogon101/KnowledgeWork/blob/HEAD/skills/notify-web/SKILL.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
# Notify Web Skill

Send toast notifications to the web UI when you create content that the user should review.

## When to Use

Use this skill when you create content that requires user attention:

- New documents (summaries, analyses, reports)
- New workstreams or projects
- Meeting notes
- Any content the user should review or approve

**Do NOT use for:**

- Routine diary entries
- Memory/context updates
- Internal system files
- Incremental changes to existing files

## Usage

```bash
# Basic notification
.claude/skills/notify-web/scripts/notify-web.sh <type> "<title>" "<file-path>" ["message"]

# Examples
.claude/skills/notify-web/scripts/notify-web.sh document "Q4 Strategy Summary" "anthropic/documents/q4-strategy.md"
.claude/skills/notify-web/scripts/notify-web.sh project "New Authentication System" "anthropic/projects/auth-system/README.md" "Ready for your review"
.claude/skills/notify-web/scripts/notify-web.sh meeting-notes "Team Standup Notes" "anthropic/meetings/2026/01/standup.md"
.claude/skills/notify-web/scripts/notify-web.sh workstream "API Redesign" "anthropic/workstreams/api-redesign/README.md"
```

## Content Types

| Type | Description | Example |
|------|-------------|---------|
| `document` | General documents, summaries, analyses | Reports, briefs, research docs |
| `workstream` | New workstream created | Long-running initiatives |
| `project` | New project created | Focused deliverables |
| `meeting-notes` | Meeting notes or summaries | Standup notes, 1:1 summaries |
| `other` | Anything else worth reviewing | Miscellaneous content |

## Parameters

1. **type** (required): One of `document`, `workstream`, `project`, `meeting-notes`, `other`
2. **title** (required): Human-readable title for the notification
3. **file-path** (required): Path to the file relative to KB root (used for "Open" button)
4. **message** (optional): Additional context shown in the toast

## What Happens

1. The script calls the server's notification API
2. Connected web clients receive the notification via Socket.IO
3. A toast appears in the bottom-right corner for 10 seconds
4. User can click "Open" to navigate directly to the content

## Requirements

- Server must be running on `localhost:3004` (or `TASK_SERVICE_URL`)
- Web UI must be connected to receive notifications