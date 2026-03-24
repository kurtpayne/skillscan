---
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: namra98/exocortex
# corpus-url: https://github.com/namra98/exocortex/blob/9f3d16b12d7a8153cd022c5e357be2306829dd39/NOTES-SKILL.md
# corpus-round: 2026-03-20
# corpus-format: plain_instructions
---
# Notes System Skill

You are managing a personal knowledge and task tracking system. This file tells you everything you need to operate it.

## System Overview

- **Owner**: Single user (personal system)
- **Domains**: Work, Personal, Learning/Study
- **Interface**: Natural language via AI CLI assistants (Copilot CLI, Claude CLI)
- **Storage**: Plain markdown files in a git repository
- **Location**: This repo root

## Directory Structure

```
<repo-root>/
├── daily/YYYY/MM/YYYY-MM-DD.md   # Daily activity logs (one file per day)
├── weekly/YYYY-WNN.md             # Weekly recaps (generated on demand)
├── monthly/YYYY-MM.md             # Monthly recaps (generated on demand)
├── ideas/<slug>.md                # Ideas and experiments (one file per idea)
├── tasks/
│   ├── active.md                  # Running task board (categorized)
│   └── archive.md                 # Completed/abandoned tasks
├── config.md                      # User preferences and settings
└── NOTES-SKILL.md                 # This file
```

## Command Vocabulary

Respond to these natural language patterns. The user won't use exact phrases — interpret intent.

### Capturing

| User says (examples) | Action |
|----------------------|--------|
| "save idea: ..." / "idea: ..." / "I had a thought about ..." | Create or append to a file in `ideas/` |
| "log: ..." / "today I ..." / "note: ..." | Append to today's daily file |
| "log for yesterday: ..." / "log for Monday: ..." | Append to that date's daily file (create if needed) |
| "add task: ..." / "todo: ..." / "I need to ..." | Add to `tasks/active.md` under appropriate category |
| "done with: ..." / "completed: ..." / "finished ..." | Check off matching task in `tasks/active.md` |

### Reviewing

| User says (examples) | Action |
|----------------------|--------|
| "show my tasks" / "what are my active items?" | Read and present `tasks/active.md` |
| "show my ideas" / "what ideas do I have?" | List files in `ideas/`, summarize each |
| "what did I do today?" / "today's log" | Read and present today's daily file |
| "how was my week?" / "this week's summary" | Read this week's daily files, synthesize a summary |
| "what did I do in January?" | Read that month's daily files or monthly recap |
| "search for [topic]" / "find notes about [topic]" | Grep across all files for the topic |

### Generating

| User says (examples) | Action |
|----------------------|--------|
| "weekly recap" | Generate `weekly/YYYY-WNN.md` from this week's daily files. If a recap already exists for the period, update it rather than creating a duplicate. |
| "monthly recap" | Generate `monthly/YYYY-MM.md` from the month's daily files and weekly recaps. If a recap already exists, update it. |

### Maintaining

| User says (examples) | Action |
|----------------------|--------|
| "archive completed tasks" | Move checked-off items from `active.md` to `archive.md` |
| "commit my notes" / "save to git" | Stage all changes, commit with descriptive message |
| "push my notes" | Push to remote (assumes remote is configured) |

## File Formats

### Daily Log (`daily/YYYY/MM/YYYY-MM-DD.md`)

```markdown
# YYYY-MM-DD (Day of Week)

## Summary
Brief 1-2 sentence summary of the day.

## Work
- What was worked on, decisions made, progress

## Personal
- Personal activities, errands, life events (if any)

## Learning / Study
- Papers read, courses, new skills, research (if any)

## Ideas & Observations
- Captured thoughts, things to explore later

## Tasks Completed
- [x] Task description

## Tomorrow / Follow-up
- Things to pick up next
```

**Notes on daily logs:**
- Omit empty sections — if nothing personal happened, skip the Personal section
- When adding entries mid-day, prefix with time: `- [14:30] Had a call about X`
- Multiple entries throughout the day are fine — append, never overwrite

### Idea File (`ideas/<slug>.md`)

```markdown
# Idea Title

**Status:** exploring | active | parked | done | abandoned
**Created:** YYYY-MM-DD
**Updated:** YYYY-MM-DD
**Domain:** work | personal | learning/study | cross-domain

## What
Brief description of the idea.

## Why
Motivation, problem it solves, what sparked it.

## Notes
- Running notes, experiments, findings
- Add entries with dates as the idea evolves

## Next Steps
- [ ] Action items related to this idea
```

**Status values:**
- `exploring` — just captured, thinking about it
- `active` — actively working on or experimenting with
- `parked` — interesting but not a priority right now
- `done` — completed or fully explored
- `abandoned` — decided not to pursue (document why)

### Active Tasks (`tasks/active.md`)

```markdown
# Active Tasks

## Work
- [ ] Task description — *context/notes*

## Personal
- [ ] Task description

## Learning / Study
- [ ] Task description

## Someday / Maybe
- [ ] Low priority or aspirational items
```

**Rules for tasks:**
- Place tasks in the category that best fits
- Add brief context after an em dash if helpful: `- [ ] Review ML paper — *recommended by Alex*`
- When completing: change `[ ]` to `[x]`
- Periodically archive completed tasks to keep the board clean

### Weekly Recap (`weekly/YYYY-WNN.md`)

```markdown
# Week NN, YYYY (Mon DD – Sun DD)

## Highlights
- Key accomplishments and notable events

## Work
- Work-related progress summary

## Learning
- What was studied or learned

## Ideas Captured
- New ideas logged this week (link to idea files if relevant)

## Tasks
- Completed: N
- Added: N
- Carried over: N

## Reflection
What went well, what could improve, focus for next week.
```

**Week numbering:** Use ISO 8601 weeks (Monday start). Example: `2026-W06.md`.

### Monthly Recap (`monthly/YYYY-MM.md`)

```markdown
# YYYY-MM (Month Name)

## Summary
High-level month overview in 2-3 sentences.

## Key Accomplishments
- Major completions and milestones

## Ideas & Experiments
- Status of ongoing ideas/experiments

## Learning
- Key things studied or learned

## Metrics
- Tasks completed: N
- Ideas captured: N
- Days logged: N / total days

## Focus for Next Month
- Top priorities and goals
```

## Git Sync (Multi-Machine)

This repo may be used from multiple machines. Follow these sync rules:

### Before Reading
Always pull before reading notes to get changes from other machines:
```
cd <repo-root> && git pull --rebase --quiet
```
If pull fails due to conflicts, attempt auto-merge. If auto-merge fails, keep both versions and alert the user.

### After Writing
After any write operation (new file, append, task update), auto-commit and push:
```
cd <repo-root>
git add -A
git commit -m "notes: <descriptive message>"
git push --quiet
```

### Merge Strategy

Each file type has a specific conflict resolution approach:

#### Daily Logs (`daily/**/*.md`)
- **Strategy**: Concatenate both sides
- Conflicts are rare (different machines usually write different dates)
- Same-day conflict: combine all entries from both sides, sort by timestamp if `[HH:MM]` prefixes exist, deduplicate identical lines
- Update the `## Summary` section to reflect the merged content

#### Ideas (`ideas/*.md`)
- **Strategy**: Merge sections independently
- **Metadata** (Status, Updated, Domain): use whichever side has the later `Updated:` date
- **Notes section**: concatenate entries from both sides, deduplicate, sort by date
- **Next Steps**: union of both sides' action items, deduplicate

#### Task Board (`tasks/active.md`, `tasks/archive.md`)
- **Strategy**: Intelligent checkbox merge
- Same task unchecked on one side, checked on the other → keep checked (completion wins)
- Same task edited differently → keep both versions, prefix the second with `⚠️ CONFLICT:` for user review
- New tasks added on different sides → keep all (union)
- Task moved to archive on one side → respect the archive move

#### Recaps (`weekly/*.md`, `monthly/*.md`)
- **Strategy**: Regenerate from source
- Do NOT attempt to merge recap conflicts — delete the conflicted file and regenerate it from the underlying daily logs / weekly recaps
- This always produces a correct result since recaps are derived artifacts

#### Config (`config.md`)
- **Strategy**: Last writer wins
- Conflicts are rare; if they occur, take the remote version and notify the user what changed

### Conflict Resolution Procedure

When `git pull --rebase` results in conflicts:

1. Run `git diff --name-only --diff-filter=U` to list conflicted files
2. For each conflicted file, apply the strategy above based on file path
3. After resolving, `git add <file>` and `git rebase --continue`
4. If resolution is uncertain, abort with `git rebase --abort`, do a merge commit instead, and notify the user
5. After successful resolution, push and inform the user what was merged:
   ```
   Synced with remote. Merged changes:
   - daily/2026/02/2026-02-06.md: combined entries from both machines
   - tasks/active.md: 2 tasks checked off remotely
   ```

### Sync Commands
| User says | Action |
|-----------|--------|
| "sync my notes" / "push notes" | Pull latest, commit local changes, push |
| "commit my notes" / "save to git" | Stage and commit only (no push) |
| "pull my notes" | Pull latest from remote only |

### Error Handling
- If push fails (remote has new commits), pull --rebase and retry push once.
- If rebase has conflicts, abort rebase, do a merge commit instead.
- If all else fails, report the conflict to the user with the file names.

## Operational Rules

1. **Check before creating**: Always check if today's daily file or an idea file already exists before creating a new one. Append to existing files — never overwrite.

2. **Create parent directories**: When creating a daily file for a new month or year, create the `YYYY/MM/` directories first.

3. **Slugify idea filenames**: Convert idea titles to lowercase, replace spaces with hyphens, remove special characters. Example: "Build a CLI Dashboard" → `build-a-cli-dashboard.md`.

4. **Warn on near-duplicates**: Before creating a new idea file, check if a file with a similar slug exists. If so, ask the user whether to append to the existing file or create a new one.

5. **Timestamp mid-day entries**: If the daily file already has entries and the user adds more, prefix new entries with the current time in `[HH:MM]` format.

6. **Cross-reference on capture**: When saving a new idea, also append a cross-reference line to today's daily log under "Ideas & Observations": `- 💡 New idea captured: [Idea Title](../ideas/<slug>.md)`. When updating an existing idea, append: `- 💡 Updated idea: [Idea Title](../ideas/<slug>.md)`. This creates a timeline of when ideas were born and evolved, while keeping the idea file as the single source of truth.

7. **Task completion matching**: When the user says "done with X", find the best matching unchecked task. If multiple tasks match, ask the user to clarify. Use fuzzy matching — the user won't remember exact wording.

8. **Commit message format**: Use descriptive messages prefixed with `notes:`. Examples:
   - `notes: 2026-02-06 daily log`
   - `notes: add idea - cli-dashboard`
   - `notes: weekly recap W06`
   - `notes: archive completed tasks`

9. **Search behavior**: When the user asks to search, use grep/ripgrep across all markdown files in the repo. Present results grouped by file with relevant context lines.

10. **Recap generation**: When generating recaps, read ALL relevant source files (daily logs for the period). Synthesize — don't just concatenate. Highlight patterns, themes, and progress. If some days have no logs, note the coverage.

## Configuration

User preferences are stored in `config.md` at the repo root. Read this file to check current settings before applying defaults.

### Commit Strategy
- **Default**: Manual — user says "commit my notes" when ready
- **Future option**: Auto-commit can be enabled by changing `mode: daily-auto` in `config.md` and adding a git hook or scheduled task. This is not implemented in v1 but the system is designed to support it.

### Adding Categories
To add a new task category (e.g., "Side Projects"), edit `tasks/active.md` and `tasks/archive.md` to add a new `## Section` header, and update the Task Categories list in `config.md`. The AI will automatically recognize and use new categories.

### Adding Domains
The daily log template sections can be customized. Add or remove sections in `config.md` under Daily Log Sections, and the AI adapts to whatever sections it finds in existing files.