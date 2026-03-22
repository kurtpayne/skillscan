---
name: skill
version: "1.0"
description: Load the best-matching skill doc from skills/ and apply it to the current task
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: s977043/river-reviewer
# corpus-url: https://github.com/s977043/river-reviewer/blob/HEAD/.claude/commands/skill.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
Find the best matching skill under `skills/` for: $ARGUMENTS

Steps:

1. Search `skills/` for the keyword using ripgrep.
2. Identify the most relevant `skills/**/skill.md`.
3. Summarize the workflow rules from that skill.
4. Apply those rules to the current task and proceed.