---
name: business growth bundle
version: "1.0"
description: "4 business growth agent skills and plugins for Claude Code, Codex, Gemini CLI, Cursor, OpenClaw. Customer success (heal
category: community
# corpus-label: benign
# corpus-source: github-scrape-r4
# corpus-repo: alirezarezvani/claude-skills
# corpus-url: https://github.com/alirezarezvani/claude-skills/blob/HEAD/.gemini/skills/business-growth-bundle/SKILL.md
# corpus-round: 2026-03-21
# corpus-format: markdown_fm
---
# Business & Growth Skills

4 production-ready skills for customer success, sales, and revenue operations.

## Quick Start

### Claude Code
```
/read business-growth/customer-success-manager/SKILL.md
```

### Codex CLI
```bash
npx agent-skills-cli add alirezarezvani/claude-skills/business-growth
```

## Skills Overview

| Skill | Folder | Focus |
|-------|--------|-------|
| Customer Success Manager | `customer-success-manager/` | Health scoring, churn prediction, expansion |
| Sales Engineer | `sales-engineer/` | RFP analysis, competitive matrices, PoC planning |
| Revenue Operations | `revenue-operations/` | Pipeline analysis, forecast accuracy, GTM metrics |
| Contract & Proposal Writer | `contract-and-proposal-writer/` | Proposal generation, contract templates |

## Python Tools

9 scripts, all stdlib-only:

```bash
python3 customer-success-manager/scripts/health_score_calculator.py --help
python3 revenue-operations/scripts/pipeline_analyzer.py --help
```

## Rules

- Load only the specific skill SKILL.md you need
- Use Python tools for scoring and metrics, not manual estimates