---
title: LLM Council Skill - Multi-Agent Project Planning
anchor: Claude Skill that orchestrates multiple LLMs as a council for collective intelligence and project planning
tags: [council, multi-agent, ai, planning, claude-code, skill, collective-intelligence, opencode, gpt-4, claude, gemini]
description: LLM Council orchestrates multiple LLMs as a council to achieve collective intelligence through peer review and synthesis. Perfect for planning full projects with diverse perspectives.
source_url: https://github.com/shuntacurosu/llm_council_skill
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: bjesuiter/nb-references
# corpus-url: https://github.com/bjesuiter/nb-references/blob/2a0ac419091eb294e018f698f03524025e253246/llm-council-skill.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

## Summary

**LLM Council** is a Claude Skill that orchestrates multiple LLMs as a "council" instead of querying a single LLM. It derives conclusions through a 3-stage process: Opinion Collection → Peer Review → Final Synthesis.

Inspired by Andrej Karpathy's llm-council concept.

## The 3-Stage Process

### Stage 1: Opinion Collection
Each council member (LLM) independently responds to the query:
- Normal mode: Text-based responses
- Worktree mode: Each member generates code changes in independent git worktrees

### Stage 2: Peer Review
All members anonymously review other members' responses:
- Responses anonymized as "Response A", "Response B", etc.
- Each member evaluates and ranks all responses
- Aggregate scores calculate overall rankings

### Stage 3: Final Synthesis
The chairman model integrates all opinions and reviews:
- Considers strengths of each member's opinion
- Reflects issues identified in peer review
- Analyzes consensus patterns and differences
- Provides clear final response representing collective intelligence

## Key Features

- **Git Worktree Integration** — Each member works in independent git worktrees
- **Anonymous Review** — Fair evaluation without bias
- **OpenCode CLI Integration** — Generate and edit code directly
- **Flexible Configuration** — Configure member models and chairman model
- **Real-time Dashboard** — TUI dashboard showing progress and live logs
- **Conversation History** — Save all council sessions in JSON

## Dashboard

Monitor council sessions in real-time:
- **Stage Flow** — Visual progress ([1] Responses → [2] Rankings → [3] Synthesis)
- **Member Status** — 🟢 Active, ⏳ Waiting, ✅ Completed, ❌ Error
- **Live Logs** — Latest 15 log entries scrolling
- **Statistics** — API calls, errors, session info

Enable with `--dashboard` or `-d` flag.

## Setup

### Environment Variables

```bash
cd scripts
cp .env.example .env
```

Edit `scripts/.env`:

```bash
# Council Members (comma-separated)
COUNCIL_MODELS=opencode/openai/gpt-4,opencode/anthropic/claude-3-5-sonnet,opencode/google/gemini-pro

# Chairman Model (performs final synthesis)
CHAIRMAN_MODEL=opencode/anthropic/claude-3-5-sonnet

# Optional: Title generation model
# TITLE_MODEL=opencode/anthropic/claude-3-5-haiku
```

### Requirements

- **Git repository** — Must run within a git repo (uses worktrees)
- **OpenCode CLI** — Must be installed and configured
- **Python 3.8+**

## Usage

### Basic Question
```bash
python scripts/run.py council_skill.py "What's the optimal caching strategy?"
```

### Code Fix (Diff Only)
```bash
python scripts/run.py council_skill.py --dry-run "Fix the bug in buggy.py"
```

### Code Fix (Auto-Merge with Confirmation)
```bash
python scripts/run.py council_skill.py --auto-merge --confirm "Add error handling"
```

### Continue Conversation
```bash
python scripts/run.py council_skill.py --continue 1 "Tell me more"
```

### View History
```bash
python scripts/run.py council_skill.py --list
```

## Merge Options (with --worktrees)

| Option | Description |
|--------|-------------|
| `--auto-merge` | Auto-merge top-ranked proposal |
| `--merge N` | Merge member N's proposal |
| `--dry-run` | Show diff without merging |
| `--confirm` | Confirm before merge |
| `--no-commit` | Apply without staging |

## For Project Planning

This is perfect for your **Dynamic Interface Experiment** and **Agent Interfaces with HATEOAS** ideas:

### Example: Plan a New Feature
```bash
python scripts/run.py council_skill.py "Plan a HATEOAS API for a task management app with decision primitives, range inputs, and chart visualizations"
```

The council will:
1. Each LLM proposes an architecture
2. Members review and rank each proposal
3. Chairman synthesizes best approach

### Example: Plan Rust File Sync App
```bash
python scripts/run.py council_skill.py "Plan a Rust-based macOS file sync app with SwiftUI frontend, APFS cloning, and daemon mode for unattended operation"
```

## Configuration Examples

### Small Council (Fast)
```bash
COUNCIL_MODELS=opencode/openai/gpt-4,opencode/anthropic/claude-3-5-sonnet
CHAIRMAN_MODEL=opencode/anthropic/claude-3-5-sonnet
```

### Large Council (Thorough)
```bash
COUNCIL_MODELS=opencode/openai/gpt-4-turbo,opencode/anthropic/claude-3-opus,opencode/google/gemini-pro,openai/o1
CHAIRMAN_MODEL=opencode/anthropic/claude-3-opus
```

## Project Structure

```
llm_council/
├── scripts/
│   ├── council_skill.py    # Main entry point
│   ├── api.py              # High-level API
│   ├── cli.py              # CLI interface
│   ├── council.py          # 3-stage logic
│   ├── dashboard.py        # TUI dashboard
│   ├── worktree_manager.py # Git worktree management
│   ├── opencode_client.py  # OpenCode CLI client
│   ├── prompts/
│   │   └── templates.py    # Prompt templates
│   ├── data/
│   │   ├── conversations/  # JSON history
│   │   └── logs/           # Execution logs
│   └── worktrees/          # Git worktrees
├── skill.json              # Claude Skill definition
└── README.md
```

## Related Concepts

- **Andrej Karpathy's llm-council** — Original inspiration
- **Multi-Agent Planning** — Reddit discussion on Codex councils
- **Council of Agents** — The Engineering Manager on group thinking
- **Your Agent HATEOAS Idea** — Perfect use case for council planning

## For Your Skills

This could become a **skill in your agent-skills repo**:

```
agent-skills/
└── skills/
    └── council-planning/   # LLM Council wrapper
        ├── SKILL.md
        └── scripts/
```

## Comparison: Single Agent vs Council

| Aspect | Single Agent | Council |
|--------|--------------|---------|
| Perspectives | One model | Multiple models |
| Review | None | Peer review + ranking |
| Output | Single opinion | Synthesized consensus |
| Robustness | Depends on model | Collective intelligence |
| Speed | Fast | Slower (3 stages) |

## When to Use

**Use Council for:**
- Architecture decisions
- Complex feature planning
- Critical code reviews
- Any decision requiring diverse perspectives

**Use Single Agent for:**
- Simple tasks
- Quick iterations
- Routine coding

## Resources

- **GitHub:** https://github.com/shuntacurosu/llm_council_skill
- **Original Inspiration:** https://github.com/karpathy/llm-council
- **Reddit Discussion:** r/codex on custom skills with councils